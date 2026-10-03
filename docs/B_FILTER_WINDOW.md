# 后续人员 B：Filter 与 Landmark 滑动窗口

本模块位于 `src/mtc_opt/filters/`，建立在 A 已冻结的 `TrustedItem`、
`FilterBackend`、`WindowPolicy` 和 `LandmarkWindowPlan` 上。它不修改 Baseline
`src/mtc/`，也不复制 Merkle、Proof、Checkpoint、Certificate 或 Sync 实现。

## 1. 实现内容

| 后端 | 类型 | 更新方式 | 主要配置 |
| --- | --- | --- | --- |
| `BloomFilter` | 动态位数组 | 支持追加，淘汰时重建窗口 | `target_fpr`、`bits_per_item`、`hash_count` |
| `CuckooFilter` | 动态桶式指纹 | 支持插入和删除 | `fingerprint_bits`、`bucket_size`、`load_factor`、`max_kicks` |
| `XorFilter` | 静态 XOR | 密封窗口整体重建 | `fingerprint_bits`、`build_attempts`、`size_factor` |
| `FuseFilter` | 分段局部静态 XOR | 密封窗口整体重建 | `fingerprint_bits`、`build_attempts`、`segment_length` |

所有后端只使用 `TrustedItem.key`，并实现：

```python
build(items)
may_contain(item)
serialize()
deserialize(payload)
stats()
```

`False` 表示确定不存在；`True` 只表示可能存在，最终必须继续使用现有 Verifier。

## 2. 单个 Filter

```python
from mtc_opt.filters import create_filter, deserialize_filter

backend = create_filter(
    "bloom",
    {"target_fpr": 0.01, "bits_per_item": 10, "hash_count": 7, "seed": 1},
)
backend.build(trusted_items)

candidate = backend.may_contain(trusted_item)
payload = backend.serialize()
restored = deserialize_filter("bloom", payload)
assert restored.serialize() == payload
```

构建过程会去重并按规范键排序，因此相同配置、seed 和输入集合产生相同序列化结果。
统计信息包括构建/查询耗时、payload/metadata 大小、峰值 Python 分配、重试和失败次数。

## 3. FilterWindowManager

`FilterWindowManager` 消费 A 生成的 `LandmarkWindowPlan`，不重新计算 H/W/S：

```python
from mtc_opt.contracts import WindowPolicy
from mtc_opt.filters import FilterWindowManager

policy = WindowPolicy(
    active_landmarks=10,      # H
    landmarks_per_filter=4,  # W
    stride=1,                # S
)
manager = FilterWindowManager(
    policy,
    "bloom",
    {"target_fpr": 0.01, "bits_per_item": 10, "hash_count": 7},
)

update = manager.apply(landmark_window_plan, items_by_landmark)
possible = manager.may_contain(item, landmark_number=landmark_number)
```

`items_by_landmark` 是 `landmark_number -> Iterable[TrustedItem]`。应用新计划时：

1. 校验活动 Landmark 连续且所有窗口无遗漏；
2. 内容未变化的同区间 Filter 直接复用；
3. 新增或变化窗口重新构建；
4. 不再活动的 Filter 被淘汰；
5. 只有全部新 Filter 构建成功后才原子替换旧状态。

窗口状态也支持稳定持久化：

```python
payload = manager.serialize()
restored = FilterWindowManager.deserialize(payload)
```

## 4. 正确性要求

- 所有已插入 Trusted Item 的 False Negative 必须为零；
- RawHashSet 是精确 oracle，概率 Filter 的输入必须与其完全相同；
- 序列化往返后查询结果一致；
- Cuckoo 插入失败、XOR/Fuse 构建失败必须显式抛出并计数；
- 窗口不能遗漏活动 Landmark，也不能保留已淘汰窗口；
- Filter 命中后仍调用现有 Verifier，最终 false accept 必须为零。

## 5. 测试与微基准

```powershell
python -m unittest discover -s tests/mtc_opt/filters -t . -v
python tools/bench_filters.py --filter all --size 10000 --queries 10000
python tools/bench_filters.py --size 10000 100000 `
  --json results/filters.json --csv results/filters.csv
```

微基准只用于 B 的实现筛选。正式方案对比、统一 workload 和结果聚合仍由 C 的
Experiment Runner 负责。
