# A（后续分工）：Sync 与 Trust-State 语义

实现位置：`src/mtc_opt/`（优化方案总包），Baseline 仍是 `src/mtc/`（冻结，只读）。

## 交付物与目录

| 交付物 | 位置 | 说明 |
| --- | --- | --- |
| Trusted Item encoder | `mtc_opt/trust_items.py` | 统一查询键 `TrustedItem.key`（Raw 与概率 Filter 输入完全一致） |
| Raw Trust-State | `mtc_opt/trust_items.py` | `RawTrustState`：C 验证过的可信子树集合，可直接生成 oracle |
| RawHashSet（oracle） | `mtc_opt/raw_set.py` | 精确集合，实现 `FilterBackend` 与 D 的 `MembershipFilter`；FN/FP 恒为 0 |
| SyncPlan / SyncResult | `mtc_opt/sync/plan.py` | 区间覆盖 + 一致性证明 + reused/new/字节数记账 |
| Landmark 窗口计划 | `mtc_opt/sync/landmark_sync.py` | H/W/S 下的活动窗口、轮换、淘汰 |
| ProofReuseStats | `mtc_opt/sync/proof_reuse.py` | 复用/新增 Hash 数量、转换时间、证明字节数 |
| R0 冻结接口 | `mtc_opt/contracts.py` | 见下表 |

## R0 冻结接口（三人共用）

| 接口 | 关键方法 / 字段 | 归属 |
| --- | --- | --- |
| `TrustedItem` | `log_id` / `start` / `end` / `hash` / `key` | A 定义 |
| `ItemEncoder` | `encode(log_id, start, end, hash)` | A 实现（`trust_items.py`） |
| `SyncResult` | `reused` / `new` / `before_bytes` / `after_bytes` / `sync_bytes` | A 输出 |
| `FilterBackend` | `build` / `may_contain` / `serialize` / `deserialize` / `stats` | B 实现 |
| `WindowPolicy` | `active_landmarks(H)` / `landmarks_per_filter(W)` / `stride(S)` | B 实现 |
| `MetricsRecordV2` | config / latency / size / accuracy / failure / provenance | C 实现 |

## 三条硬约束

1. **单向依赖**：`mtc_opt` → `mtc`；Baseline 不 import `mtc_opt`（有契约测试兜住）。
2. **不复制实现**：本包只调用 Baseline 的哈希、MTH、Proof、Checkpoint、Certificate。
3. **统一键**：任何 Filter 与 RawHashSet 使用同一个 `TrustedItem.key`，Raw 结果是标准答案。

## 运行

```bash
python -m unittest discover -s tests/mtc_opt -t .   # A 的新测试
python -m unittest discover -s tests -t .           # 全量（Baseline + 新包）
```

## 里程碑对应

| 里程碑 | A 的产出 |
| --- | --- |
| R0 | `contracts.py` + 契约测试 + Raw Trust-State |
| R1 | `SyncRaw` 方案：同一 10K workload 下与 Baseline 可比 |
| R2 | 窗口边界下的 Sync / Raw 正确性（与 B 的 Filter 对比） |
| R3 | `ProofReuseStats`：Hash 复用率、同步字节、转换时间 |
| R4 | 固定环境与参数，重复实验与置信区间 |
