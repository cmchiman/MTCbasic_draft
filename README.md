# MTCbasic_draft
https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-10对此草案实现
本阶段不实现 Checkpoint/Landmark 同步、Proof Reuse、Bloom/Cuckoo Filter、Outer Landmark Merkle Tree 等；这些要以后统一建立在 Baseline 上
mtc-python/
│
├── src/
│   └── mtc/
│       │
│       ├── core/                  # A/B/C 公共协议对象
│       │   ├── models.py
│       │   ├── interfaces.py
│       │   └── exceptions.py
│       │
│       ├── merkle/                # A
│       ├── log/                   # A
│       │
│       ├── ca/                    # B
│       ├── checkpoint/            # B
│       ├── cosigner/              # B
│       │
│       ├── certificate/           # C
│       ├── landmark/              # C
│       ├── verifier/              # C
│       │
│       ├── protocol/              # D
│       │   ├── authenticating_party.py
│       │   ├── relying_party.py
│       │   ├── certificate_selector.py
│       │   ├── trust_anchor.py
│       │   └── acme.py
│       │
│       ├── service/               # D
│       │   ├── ca_client.py
│       │   ├── log_client.py
│       │   ├── cosigner_client.py
│       │   └── adapters/
│       │
│       ├── monitor/               # D
│       │   ├── monitor.py
│       │   └── consistency.py
│       │
│       ├── experiment/            # D
│       │   ├── workload.py
│       │   ├── metrics.py
│       │   ├── recorder.py
│       │   └── runner.py
│       │
│       └── policy/                # 为以后预留
│           ├── original.py
│           └── interfaces.py
│
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   └── e2e/
│
├── configs/
│
├── scripts/
│
├── results/
│
└── pyproject.toml


## Merkle Tree Certificates — A 模块：Merkle Tree / Subtree / Issuance Log Core

### 1. 协议基线

唯一基线：**[draft-davidben-tls-merkle-tree-certs-10](https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-10)**
（Merkle Tree Certificates）。

* 不使用后续 draft、不使用他人的 MTC 实现；
* 不实现 Checkpoint/Landmark 同步优化、Proof Reuse、Bloom/Cuckoo Filter、
  Outer Landmark Merkle Tree、自定义 Trust-State 压缩；
* draft 引用的 [RFC9162]（Merkle 树、证明）、[RFC5280]（X.509 字段语义）、
  [X.690]（DER）按其语义实现；缺细节的地方不猜，列入
  [`docs/OPEN_SPEC_QUESTIONS.md`](docs/OPEN_SPEC_QUESTIONS.md)（MISSING SPEC 格式）。

### 2. 目录结构

```
src/mtc/
  core/       types.py（冻结公共类型） errors.py（统一错误模型）
  encoding/   der.py（X.690） asn1.py（Name/Validity/Extension/SPKI） tls.py（RFC8446 §3）
  merkle/     hash.py tree.py subtree.py proof.py consistency.py interval.py
  log/        parameters.py log_id.py entry.py issuance_log.py storage.py publish.py pruning.py
tests/        merkle/ subtree/ proof/ entry/ issuance_log/ pruning/
examples/     issuance_log_demo.py
docs/         A_IssuanceLogCore.md  OPEN_SPEC_QUESTIONS.md
tools/        bench_merkle_log.py
```

逻辑分层与提示词要求的 `src/{merkle,log,encoding,core}` 一一对应，只是在
`src/` 下多包了一层 `mtc` 命名空间，避免 `log`、`core`、`merkle` 这类通用包名
污染 site-packages。核心库可以独立 import：`import mtc`，不依赖 CA/Certificate 代码。

### 3. 公共 API

#### 3.1 快速上手

```python
from mtc import IssuanceLog, LogID
from mtc.log.entry import tbs_cert_entry_for
from mtc.encoding.asn1 import Name, Validity, ed25519_spki

log_id = LogID.from_arcs("32473.1")        # 日志身份
log = IssuanceLog.new(log_id)              # 新建日志，自动写入 index 0 = null_entry
assert log.tree_size() == 1

spki = ed25519_spki(bytes(range(32)))      # 主体公钥的 SubjectPublicKeyInfo（DER）
entry = tbs_cert_entry_for(                # 构造一条待签发的日志条目
    log_id,
    spki_der=spki,
    subject=Name.common_name("example.com"),
    validity=Validity("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00"),
)
index = log.append(entry)                  # 返回 index；第一个真实证书是 1

root = log.root()                          # 当前日志状态的根哈希
proof = log.inclusion_proof(index)         # 该条目对当前 tree size 的包含证明
assert log.verify_inclusion_proof(index)   # 就地验证
```

#### 3.2 写入与查询

| 方法 | 功能 | 用法 |
| --- | --- | --- |
| `IssuanceLog.new(log_id, hash_algorithm=SHA256, ...)` | 新建空日志并写入 `null_entry` | `log = IssuanceLog.new(log_id)` |
| `IssuanceLog.from_entries(log_id, entries, ...)` | 由既有条目重建日志（自动补 `null_entry`） | `IssuanceLog.from_entries(log_id, [e1, e2])` |
| `append(entry)` / `Append(entry)` | 追加条目，返回其 index；校验 `tbs_cert_entry` 的 issuer 与哈希长度 | `index = log.append(tbs_entry)` |
| `append_tbs_cert_entry(tbs, validate=True)` | 直接追加 `TBSCertificateLogEntry` | `log.append_tbs_cert_entry(tbs)` |
| `get_entry(index)` / `entry(index)` | 取条目编码（字节）；越界抛 `InvalidIndex`，已裁剪抛 `UnavailableEntry` | `log.get_entry(3)` |
| `entry_object(index)` / `tbs_certificate_log_entry(index)` | 取解码后的 `MerkleTreeCertEntry` / `TBSCertificateLogEntry` | `log.entry_object(3).is_null_entry` |
| `tree_size()` / `size` / `len(log)` | 日志条目总数（即 checkpoint 的 tree size） | `log.tree_size()` |
| `leaf_hash(index)` / `entry_hash(index)` | 该条目的叶子哈希 `HASH(0x00 ‖ entry)` | `log.entry_hash(3)` |
| `iter_entries(start=0)` | 迭代 `(index, 编码)`，跳过已裁剪条目 | `for i, raw in log.iter_entries(10): ...` |
| `is_available(index)` / `checkpoint_is_available(n)` / `subtree_is_available(s, e)` | availability 判定 | `log.is_available(3)` |
| `self_check(deep=False)` | 自检结构不变量；`deep=True` 时按叶哈希重算所有历史根 | `log.self_check(deep=True)` |
| `stats()` | 返回 tree size、minimum index、存储条目数、内部节点数等指标 | `log.stats()["stored_interior_nodes"]` |

#### 3.3 子树与证明

| 方法 | 功能 | 用法 |
| --- | --- | --- |
| `root(tree_size=None)` / `Root(...)` | 当前或历史 tree size 的根 `MTH(D[0:tree_size])` | `log.root()`、`log.root(13)` |
| `subtree_root(start, end)` / `SubtreeRoot(...)` | 子树哈希 `MTH(D[start:end])`；非法区间抛 `InvalidSubtree` | `log.subtree_root(8, 13)` |
| `is_valid_subtree(start, end)` | 判断 `[start, end)` 是否为合法子树 | `log.is_valid_subtree(8, 13)` |
| `cover_interval(start, end)` / `covering_subtrees(...)` | 把任意区间映射为 1~2 棵子树（含各自哈希） | `log.cover_interval(5, 13)  # [Subtree(4,8), Subtree(8,13)]` |
| `checkpoint(tree_size=None)` | 构造 `Checkpoint`（log ID + tree size + 根哈希） | `cp = log.checkpoint(13)` |
| `inclusion_proof(index, tree_size=None)` / `InclusionProof(...)` | 对某个 checkpoint 的包含证明 | `log.inclusion_proof(10, 13)` |
| `subtree_inclusion_proof(index, start, end)` | 条目在某棵子树内的包含证明 | `log.subtree_inclusion_proof(10, 8, 13)` |
| `consistency_proof(first, second=None)` / `ConsistencyProof(...)` | 两个 checkpoint 之间的一致性证明 | `log.consistency_proof(8)` |
| `subtree_consistency_proof(start, end, tree_size=None)` | 子树与日志一致性证明 | `log.subtree_consistency_proof(8, 13)` |
| `evaluate_inclusion_proof(index, start, end, entry_hash, proof)` | 由证明算出子树哈希（静态方法） | 见验证一节 |

证明对象是 `HashValue` 的元组子类，可直接 `len(proof)`、遍历、索引；`SubtreeInclusionProof` /
`SubtreeConsistencyProof` 还额外记录 `index` / `start` / `end` / `tree_size`。

#### 3.4 验证

两种入口：**便利版**返回布尔值且不抛异常，**严格版**（`check_*`）抛出具体错误类型。

| 入口 | 说明 |
| --- | --- |
| `log.verify_inclusion_proof(index, entry_hash=None, inclusion_proof=None, root_hash=None, tree_size=None)` | 用日志自身状态验证；参数省略时自动取当前 tree size、证明与根 |
| `log.verify_consistency_proof(first[, second])` | 同上，验证两个 checkpoint 的一致性 |
| `log.verify_subtree_inclusion_proof(index, start, end)` / `log.verify_subtree_consistency_proof(start, end)` | 子树版本的验证 |
| `IssuanceLog.verify_inclusion(index, tree_size, entry_hash, proof, root_hash)` | 静态方法：验证方只拿到证明与 checkpoint 根时使用，不需要日志实例 |
| `IssuanceLog.verify_consistency(first, second, root_first, root_second, proof)` | 静态一致性验证 |
| `IssuanceLog.verify_subtree_inclusion(...)` / `verify_subtree_consistency(...)` | 静态子树验证 |
| `mtc.merkle.proof.check_subtree_inclusion_proof(...)`、`mtc.merkle.consistency.check_subtree_consistency_proof(...)` 等 | 严格版：失败时抛 `InvalidInclusionProof` / `InvalidConsistencyProof`，参数非法时抛 `InvalidIndex` / `InvalidTreeSize` / `InvalidSubtree` / `EncodingError` |

#### 3.5 发布与持久化

```python
from mtc.log.publish import LogPublisher, FilesystemPublisher

pub = LogPublisher(log)                      # 内存日志的发布接口
pub.get_log_parameters()                     # log ID、哈希算法、minimum index
pub.get_entry(3)                             # 读取可用条目
pub.get_checkpoint_hash(13)                  # 任意可用 checkpoint 的根
pub.get_inclusion_proof(10, 13)              # 条目 -> checkpoint 的包含证明
pub.get_consistency_proof(8, 21)             # checkpoint -> checkpoint 的一致性证明
pub.get_subtree_hash(8, 13)                  # 任意可用子树的哈希
pub.get_subtree_inclusion_proof(10, 8, 13)   # 条目在某棵子树内的包含证明
pub.get_subtree_consistency_proof(8, 13)     # 子树 -> checkpoint 的一致性证明
pub.get_node(2, 2)                           # 第 2 层第 2 个节点（= MTH(D[8:12])）
pub.iter_available_entries()                 # 遍历可用条目
pub.get_checkpoint_signature_input(13, cosigner_id)   # 签名输入（给签名方使用）

fs = FilesystemPublisher("state.json", publish_state=log)   # 落盘的发布接口
fs.refresh()                                                # 重新读取状态文件

log.save("log.json")                         # 保存日志状态（条目 + 树 + minimum index）
recovered = IssuanceLog.load("log.json")
```

#### 3.6 条目构造与哈希

| 函数 | 功能 |
| --- | --- |
| `tbs_cert_entry_for(log_id, *, spki_der, subject, validity, extensions=(), version=VERSION_V3, hash_algorithm=SHA256)` | 由公钥、主题、有效期构造一条 `tbs_cert_entry`；`issuer` 自动填为 log ID 的区分名 |
| `compute_spki_hash(spki_der, hash_algorithm=SHA256)` | `subjectPublicKeyInfoHash`：对完整 `SubjectPublicKeyInfo` DER 求哈希 |
| `entry_hash(entry, hash_algorithm=SHA256)` | 条目（对象或字节）的叶子哈希 |
| `entry_hash_single_pass(tbs, hash_algorithm=SHA256)` | 不重建完整条目的单趟哈希计算，结果与 `entry_hash` 一致 |
| `MerkleTreeCertEntry.null()` / `.tbs_cert(tbs)` / `.encode()` / `MerkleTreeCertEntry.decode(data[, length])` | 条目构造与编解码 |

#### 3.7 公共类型

| 类型 | 功能 |
| --- | --- |
| `LogID`（=`TrustAnchorID`） | 日志身份；`from_arcs("32473.1")` / `from_oid_der(...)` / `from_opaque(bytes)` |
| `HashValue` | 哈希值类型（`bytes` 子类，可校验长度） |
| `MerkleTreeCertEntryType` | `NULL_ENTRY = 0`、`TBS_CERT_ENTRY = 1` |
| `MerkleTreeCertEntry` | 日志条目：类型 + 载荷，含 `encode()` / `decode()` |
| `TBSCertificateLogEntry` | 条目载荷：`version/issuer/validity/subject/subjectPublicKeyInfoHash/...`，`content_octets()` 即日志存储的字节 |
| `Subtree` | `(start, end, hash)`，含 `size` / `is_full` / `level` |
| `InclusionProof` / `ConsistencyProof` | 证明节点序列 |
| `SubtreeInclusionProof` / `SubtreeConsistencyProof` | 同上，另带区间与 index 元信息 |
| `LogParameters` | log ID + 哈希算法 + minimum index |
| `EntryStorage` | 条目存储：`append` / `get` / `has` / `prune_below` / `to_state` |
| `IssuanceLog`（=`IssuanceLogCore`） | 日志主体，即上文 API |
| `Checkpoint` / `MTCProof` / `MTCSignature` / `Cosignature` | 预留占位类型：仅数据类型与编码，无签名与证书逻辑 |

#### 3.8 错误模型

```python
from mtc.core.errors import (
    InvalidIndex, InvalidTreeSize, InvalidSubtree, InvalidMinimumIndex,
    UnavailableEntry, UnsupportedEntryType, MalformedEntry, EncodingError,
    InvalidProof, InvalidInclusionProof, InvalidConsistencyProof,
)
```

| 错误 | 抛出场景 |
| --- | --- |
| `InvalidIndex` | index 越界或超出所给区间 |
| `InvalidTreeSize` | tree size 为负、超出当前规模 |
| `InvalidSubtree` | `[start, end)` 不满足子树对齐条件 |
| `InvalidMinimumIndex` | minimum index 回退或超出 tree size |
| `UnavailableEntry` | 条目已被裁剪（低于 minimum index） |
| `UnsupportedEntryType` | 条目类型不被识别（CA 不应签署此类条目） |
| `MalformedEntry` | 条目字节无法解码 |
| `EncodingError` | 编码/解码相关错误（`MalformedEntry` 是其子类） |
| `InvalidProof` / `InvalidInclusionProof` / `InvalidConsistencyProof` | 证明校验失败（严格版 API） |

#### 3.9 剪枝与自检

```python
log.prune(9)                    # 只把 minimum_index 提到 9：tree size、历史根、index 全部不变
log.prune(20, physical=True)    # 额外丢弃正文与叶哈希（可选项），树结构与历史根仍不变
log.is_available(3)             # -> False（已不在可用范围内）
log.revoked_by_index(3)         # -> True
log.self_check(deep=True)       # 校验结构不变量并重算历史根
```

### 4. 构建

```bash
# 无需安装即可使用（src 布局）
python -c "import sys; sys.path.insert(0,'src'); import mtc; print(mtc.__version__)"

# 构建 wheel
python -m pip wheel . --no-build-isolation --no-deps -w dist

# 或可编辑安装
python -m pip install -e . --no-build-isolation --no-deps
```

运行期无第三方依赖；`cryptography` 仅用于测试中与自研 DER 编码做交叉校验
（`pip install -e ".[dev]"`）。


### 5. 示例与基准

```bash
python examples/issuance_log_demo.py                      # 端到端演示（A 模块内）
python tools/bench_merkle_log.py --entries 1000 --csv bench.csv
```

### 6. 文档

* [`docs/A_IssuanceLogCore.md`](docs/A_IssuanceLogCore.md)：Section→模块映射、
  公共类型、错误模型、裁剪语义、验收对照、A0–A5 阶段状态、给 B/C/D 的接入说明。
* [`docs/OPEN_SPEC_QUESTIONS.md`](docs/OPEN_SPEC_QUESTIONS.md)：MISSING SPEC 列表。
