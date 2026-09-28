# MTCbasic_draft
https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-10对此草案实现
本阶段不实现 Checkpoint/Landmark 同步、Proof Reuse、Bloom/Cuckoo Filter、Outer Landmark Merkle Tree 等；这些要以后统一建立在 Baseline 上
```
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
```

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

Merkle/日志核心本身只使用标准库。B 的签名层声明了 `cryptography` 和
`pqcrypto` 运行期依赖，安装项目时会自动安装。开发依赖使用
`pip install -e ".[dev]"`。


### 5. 示例与基准

```bash
python examples/issuance_log_demo.py                      # 端到端演示（A 模块内）
python tools/bench_merkle_log.py --entries 1000 --csv bench.csv
```

### 6. 文档

* [`docs/A_IssuanceLogCore.md`](docs/A_IssuanceLogCore.md)：Section→模块映射、
  公共类型、错误模型、裁剪语义、验收对照、A0–A5 阶段状态、给 B/C/D 的接入说明。
* [`docs/B_CA_CHECKPOINT_COSIGNER.md`](docs/B_CA_CHECKPOINT_COSIGNER.md)：B 模块安装、
  密钥、CA 签发、Checkpoint、Cosigner、外部签名和持久化使用说明。
* [`docs/OPEN_SPEC_QUESTIONS.md`](docs/OPEN_SPEC_QUESTIONS.md)：MISSING SPEC 列表。

## Merkle Tree Certificates — B 模块：CA / Checkpoint / Cosigner

### 1. 负责范围

B 模块建立在 A 模块提供的 `IssuanceLog`、Merkle Root、Subtree 和 Proof API 上，
不重复实现 Merkle 树。它负责：

* 校验 CA 签发请求，并把规范的 `tbs_cert_entry` 追加到 A 的日志；
* 根据日志快照生成 Checkpoint，以及覆盖新增区间的一至两棵 Subtree；
* 验证 Checkpoint/Subtree 与当前日志的一致性后进行签名；
* 收集并校验外部 Cosigner 签名，可配置通过阈值；
* 原子发布 `CheckpointBatch`，并持久化 Cosigner 和已发布批次的公开状态。

主要实现位于：

| 目录 | 功能 |
| --- | --- |
| `src/mtc/ca/` | 签发请求校验、日志追加、Checkpoint job 编排 |
| `src/mtc/checkpoint/` | 已签名 Checkpoint/Subtree 模型及文件持久化 |
| `src/mtc/cosigner/` | 签名算法、一致性策略、外部 Cosigner 收集 |

### 2. 最小使用示例

```python
from mtc import (
    CAOrchestrator,
    Cosigner,
    IssuanceLog,
    IssuanceLogVerifier,
    Name,
    PrivateKeySigner,
    SignatureAlgorithm,
    TrustAnchorID,
    Validity,
    ed25519_spki,
)
from mtc.ca import IssuanceRequest


class RequestValidator:
    def validate(self, request: IssuanceRequest) -> None:
        # 在此加入授权、Subject、有效期、扩展等本地 CA 策略。
        pass


log_id = TrustAnchorID.from_arcs("32473.1")
ca_id = TrustAnchorID.from_arcs("32473.2")
log = IssuanceLog.new(log_id)
signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)

ca_cosigner = Cosigner(
    cosigner_id=ca_id,
    signer=signer,
    log_verifier=IssuanceLogVerifier(log),
)
ca = CAOrchestrator(
    log=log,
    request_validator=RequestValidator(),
    ca_cosigner=ca_cosigner,
)

request = IssuanceRequest(
    spki_der=ed25519_spki(bytes(range(32))),
    subject=Name.common_name("example.com"),
    validity=Validity(
        "2026-01-01T00:00:00+00:00",
        "2026-04-01T00:00:00+00:00",
    ),
)
issued = ca.submit(request)
batch = ca.run_checkpoint_job()

print(issued.log_index, issued.tree_size)
print(batch.signed_checkpoint.checkpoint.tree_size)
```

`submit()` 先执行部署方提供的 `RequestValidator`，通过后才调用 A 的规范条目构造和
追加接口。`run_checkpoint_job()` 验证并签署 Checkpoint 及 Subtree；从上次发布后没有
新增条目时返回 `None`。

### 3. 持久化部署

生产部署应保存签名私钥，并为 Cosigner 状态和发布批次配置文件 store：

```python
from mtc import FileCheckpointBatchStore, FileCosignerStateStore

ca_cosigner = Cosigner(
    cosigner_id=ca_id,
    signer=signer,
    log_verifier=IssuanceLogVerifier(log),
    state_store=FileCosignerStateStore("state"),
)
ca = CAOrchestrator(
    log=log,
    request_validator=RequestValidator(),
    ca_cosigner=ca_cosigner,
    batch_store=FileCheckpointBatchStore("state"),
)
```

文件 store 只保存公开状态，不保存私钥。经典签名支持 Ed25519、ECDSA P-256/SHA-256
和 ECDSA P-384/SHA-384；ML-DSA 支持 ML-DSA-44、65 和 87。外部 Cosigner 客户端、
阈值收集、密钥导入导出和重启恢复示例见
[`docs/B_CA_CHECKPOINT_COSIGNER.md`](docs/B_CA_CHECKPOINT_COSIGNER.md)。

### 4. 运行 B 模块测试

```bash
python -m unittest tests.test_b_signing tests.test_b_integration -v
```



## Merkle Tree Certificates — C 模块：Certificate / Landmark / Relying Party

### 1. 负责范围

唯一协议基线为 **draft-davidben-tls-merkle-tree-certs-10**。

C 模块建立在 A 的日志、编码和 Merkle Proof API，以及 B 的
CheckpointBatch 和签名验证接口之上，负责：

* MTC X.509 证书和 MTCProof 的编解码；
* 证书信息与日志条目的双向转换、SPKI 匹配及叶子哈希重建；
* Full Certificate 与 Signatureless Certificate 构造；
* Landmark 序列、分配规则、发布文本及子树选择；
* Trust Anchor、协签策略、撤销索引区间和可信子树管理；
* Checkpoint 协签与一致性证明校验，以及可信子树更新；
* 完整证书和无签名证书的统一验证。

C 复用 A 的 Merkle 算法和 B 的密码学验签实现，不重复实现底层算法。
TLS/ACME 协议交互、网络服务、证书协商及系统实验由 D 接入。

本阶段实现基础 Landmark 分配与可信状态更新，不实现同步优化、
Proof Reuse、Bloom/Cuckoo Filter、Outer Landmark Merkle Tree 等扩展。

### 2. 目录结构

```text
src/mtc/
  certificate/
    x509_codec.py          # X.509 MTC 证书结构与 DER 编解码
    proof_codec.py         # 公共 MTCProof 编解码封装与格式检查
    entry_mapping.py       # 证书与日志条目转换、SPKI/叶子哈希
    full.py                # 基于 B 的 CheckpointBatch 构造完整证书
    signatureless.py       # 基于 Landmark 构造无签名证书

  landmark/
    sequence.py            # Landmark 序列、编号和活动窗口
    allocation.py          # 按时间区间分配 Landmark
    publication.py         # Landmark 发布文本序列化与解析
    subtrees.py            # Landmark 子树区间、选择和根哈希查询

  verifier/
    trust_anchor.py        # 日志信任配置、协签方公钥及多日志查询
    cosigner_policy.py     # CA 与外部协签方接受策略
    revocation.py          # 撤销索引区间管理
    trusted_subtrees.py    # 可信子树存储和精确区间查询
    trust_update.py        # 验证证据后更新可信子树
    inclusion.py           # 调用 A 的包含证明算法
    signatures.py          # 调用 B 的验签接口并检查协签策略
    certificate_checks.py  # 有效期、撤销、扩展及应用身份检查接口
    verify.py              # 统一验证入口
```

共享的 `Checkpoint`、`Subtree`、`MTCProof`、`MTCSignature`、
`Cosignature` 等类型继续使用公共模块定义。

### 3. 公共 API

#### 3.1 完整证书构造与验证

下面示例接续 B 的签发流程，假定已经取得：

* A 的 `log`；
* B 的 `issued`、`request` 和非空 `batch`；
* CA 与外部 Cosigner 的身份及公开验签密钥。

```python
from datetime import datetime, timezone

from mtc.certificate.full import build_full_certificate
from mtc.verifier.cosigner_policy import CosignerPolicy
from mtc.verifier.trust_anchor import TrustedCosigner, TrustAnchor
from mtc.verifier.verify import verify_certificate

anchor = TrustAnchor(
    log_id=log.log_id,
    hash_algorithm=log.hash_algorithm,
    cosigners=(
        TrustedCosigner(
            ca_id,
            ca_verifier.algorithm.value,
            ca_verifier.public_key_der(),
        ),
        TrustedCosigner(
            witness_id,
            witness_verifier.algorithm.value,
            witness_verifier.public_key_der(),
        ),
    ),
    policy=CosignerPolicy(
        ca_ids={ca_id},
        witness_ids={witness_id},
        witness_threshold=1,
    ),
)

full = build_full_certificate(
    log,
    batch,
    index=issued.log_index,
    spki_der=request.spki_der,
    anchor=anchor,
)
certificate_der = full.to_der()

result = verify_certificate(
    certificate_der,
    anchor,
    now=datetime(2026, 2, 1, tzinfo=timezone.utc),
)
print(result.trust_source)
print(result.verified_cosigners)
```

示例使用固定验证时间，需要处于证书有效期内。
它未配置应用身份检查，不能单独作为 TLS 服务端身份验证示例。

`batch` 必须包含满足 `anchor.policy` 的签名；仅有 CA 签名的批次，
不能满足上述“CA + 一个外部 Cosigner”的策略。

完整证书构造会检查：

* 日志、Checkpoint 和 Trust Anchor 的身份及哈希算法一致；
* Checkpoint 和子树根与 A 的日志一致；
* 证书索引位于批次新增区间，且尚未被裁剪；
* CA 和外部 Cosigner 的 Checkpoint、所选子树签名有效；
* 有效协签方集合满足配置策略；
* 证书公钥与日志中的 SPKI 哈希匹配，包含证明正确。

证书中写入的是所选子树的签名，不使用 Checkpoint 签名替代。

#### 3.2 证书编解码与条目转换

| 接口                                                         | 功能                                    |
| ------------------------------------------------------------ | --------------------------------------- |
| `TBSCertificate.from_der(data)` / `.to_der()`                | 解析、输出 TBSCertificate，保留字段 DER |
| `MTCCertificate(tbs_certificate, proof)`                     | 由 TBS 和公共 MTCProof 组装证书         |
| `MTCCertificate.from_der(data, hash_algorithm=SHA256)`       | 解析 MTC 证书                           |
| `MTCCertificate.to_der()`                                    | 输出 X.509 DER                          |
| `encode_proof(proof, index=None)`                            | 检查并编码 MTCProof                     |
| `decode_proof(data, hash_algorithm=SHA256, index=None)`      | 解码证明并检查范围、长度及可选索引      |
| `from_log_entry(entry, *, index, spki_der, log_id, hash_algorithm=SHA256)` | 从日志条目构造 TBS                      |
| `to_log_entry(tbs, log_id, hash_algorithm=SHA256)`           | 从证书 TBS 重建日志条目                 |
| `certificate_entry_hash(tbs, log_id, hash_algorithm=SHA256)` | 调用 A 的哈希接口计算重建条目的叶子哈希 |

`serialNumber` 使用日志索引本身，不进行加一转换。
索引零为 `null_entry`，不能用于证书。

`MTCProof` 以 TLS 编码直接存入证书的 `signatureValue` BIT STRING，
不额外包裹 ASN.1 OCTET STRING。哈希算法由日志配置提供，
解析非 SHA-256 证书时必须显式传入。

#### 3.3 Landmark 管理

| 接口                                                         | 功能                                                      |
| ------------------------------------------------------------ | --------------------------------------------------------- |
| `LandmarkSequence(base_id, max_landmarks, landmark_url, tree_sizes=(0,))` | 创建完整 Landmark 历史                                    |
| `sequence.append(tree_size)`                                 | 返回追加后的新序列，要求树大小严格增长                    |
| `sequence.get(number)` / `.latest` / `.active`               | 查询指定、最新或活动 Landmark                             |
| `sequence.first_covering(index)`                             | 查找首次覆盖索引的 Landmark；尚未覆盖时返回 `None`        |
| `sequence.trust_anchor_id(number)`                           | 生成对应 Landmark 的 Trust Anchor ID                      |
| `recommended_max_landmarks(lifetime, interval)`              | 计算 `ceil(lifetime / interval) + 1`                      |
| `allocate_landmark(...)`                                     | 根据显式时间、Checkpoint 树大小和历史分配状态决定是否追加 |
| `serialize_publication(sequence)`                            | 输出 UTF-8 发布文本                                       |
| `parse_publication(data, *, max_landmarks, latest_tree_size)` | 校验并解析发布文本                                        |
| `landmark_intervals(sequence, number)`                       | 调用 A 的区间覆盖算法，返回子树区间                       |
| `landmark_subtrees(sequence, number, log, *, log_id)`        | 查询子树区间及根哈希                                      |
| `select_landmark_subtree(sequence, index, ...)`              | 选择覆盖证书索引的 Landmark 子树                          |

分配函数每个固定时间区间最多追加一次。调用方需要同时保存返回的
新序列和 `last_allocation_time`，并在重启后恢复二者。

Landmark 发布文本包含活动窗口及其前驱树大小。
解析成功只代表格式和边界合法，不代表这些数据已获信任。

#### 3.4 无签名证书构造

```python
from mtc.certificate.signatureless import build_signatureless_certificate

signatureless = build_signatureless_certificate(
    log,
    sequence,
    index=issued.log_index,
    spki_der=request.spki_der,
    log_id=log.log_id,
    require_active=True,
)

certificate_der = signatureless.to_der()
landmark_id = signatureless.selection.trust_anchor_id

assert signatureless.certificate.proof.signatures == ()
```

默认选择首次覆盖该条目的 Landmark。尚无对应 Landmark 时抛出
`LandmarkNotReady`，函数不会阻塞等待。

可通过 `landmark_number` 显式选择后续 Landmark，但其实际子树必须覆盖
目标索引。`require_active=True` 要求所选 Landmark 仍处于活动窗口。

返回值包含证书、Landmark 选择信息和子树根；只有证书部分写入 DER。
Landmark ID 可交给 D 用于协议协商。

#### 3.5 信任配置与撤销

| 类型或接口                                                   | 功能                                           |
| ------------------------------------------------------------ | ---------------------------------------------- |
| `TrustedCosigner(cosigner_id, algorithm, public_key)`        | 保存协签方身份、算法和公开密钥                 |
| `TrustAnchor(...)`                                           | 聚合某个日志的协签配置、可信子树与撤销状态     |
| `TrustAnchorStore(anchors=())` / `.get(log_id)`              | 多日志信任锚查询                               |
| `CosignerPolicy(ca_ids, witness_ids, witness_threshold)`     | 至少一个配置的 CA 身份，加指定数量的其他协签方 |
| `RevokedRange(start, end)`                                   | 非空半开撤销区间 `[start, end)`                |
| `RevocationList(log_id, ranges=())`                          | 合并重叠、相邻区间                             |
| `revocations.contains(index)` / `.revoke(start, end)`        | 查询或返回增加撤销范围后的新对象               |
| `TrustedSubtreeStore(log_id, hash_algorithm=SHA256, subtrees=())` | 保存可信子树                                   |
| `store.lookup(start, end)`                                   | 精确匹配区间，不以包含关系替代                 |
| `anchor.with_signers(cosigners, policy)`                     | 更新签名配置，同时清空待重新认证的可信根       |

协签数量按通过验签的不同身份计算，重复签名不重复计数。
经典公钥使用完整 SPKI DER；ML-DSA 公钥格式遵循 B 的原始字节接口。

这些状态采用不可变快照；更新时应保留返回的新对象。

#### 3.6 可信子树更新

```python
from mtc.verifier.trust_update import (
    CheckpointEvidence,
    SubtreeEvidence,
    update_trusted_subtrees,
)

checkpoint = batch.signed_checkpoint.checkpoint

checkpoint_evidence = [
    CheckpointEvidence(
        checkpoint,
        batch.signed_checkpoint.cosignature,
    ),
]
checkpoint_evidence.extend(
    CheckpointEvidence(checkpoint, item.checkpoint_cosignature)
    for item in batch.external_cosignatures
)

from mtc.landmark.subtrees import landmark_subtrees

roots = {}
for landmark in sequence.active:
    for subtree in landmark_subtrees(
        sequence, landmark.number, log, log_id=log.log_id
    ):
        roots[(subtree.start, subtree.end)] = subtree

subtree_evidence = [
    SubtreeEvidence(
        subtree,
        tuple(log.subtree_consistency_proof(
            subtree.start,
            subtree.end,
            checkpoint.tree_size,
        )),
    )
    for subtree in roots.values()
]

updated = update_trusted_subtrees(
    anchor,
    sequence,
    checkpoint,
    checkpoint_evidence,
    subtree_evidence,
)
anchor = updated.anchor
```

上述示例要求参考 Checkpoint 已包含最新 Landmark。
函数验证足够的 Checkpoint 协签，以及所有活动子树到参考 Checkpoint
的一致性证明，全部成功后才返回新状态。

协签方也可以签署后续 Checkpoint，此时对应 `CheckpointEvidence`
需要携带从参考 Checkpoint 到该后续 Checkpoint 的一致性证明。

后续刷新必须传入上次返回的 `previous` 状态，以及必要的
`previous_consistency_proof`，以检查历史回退或改写。
首次初始化所用序列的来源、日志绑定和新鲜度由调用方保证。

#### 3.7 统一验证

| 接口                                                   | 功能                                        |
| ------------------------------------------------------ | ------------------------------------------- |
| `evaluate_certificate_inclusion(certificate, anchor)`  | 重建条目并计算证明对应的子树根              |
| `check_trusted_subtree(certificate, anchor)`           | 检查精确区间及可信根                        |
| `verified_cosigner_ids(signatures, subtree, anchor)`   | 返回通过 B 验签的不同协签方身份             |
| `check_cosignatures(signatures, subtree, anchor)`      | 进一步要求满足协签策略                      |
| `check_certificate(certificate, anchor, *, now, ...)`  | 常规结构、有效期、撤销和配置的扩展/身份检查 |
| `verify_certificate(certificate, anchor, *, now, ...)` | 串联常规检查、包含证明和信任判断            |
| `is_valid_certificate(certificate, anchor, **options)` | 布尔便利入口                                |

`verify_certificate()` 返回 `VerificationResult`，包含：

* `certificate`：解析后的证书；
* `subtree`：计算出的子树及根哈希；
* `trust_source`：`trusted_subtree` 或 `cosignatures`；
* `verified_cosigners`：签名路径实际验证通过的身份集合。

验证顺序为：

1. 检查结构、日志身份、有效期、撤销及配置的扩展和应用身份；
2. 重建日志条目，验证包含证明并计算子树根；
3. 若精确匹配已配置的可信子树，要求根哈希一致；
4. 否则验证证书携带的协签，并要求满足策略。

可信子树根冲突时直接失败，不回退到签名路径。
无签名证书没有匹配的可信子树时验证失败。

严格入口失败时抛异常。布尔入口仅将 `MTCError` 转为 `False`，
不会隐藏应用回调中的编程错误。

### 4. 错误模型

C 复用公共错误，并增加对应业务错误：

| 错误                                            | 场景                               |
| ----------------------------------------------- | ---------------------------------- |
| `EncodingError` / `DecodeError`                 | 配置、DER、TLS 或字段格式错误      |
| `InvalidIndex` / `InvalidTreeSize`              | 索引或日志规模不符合要求           |
| `UnavailableEntry`                              | 构造证书所需条目已不在日志发布范围 |
| `LandmarkNotReady`                              | 尚未分配覆盖该条目的 Landmark      |
| `InvalidInclusionProof`                         | 包含证明或可信子树根不匹配         |
| `InvalidConsistencyProof`                       | Checkpoint/子树一致性证明失败      |
| `InsufficientCosignatures`                      | 有效协签身份不满足策略             |
| `CertificateExpired` / `CertificateNotYetValid` | 当前时间不在有效期内               |
| `CertificateRevoked`                            | 证书索引命中撤销区间               |
| `UnsupportedCriticalExtension`                  | 关键扩展没有对应处理器             |
| `CertificateCheckError`                         | 其他常规证书检查失败               |
| `LogStateError` / `LogContractViolation`        | 信任状态冲突、历史回退或批次不一致 |

### 5. 接入边界

* `now` 必须为带时区的时间；有效期起止端点均包含在内。
* 未识别的关键扩展默认拒绝。扩展处理器必须处理实际语义，
  不能只把 OID 加入白名单。
* 应用身份检查需要同时传入 `expected_identity` 和
  `identity_checker`；未提供时不执行域名或应用身份匹配。
* KU/EKU、名称约束等语义需要配置处理器或外围 X.509 验证器。
  当前接口不能替代完整 TLS/X.509 路径验证。
* 可信状态的网络获取、持久化和并发提交由调用方负责；
  解析 Landmark 文本不会自动建立信任。
* C 的信任配置与验证逻辑由 D 调用；TLS Trust Anchor 协商、
  Full/Signatureless 选择和服务接口由 D 实现。
* Ed25519、ECDSA 及 SHA-256/SHA-512 日志哈希已参与此前集成测试。
  C 对 ML-DSA 的运行验证尚未完成，不能仅依据接口存在认定通过。

### 6. 运行 C 模块测试

此前实现的 C 测试分别位于：

```text
tests/certificate/
tests/landmark/
tests/verifier/
```

将这些测试同步到当前仓库后，在项目根目录运行：

```bash
python -m unittest discover -s tests/certificate -v
python -m unittest discover -s tests/landmark -v
python -m unittest discover -s tests/verifier -v
```
