# A 模块开发说明：Merkle Tree / Subtree / Issuance Log Core

协议基线：`draft-davidben-tls-merkle-tree-certs-10`
（[datatracker](https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-10)）。
本文档覆盖：Section→模块映射、公共类型、错误模型、裁剪语义、验收对照、开发阶段状态、
给 B/C/D 的接入说明。

## 1. Draft Section → implementation module

| Draft / 规范 | 内容 | 实现模块 | 测试 |
| --- | --- | --- | --- |
| RFC9162 §2.1.1 / prompt §6 | Leaf Hash `HASH(0x00‖entry)`、Internal `HASH(0x01‖L‖R)`、MTH | `merkle/hash.py`、`merkle/tree.py`（`mth` 参考实现） | `tests/merkle/test_hash.py` |
| prompt §7 | append-only tree：`append` / `tree_size()` / `root()` / `root(tree_size)` / `leaf_hash(index)` | `merkle/tree.py` | `tests/merkle/test_tree.py` |
| §4.1 | Subtree 定义与合法性（`start % 2**BIT_WIDTH(end-start-1) == 0`） | `merkle/subtree.py` | `tests/subtree/test_subtree.py` |
| §4.2 / Appendix B.1 | 层级、满/部分子树、跳过层级 | `merkle/subtree.py`（`bit_ceil` / `subtree_level` / `is_full_subtree`） | `tests/subtree/test_subtree.py` |
| §4.3.1–4.3.2 | Subtree Inclusion Proof 生成与求值 | `merkle/tree.py`（`_path`）、`merkle/proof.py`（`evaluate_subtree_inclusion_proof`） | `tests/proof/test_inclusion.py` |
| §4.3.3 | Subtree Inclusion Proof 验证 | `merkle/proof.py` | `tests/proof/test_inclusion.py`、`tests/merkle/test_errors.py` |
| §4.4.1 | `SUBTREE_PROOF` 递归生成 | `merkle/tree.py`（`_subproof`） | `tests/proof/test_consistency.py` |
| §4.4.3 | Subtree Consistency Proof 验证 | `merkle/consistency.py` | `tests/proof/test_consistency.py` |
| §4.5 / prompt §9 | Arbitrary Intervals：`cover_interval` | `merkle/interval.py` | `tests/subtree/test_interval.py` |
| §5.1 | Log Parameters | `log/parameters.py` | `tests/issuance_log/test_issuance_log.py` |
| §5.2 | Log ID / Trust Anchor ID、实验性 DN | `log/log_id.py`、`encoding/asn1.py`（`Name.log_id`） | `tests/entry/test_tbs_cert.py` |
| §5.3 / prompt §10-11 | MerkleTreeCertEntry、null_entry、`tbs_cert_entry_data`（DER contents octets） | `log/entry.py` | `tests/entry/test_entry.py`、`tests/entry/test_tbs_cert.py` |
| §5.4.1 | `MTCSubtree` / `MTCSubtreeSignatureInput` 编码（仅编码，签名属 B） | `core/types.py` | `tests/entry/test_public_types.py` |
| §5.6 / §5.6.1 | Publishing 与 Pruning（minimum index 语义） | `log/publish.py`、`log/pruning.py` | `tests/issuance_log/test_publish.py`、`tests/pruning/test_pruning.py` |
| §6.1 | `MTCProof` / `MTCSignature` 编码（占位类型，验证属 C） | `core/types.py` | `tests/entry/test_public_types.py` |
| §7.2 | `entry_hash` 与单趟计算 | `log/entry.py`（`entry_hash`、`entry_hash_single_pass`） | `tests/entry/test_entry.py` |
| prompt §12 | `subjectPublicKeyInfoHash = HASH(DER SubjectPublicKeyInfo)` | `log/entry.py`（`compute_spki_hash`） | `tests/entry/test_tbs_cert.py` |
| Appendix A | `TBSCertificateLogEntry` ASN.1（DEFINITIONS IMPLICIT TAGS） | `log/entry.py` + `encoding/der.py` + `encoding/asn1.py` | `tests/entry/test_tbs_cert.py`、`tests/entry/test_der.py` |
| RFC8446 §3 | TLS presentation language 原语 | `encoding/tls.py` | `tests/entry/test_public_types.py` |

## 2. 分层与模块职责

```
core/      types.py  第一批冻结公共类型（HashValue、MerkleTreeCertEntryType、Subtree、
                      InclusionProof/ConsistencyProof/SubtreeInclusionProof/SubtreeConsistencyProof、
                      Checkpoint/MTCProof/MTCSignature/Cosignature 占位、§5.4.1 编码）
           errors.py 统一错误模型（prompt §17）
encoding/  der.py    X.690 DER 编解码（canonical，最小长度/最小整数/DEFAULT 省略）
           asn1.py   Name / Validity / Extension / SubjectPublicKeyInfo 构造
           tls.py    TLS presentation language 原语
merkle/    hash.py   HASH 抽象（可换算法）+ leaf/interior 前缀规则
           subtree.py 子树合法性与位运算（§4.1、Appendix B.1）
           tree.py   append-only Merkle 树、Root/SubtreeRoot、证明生成
           proof.py  包含证明求值与验证（§4.3.2/4.3.3）
           consistency.py 一致性证明验证（§4.4.3）
           interval.py     §4.5 区间覆盖
log/       parameters.py LogParameters（§5.1）
           log_id.py    LogID / TrustAnchorID（§5.2）
           entry.py     MerkleTreeCertEntry、TBSCertificateLogEntry、SPKI hash、单趟 entry_hash
           issuance_log.py IssuanceLog（A 交付物，冻结 API）
           storage.py   EntryStorage（追加、availability 空洞、序列化）
           publish.py   LogPublisher / InMemoryPublisher / FilesystemPublisher（§5.6）
           pruning.py   minimum index 模型与裁剪不变式（§5.6.1）
```

依赖方向单向：`core ← encoding ← merkle ← log`（`core/types.py` 只通过
`TYPE_CHECKING` 引用 log 层类型，运行期不反向依赖）。

## 3. 第一批冻结公共类型

| 类型 | 位置 | 说明 |
| --- | --- | --- |
| `HashValue` | `core/types.py` | `bytes` 子类，binary-safe，可选 `HASH_SIZE` 校验；禁止用 `str` |
| `MerkleTreeCertEntryType` | `core/types.py` | `NULL_ENTRY=0`、`TBS_CERT_ENTRY=1`，`is_recognized()` |
| `MerkleTreeCertEntry` | `log/entry.py` | §5.3 编码；`encode()`/`decode()`；null_entry 恒为 `00 00` |
| `TBSCertificateLogEntry` | `log/entry.py` | Appendix A ASN.1；`content_octets()` 即 `tbs_cert_entry_data` |
| `Subtree` | `core/types.py` | `(start, end, hash)`，`is_full` / `level` |
| `InclusionProof` / `ConsistencyProof` | `core/types.py` | `HashValue` 的 tuple 子类 |
| `SubtreeInclusionProof` / `SubtreeConsistencyProof` | `core/types.py` | 同上，另带 `index`/`start`/`end`/`tree_size` 元信息 |
| `LogParameters` | `log/parameters.py` | log ID、hash 函数、minimum index |
| `LogID`（=`TrustAnchorID`） | `log/log_id.py` | §5.2；`from_arcs` / `from_oid_der` / `from_opaque` |
| `IssuanceLog`（=`IssuanceLogCore`） | `log/issuance_log.py` | A 交付物 |
| `Checkpoint` / `MTCProof` / `MTCSignature` / `Cosignature` | `core/types.py` | **占位**：只含数据类型与 §5.4.1/§6.1 编码，不含签名/验证/证书逻辑 |

`IssuanceLogCore` 是分工文档使用的旧名，保留为 `IssuanceLog` 的别名。

## 4. 错误模型（prompt §17）

```
MTCError
├─ EncodingError ├─ DecodeError ├─ MalformedEntry
├─ InvalidIndex、InvalidTreeSize、InvalidSubtree、InvalidMinimumIndex、UnavailableEntry、
│  UnsupportedEntryType
├─ ProofError ├─ ProofGenerationError
│            └─ InvalidProof ├─ InvalidInclusionProof、InvalidConsistencyProof
└─ LogStateError
```

* 严格 API：`check_*`（`check_subtree_inclusion_proof`、`check_tree_inclusion_proof`、
  `check_subtree_consistency_proof`、`check_tree_consistency_proof`）抛出上面最具体的错误，
  先做输入校验（大小/区间/长度），再判断证明。
* 便利 API：`verify_*` 返回 `True`/`False`，内部捕获全部 `MTCError`，保证**畸形输入不会
  让验证方崩溃**。
* 历史别名：`ProofVerificationError = InvalidProof`、`EntryUnavailable = UnavailableEntry`。

## 5. Pruning 语义（prompt §16）

`prune(k)` 只把 minimum index 提到 `k`：

* 不改逻辑历史：tree size、全部历史 root、全部 index、全部证明结果保持不变；
* 禁止 re-index / 用剩余叶子重建树 / 修改历史 root；
* 第一版**保留全部节点**，仅改变 availability（`physical=False` 为默认）；
  `prune(k, physical=True)` 才会额外丢弃条目正文与已可被父节点替代的叶哈希，
  同样不触碰树结构与历史 root；
* 裁剪不可回退（minimum index 只能前进）。

availability 规则（§5.6.1）：entry 可用 ⟺ `index ≥ minimum_index`；checkpoint 可用 ⟺
`tree_size > minimum_index`；subtree 可用 ⟺ `end > minimum_index`。这三条在
`log/pruning.py` 中单点实现，供发布层与验证方共用。

## 6. 验收对照

A 的正确性验收（分工文档 §5）：

| 验收项 | 结论 | 证据 |
| --- | --- | --- |
| Entry 编码/解码一致 | ✅ | `decode(encode(x)) == x`、`encode(decode(b))` 字节一致（`tests/entry`） |
| SPKIHash 正确 | ✅ | 输入必须是完整 `SubjectPublicKeyInfo` DER；RSA/EC/Ed25519 与 `cryptography` 交叉校验一致 |
| index 0 为 null_entry | ✅ | 新建日志自动写入；非零位置写入 null_entry 被拒；null_entry 编码 `00 00` |
| Root 计算正确 | ✅ | 与 RFC9162 §2.1.1 原始递归逐规模比对；含 RFC 参考向量 |
| InclusionProof 正确 | ✅ | 必测规模 × 全部 index 全验证；篡改矩阵（leaf/index/tree_size/proof/root/删节点/加节点） |
| ConsistencyProof 正确 | ✅ | 必测 checkpoint 组合（1→2 … 16→33）+ 全部子树一致性 + 篡改 |
| 非 2^k 树规模正确 | ✅ | prompt §19 规模表（重点 3/5/7/9/13/17/33） |
| Subtree 边界正确 | ✅ | 合法性真值表 + 非法 start/end/alignment/index-outside 全部拒绝 |

接口验收（分工文档 §14）：`Append` / `Root` / `SubtreeRoot` / `InclusionProof` /
`ConsistencyProof` 为稳定 API（`tests/issuance_log/test_issuance_log.py::test_frozen_pascal_case_api`），
调用方只通过公开 API 操作，**不依赖 Merkle 树内部节点布局**。

## 7. 开发阶段状态（prompt §25）

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| A0 | 目录骨架、依赖配置（`pyproject.toml`）、公共类型、错误模型、测试框架、README、API skeleton | ✅ 本轮按提示词对齐 |
| A1 | hash / MTH / append / root / inclusion / consistency / verify | ✅ 已实现并测试 |
| A2 | subtree 合法性 / root / inclusion / consistency / arbitrary interval | ✅ |
| A3 | Log ID / MerkleTreeCertEntry / TBSCertificateLogEntry / DER / SPKI hash / null entry | ✅ |
| A4 | IssuanceLog / storage / historical root / proof API / publish / logical pruning | ✅ |
| A5 | 全量 unit + integration + negative 测试、API 文档 | ✅（规模上限测试默认不跑） |

> 说明：仓库不是新建的空仓库，本轮是**按提示词调整既有实现**（重排目录、补齐公共类型与
> 错误模型、修正 API 命名、把裁剪改为「先逻辑后物理」），因此 A1–A5 已同时满足；
> 提示词要求的「本轮只做 A0 再停」不再适用。若要严格按阶段推进，可从 A5 的验收矩阵开始复核。

## 8. 给 B/C/D 的接入说明

* **B（CA / Checkpoint / Cosigner）**
  `IssuanceLog.new(log_id)` 建日志，`append_tbs_cert_entry(tbs)` / `Append(entry)` 写入；
  用 `cover_interval(start, end)` 选取待签名子树；用 `Root(tree_size)` 得到 checkpoint root；
  签名输入用 `LogPublisher.get_checkpoint_signature_input` /
  `get_subtree_signature_input`（§5.4.1 标签与编码已冻结，不要自行拼接）。
* **C（Certificate / Relying Party）**
  `MerkleTreeCertEntry.decode` + `TBSCertificateLogEntry` 重建 entry；`compute_spki_hash`
  计算 SPKI 哈希；`entry_hash_single_pass` 单趟计算 `entry_hash`；`MTCProof` 负责
  `signatureValue` 编解码；包含性用 `IssuanceLog.verify_subtree_inclusion` 验证，
  **无需自己实现 MTH**。
* **D（Integration / Monitor / Benchmark）**
  `LogPublisher`（内存）与 `FilesystemPublisher`（落盘状态）覆盖 §5.6.1 的 2–8 项能力；
  `log.stats()` 提供 tree size、minimum index、存储条目数、内部节点数与估算字节数；
  `log.save/load` 提供可重复实验的状态快照；A 组指标基准见 `tools/bench_merkle_log.py`。
