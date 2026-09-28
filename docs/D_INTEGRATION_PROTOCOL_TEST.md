# D0：真实 A/B 集成契约

协议唯一基线：`draft-davidben-tls-merkle-tree-certs-10`。
初始代码基线：`df86050c1052fc68836ace834001f4eb121ecb80`。

## 本阶段范围

D0 使用现有 A/B 的公开 API 验证下游消费契约，停止在已签名日志材料。
不修改 A/B，不构造证书、不实现证书验证，也不新增公共协议模型。
测试中没有 Fake A/B。请求策略通过 B 的 `IssuanceRequestValidator` 边界注入，
仅用于测试部署的接受/拒绝场景，不是生产 CA 授权策略。

## 运行

在仓库根目录使用 Python 虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest tests.contract.test_d_ab_contract -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -t .
```

依赖以 `pyproject.toml` 为准：`cryptography==50.0.1`、`pqcrypto==1.0.0`。
即使测试选择 Ed25519，当前包导入链仍需要 pqcrypto。
默认测试不运行四个大规模用例；大规模配置见 `tests/issuance_log/test_scale.py`。

本次验证环境为 Windows、Python 3.12.14，结果如下：

- 修改前：运行 288 项，284 项通过，4 项大规模测试跳过。
- D0 契约：5 项全部通过。
- 修改后全量回归：运行 293 项，289 项通过，4 项大规模测试跳过。
- `python -m pip check`：依赖一致性检查通过。

这些结果不代表 C、TLS/ACME 或完整 E2E 已完成。

## 已锁定的消费契约

测试文件：`tests/contract/test_d_ab_contract.py`，使用 `unittest`。

| 场景 | 现有 API 与检查 |
| --- | --- |
| 请求到批次 | `CAOrchestrator.submit()` 返回 `LoggedIssuance`，三个请求的 index 为 1/2/3，提交时 tree size 为 2/3/4；同一批次的 tree size 为 4 |
| 待发布状态 | `LogPublisher.get_checkpoint()` 可以返回尚未被 B 发布签名的快照；签名材料从 `CheckpointBatchStore.load_latest()` 或 `ca.latest_batch` 获取 |
| A/B 材料交接 | 通过 Publisher 取得 Entry；A 的 `MerkleTreeCertEntry.decode()`、`compute_spki_hash()` 核对请求字段；A 的包含性/一致性验证和 B 的 `verify_subtree_cosignature()` 验证批次材料 |
| 历史快照 | 发布第二批次后，第一批次的签名子树与 Proof 仍可消费；新条目不能向不包含它的旧 Checkpoint 请求包含证明 |
| 跨批次一致性 | `LogPublisher.get_consistency_proof(4, 5)` 配合 `IssuanceLog.verify_consistency()` |
| 无新增条目 | `run_checkpoint_job()` 返回 `None`，已发布批次及 Cosigner 状态保持不变 |
| 请求拒绝 | `InvalidIssuanceRequest` 不改变已发布状态和日志大小，后续接受请求的 index 没有空洞 |
| 材料损坏 | 仅变异真实返回的 Proof/签名字节；A/B 现成验证器拒绝，无替代算法 |
| 逻辑裁剪 | `log.prune(2)` 后正文仍可能保留，但 Publisher 拒绝不可用 Entry、Proof 和 Checkpoint；Monitor 必须通过 Publisher 读取 |

这些是日志材料的契约测试，不是 MTC Certificate 验证，也不是完整系统 E2E。
本阶段只有 CA Cosigner；外部 Cosigner 阈值由现有 B 集成测试覆盖。

## 下游集成约束

- 单写入者、顺序调用 `submit()` 和 `run_checkpoint_job()`；不假定 A/B 支持并发写入。
- 保存 `LoggedIssuance.request`、索引及对应批次。不能把提交时的 tree size 当作最终批次大小。
- 使用 B 返回的 `SignedSubtree`；D 不重新计算区间覆盖、Entry 编码、Hash 或 Proof。
- 公共对象继续使用 `mtc.core.types`、`mtc.ca`、`mtc.checkpoint` 的现有类型。
- 多个 Cosigner 使用不同状态目录：B 文件路径按 log ID 命名，不含 Cosigner ID。
- D0 使用逻辑裁剪；不把所有历史根在物理裁剪后的可查询性作为保证。
- `IssuanceLog.from_entries()` 的裸 `TBSCertificateLogEntry` 首元素分支引用了不存在的
  `.entries` 模块，已记录为 A 的独立缺陷；D0 使用 `new()` + `ca.submit()`，不修改此分支。

## 下一阶段的 C 边界（尚未实现或冻结具体方法签名）

C 尚无完整 Certificate / Landmark / Verifier API。D1 只需两个适配边界：

1. Certificate service：接收已有 `LoggedIssuance`、`CheckpointBatch` 和日志读取能力，
   返回 C 持有的不透明证书句柄及后续选择所需元数据。
2. Certificate verifier：接收句柄和 C 的验证上下文，将验证结论交回 Client simulator。

FakeCertificateService / FakeCertificateVerifier 仅放在测试支持目录，用预设结果驱动流程。
Fake 不构造 `MTCProof`、Full/Signatureless 编码，不计算 Landmark，也不实现密码学验证。
不在 D 建立 Certificate、Landmark、TrustState 的另一套公共模型。
涉及 Trust Anchor ID 的外部表示时，继续遵循 `docs/OPEN_SPEC_QUESTIONS.md` 的未决项。

后续依次开展 Fake C E2E、TLS/ACME/Monitor、真实 C 接入、统一实验。
不实现 Checkpoint/Landmark Sync、Proof Reuse、过滤器、Outer Landmark Merkle Tree
或自定义 Trust-State 压缩。
