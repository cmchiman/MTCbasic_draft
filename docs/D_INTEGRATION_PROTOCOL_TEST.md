# D：集成协议与测试

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

## D1：最小 C 边界与 E2E

C 尚无完整 Certificate / Landmark / Verifier API。D1 已加入两个最小适配边界：

1. `mtc.service.CertificateService`：接收已有 `LoggedIssuance`、`CheckpointBatch`
   和 `LogPublisher`，返回 C 持有的不透明 `CertificateArtifact`。
2. `mtc.service.CertificateVerifier`：接收不透明句柄，将验证结论交回
   `mtc.protocol.RelyingParty`。

`AuthenticatingParty` 只负责调用 C、保存不透明句柄，并按现有 `TrustAnchorID`
完成模拟 TLS 的兼容证书路由。`RelyingParty` 暴露其 Trust Anchor ID 列表，先检查
路由结果，再把证书验证委托给 C。这里没有定义 TLS wire encoding。

FakeCertificateService / FakeCertificateVerifier 仅位于 `tests/support/fake_c.py`，
用不透明 token 和预设结果驱动 `tests/e2e/test_baseline_fake_c.py`。
Fake 不构造 `MTCProof`、Full/Signatureless 编码，不计算 Landmark，也不实现密码学验证。
不在 D 建立 Certificate、Landmark、TrustState 的另一套公共模型。
涉及 Trust Anchor ID 的外部表示时，继续遵循 `docs/OPEN_SPEC_QUESTIONS.md` 的未决项。

D1 E2E 的调用链为：

`IssuanceRequest -> CAOrchestrator.submit -> LoggedIssuance ->`
`CAOrchestrator.run_checkpoint_job -> CheckpointBatch ->`
`AuthenticatingParty -> CertificateService -> opaque artifact ->`
`RelyingParty -> CertificateVerifier`。

运行 D1：

```powershell
.\.venv\Scripts\python.exe -m unittest tests.e2e.test_baseline_fake_c -v
```

D1 新增 4 项 E2E 测试；全量回归共运行 297 项，293 项通过，4 项大规模测试跳过。

后续依次开展 Full/Signatureless 选择、TLS/ACME/Monitor、真实 C 接入、统一实验。
不实现 Checkpoint/Landmark Sync、Proof Reuse、过滤器、Outer Landmark Merkle Tree
或自定义 Trust-State 压缩。

## D2a：真实 Full Certificate 端到端集成（已完成）

D2a 只增加 D 对真实 C Full Certificate API 的适配，不改变 A/B/C 的职责：

- `RealCertificateService` 把现有 `LoggedIssuance`、`CheckpointBatch` 和
  `LogPublisher.core` 交给 C 的 `build_full_certificate()`；D 不生成 Entry、
  Merkle Root、Proof、证书字段或签名。
- C 返回的 Full Certificate 通过 C 的 `to_der()` 固化为不透明 DER 字节；
  正常验证路径把 DER 交回 C 的 `is_valid_certificate()`，因此实际覆盖了
  Certificate/MTCProof 编码与重新解析，不依赖 C 的进程内对象身份。
- `RealCertificateArtifact` 只保留 Trust Anchor ID、证书种类和 DER；
  `AuthenticatingParty` / `RelyingParty` 仍只负责模拟协商、路由和委托验证。
- 服务端构造与客户端验证分别使用 `TrustAnchorStore`。未知 Trust Anchor
  在调用 C 构造或验证前失败；已知锚的密码学与证书检查全部由 C 执行。

真实调用链为：

`IssuanceRequest -> CAOrchestrator.submit -> IssuanceLog ->`
`CAOrchestrator.run_checkpoint_job -> CA + external Cosigner signatures ->`
`AuthenticatingParty -> RealCertificateService -> C Full Certificate DER ->`
`RelyingParty -> RealCertificateVerifier -> C verify`。

`tests/e2e/test_baseline_real_c_full.py` 共 11 项，覆盖：

| 场景 | 断言 |
| --- | --- |
| 正常 A → B → C → D | Full Certificate 经 DER 编解码，携带 CA 与 Witness 签名并验证成功 |
| 未知 Trust Anchor | 服务端无锚拒绝构造；客户端声明与验证器配置缺失均拒绝，且不调用 C 验证 |
| 证书过期 | 使用显式带时区时钟，C 验证返回失败 |
| SPKI 不匹配 | C 构造器拒绝与日志条目不符的 SPKI；篡改证书 SPKI 后 C 验证失败 |
| Proof 损坏 | 在非空 Inclusion Proof 的真实批次中变异一个节点，C 验证失败 |
| 签名损坏 | 变异真实 Full Certificate 中一个 Cosigner 签名，C 验证失败 |
| Cosigner 阈值不足 | C 构造器拒绝缺少 Witness 的批次；移除证书 Witness 签名后 C 验证失败 |

在仓库根目录使用项目本地虚拟环境运行：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m unittest tests.contract.test_d_ab_contract -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/e2e -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
.\.venv\Scripts\python.exe -m pip check
```

本次验证环境为 Windows、Python 3.11.4：

- D 契约测试：5 项全部通过。
- D E2E 测试：15 项全部通过，其中真实 C Full Certificate 11 项、Fake C 边界 4 项。
- 完整回归：运行 308 项，304 项通过，4 项大规模测试按默认配置跳过。
- `python -m pip check`：依赖一致性检查通过。

D2a 不执行应用身份、KU/EKU、名称约束或完整 X.509 路径验证；C 的公共文档已要求
这些语义由回调或外围验证器提供。D2a 也不实现 Signatureless、TLS/ACME、Monitor、
Benchmark、Sync、Proof Reuse 或 Filter。Trust Anchor ID 的外部二进制表示继续采用
`docs/OPEN_SPEC_QUESTIONS.md` 中的既有未决项，本阶段没有新增协议猜测。
