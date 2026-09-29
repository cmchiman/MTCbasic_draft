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

## D2b：真实 Signatureless、可信子树更新与证书选择（已完成）

D2b 保留 D2a Full Certificate 与 D1 Fake C 边界，并只在 D 中增加编排和语义选择：

- `RealCertificateVerifier.update_trusted_subtrees()` 从现有 B `CheckpointBatch` 和
  A `LogPublisher` 组织 `CheckpointEvidence`、`SubtreeEvidence`，调用 C 的
  `update_trusted_subtrees()`；仅在 C 完整验证 Checkpoint 签名阈值、历史一致性和
  所有活动 Landmark 子树 Proof 后，才原子替换内存中的 `TrustAnchor`。
- `RealCertificateService.build_signatureless_certificate()` 把 A 日志、C
  `LandmarkSequence`、索引、SPKI 和 log ID 交给 C 的
  `build_signatureless_certificate()`。D 只保存 C 返回的不透明 DER 和选择元数据，
  不构造或暴露 C 的 Proof 模型。
- `RealCertificateArtifact.routing_trust_anchor_id` 用于协商路由：Full 为 log ID，
  Signatureless 为 Landmark ID；`verification_log_id` 始终用于查找以 log ID 为键的
  C `TrustAnchorStore`。D2a 的 `trust_anchor_id` 属性及旧的 Full 构造形式继续兼容。
- Signatureless 能力是独立的 `SignaturelessCertificateService` 协议；现有
  `FakeCertificateService` 无需实现它。
- `CertificateSelector` / `SelectionPolicy` 只处理 §8 的语义能力，不实现 TLS wire。
  候选按证书种类、Landmark 编号、两个 ID 和不透明 DER 形成稳定顺序，不依赖
  provisioning 顺序。兼容且已广告的 Landmark 优先 Signatureless；只有 log ID、
  Landmark 未覆盖/不活动/未建立信任或范围不兼容时回退 Full；无共同锚返回 `None`。
- `LandmarkTrustAnchor.from_trust_update()` 从 C 的 `TrustUpdateResult` 导出可广告的
  活动 Landmark 语义能力。一个未经验证而手工声明的路由能力本身不建立可信根，
  空签名证书仍会被 C 拒绝。

真实调用链为：

`A IssuanceLog -> B CheckpointBatch -> D evidence orchestration ->`
`C update_trusted_subtrees -> C-verified TrustUpdateResult ->`
`C build_signatureless_certificate -> opaque DER -> D selection/routing ->`
`C verify_certificate (trusted_subtree)`。

### 需求到测试的映射

| 需求 | 测试与断言 |
| --- | --- |
| 真实 A → B → C Trust Update → C DER → D → C Verify | `test_real_trust_update_signatureless_der_and_verify_flow`；验证更新后的精确子树存在且客户端验证成功 |
| DER 编解码、空 signatures、可信子树验证 | 同上及契约测试 `test_public_trust_update_builder_and_verifier_compose`；C 返回 `trust_source == "trusted_subtree"` |
| Full/Signatureless 选择不依赖加入顺序 | `test_signatureless_is_preferred_independent_of_provision_order`；以 Landmark 2 语义能力选择路由为 Landmark 1 的兼容证书 |
| 只有 log ID、未就绪或不兼容时回退 Full | `test_log_id_only_client_falls_back_to_full`、`test_landmark_not_ready_does_not_displace_existing_full`；未提供已验证 Landmark 能力即不选择 Signatureless |
| 无共同 Trust Anchor | `test_no_common_trust_anchor_returns_none` |
| Landmark 不活动且要求 active | `test_inactive_landmark_is_rejected_and_full_remains_available` |
| 未验证根不能建立信任 | `test_unverified_landmark_advertisement_cannot_establish_trust`；契约测试同时验证缺少 Checkpoint 阈值和损坏子树一致性 Proof 时不返回新状态 |
| 错误可信子树、损坏 Certificate Proof | `test_wrong_trusted_subtree_is_rejected_by_c`、`test_damaged_signatureless_proof_is_rejected_by_c` |
| 过期和撤销 index | `test_expired_signatureless_certificate_is_rejected_by_c`、`test_revoked_signatureless_index_is_rejected_by_c` |
| Landmark 路由 ID / verification log ID 分离 | `test_landmark_routing_id_is_not_a_verification_log_id`；混用后找不到 log-keyed anchor 并失败 |
| D2a / D1 回归 | 原 11 项真实 Full 与 4 项 Fake C E2E 全部继续通过 |

### 运行与结果

在仓库根目录使用既有项目 `.venv`：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests/contract -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/e2e -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
.\.venv\Scripts\python.exe -m pip check
```

本次验证环境为 Windows、Python 3.11.4：

- D 契约：13 项全部通过，其中 D/C Signatureless 公共接口契约 3 项、
  Certificate Selection 契约 5 项。
- D E2E：27 项全部通过，其中 Fake C 4 项、真实 Full 11 项、真实
  Signatureless 12 项。
- 完整回归：运行 328 项，324 项通过，4 项大规模测试按默认配置跳过。
- `python -m pip check`：依赖一致性检查通过。

### 未决问题与 D3 前置条件

- `docs/OPEN_SPEC_QUESTIONS.md` 中 Trust Anchor ID 的 TLS 二进制表示仍未决；D2b
  只持有不透明 ID 和显式 Landmark `base_id` / number / range，不猜 wire encoding。
- C 的注释明确要求调用方保证首个 `LandmarkSequence` 的真实性、新鲜度，并持久化
  `TrustUpdateResult` 以防回滚。D2b 只实现进程内原子状态更新；D3 在接入真实传输前
  必须明确可信 bootstrap、持久化/恢复和并发更新边界。
- D3 需要把已验证的本地 Landmark 能力映射到 ClientHello / CertificateRequest 的
  Trust Anchor 表示，并把对端广告解析回本节的语义对象；该序列化边界必须等待
  未决外部格式确认。
- 应用身份、KU/EKU、名称约束和完整 X.509 路径验证仍需通过 C 的现有回调或外围
  验证器接入，不属于证书路由本身。

D2b 未实现 TLS/ACME、Monitor、Benchmark、Sync、Proof Reuse 或 Filter，也未修改
A/B/C 源码。

## D3：TLS / ACME 证书协商语义模拟（已完成）

D3 在 D2b 的 `CertificateSelector` 上增加独立的协议语义层，不实现 socket、
ClientHello/CertificateRequest wire codec，也不猜测外部 Trust Anchor ID 编码：

- `TLSClientCapabilities` 明确区分客户端支持的 log ID 和经 C 验证后广告的
  `LandmarkTrustAnchor`。`TLSSemanticNegotiator` 先调用 Authenticating Party 的
  确定性选择入口，再把不透明 DER 交给 Relying Party；后者仍通过 C 的
  `verify_certificate()` 验证。
- Full 只由 log ID 路由；Signatureless 只在收到兼容 Landmark 信任信号时路由；
  两者同时可用时沿用 D2b 规则优先 Signatureless。错误类型、客户端宣称超出本地
  已验证能力或无共同锚均安全失败，不发送 Signatureless。
- `AcmeSemanticService` 支持精确的
  `Accept: application/pem-certificate-chain-with-properties`，返回真实 DER 转成的
  PEM 链和语义化 Trust Anchor properties；Full properties 使用 log ID，
  Signatureless properties 同时保存 Landmark 路由 ID、verification log ID 和
  兼容范围。
- 可用资源返回 200；未知 URL 返回 404；不支持的 Accept 返回 406；尚未就绪的
  Signatureless 返回 503 和 `Retry-After`；Full 可携带 alternate Signatureless URL。
- `network_bytes` 只统计本模拟实际序列化的状态行、已知响应头和 PEM body。
  尚无规范定义的 properties wire bytes 不计入，避免把推测编码包装成测量结果。

真实 TLS 调用链为：

`RP verified capabilities -> TLS semantic request -> AuthenticatingParty ->`
`CertificateSelector -> opaque DER -> RelyingParty -> C verify_certificate`。

ACME 下载链为：

`Accept + resource URL -> AcmeSemanticService -> PEM(real DER) + semantic properties ->`
`AcmeSemanticClient property/body validation`。

### D3 需求到测试的映射

| 需求 | 测试与断言 |
| --- | --- |
| Landmark 信号存在时优先真实 Signatureless 并由 C 验证 | `test_tls_semantics_prefer_real_signatureless_and_verify_with_c` |
| 没有 Landmark 信号时不得发送 Signatureless，回退真实 Full | `test_tls_without_landmark_signal_uses_real_full_certificate` |
| 错误协商输入安全失败 | `test_malformed_tls_input_fails_without_exception` |
| ACME 真实 Full / Signatureless DER、PEM 与属性 | `test_acme_semantics_deliver_real_full_and_signatureless_der`、`test_full_acme_response_contains_pem_and_log_properties`、`test_signatureless_acme_properties_carry_landmark_range` |
| 不支持 Accept、资源缺失、Signatureless 待就绪 | `test_unsupported_accept_is_not_acceptable`、`test_unknown_resource_has_no_certificate`、`test_pending_signatureless_uses_503_and_retry_after` |
| 缺失、错误或与证书不匹配的 properties 安全失败 | `test_missing_wrong_or_malformed_properties_are_rejected` |

### D3 运行与结果

```powershell
.\.venv\Scripts\python.exe -m unittest tests.contract.test_d_tls_acme_contract -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/contract -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/e2e -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
.\.venv\Scripts\python.exe -m pip check
```

- TLS/ACME 契约：7 项全部通过。
- D 契约：20 项全部通过。
- D E2E：30 项全部通过，其中 Fake C 4 项、真实 Full 11 项、真实
  Signatureless/TLS/ACME 15 项。
- 完整回归：运行 338 项，334 项通过，4 项大规模测试按默认配置跳过。
- `python -m pip check`：依赖一致性检查通过。

D3 不实现生产 TLS/ACME wire、Monitor、Benchmark、Sync、Proof Reuse 或 Filter，
也未修改 A/B/C 源码。外部 Trust Anchor ID / certificate properties 编码继续记录在
`docs/OPEN_SPEC_QUESTIONS.md`，未来 codec 可在不改变这些语义对象的情况下接入。

## D4：Issuance Log Monitor（已完成）

`src/mtc/monitor` 只消费 A/B 的公开边界：

- `PublishedLogView` 是 `LogPublisher` 只读表面的结构协议；Monitor 不读取
  `IssuanceLog` 的 storage/tree/私有状态。
- `CosignerView` 携带 B 的 `SignedCheckpoint`、公开签名验证器和 Publisher。
  Checkpoint 签名调用 B `verify_subtree_cosignature()`；Checkpoint 之间的
  Proof 调用 A `IssuanceLog.verify_consistency()`。
- `MonitorPolicy` 对所有受支持 Relying Party `CosignerPolicy` 取 signer ID 并集，
  每个涉及的 CA/外部 Cosigner 都必须有视图，不仅检查满足阈值的子集。
- 同一 Cosigner 的前后视图检测 tree-size 回退、同 size 不同 root 和错误
  consistency proof；所有当前 Cosigner 视图也与确定选出的最新视图比较。
- 日志内容只从最新视图的 Publisher 读一遍，逐 index 检查可用性并调用 A
  `MerkleTreeCertEntry.decode()`；不重算 Merkle Root，不复制 Proof 验证。
- `MonitorEvent` / `MonitorResult` 结构化记录回退、split view、损坏 Proof/root、
  缺失 Entry/视图、坏签名、越权裁剪和服务不可用，并给出耗时、视图数、
  Entry 数和内容读取趟数。

### D4 需求到测试的映射

| 需求 | 测试与断言 |
| --- | --- |
| 真实 CA + 外部 Cosigner + Publisher，连续 Checkpoint | `test_real_ca_external_cosigner_publisher_and_monitor` |
| 内容仅读一遍且 Entry 全部可用 | `test_normal_views_check_every_entry_from_one_publisher` |
| tree-size 回退 / split view | `test_tree_size_rollback_is_detected_across_runs`、`test_same_size_different_roots_are_a_split_view` |
| 损坏 Consistency Proof / Checkpoint Root | `test_damaged_consistency_proof_is_detected`、`test_checkpoint_root_mismatch_is_detected` |
| 缺失 Entry / 越权裁剪 / 服务不可用 | `test_missing_entry_is_detected`、`test_unauthorized_pruning_is_detected`、`test_service_unavailability_is_structured` |
| 所有策略 Cosigner 视图与签名 | `test_every_policy_cosigner_must_have_a_view`、`test_invalid_checkpoint_cosignature_is_detected` |

### D4 运行与结果

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests/monitor -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/contract -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests/e2e -t . -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
.\.venv\Scripts\python.exe -m pip check
```

- Monitor：10 项全部通过。
- D 契约：20 项全部通过。
- D E2E：31 项全部通过。
- 完整回归：运行 349 项，345 项通过，4 项大规模测试按默认配置跳过。
- `python -m pip check`：依赖一致性检查通过。

D4 未实现 Sync、Proof Reuse 或 Filter，也未修改 A/B/C 源码。
