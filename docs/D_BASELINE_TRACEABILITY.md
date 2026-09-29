# D：draft-10 Baseline 需求追踪

协议唯一基线：`draft-davidben-tls-merkle-tree-certs-10`。

本表综合 `mtc基础方案分工.pdf`、`分工.pdf`、draft-10 §3–§12、附录 A、
附录 B，以及仓库当前公共 API。状态会在每个 D 阶段提交前更新。

状态定义：

- **已完成**：实现、负向测试和全量回归均存在。
- **已完成（待提交）**：工作区实现已验收，但尚未形成独立本地提交。
- **部分完成**：核心存在，但系统层验收或文档仍缺失。
- **未完成**：当前没有对应实现。
- **规范待定**：继续实现 wire 表示会引入规范猜测；必须保持语义/codec 分层。

## 1. 协议与模块追踪

| Draft-10 / 分工要求 | Baseline 要求 | 当前实现文件 | 当前测试 | 状态 | 边界 |
| --- | --- | --- | --- | --- | --- |
| §3 Overview | Request → CA → Log → Cosigner → Certificate → Server → Client → Monitor | `ca/orchestrator.py`、`protocol/`、`service/` | D 契约、Fake/Full/Signatureless E2E | 部分完成：Monitor 与统一 Runner 缺失 | A/B/C/D |
| §4.1、§4.2、附录 B.1 | Subtree 定义、合法区间、非 2^k 树 | `merkle/subtree.py`、`merkle/tree.py` | `tests/subtree/test_subtree.py`、`tests/merkle/test_tree.py` | 已完成 | A |
| §4.3、附录 B.2 | Subtree Inclusion Proof 生成、求值、验证 | `merkle/proof.py`、`merkle/tree.py` | `tests/proof/test_inclusion.py` | 已完成 | A |
| §4.4、附录 B.3/B.4 | Subtree/Tree Consistency Proof | `merkle/consistency.py`、`merkle/tree.py` | `tests/proof/test_consistency.py` | 已完成 | A |
| §4.5 | 任意区间的一至两棵 Subtree 覆盖 | `merkle/interval.py` | `tests/subtree/test_interval.py` | 已完成 | A |
| §5.1–§5.3、附录 A | Log 参数、Log ID、Entry、SPKI Hash、index 0 null entry、DER | `log/parameters.py`、`log/log_id.py`、`log/entry.py`、`encoding/` | `tests/entry/`、`tests/issuance_log/` | 已完成 | A |
| §5.4、§5.4.1、§5.4.2 | MTCSubtree 签名输入、算法、Cosignature | `core/types.py`、`cosigner/signing.py` | `tests/entry/test_public_types.py`、`tests/test_b_signing.py` | 已完成 | A/B |
| §5.5 | CA Cosigner 只签认可 Entry 与一致日志视图 | `ca/orchestrator.py`、`cosigner/service.py` | `tests/test_b_integration.py` | 已完成 | B |
| §5.6、§5.6.1 | 发布、可用性、裁剪不改历史 Root/Index | `log/publish.py`、`log/pruning.py`、`log/storage.py` | `tests/issuance_log/test_publish.py`、`tests/pruning/` | 已完成 | A |
| §6.1、附录 A | MTC X.509 / MTCProof DER | `certificate/x509_codec.py`、`certificate/proof_codec.py` | 真实 Full/Signatureless DER E2E；独立 C 测试目录未同步 | 部分完成：D 仅补公共接口契约，不复制 C | C/D |
| §6.2 | Full Certificate：批次 Subtree、CA+外部 Cosigner、DER、验证 | `certificate/full.py`、`service/real_certificate.py` | `test_baseline_real_c_full.py` 11 项 | 已完成；提交 `6f7357d` | C/D |
| §6.3.1、§6.3.2 | Landmark 序列、活动窗口、分配、发布 | `landmark/sequence.py`、`allocation.py`、`publication.py` | 通过 D/C 契约和真实 E2E 消费；独立 C 测试目录未同步 | 部分完成：核心存在，统一 Runner 尚未接入分配策略 | C/D |
| §6.3.3 | Signatureless：首个覆盖 Landmark、空签名、Full 并存 | `certificate/signatureless.py`、`service/real_certificate.py` | `test_d_c_signatureless_contract.py`、`test_baseline_real_c_signatureless.py` | 已完成（待提交） | C/D |
| §7.1 | TrustAnchor / TrustAnchorStore | `verifier/trust_anchor.py` | Full/Signatureless E2E | 已完成 | C |
| §7.2 | 统一验证：DER、撤销、Entry Hash、Proof、可信根/签名 | `verifier/verify.py`、`certificate_checks.py`、`inclusion.py` | Full/Signatureless 正常与破坏性 E2E | 已完成 | C/D |
| §7.3、§10.2 | CA + 外部 Cosigner 策略；Monitor 检查策略涉及的全部视图 | `verifier/cosigner_policy.py` | Full 阈值、D/C Trust Update 契约 | 部分完成：Monitor 视图联合检查缺失 | C/D |
| §7.4 | CheckpointEvidence + SubtreeEvidence 验证后更新 Trusted Subtree | `verifier/trust_update.py`、`service/real_certificate.py` | D/C 契约 3 项、Signatureless E2E | 已完成（待提交）；状态仅内存 | C/D |
| §7.5 | Index 半开区间撤销 | `verifier/revocation.py` | Signatureless 撤销 E2E | 已完成 | C |
| §8.1 | Trust Anchor Range 语义与未来 wire codec 分层 | `protocol/certificate_selector.py` | Signatureless 选择 E2E | 已完成（待提交）：仅语义对象 | D |
| §8.1 / 外部 Trust Anchor ID draft | TrustAnchorID wire 二进制 | `log/log_id.py` 只持有不透明字节 | 编码测试 | 规范待定：见 `OPEN_SPEC_QUESTIONS.md` | A/D |
| §8.2 | Full 用 log ID；Signatureless 用 Landmark ID；兼容时优先 Signatureless | `protocol/certificate_selector.py`、`authenticating_party.py`、`relying_party.py` | provision 顺序、log-only、无共同锚、ID 混淆 | 已完成（待提交） | D |
| §8 TLS 语义模拟 | ClientHello/CertificateRequest 语义输入、安全失败、DER 委托 C | 尚无 | 尚无 | 未完成 | D |
| §9 ACME | `Accept: application/pem-certificate-chain-with-properties`、链、Trust Anchor properties、alternate/503 语义 | 尚无 | 尚无 | 未完成；properties wire codec 不猜测 | D |
| §10.1.3、§10.2、§10.3、§12.2 | Monitor：Entry 一次读取、Root、Consistency、Cosigner split view、可用性/越权裁剪 | 尚无 `src/mtc/monitor` | D0 仅锁定 Publisher 可用性契约 | 未完成 | D（复用 A/B） |
| §10.4 | Full 与 Signatureless/续期证书并存选择 | `AuthenticatingParty` 可保存多证书 | D2b 选择 E2E | 部分完成：没有续期场景系统测试 | D |
| §11 | Trust Anchor 广告隐私风险 | 无 wire 实现 | 无 | 规范/部署事项：文档记录，不实现真实传输 | D |
| §12.1–§12.6 | 真实性、透明性、公钥 Hash、不可抵赖、未知 Entry、DER 非可塑性 | A/B/C 验证链 | A/B 单元测试、D 破坏性 E2E | 部分完成：Monitor 缺失；应用 X.509 路径不在本原型范围 | A/B/C/D |

## 2. 系统与实验追踪

| 基础分工要求 | 当前实现 | 当前测试 | 状态 | 边界 |
| --- | --- | --- | --- | --- |
| Authenticating Party / Relying Party | `protocol/authenticating_party.py`、`relying_party.py` | Fake、Full、Signatureless E2E | 已完成（D2b 待提交） | D |
| TLS Trust Anchor ID 语义模拟 | 选择器已有底层语义对象 | 选择 E2E | 部分完成：独立协商请求/结果与安全失败模型缺失 | D |
| ACME 下载语义模拟 | 无 | 无 | 未完成 | D |
| MonitorEvent / MonitorResult | 无 | 无 | 未完成 | D |
| Workload Generator（显式 seed） | `tools/bench_merkle_log.py` 仅 A 局部基准 | A scale 测试 | 未完成统一工作负载 | D |
| 统一 Metrics Recorder | 无 | 无 | 未完成 | D |
| CPU / Wall / allocation / RSS / Disk / Network | 无统一 schema | 无 | 未完成 | D |
| Full / Signatureless build+verify 指标与真实字节大小 | 无统一 Runner | 无 | 未完成 | D |
| Validation P50/P95/P99 | 无 | 无 | 未完成 | D |
| Trusted State、Monitor 时间与异常数 | 无 | 无 | 未完成 | D |
| CSV / JSON 同一稳定 schema | 无 | 无 | 未完成 | D |
| 快速 Baseline CLI | 无 | 无 | 未完成 | D |
| 10^3/10^4/10^5/3×10^5/10^6 显式规模 | A scale 覆盖部分 Merkle 操作 | `test_scale.py` 大规模默认跳过 | 部分完成：统一 Runner 参数缺失 | A/D |
| README 与实际目录一致 | README 顶部仍是规划树，并声称不存在的 C 测试目录可同步 | 无 | 未完成 | D |

## 3. 后续优化扩展点

| 接口 | Baseline 目标 | 当前状态 |
| --- | --- | --- |
| `CheckpointPolicy` | 只决定何时运行现有 B Checkpoint job | 未完成 |
| `LandmarkPolicy` | 只决定何时调用 C Landmark 分配 | C 有函数，D 策略接口未完成 |
| `CertificateSelectionPolicy` | 不改变证书/Proof，仅替换选择偏好 | 已完成：运行时协议 + Baseline `SelectionPolicy` |
| `TrustStateProvider` | 向 D 提供经 C 验证的不可变信任状态 | 未完成 |
| `MembershipFilter` | 未来 Raw/Bloom/Cuckoo/XOR/Fuse 插件边界；Baseline 不实现过滤器 | 未完成接口 |
| Metrics `strategy` / `filter` | 同一 workload/schema 比较未来优化 | 未完成 |

## 4. 阶段与提交状态

| 阶段 | 验收状态 | 本地提交 |
| --- | --- | --- |
| D2a 真实 Full | 已完成 | `6f7357d` |
| 阶段 1：真实 Signatureless / Trusted Update | 已完成 | `978d712` |
| 阶段 2：确定性证书选择 | 已完成（待提交） | 待创建 |
| 阶段 3：TLS/ACME 语义模拟 | 未完成 | 待创建 |
| 阶段 4：Monitor | 未完成 | 待创建 |
| 阶段 5：统一实验与 Benchmark | 未完成 | 待创建 |
| 最终 draft-10 Baseline 验收 | 未完成 | 待创建 |

## 5. 当前基线

- 审计 HEAD：`6f7357d feat(d): integrate real full certificates end to end`。
- 阶段 2 工作区验收：D 契约 13 项；D E2E 27 项；完整 unittest 328 项，
  324 通过、4 项规模测试跳过；`pip check` 通过。
- 当前缺口：TLS/ACME、Monitor、统一 Workload/Metrics/Recorder/Runner、CLI、结果样例、
  策略扩展接口、README 实际目录收口。
- 明确排除：Checkpoint/Landmark Sync、Proof Reuse、Bloom/Cuckoo/XOR/Fuse Filter、
  Outer Landmark Merkle Tree、自定义 Trust-State 压缩。
