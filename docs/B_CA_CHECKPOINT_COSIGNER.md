# B 模块使用说明：CA、Checkpoint 与 Cosigner

本文说明如何使用仓库中人员 B 负责的实现。协议唯一基线为
`draft-davidben-tls-merkle-tree-certs-10`。B 直接复用人员 A 的公共类型、日志条目
编码、Merkle Tree、Subtree 和 Proof 实现，不维护第二套协议模型。

## 1. 安装

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m unittest discover -s tests -v
```

B 的签名层使用 `cryptography` 和 `pqcrypto`，会随项目一起安装。

## 2. 主要模块

| 模块 | 用途 |
|---|---|
| `mtc.ca` | 请求验证、日志追加和 Checkpoint job 编排 |
| `mtc.checkpoint` | 已签批次模型及原子 JSON 持久化 |
| `mtc.cosigner` | 签名算法、一致性策略、外部 Cosigner 收集 |
| `mtc.log` | A 提供的 Issuance Log、Root、Subtree 和 Proof |
| `mtc.core.types` | A/B/C 共用的 Checkpoint、Subtree、Cosignature |

典型调用链：

```text
IssuanceRequest
    -> CAOrchestrator.submit
    -> A.tbs_cert_entry_for
    -> A.IssuanceLog.append

CAOrchestrator.run_checkpoint_job
    -> A.root / covering_subtrees / consistency proofs
    -> Cosigner consistency verification
    -> CA and external cosignatures
    -> FileCheckpointBatchStore publication
```

## 3. 创建日志、ID 和签名密钥

```python
from mtc import (
    IssuanceLog,
    PrivateKeySigner,
    SignatureAlgorithm,
    TrustAnchorID,
)

log_id = TrustAnchorID.from_arcs("32473.1")
ca_cosigner_id = TrustAnchorID.from_arcs("32473.2")

# IssuanceLog.new 自动在 index 0 写入 null_entry。
log = IssuanceLog.new(log_id)
assert log.tree_size() == 1

signer = PrivateKeySigner.generate(SignatureAlgorithm.ED25519)
```

生产环境应持久化私钥，而不是每次启动重新生成：

```python
from pathlib import Path

Path("secrets/ca-key.pem").write_bytes(
    signer.private_key_pem(password=b"replace-with-a-strong-password")
)

signer = PrivateKeySigner.from_pem(
    SignatureAlgorithm.ED25519,
    Path("secrets/ca-key.pem").read_bytes(),
    password=b"replace-with-a-strong-password",
)
```

经典算法包括：

- `ED25519`
- `ECDSA_P256_SHA256`
- `ECDSA_P384_SHA384`

ML-DSA 使用原始 FIPS 204 密钥编码：

```python
from mtc import MLDSAPrivateKeySigner, SignatureAlgorithm

mldsa_signer = MLDSAPrivateKeySigner.generate(SignatureAlgorithm.ML_DSA_65)
public_key = mldsa_signer.public_key_bytes()
secret_key = mldsa_signer.private_key_bytes()

# 加载时会验证公私钥是否匹配。
mldsa_signer = MLDSAPrivateKeySigner.from_bytes(
    SignatureAlgorithm.ML_DSA_65,
    public_key,
    secret_key,
)
```

还支持 `ML_DSA_44` 和 `ML_DSA_87`。原始 ML-DSA 私钥必须由 KMS、受保护的
secret volume 或等价设施保护。

## 4. 实现 CA 请求策略

`IssuanceRequest` 使用 A 的结构化 X.509 类型，而不是再解析一次完整
TBSCertificate DER：

```python
from mtc import InvalidIssuanceRequest
from mtc.ca import IssuanceRequest


class RequestValidator:
    def validate(self, request: IssuanceRequest) -> None:
        # 在此检查授权、Subject、有效期、扩展和本地 CA 策略。
        if not request.spki_der:
            raise InvalidIssuanceRequest("missing SPKI")
```

构造请求：

```python
from mtc import Name, Validity, ed25519_spki
from mtc.ca import IssuanceRequest

request = IssuanceRequest(
    spki_der=ed25519_spki(bytes(range(32))),
    subject=Name.common_name("example.com"),
    validity=Validity(
        "2026-01-01T00:00:00+00:00",
        "2026-04-01T00:00:00+00:00",
    ),
    extensions=(),
)
```

`CAOrchestrator.submit()` 会调用 A 的 `tbs_cert_entry_for()` 构造规范日志条目，
然后追加到日志。B 不复制 A 的 DER、SPKI Hash 或 entry 编码逻辑。

## 5. 组装 CA Cosigner

```python
from mtc import (
    CAOrchestrator,
    Cosigner,
    FileCheckpointBatchStore,
    FileCosignerStateStore,
    IssuanceLogVerifier,
)

state_directory = "state"

ca_cosigner = Cosigner(
    cosigner_id=ca_cosigner_id,
    signer=signer,
    log_verifier=IssuanceLogVerifier(log),
    state_store=FileCosignerStateStore(state_directory),
)

ca = CAOrchestrator(
    log=log,
    request_validator=RequestValidator(),
    ca_cosigner=ca_cosigner,
    batch_store=FileCheckpointBatchStore(state_directory),
)
```

`IssuanceLogVerifier` 把 B 的对象式安全检查映射到 A 的 Proof 验证函数。首次
Checkpoint 必须与本地 A 日志的同高度 Root 完全一致；后续 Checkpoint 必须通过
append-only consistency proof。

文件 store 只保存公开状态：

```text
state/
  cosigner/<sha256(log-id)>.json
  published/<sha256(log-id)>.json
```

私钥不会写入这些文件。

## 6. 提交签发请求

```python
result = ca.submit(request)
print(result.log_index)  # 第一个真实证书条目为 1
print(result.tree_size)  # 包含 index 0 null_entry
```

调用顺序为：

1. 执行部署方的 `RequestValidator`；
2. 由 A 构造 `MerkleTreeCertEntry`；
3. 由 A 追加条目；
4. B 检查 index 大于 0；
5. B 检查 `tree_size == index + 1`。

验证失败时不会追加日志。

## 7. 运行 Checkpoint job

```python
batch = ca.run_checkpoint_job()
if batch is None:
    print("上次发布后没有新条目")
else:
    checkpoint = batch.signed_checkpoint.checkpoint
    print(checkpoint.tree_size, checkpoint.root_hash.hex())
```

一次 job 会固定 A 的历史快照，获取 Root，验证并签署 Checkpoint，再使用 A 返回的
一至两棵 `Subtree` 及其 consistency proof 完成签名。全部步骤成功后才原子发布
`CheckpointBatch`。中途失败不会发布半成品，可以修复后重试。

批次提供给 C/D 的主要字段：

```python
batch.previous_tree_size
batch.signed_checkpoint
batch.signed_subtrees
batch.external_cosignatures
```

## 8. 独立 Cosigner

独立服务验证并签署候选 Checkpoint：

```python
proof = log.consistency_proof(old_size, checkpoint.tree_size)
signed = cosigner.sign_checkpoint(checkpoint, proof)
```

签署普通 Subtree：

```python
proof = log.subtree_consistency_proof(
    subtree.start,
    subtree.end,
    current_checkpoint.tree_size,
)
signature = cosigner.sign_subtree(log_id, subtree, proof)
```

Cosigner 会拒绝首次不可信 Root、回滚、同高度不同 Root、无效 Proof、超出当前
Checkpoint 的 Subtree、损坏的持久化状态和并发覆盖。

## 9. 外部 Cosigner

传输层实现 `ExternalCosignerClient`：

```python
class HTTPSCosignerClient:
    @property
    def cosigner_id(self): ...

    @property
    def verifier(self): ...  # 只包含远端公钥

    def cosign_checkpoint(self, checkpoint): ...

    def cosign_subtree(self, log_id, subtree): ...
```

配置签名阈值：

```python
from mtc import CosignerCollector

collector = CosignerCollector(
    (client_1, client_2, client_3),
    required_signatures=2,
    hash_algorithm=log.hash_algorithm,
)

ca = CAOrchestrator(
    log=log,
    request_validator=RequestValidator(),
    ca_cosigner=ca_cosigner,
    batch_store=FileCheckpointBatchStore("state"),
    external_collector=collector,
)
```

Collector 会验证外部 ID、Checkpoint 签名和每个 Subtree 签名。只有完整有效集合
达到阈值时才允许发布。网络协议、认证、超时和重试由 D 的适配层实现；远端服务
必须从可信日志源获得 Proof，不能只根据请求内容盲签。

## 10. 重启要求

重启时必须保持以下配置不变：

- 日志 ID、日志内容和 Hash 算法；
- CA/外部 Cosigner ID；
- CA 私钥；
- B 的状态目录；
- 外部 Cosigner 公钥和阈值。

重新构造 `Cosigner` 和 `CAOrchestrator` 时会验证已保存签名。状态损坏、私钥不匹配
或同高度 Root 冲突都会阻止启动，不应通过删除状态强行绕过。

## 11. 主要异常

| 异常 | 含义 |
|---|---|
| `InvalidIssuanceRequest` | CA 策略拒绝请求 |
| `InvalidKeyMaterial` | 密钥格式、算法或密钥对错误 |
| `InconsistentLogView` | 日志演进、Root、Subtree 或 Proof 不一致 |
| `CorruptCosignerState` | 持久化签名状态损坏或密钥不匹配 |
| `ConcurrentStateUpdate` | 并发更新期间状态已变化 |
| `LogContractViolation` | A/B 调用结果违反既定不变量 |
| `CosignerCollectionError` | 外部有效签名集合没有达到阈值 |

这些异常都继承 `MTCError`。其中一致性或状态损坏错误应停止签名并告警。
