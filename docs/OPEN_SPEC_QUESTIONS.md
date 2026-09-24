# MISSING SPEC / 待确认的规范问题

按提示词要求：draft 引用的其它规范如果缺少实现所需细节，**不猜**，在此登记。

---

MISSING SPEC

* RFC: draft-ietf-tls-trust-anchor-ids（被 draft-davidben-tls-merkle-tree-certs-10 引用）
* Section: 第 3 节「Trust Anchor ID 的二进制表示」（draft-10 §5.2、§5.4.1 引用）
* Needed by: `mtc.log.log_id.LogID` / `TrustAnchorID`；`MTCSubtree` 与
  `MTCSubtreeSignatureInput` 的 `log_id` / `cosigner_id` 字段编码（§5.4.1）
* Why: draft-10 只给出示例（log named 32473.1 的 DN 值为 RELATIVE-OID
  `0d0481fd5901`，即 arc 串 `81fd5901`），没有给出 trust anchor ID 在 TLS 结构里
  的二进制表示定义。本实现按示例取「各 arc 独立 base-128 编码」，并同时提供
  `from_oid_der()`（完整 DER OID）与 `from_opaque()`（自定义字节）两种构造，
  其余代码全部按不透明字节处理，因此该假设只影响编码取值，不影响 Merkle/日志逻辑。
  若 B/C 采用其它表示，只需改构造方式。

---

其它已知的 draft 内部 TBD（不属于缺失规范，仅记录）：

* `id-rdna-trustAnchorID`、`id-alg-mtcProof`、`id-mod-mtc-2025` 的 OID 弧值在 draft-10
  中为 `TBD`；实现使用 draft 明确给出的早期实验值
  （属性类型 `1.3.6.1.4.1.44363.47.1`、算法 `1.3.6.1.4.1.44363.47.0`）。
* draft §7.2 的单趟 `entry_hash` 编号列表未显式写 `0x00` 叶子前缀，但同节第 5 步定义
  `MTH({entry}) = HASH(0x00 || entry)`；实现按第 5 步执行，并用测试锁定两条路径等价
  （见 `docs/A_IssuanceLogCore.md` 与 `tests/entry/test_entry.py`）。
