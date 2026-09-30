"""MTC 优化方案总包：Sync / Proof Reuse / Filter / Experiment。

只复用 Baseline ``mtc`` 的公共 API，不复制其中的 Merkle、Proof、Checkpoint 或
Certificate 逻辑；Baseline 不依赖本包，可以独立运行作为对照。
跨方案共享的新类型统一定义在 :mod:`mtc_opt.contracts`。
"""

from __future__ import annotations

__all__ = ["contracts"]
__version__ = "0.1.0"
