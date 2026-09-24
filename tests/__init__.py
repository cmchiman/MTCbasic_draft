"""Test suite for the MTC Issuance Log Core (work package A).

Test layout: ``tests/{merkle,subtree,proof,entry,issuance_log,pruning}``.

The package adds ``src`` to ``sys.path`` so the suite runs straight from a
checkout, without installing the package::

    python -m unittest discover -s tests -t.
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
