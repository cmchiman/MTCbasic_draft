# MTCbasic_draft
https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-10对此草案实现
本阶段不实现 Checkpoint/Landmark 同步、Proof Reuse、Bloom/Cuckoo Filter、Outer Landmark Merkle Tree 等；这些要以后统一建立在 Baseline 上
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
