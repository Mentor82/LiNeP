# LiNeP & Cluster Contract Governance — Agent & Copilot Instructions

## 1. Core Principle: Zero-Drift Canonical Architecture
All cross-service and inter-node communication in the L.I.A.R.A. OS ecosystem is governed by **EQUORUS (Canonical Profile: `equorus-value-v1`)**.
- **Do NOT create custom JSON serializers or ad-hoc hashing logic.**
- Any shared payload (Heartbeats, LLM Inferenz-Requests, Provenance, Artifacts) must be wrapped in a validated EQUORUS Envelope (`type_id`, `schema_version`, `provenance`, `payload`).
- Computing integrity must use the deterministic detached SHA-256 integrity record (`compute_integrity` / `equorus::compute_integrity`).

---

## 2. Standard Imports by Language

### Python (L.I.A.R.A. OS system-wide or repo)
```python
from equorus import Envelope, Limits, ContractError, compute_integrity

# Decoding & Integrity calculation
envelope = Envelope.decode(raw_bytes, "linep.v02.request")
record = compute_integrity(envelope)
canonical_sha256 = record.digest
```

### C++20 (L.I.A.R.A. OS `/usr/include/equorus` or CMake `equorus::`)
```cpp
#include <equorus/equorus.hpp>
#include <equorus/integrity.hpp>
#include <equorus/adapters/linep.hpp>

// Decoding & Integrity calculation
auto env = equorus::pilot::decode(raw_json_string, "linep.v02.request");
auto record = equorus::compute_integrity(env);
std::string canonical_sha256 = record.digest;
```

### C ABI (FFI, Dynamic Libraries, C callers)
```c
#include <equorus/equorus_c.h>

equorus_envelope_t* env = NULL;
equorus_envelope_decode(json_ptr, json_len, "linep.v02.request", 17, &env);
// ...
equorus_envelope_free(env);
```

### Rust (100% Rust Standard Library, Zero Dependencies)
```rust
use equorus::{Envelope, compute_integrity};

let env = Envelope::decode(raw_bytes, "vinox.provenance.snapshot")?;
let record = compute_integrity(&env)?;
println!("Digest: {}", record.digest);
```

---

## 3. Pre-Commit / Pre-Merge Conformance Verification
Before merging code or committing payloads generated across different AI chats or worktrees:

1. **Verify via Cluster CLI Tool (on VM 107 / VM 108):**
   ```bash
   equorus-verify <payload.json> [type_id]
   # Or pipe stdin:
   cat payload.json | equorus-verify -
   ```

2. **Verify via Live 5-Runtime Cluster Daemon API:**
   ```bash
   curl -s -X POST http://192.168.178.161:8088/api/compare \
     -H "Content-Type: application/json" \
     -d '{"type_id": "linep.v02.request", "raw": "..."}'
   ```
   *Rule:* A payload or adapter is only valid if `all_match: true` across all 5 runtimes (C++20, Rust, Go, Python, Browser JS).

3. **Inspect Interactively:**
   Open the cluster workbench: **`http://192.168.178.161:8088/`** $\rightarrow$ Tab **Live Node Compare**.
