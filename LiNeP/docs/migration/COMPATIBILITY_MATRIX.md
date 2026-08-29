# LiNeP V0.1 / V0.2 Compatibility Matrix

| Capability / Semantics | V0.1 | V0.2 |
|---|---:|---:|
| UDP Control Plane | ✅ | ✅ |
| TCP Data Plane | ✅ | ✅ |
| Dual-plane architecture | ✅ | ✅ generalized |
| Persistent multiplexed TCP | ❌ | ✅ |
| Canonical runtime envelope families | ❌ | ✅ |
| Full `(request_id, execution_id, output_id)` identity | ❌ | ✅ |
| Logical `event_seq` | ❌ | ✅ |
| Explicit flow-control/window protocol | ❌ | ✅ |
| Runtime profiles | limited / ad-hoc | ✅ |
| Embedding-space identity | ❌ | ✅ |
| Control epoch/incarnation | ❌ | ✅ |
| Explicit UDP↔TCP lease binding | limited | ✅ |
| Explicit terminal `UNKNOWN` outcome | ❌ | ✅ |
| Cross-language golden-frame conformance | ❌ | ✅ |

## Important

The shared use of UDP and TCP does **not** imply wire or semantic compatibility between the versions.

A component may be:

- V0.1-only;
- V0.2-only;
- dual-version with explicit version separation.

It MUST NOT silently apply V0.2 semantics to V0.1 traffic or vice versa.
