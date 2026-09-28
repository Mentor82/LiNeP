# LiNeP V0.2 Conformance Harness & Verification Specification

## 1. Conformance Principle

Conformance to LiNeP V0.2 is based strictly on **executed test suite verification**, not adapter self-declaration. Any engine or runtime claiming compatibility must pass the automated conformance test suites.

---

## 2. Standardized Conformance Test Suites

| Suite ID | Tested Invariants | Required For |
|---|---|---|
| `CAPABILITIES_HANDSHAKE` | Querying & decoding `capabilities_envelope`, model availability, streaming support. | All Profiles |
| `BASIC_CHAT_STREAMING` | Request dispatch, sequence monotonicity `1..N`, non-empty delta delivery, terminal `completed` (200). | `PROFILE_GENERATE`, `PROFILE_CHAT` |
| `REASONING_DELTAS` | Strict ordering: all `reasoning_delta` events must arrive strictly before `content_delta`. | `PROFILE_CHAT` |
| `EMBEDDING_SPACE_CONFORMANCE` | Vector dimension matching, L2 normalization ($\|v\|_2 \approx 1.0$), cosine metric validation. | `PROFILE_EMBED` |
| `CANCEL_UNDER_LOAD` | Immediate cessation of token generation upon network `cancel`, terminal `cancelled` (499). | `PROFILE_GENERATE`, `PROFILE_CHAT` |
| `BACKPRESSURE_FLOW_CONTROL` | Bounded in-flight buffer window pacing via cumulative monotonic `WINDOW_UPDATE`. | `PROFILE_GENERATE`, `PROFILE_CHAT` |
| `PROTOCOL_VIOLATION_FAIL_CLOSED` | Immediate socket teardown (`close()`) upon tampered magic or corrupt framing. | All Profiles |
| `CONTENT_SNAPSHOT_EQUIVALENCE` | Full cumulative text snapshot delivery via `content_snapshot` events. | `PROFILE_GENERATE` |
| `MULTI_OUTPUT_STREAMING` | Concurrent delivery of multiple candidates (`output_id = 0, 1, ...`) under shared execution. | `PROFILE_GENERATE` |
| `SL1_MUTUAL_HANDSHAKE` | Signed `SESSION_BIND` (`auth_seq = 1`, client $\to$ server) with signed server confirmation (`auth_seq = 1`, server $\to$ client). | `PROFILE_SL1` |
| `SL1_AUTHENTICATED_STREAMING` | Full HMAC-SHA256 authenticated streaming pipeline with monotonic `auth_seq >= 2` and key validation. | `PROFILE_SL1` |
| `SL1_MISSING_AUTH_REJECTION` | Unauthenticated frame rejected on active SL1 session; connection terminates fail-closed. | `PROFILE_SL1` |
| `SL1_WRONG_KEY_REJECTION` | Tampered signature or invalid `key_id` rejected with 401 Unauthorized. | `PROFILE_SL1` |
| `SL1_REPLAY_REJECTION` | Stale or replayed `auth_seq` rejected with 401 Unauthorized; strict sequence monotonicity. | `PROFILE_SL1` |

---

## 3. Profile Conformance Matrix

```text
PROFILE_GENERATE ...... CONFORMANT
PROFILE_CHAT .......... CONFORMANT
PROFILE_EMBED ......... CONFORMANT
PROFILE_SL1 ........... CONFORMANT
```

---

## 4. Deterministic Mock Runtime Failure Modes

The `mock_runtime_server` provides deterministic reproduction of edge cases:
- `--delay-per-event`: Simulates inference latency per chunk.
- `--delta-mode` / `--snapshot-mode`: Verifies delta vs snapshot streaming equivalence.
- `--multi-output`: Emits multiple candidate outputs per prompt.
- `--batch-embed N`: Emits batch embedding vectors across indexed output scopes.
- `--fail-after N`: Forces runtime error 500 mid-stream.
- `--cancel-after-accept`: Tests cancellation race before first output is generated.
- `--disconnect-before-terminal`: Tests client behavior under abrupt TCP teardown.
- `--require-sl1`: Enforces strict SL1 authenticated framing on all incoming data connections.
- `--sl1-key <hex>`: Configures 256-bit pre-shared symmetric key (hex-encoded, $\ge 32$ bytes).
- `--sl1-key-id <id>`: Configures the active `key_id` (default: 1).
