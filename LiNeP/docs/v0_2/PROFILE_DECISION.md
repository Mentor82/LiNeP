# LiNeP V0.2 Runtime Profile: PROFILE_DECISION (SystemOne / Decision Inference)

Status: **Normative Specification Baseline** (Gate C2/C3 Decision Extension).  
Governing Standard: `equorus-value-v1`, LiNeP V0.2 Protocol Specifications.  
Compatibility Target: Fully interoperable with `PROFILE_VISION.md` (Profile 4, Event 13) and baseline V0.2 profiles.

---

## 1. Overview & Architectural Role

`PROFILE_DECISION` standardizes structured decision, classification, scoring, and ranking inference (such as ModernBERT / SystemOne architectures, including `Laya 322M` and `d1-omni`) within the LiNeP V0.2 protocol family.

### Architectural Invariants:
1. **Separation of Concerns:**
   - **Text Generation Runtimes:** Serve `PROFILE_CHAT` (1) and `PROFILE_GENERATE` (2) for free-form streaming auto-regressive token generation.
   - **Embedding Runtimes:** Serve `PROFILE_EMBED` (3) for dense vector space transformations.
   - **Vision Accelerators:** Serve `PROFILE_VISION` (4, Event 13) for 2D/3D perception and spatial object detection.
   - **Decision Runtimes:** Serve `PROFILE_DECISION` (5, Event 14) for bounded, deterministic choice evaluation, confidence scoring, criteria weighting, and noul probability estimation over discrete hypothesis spaces.
2. **Deterministic Non-Streaming Result Delivery:**
   - Unlike auto-regressive text streaming, decision inference produces structured result payloads delivered in a single `runtime_event_type::decision_result` (14) DATA event per item or question batch, followed by canonical `terminal_outcome::completed` terminal envelope.
3. **Hardware & Execution Independence:**
   - The wire protocol operates identically across standalone C++ engine servers (`linep-llama-server`), in-process Go client adapters (`LiNeP-Ollama`), and trunk multiplexers/routers (`liara-noded 1.18.0`).

---

## 2. Wire Allocation & Envelope Values

| Identifier | Type | Wire Value | Meaning |
| :--- | :--- | :--- | :--- |
| `runtime_profile::decision` | `uint8_t` | `5` | Profile identifier for decision / scoring runtimes |
| `runtime_event_type::decision_result` | `uint8_t` | `14` | Non-terminal DATA event containing structured decision answers |
| `runtime_profile::vision` | `uint8_t` | `4` | Co-existing computer vision runtime profile |
| `runtime_event_type::vision_result` | `uint8_t` | `13` | Co-existing computer vision event type |

---

## 3. Framing Budgets & Bounds (Fail-Closed)

To prevent resource exhaustion and buffer denial-of-service across distributed micro-nodes and edge devices, all implementations strictly enforce the following normative limits:

| Constant | Value | Description |
| :--- | :--- | :--- |
| `LINEP_V02_MAX_DECISION_STRING_BYTES` | `256` bytes | Maximum length for identifiers (`model_id`, `model_revision`, `decision_type`) |
| `LINEP_V02_MAX_DECISION_MODELS` | `1024` | Maximum models advertised in a single capabilities envelope |
| `LINEP_V02_DECISION_FRAME_CEILING` | `1,044,480` bytes | Strict maximum envelope frame size ($1\text{ MiB} - 4\text{ KiB}$) |
| `LINEP_V02_DECISION_BODY_BUDGET_SL1` | `1,044,393` bytes | Maximum JSON payload body budget under SL1 authenticated sessions |
| `LINEP_V02_DECISION_BODY_BUDGET_PLAIN` | `1,044,417` bytes | Maximum JSON payload body budget under SL0 unauthenticated sessions |

Any frame exceeding these limits or containing truncated strings MUST be rejected fail-closed without parsing or memory pre-allocation.

---

## 4. Input Contract (REQUEST Envelope 1)

A client initiates decision inference using a standard `request_envelope`:
- `profile`: `runtime_profile::decision` (`5`)
- `model_id`: Identifier of the advertised decision model (e.g. `"clef-decision:test"`, `"laya-322m"`, `"lfm2-d1-omni"`)
- `stream`: Explicit `stream_identity` (`request_id`, `execution_id`, `output_id`)
- `payload`: UTF-8 encoded JSON payload conforming to the SystemOne decision schema:
  - `model`: Model identifier string matching `model_id`.
  - `state`: Optional session state object (e.g. `{"session_id": "test-c1-001"}`).
  - `questions`: Map of question IDs to question definitions:
    - `type`: `"choice"`, `"score"`, or `"noul"`.
    - `instructions`: Natural language question or scenario prompt.
    - `criteria`: Map of candidate choices / criteria to null or option configs.
- Options:
  - Auto-regressive token sampling options (`temperature`, `top_p`, `top_k`) are ignored or constrained to $0.0$.
  - `max_tokens` is bounded by the backend KV context window ($8192$ tokens for SystemOne).

---

## 5. Output Contract (EVENT Envelope 2 `decision_result`)

Decision results are returned over the event stream associated with the request's `stream_identity`:

### A. Non-Terminal Event Invariants
1. `event_type == runtime_event_type::decision_result` (`14`).
2. `is_terminal() == false`: The `decision_result` event is strictly a DATA event. It MUST NOT carry `terminal_outcome::completed` or terminate the stream.
3. Payload MUST NOT be empty (`payload.empty()` is invalid and rejected fail-closed).
4. Timestamp MUST be monotonic microsecond epoch (`timestamp_us > 0`).

### B. Payload Structure (JSON)
The event payload contains a serialized JSON object:
- `model`: Evaluated model identifier string.
- `answers`: Map of question IDs matching the input request to result objects:
  - `choice`: Selected string key from input criteria with highest softmax probability.
  - `score`: Normalized float confidence score $\in [0.0, 1.0]$.
  - `noul`: In noul mode, calibrated continuous float metric $\in [0.0, 1.0]$.
- `usage`: Token consumption metrics:
  - `input_tokens`: uint32 prompt / context token count.
  - `output_tokens`: uint32 evaluation token count.

### C. Stream Finalization
Following the transmission of all `decision_result` events, the provider MUST emit a final terminal event (`event_type == completed` or outcome set) to close the `stream_identity` lifecycle.

---

## 6. Model Capabilities Declaration (Envelope 4 Capabilities - Positional Pfad A)

LiNeP V0.2 declares specialized capabilities using canonical positional extensions at the end of `capabilities_envelope`. This guarantees zero-copy backward compatibility with V0.1 and baseline V0.2 peers.

### A. Positional Sequencing
```
[Baseline Capabilities V0.2 (profiles, models, spaces, limits)]
  [supported_vision_models_count: uint16_le]  = V
  [V vision_model_descriptors...]
    [supported_decision_models_count: uint16_le] = D
    [D decision_model_descriptors...]
```

### B. Positional Anchor Rule (Pfad A Invariant)
1. **Both Present:** $V > 0$ vision models are serialized, followed immediately by $D > 0$ decision models.
2. **Decision Only ($V = 0$):** If a runtime supports decision models but no vision models, it MUST write `0u16` for the vision count as an explicit positional anchor, followed by $D > 0$ decision models.
3. **Vision Only ($D = 0$):** If a runtime supports vision models but no decision models, the frame terminates after the vision descriptors. No trailing decision count is written.
4. **Baseline Only ($V = 0 \land D = 0$):** The payload terminates after the baseline embedding space descriptors. Neither vision nor decision bytes are written.

### C. Decision Model Descriptor Wire Format
For each of the $D$ decision models:
```
[model_id_len: uint16_le]       = length of model_id string (1 .. 256)
[model_id: bytes]               = UTF-8 string
[model_rev_len: uint16_le]      = length of model_revision string (0 .. 256)
[model_rev: bytes]              = UTF-8 string
[decision_type_len: uint16_le]  = length of decision_type string (1 .. 256)
[decision_type: bytes]          = UTF-8 string (e.g. "choice,score,noul" or GGUF metadata)
```

### D. Security & Pre-Allocation Guard
Decoders MUST validate:
$$D \le \text{LINEP\_V02\_MAX\_DECISION\_MODELS}\ (1024) \quad \text{and} \quad D \le \frac{\text{remaining\_bytes}}{6}$$
Buffers failing this check MUST be rejected immediately to prevent heap exhaustion.

---

## 7. Authentication, Sessions & Lease Contract (SL0 / SL1)

1. **SL0 (Plain Mode):**
   - Allowed on loopback (`127.0.0.1`) for local orchestrator-to-runner connections without authentication headers.
2. **SL1 (Authenticated Mode):**
   - For network and routed hops, frames carry `wire_auth_extension` signed with HMAC-SHA256 over the canonical 80-byte header prefix:
     `magic` (4B) + `version` (2B) + `envelope_type` (1B) + `auth_flag` (1B) + `stream_identity` (24B) + `length` (4B) + `auth_seq` (8B) + `key_id` (4B) + `timestamp` (8B) + `control_epoch` (8B) + `lease_token` (8B) + `reserved` (8B).
3. **Lease Enforcement & Process Ownership:**
   - Native decision runners bind to an active `lease_token` issued via `session_bind` (Envelope 8).
   - In single-slot mode (`--slots 1`), requests with mismatched lease tokens or concurrent leases are rejected fail-closed.

---

## 8. OldPeer Compatibility & Cross-Runtime Routing Matrix

| Peer Version | Capabilities Behavior | Routing / Admission Behavior |
| :--- | :--- | :--- |
| **V0.2 Legacy (1.16)** | Does not parse vision or decision; treats payload ending at base descriptors as complete. | Does not advertise Profile 5; requests to Profile 5 fail with `UNSUPPORTED_PROFILE`. |
| **V0.2 Vision (1.17)** | Parses $V$ vision models; ignores or rejects unconsumed trailing bytes if strict. | Profile 4 supported; Profile 5 rejected as unknown profile. |
| **V0.2 Full (1.18+)** | Parses both $V$ and $D$ via Positional Pfad A; validates DoS bounds and trailing garbage. | Full dual-stack support for Profile 4 (`VISION`) and Profile 5 (`DECISION`). |

### Strict Router Invariant (`liara-noded 1.18.0`):
Typed profiles (`PROFILE_VISION` and `PROFILE_DECISION`) are **strictly excluded** from generic wildcard (`any_model`) fallbacks. A decision request is routed ONLY to runtimes explicitly advertising `PROFILE_DECISION` (5) and matching the requested `model_id`.

---

## 9. Golden Test Vectors

### Golden Vector 1: Standard Choice Question Request (Plain, 307 Bytes)
- **Envelope:** `request_envelope` (Envelope 1), Profile: 5 (`decision`), Model: `"clef-decision:test"`
- **Stream:** `request_id = 1`, `execution_id = 1`, `output_id = 1`
- **Wire Hex (307 Bytes):**
  ```
  324C4E5000020100010000000000000001000000000000000100000013010000051200636C65662D6465636973696F6E3A74657374F100
  00007B226D6F64656C223A22636C65662D6465636973696F6E3A74657374222C227374617465223A7B2273657373696F6E5F6964223A22
  746573742D63312D303031227D2C227175657374696F6E73223A7B227131223A7B2274797065223A2263686F696365222C22696E737472
  756374696F6E73223A2257656C636865732050726F746F6B6F6C6C2062696574657420737472696B7465204661696C2D436C6F73656420
  476172616E7469656E3F222C226372697465726961223A7B22485454502F312E31223A6E756C6C2C224C694E65502056302E32223A6E75
  6C6C2C22576562536F636B6574223A6E756C6C7D7D7D7D000000000000000000
  ```

### Golden Vector 2: Noul Probability Event (SL1 Authenticated, 211 Bytes)
- **Envelope:** `event_envelope` (Envelope 2), Event Type: 14 (`decision_result`), Outcome: `unknown` (DATA)
- **Stream:** `request_id = 1`, `execution_id = 1`, `output_id = 1`, `event_seq = 1`
- **SL1 Security:** `key_id = 0x0100`, `auth_seq = 1`, Direction: Responder $\rightarrow$ Initiator
- **Wire Hex (211 Bytes):**
  ```
  324C4E500002020101000000000000000100000000000000010000009B0000000100000000010000152FE0ECB29AEA0114A2E4D3A52B60
  1F01000000000000000E000000000000000000007C0000007B226D6F64656C223A22636C65662D6465636973696F6E3A74657374222C22
  616E7377657273223A7B227132223A7B2274797065223A226E6F756C222C226E6F756C223A302E393939357D7D2C227573616765223A7B
  22696E7075745F746F6B656E73223A33382C226F75747075745F746F6B656E73223A31357D7D00502B5450250600
  ```

---

## 10. Error Codes & Failure Modes

| Error Category | Code / Reason | Trigger Condition |
| :--- | :--- | :--- |
| `error_category::unsupported` | `"DECISION_UNSUPPORTED_PROFILE"` | Node or runtime does not support Profile 5 |
| `error_category::unsupported` | `"DECISION_MODEL_NOT_FOUND"` | Requested `model_id` is not advertised in `supported_decision_models` |
| `error_category::bad_request` | `"DECISION_INVALID_PAYLOAD"` | Payload is empty, not valid JSON, or exceeds framing budget |
| `error_category::bad_request` | `"DECISION_EMPTY_QUESTIONS"` | JSON payload contains no questions to evaluate |
| `error_category::security_violation` | `"DECISION_AUTH_MISMATCH"` | Missing SL1 MAC or invalid session/lease signature |
| `error_category::resource_exhausted` | `"DECISION_BUFFER_OVERFLOW"` | Payload exceeds `LINEP_V02_DECISION_FRAME_CEILING` |
| `error_category::internal_error` | `"DECISION_EVALUATION_FAILED"` | Backend forward-pass error or NaN output in softmax normalization |
