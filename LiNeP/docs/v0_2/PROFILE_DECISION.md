# LiNeP V0.2 Runtime Profile: PROFILE_DECISION (SystemOne / Decision Inference)

Status: **Normative Specification Baseline** (Gate C2/C3 Decision Extension).  
Governing Standard: `equorus-value-v1`, LiNeP V0.2 Protocol Specifications.  
Compatibility Target: Interoperable with `PROFILE_VISION.md` (Profile 4, Event 13) and baseline V0.2 profiles.

---

## 1. Overview & Architectural Role

`PROFILE_DECISION` standardizes structured decision, classification, scoring, and ranking inference (such as ModernBERT / SystemOne architectures, including `Laya 322M` and `d1-omni`) within the LiNeP V0.2 protocol family.

### Architectural Invariants:
1. **Separation of Concerns:**
   - **Text Generation Runtimes:** Serve `PROFILE_GENERATE` (1) and `PROFILE_CHAT` (2) for auto-regressive token streaming.
   - **Embedding Runtimes:** Serve `PROFILE_EMBED` (3) for dense vector space transformations.
   - **Vision Accelerators:** Serve `PROFILE_VISION` (4, Event 13) for 2D spatial perception and object detection.
   - **Decision Runtimes:** Serve `PROFILE_DECISION` (5, Event 14) for bounded choice evaluation, scoring, rubric rating, and noul likelihood estimation over discrete hypothesis spaces.
2. **Deterministic Event Delivery Lifecycle:**
   - Decision inference produces structured answer payloads delivered in a single `runtime_event_type::decision_result` (14) DATA event per evaluated request, followed by a standard terminal event (`runtime_event_type::completed`, value 10).
3. **Execution Decoupling:**
   - The wire protocol operates identically across standalone C++ engine servers (`linep-llama-server`), in-process Go client adapters (`LiNeP-Ollama`), and trunk multiplexers/routers (`liara-noded 1.18.0`).

---

## 2. Wire Allocation & Envelope Values

| Identifier | Type | Wire Value | Meaning |
| :--- | :--- | :--- | :--- |
| `runtime_profile::generate` | `uint8_t` | `1` | Text completion / generation profile |
| `runtime_profile::chat` | `uint8_t` | `2` | Interactive chat profile |
| `runtime_profile::embed` | `uint8_t` | `3` | Dense embedding space profile |
| `runtime_profile::vision` | `uint8_t` | `4` | Computer vision profile |
| `runtime_profile::decision` | `uint8_t` | `5` | Decision / scoring runtime profile |
| `runtime_event_type::completed` | `uint8_t` | `10` | Stream finalization terminal event |
| `runtime_event_type::cancelled` | `uint8_t` | `11` | Client cancellation terminal event |
| `runtime_event_type::failed` | `uint8_t` | `12` | Runtime error terminal event |
| `runtime_event_type::vision_result` | `uint8_t` | `13` | Structured vision result event |
| `runtime_event_type::decision_result` | `uint8_t` | `14` | Structured decision result DATA event |

---

## 3. Framing Budgets & Decoder Bounds (Fail-Closed)

### A. Normative Decoder Wire Bounds
To prevent resource exhaustion across distributed nodes, decoders in C++, Go, and Rust enforce the following normative validation boundaries on wire capabilities frames:
- `LINEP_V02_MAX_DECISION_STRING_BYTES = 256` bytes: Upper bound on string lengths for `model_id`, `model_revision`, and `decision_type`.
- `LINEP_V02_MAX_DECISION_MODELS = 1024`: Maximum decision models allowed in a single capabilities envelope.
- **Pre-Allocation DoS Guard:** Decoders must verify $D \le 1024 \land D \le (\text{remaining\_bytes} / 6)$ before allocating descriptor vectors.
- **Strict Canonical Framing:** Capabilities and envelopes must consume all declared bytes; trailing unparsed garbage causes immediate decoding failure (`return false`).

### B. Protocol Framing Budgets (Payload Sizing)
The following constants define protocol-level framing envelopes:
- `LINEP_V02_DECISION_FRAME_CEILING = 1,044,480` bytes ($1\text{ MiB} - 4\text{ KiB}$ maximum envelope frame size).
- `LINEP_V02_DECISION_BODY_BUDGET_SL1 = 1,044,393` bytes: Usable JSON payload budget under SL1 authenticated sessions.
- `LINEP_V02_DECISION_BODY_BUDGET_PLAIN = 1,044,417` bytes: Usable JSON payload budget under SL0 unauthenticated sessions.

---

## 4. Input Contract (REQUEST Envelope 1)

A client initiates decision inference using a standard `request_envelope`:
- `profile`: `runtime_profile::decision` (`5`).
- `model_id`: Identifier of the decision model (e.g. `"laya:322m-multilingual-bf16"`, `"clef-decision:test"`, or concrete model path).
- `stream`: Explicit `stream_identity` (`request_id`, `execution_id`, `output_id`).
- `payload`: UTF-8 encoded JSON payload adhering to the SystemOne schema:
  - `model`: String identifier matching or aliased to `model_id`.
  - `state`: **Mandatory and not-null** (`"state"` must be provided). Describes the problem context, conversation history, or session state. If passed as a JSON string, it is used verbatim; if passed as a structured JSON object or array, it is serialized to string representation (e.g. via `dump()`).
  - `questions`: Non-empty map of question IDs (`"q1"`, `"q2"`, ...) to question specifications:
    - `"type": "choice"`: Discrete candidate selection (2 to 255 options). Requires `instructions` (non-empty string). Options are supplied either via `criteria` (map of option keys to descriptive labels, e.g. `{"A": "Option 1", "B": "Option 2"}`) or via `options` (array of option key strings).
    - `"type": "score"`: Rubric/rating evaluation (2 to 10 discrete levels). Requires `instructions` (non-empty string). Levels are supplied either via `criteria` (ordered array of level descriptors, e.g. `["low", "medium", "high", "critical"]`) or via `options` (array of 2 to 10 level labels).
    - `"type": "noul"`: Direct binary hypothesis / probability estimation over boolean outcomes (`"false"`, `"true"`). Requires `instructions` (non-empty string). Optionally accepts `criteria` describing the binary outcomes.
  - *Note on Schema Flexibility:* The listed schemas represent the minimal normative wire baseline; backends accept canonical `criteria` mappings as well as compatibility `options` arrays.
- Token Context Window:
  - Context size is bounded by the runtime's engine budget configuration (e.g. 8,192 tokens for Laya ModernBERT or 16,384 tokens for d1-omni as reference deployments, rather than a fixed architectural ceiling).
  - Generative sampling options (`temperature`, `top_p`, `top_k`) are not applicable to deterministic decision scoring and are ignored or fixed to $0.0$.

---

## 5. Output Contract (EVENT Envelope 2 `decision_result`)

Decision results are returned over the event stream associated with the request's `stream_identity`:

### A. Non-Terminal Event Invariants
1. `event_type == runtime_event_type::decision_result` (`14`).
2. `is_terminal() == false`: `decision_result` is strictly a non-terminal DATA event. Envelopes where `event_type == 14` must have `is_terminal() == false` (terminal events are exclusively types 10, 11, and 12).
3. Payload must not be empty (`payload.empty()` is invalid and rejected fail-closed).

### B. Result Payload Schema (JSON)
The event payload contains a single JSON object:
- `model`: String identifier of the serving engine / model blob.
- `answers`: Map of question IDs matching the input request:
  - For `"choice"`:
    - `"type": "choice"`
    - `"choice"`: Key of the winning candidate (highest softmax score).
    - `"probabilities"`: Map of candidate keys to softmax probabilities $\in [0.0, 1.0]$.
    - `"confidence"`: Calibrated decision confidence $\in [0.0, 1.0]$. In standard models (TypeSafe definition):
      $$\text{confidence} = \max\left(0.0, \frac{p_{\max} - \frac{1}{n}}{1.0 - \frac{1}{n}}\right)$$
      where $n$ is the option count and $p_{\max} = \max_i P(i)$. For entropy-based architectures (`vllm-decision2`, `vllm-d3`), normalized entropy $1 - \frac{H}{\ln n}$ is used ($H = -\sum p_i \ln p_i$).
  - For `"score"`:
    - `"type": "score"`
    - `"score"`: Expected rubric score $\sum_{i=0}^{n-1} i \cdot P(i)$ computed over the rubric levels (e.g. $1.5529$ for a 4-level scale $0 \dots 3$).
    - `"legend"`: Map of level indices (`"0"`, `"1"`, ...) to rubric labels.
    - `"probabilities"`: Map of level indices to softmax probabilities.
    - `"confidence"`: Mean distance to the mode relative to a uniform distribution:
      $$\text{dist} = \sum_{i=0}^{n-1} P(i) \cdot |i - \text{mode}|,\quad \text{dist}_{\text{uniform}} = \frac{1}{n}\sum_{i=0}^{n-1} \left|i - \frac{n-1}{2}\right|$$
      $$\text{confidence} = \max\left(0.0, 1.0 - \frac{\text{dist}}{\text{dist}_{\text{uniform}}}\right)$$
  - For `"noul"`:
    - `"type": "noul"`
    - `"noul"`: Probability of truth $P(\text{"true"})\in [0.0, 1.0]$. For ordinal rating scales (such as `LEV` with $n=9$ levels $0 \dots 8$), expected normalized rating $\sum_{i=0}^{n-1} \frac{P(i) \cdot i}{n - 1}$. Note: `noul` produces no separate `confidence` field.
- `usage`:
  - `input_tokens`: Prompt / context tokens processed.
  - `output_tokens`: Output tokens produced (typically 0 for pure classification/scoring).
- *Permissible Implementation / Wrapper Fields:* Engine wrappers and test harnesses may include additional diagnostic or compatibility fields (such as `id`, `question_id`, `options`, `answers_list`, `choice.score`, or detailed usage breakdowns); consumers MUST ignore unknown fields.

### C. Stream Lifecycle Finalization
1. **Successful Inference:** Exactly one non-terminal `decision_result` (14) event is emitted, immediately followed by a terminal `event_envelope` with `event_type == runtime_event_type::completed` (`10`) and outcome `terminal_outcome::completed`.
2. **Early Abort / Failure:** If request validation fails, resources are exhausted, or an inference error occurs, the provider MUST terminate the stream directly with `event_type == runtime_event_type::failed` (`12`) and the corresponding `error_category` without emitting an intermediate `decision_result` (14) event.
3. **Client Cancellation:** If cancelled by the client, the stream terminates directly with `event_type == runtime_event_type::cancelled` (`11`).

---

## 6. Model Capabilities Declaration (Envelope 4 Capabilities - Positional Pfad A)

Capabilities declare decision support using canonical positional extension framing at the end of `capabilities_envelope`:

### A. Positional Sequencing
```
[Baseline Capabilities V0.2]
  [supported_vision_models_count: uint16_le = V]
  [V x vision_model_descriptor...]
    [supported_decision_models_count: uint16_le = D]
    [D x decision_model_descriptor...]
```

### B. Positional Anchor Rule (Pfad A Invariant)
1. **Both Present ($V > 0 \land D > 0$):** $V$ vision models are serialized first, followed immediately by $D$ decision models.
2. **Decision Only ($V = 0 \land D > 0$):** An explicit `0u16` is written as the vision count positional anchor, followed by $D$ decision models.
3. **Vision Only ($V > 0 \land D = 0$):** $V$ vision models are serialized. No decision bytes are appended.
4. **Baseline Only ($V = 0 \land D = 0$):** Payload terminates after baseline descriptors. Neither vision nor decision bytes are appended.

### C. Decision Model Descriptor Wire Format
For each of the $D$ decision models:
```
[model_id_len: uint16_le]       = length of model_id string (1 .. 256)
[model_id: bytes]               = UTF-8 string
[model_rev_len: uint16_le]      = length of model_revision string (0 .. 256, may be empty)
[model_rev: bytes]              = UTF-8 string
[decision_type_len: uint16_le]  = length of decision_type string (1 .. 256)
[decision_type: bytes]          = UTF-8 string (e.g. "laya", "lfm2-d1-omni", or GGUF decision.type)
```

---

## 7. Authentication, Sessions & Lease Contract (SL0 / SL1)

### A. Transport Security Levels
1. **SL0 (Plain Mode):** Permitted on loopback (`127.0.0.1`) for local IPC and container-internal multiplexing without cryptographic MACs.
2. **SL1 (Authenticated Mode):** Required across network and inter-node boundaries.

### B. Canonical SL1 Cryptographic MAC Construction
Under SL1, envelopes carry a 16-byte MAC calculated as the truncated first 16 bytes of HMAC-SHA256 over a canonical authentication context buffer (80-byte prefix followed by payload):
1. **Envelope Header** (32 bytes Little-Endian with `FLAG_AUTHENTICATED` asserted)
2. **AuthExt Prefix** (8 bytes Little-Endian):
   - `auth_seq` (4 bytes, `uint32_t`)
   - `key_id` (2 bytes, `uint16_t`)
   - `reserved` (2 bytes, `uint16_t`, must be 0)
3. **Bound Identity & Lease Scope** (36 bytes Little-Endian):
   - `node_id` (8 bytes, `uint64_t`)
   - `runtime_id` (8 bytes, `uint64_t`)
   - `endpoint_id` (4 bytes, `uint32_t`)
   - `control_epoch` (8 bytes, `uint64_t`)
   - `lease_token` (8 bytes, `uint64_t`)
4. **Direction** (4 bytes):
   - `direction` (1 byte: `0x01` initiator $\to$ responder, `0x02` responder $\to$ initiator)
   - Zero padding (3 bytes, `0x00, 0x00, 0x00`)
5. **Payload** ($N$ bytes, `payload_len` length)

### C. Session Binding & Lease Scope
- Mutual key confirmation is established via signed `SESSION_BIND` (Envelope 5).
- Standalone C++ engine runners (`linep-llama-server`) support configurable security enforcement via CLI flags: `--require-sl1` and `--require-lease` (defaulting to `false` for loopback plain/dev operation).
- In authenticated D1 topologies and production environments, operator policy mandates `--require-sl1` and `--require-lease`, enforcing that incoming connections establish a valid `SESSION_BIND` and maintain active session state (`bound_current`) before serving requests.

---

## 8. OldPeer Compatibility & Cross-Runtime Routing

### A. OldPeer Behavior (Strict Fail-Closed)
Because canonical LiNeP V0.2 framing rejects unconsumed trailing bytes:
- **Peers without Decision Extension (e.g. baseline 1.16 or vision-only 1.17):** Fail-closed reject capabilities envelopes containing decision extensions due to trailing garbage checks.
- Old peers do not advertise Profile 5; requests targeting Profile 5 on unextended nodes are rejected fail-closed (or terminate with `error_category::unsupported` where explicit profile validation is implemented).

### B. Router Invariant (`liara-noded 1.18.0`)
- **Typed Profile Routing:** In `trunk_router.rs`, requests for `PROFILE_DECISION` (5) are routed strictly to runtimes that advertise Profile 5 and match the requested `model_id` via `model_matches(&dm.model_id, requested_model)` over their declared `supported_decision_models`.
- **Capability vs Request Scope:** Wire requests do not carry `decision_type`; `decision_type` is an advertised capability property verified by clients or providers during capability negotiation.
- **Independent Descriptor Lists:** Typed DECISION routing requires only matching entries in `supported_decision_models`; an entry in the generic `supported_models` list is not required.
- **Wildcard Exclusion:** Typed profiles (both `VISION` and `DECISION`) are **strictly excluded** from generic `any_model` wildcard fallbacks (`candidates()` returns `(Vec::new(), false)` if no explicit descriptor matches).

---

## 9. Golden Test Vectors

### Golden Vector 1: Standard Choice Question Request (Plain, 307 Bytes)
- **Envelope:** `request_envelope` (Envelope 1), Profile: 5 (`decision`), Model: `"clef-decision:test"`
- **Stream Identity:** `request_id = 1`, `execution_id = 1`, `output_id = 1`
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
- **Envelope:** `event_envelope` (Envelope 2), Event Type: 14 (`decision_result`), Outcome: `unknown` (0)
- **Stream Identity:** `request_id = 1`, `execution_id = 1`, `output_id = 1`, `event_seq = 1`
- **SL1 Security Parameters:**
  - Pre-Shared Key (Fixture): 32 bytes `0x42`
  - Bound Scope: `node_id = 1`, `runtime_id = 2`, `endpoint_id = 3`, `control_epoch = 4`, `lease_token = 5`
  - Auth Extension: `key_id = 0x0100`, `auth_seq = 1`, Direction: Responder $\to$ Initiator (`0x02`)
  - Timestamp: `1729876800000000` $\mu\text{s}$
- **Wire Hex (211 Bytes):**
  ```
  324C4E500002020101000000000000000100000000000000010000009B0000000100000000010000152FE0ECB29AEA0114A2E4D3A52B60
  1F01000000000000000E000000000000000000007C0000007B226D6F64656C223A22636C65662D6465636973696F6E3A74657374222C22
  616E7377657273223A7B227132223A7B2274797065223A226E6F756C222C226E6F756C223A302E393939357D7D2C227573616765223A7B
  22696E7075745F746F6B656E73223A33382C226F75747075745F746F6B656E73223A31357D7D00502B5450250600
  ```

---

## 10. Error Handling & Categories

Implementations convey failure conditions using the standard V0.2 `error_category` enumeration within `event_envelope` (Envelope 2):

| Error Category | Value | Application Condition (Illustrative Diagnostic Mappings) |
| :--- | :--- | :--- |
| `error_category::unsupported` | `6` | Profile 5 not supported by node, or requested `model_id` not advertised |
| `error_category::bad_request` | `2` | Malformed JSON payload, missing questions, or invalid criteria format |
| `error_category::unauthorized` | `3` | Missing or invalid SL1 HMAC, expired lease, or unauthenticated session bind |
| `error_category::resource_exhausted` | `4` | Payload exceeds framing ceiling or system slot capacity |
| `error_category::internal` | `7` | Inference engine forward-pass failure or numerical softmax anomaly |
