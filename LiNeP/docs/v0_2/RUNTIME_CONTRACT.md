# LiNeP V0.2 Runtime Baseline Specification & Protocol Contract

## 1. Overview & Architectural Scope

The **LiNeP V0.2 Runtime Baseline** defines an engine-neutral protocol for streaming, chat, reasoning, embeddings, and control multiplexing across local and distributed AI inference runtimes.

LiNeP V0.2 maintains strict separation from the frozen V0.1 baseline:
- `LINEP_BUILD_V02` defaults to `OFF`.
- V0.1 framing, headers, C-ABI, and unit tests are completely untouched.
- V0.2 headers reside in `include/linep/v0_2/`.

---

## 2. Envelope Families & Canonical Header

All V0.2 communication uses 32-byte canonical little-endian headers (`wire_envelope_header`):

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Magic (0x504E4C32 - "2LNP")                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version Major | Version Minor | Envelope Type |     Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         request_id (64)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        execution_id (64)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         output_id (32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload_len (32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Envelope Families:
1. `RUNTIME_REQUEST (1)`: Client initiates generation, chat, or embedding stream.
2. `RUNTIME_EVENT (2)`: Server emits streaming tokens, reasoning, embeddings, or terminal outcomes.
3. `RUNTIME_CONTROL (3)`: Scoped cancellation (`cancel`) or cumulative flow control (`window_update`).
4. `RUNTIME_CAPABILITIES (4)`: Profile discovery and vector space negotiation.

---

## 3. Identity Scopes & Stream Lifecycle

A logical stream is uniquely identified by `stream_identity`:
- `request_id`: Identifies the client-level logical request.
- `execution_id`: Identifies a single execution attempt of the request.
- `output_id`: Distinguishes candidates in multi-output requests (`n > 1`) or batch embedding items.

### Lifecycle State Machine & Mutual Exclusion
```text
[idle] -> submit_request() -> [active] -> cancel() -> [cancel_requested]
                                  |                         |
                           completed/failed            cancelled
                                  \                         /
                                   -> [terminal] (Exactly ONE authoritative outcome)
```

1. `CANCEL_REQUESTED` is non-terminal.
2. Exactly **ONE authoritative terminal outcome** is produced (`completed`, `cancelled`, `failed`, or `unknown`).
3. Once terminal, all subsequent cancellation attempts or terminal transitions are rejected with code `410 Gone`.

---

## 4. Flow Control & Bounded Buffering

LiNeP V0.2 implements hybrid backpressure:
1. **Local Bounded Send Queue (`stream_send_scheduler`)**:
   - Per-stream frame limits (`max_frames_per_stream = 16`).
   - Per-stream byte limits (`max_bytes_per_stream = 1 MiB`).
   - Connection-wide memory limit (`max_total_connection_bytes = 8 MiB`).
   - Round-Robin trunk multiplexing with single-writer `flush_mutex_`.
   - **Zero Silent Loss**: Frames are peeked and only committed upon verified successful socket delivery. On socket failure/teardown, uncommitted frames remain in the queue.
2. **Protocol Credit Pacing (`control_envelope::window_update`)**:
   - Monotonic cumulative byte offset (`ack_offset_bytes`).
   - Idempotent and replay-safe against duplicate ACKs.
   - Fail-closed: `ack_offset_bytes > total_produced_bytes` is rejected with protocol violation error code `422`.

---

## 5. Embedding Profiles & Representation Identity

Embedding results require vector space compatibility descriptors:
- `embedding_space_id`: Canonical space name (e.g. `nomic-embed-v1.5`, `text-embedding-3-small`).
- `model_id` & `model_revision`.
- `dimensions`: Exact dimensionality (e.g. 768, 1536).
- `normalization`: e.g. `l2`.
- `distance_metric`: `cosine`, `dot`, `euclidean`.

> [!IMPORTANT]
> Equal dimensions alone **never** imply vector space compatibility.
