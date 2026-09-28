# LiNeP V0.2 Reference

**Status: CURRENT NORMATIVE BASELINE**

LiNeP V0.2 standardizes communication between heterogeneous AI runtimes, orchestrators, and nodes. It standardizes protocol semantics, not the internal implementation of an AI runtime.

## Core model

```text
LiNeP V0.2
UDP Control Plane reference profile
        +
Persistent TCP Data Plane reference profile
        ↓
Dual-Plane Runtime Contract
```

LiNeP semantics are transport-neutral. UDP and TCP are reference transport profiles, not the semantic definition of LiNeP itself.

## Node model

LiNeP V0.2 distinguishes the network participant from the runtime implementation beneath it:

```text
LiNeP Node
  ├── Scheduler / Orchestrator function
  └── one or more Runtime(s)
         └── one or more Endpoint(s)
```

The canonical identity hierarchy is:

```text
node_id
  └── runtime_id
       └── endpoint_id
```

A scheduler/orchestrator is a node function or role and is not inherently a separate network identity. A runtime adapter such as an Ollama adapter is likewise not necessarily a complete LiNeP Node.

See [`NODE_MODEL.md`](./NODE_MODEL.md) for the normative definitions of Node, Runtime, Endpoint, Scheduler/Orchestrator, adapter boundaries, and topology.

## Identity

### Runtime/control identity

```text
(node_id, runtime_id, endpoint_id, control_epoch)
```

A lease token binds an authorized control-plane incarnation to a TCP runtime/trunk session.

### Runtime stream identity

```text
(request_id, execution_id, output_id)
```

Implementations MUST preserve all three components where stream-specific state is tracked. `output_id` MUST NOT be discarded from stream ownership, event sequencing, terminal state, or output-targeted control.

Control identity, runtime stream identity, conversation identity, transport session identity, and LiNeP-SL security-session identity are distinct concepts and MUST NOT be conflated.

## Data Plane

The reference data plane uses persistent TCP sessions with multiplexed logical runtime streams. The canonical V0.2 envelope header is 32 bytes and uses little-endian encoding.

Top-level envelope families:

- `RUNTIME_REQUEST` (1)
- `RUNTIME_EVENT` (2)
- `RUNTIME_CONTROL` (3)
- `RUNTIME_CAPABILITIES` (4)
- `SESSION_BIND` (5)

`event_seq` describes logical runtime event ordering. It is not a TCP packet sequence, UDP `control_seq`, or transport fragment sequence.

### Dual-Plane Session Handshake & Connection State Machine

A persistent TCP data-plane connection binds to the UDP control-plane identity and active lease via the `SESSION_BIND` envelope (envelope type `5`, payload size exactly 36 bytes canonical little-endian: `node_id [8B] · runtime_id [8B] · endpoint_id [4B] · control_epoch [8B] · lease_token [8B]`). Stream IDs in the 32-byte header MUST be `(0, 0, 0)`.

```text
TCP CONNECT
    │
    ▼
UNBOUND  ──[CAPABILITIES query/response allowed]
    │
    │ SESSION_BIND
    ▼
BOUND_CURRENT
    ├── REQUEST (accepted & multiplexed)
    ├── duplicate SESSION_BIND (idempotent no-op)
    │
    │ UDP lease rotation / epoch increment
    ▼
BOUND_STALE
    ├── in-flight executions finish
    ├── new REQUEST rejected (401 Unauthorized)
    │
    │ SESSION_BIND (new lease/epoch)
    ▼
BOUND_CURRENT
```

Key invariants:
- **`REQUEST` MUST NOT be accepted while UNBOUND or BOUND_STALE**: Any `REQUEST` envelope received before a valid `SESSION_BIND` or during `BOUND_STALE` is rejected with 401 Unauthorized.
- **Connection Persistence on Stale Requests**: While an `UNBOUND` request closes the connection, a `REQUEST` received during `BOUND_STALE` is rejected with 401 (`stale_binding`), but the **TCP connection MUST remain open**. This allows the client to immediately issue `SESSION_BIND(epoch+1, lease+1)` on the existing connection without reconnect overhead.
- **Connection-Reassignment Prevention**: An established connection is bound to a single node endpoint identity `(node_id, runtime_id, endpoint_id)`. Any `SESSION_BIND` on an existing connection (`BOUND_CURRENT` or `BOUND_STALE`) specifying a different identity MUST be rejected with a terminal connection-level event `(0, 0, 0)` and code 401 (`identity_change_on_existing_connection`), followed by immediate socket closure.
- **Connection-Level Events**: The stream identity tuple `(0, 0, 0)` (`request_id = 0, execution_id = 0, output_id = 0`) is **normatively reserved** for connection-level events (such as lease/binding failures). It MUST NOT be used for normal runtime task execution streams.
- **Separation of Decode and Semantic Authorization**:
  - `decode_session_bind()` performs purely syntactic validation (magic, versions, flags == 0, null stream IDs, exact 36-byte payload size).
  - Semantic lease validity is performed via `validate_tcp_session_binding()` against the UDP control plane router state.
- **Lease Token Semantics vs. Cryptographic Protection**: The 64-bit `lease_token` is an opaque handle and short-term lease identifier for logical dual-plane binding. It is **explicitly not a cryptographically strong bearer authentication secret**. Cryptographic authenticity, integrity, anti-replay, and confidential transport protection are provided exclusively by the LiNeP-SL security layer profiles.

### Client handshake (`lease_client`)

`include/linep/v0_2/lease.hpp` implements the client (node role) side so trunk clients do not re-implement it:

```cpp
lease_client_config cfg{};
cfg.control_host = "192.168.178.160"; // lease issuer UDP control port (IPv4)
cfg.control_port = 9001;
cfg.trunk_port   = 9000;              // advertised in NODE_HELLO / LEASE_ACK
lease_client lease(cfg);              // random identity, wall-clock control epoch
lease.acquire();                      // NODE_HELLO -> INVITE -> LEASE_ACK (+ delivery probe)
lease.start_keepalive();              // HEARTBEATs keep the lease from expiring
auto conn = connect_bound("192.168.178.160", 9000, lease); // TCP + SESSION_BIND
// on a stream EVENT with is_stale_binding_event(evt): lease.renew(); lease.bind(*conn); retry
```

- `NODE_HELLO` is retransmitted every `retransmit_ms` until an INVITE arrives.
- `LEASE_ACK` has no reply. The client probes with a same-epoch `NODE_HELLO`: a re-sent INVITE means the ACK was lost and it is re-sent, silence means the lease is active.
- `renew()` opens a new incarnation (higher `control_epoch`) with a fresh lease; existing connections re-bind in-band with `bind()`.

`lease_issuer` is the matching scheduler side (UDP listener around `control_plane_router`); `linep-v02-mock-runtime --udp-port P --require-lease` uses it, and `linep-v02-conformance --control host:P` exercises it (`dual_plane` profile).

## Security Layer: Profile SL1 (Shared-Key Authentication & Framing)

LiNeP-SL defines security profiles layered over the canonical wire envelopes. While SL0 denotes the unauthenticated plaintext transport, **SL1** provides symmetric-key authentication, frame integrity, and anti-replay protection via HMAC-SHA256 (truncated to 16 bytes).

### Wire Format & Extension Header

An authenticated frame sets the bit flag `FLAG_AUTHENTICATED` (`0x01`) in byte 7 (`flags`) of the 32-byte envelope header.
When `FLAG_AUTHENTICATED` is set, a 24-byte `wire_auth_extension` MUST be placed immediately after the 32-byte envelope header and immediately before any payload bytes:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Canonical Envelope Header (32B)               |
|            (byte 7: flags with FLAG_AUTHENTICATED = 0x01)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           auth_seq                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            key_id             |           reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     mac (16 bytes, HMAC-SHA256)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Bytes                         |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Total frame size = $32 + 24 + \text{payload\_len}$ bytes.
- For an authenticated `SESSION_BIND` envelope (payload = 36 bytes), total frame size is exactly **92 bytes**.

### Cryptographic MAC Construction

The 16-byte MAC is computed as the truncated first 16 bytes of HMAC-SHA256 over a canonical authentication context buffer (80-byte prefix followed by payload):
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

### Mutual Key Confirmation via Signed `SESSION_BIND`

In SL1, the session bind itself is signed, establishing mutual cryptographic key confirmation before any application payloads flow:
1. The initiator emits `SESSION_BIND` with `FLAG_AUTHENTICATED`, `auth_seq = 1`, and direction `initiator_to_responder` (`0x01`).
2. The responder verifies the MAC using the key matching `key_id`. If valid, the responder replies with a signed confirmation `SESSION_BIND` frame with `FLAG_AUTHENTICATED`, `auth_seq = 1`, and direction `responder_to_initiator` (`0x02`).
3. The initiator verifies the responder's signature on the confirmation frame. Both peers have verified that the counterparty possesses the valid pre-shared key for `key_id` before any runtime request or stream event is accepted.

### Post-Bind Error Authentication & Connection Security

- **Strict Post-Bind Authentication**: Once SL1 is active on a connection, **all** frames emitted by either peer MUST be signed with `FLAG_AUTHENTICATED`. This includes runtime error events emitted on `(0, 0, 0)` and `CAPABILITIES`.
- **Fail-Closed Teardown on Unsigned Frames**: If an unauthenticated frame arrives on an active SL1 connection, the receiver MUST immediately terminate the connection (fail-closed) and close the socket. This prevents off-path or on-path attackers from killing an active connection with a forged, unsigned "401" frame.
- **Pre-Bind Exceptions**: Unsigned frames are permitted only before or during the initial handshake (e.g. preliminary capabilities discovery or pre-bind lease rejections).

### Monotonic Sequences & Overflow Protection (`auth_seq`)

- Sequence counters increment monotonically per direction starting at 1 (consumed by `SESSION_BIND` and its confirmation). Application envelopes start at `auth_seq = 2`.
- Inbound sequences must increment monotonically per direction without gaps or replays ($S_{new} = S_{last} + 1$). Replays or sequence mismatches are rejected with 401 (`auth_replay`).
- **No Wrap-Around**: At $2^{32} - 1$ (`0xFFFFFFFF`), the sequence counter MUST NOT wrap around to 0 or 1. Any attempt to send or receive a frame with `auth_seq == 0xFFFFFFFF` terminates the connection with 401 (`auth_seq_exhausted`). The connection must perform a fresh handshake on a new incarnation.

### Receiver Key Rotation & Grace Window

- The sender always signs outgoing envelopes using `current_key_id`.
- The receiver accepts `current_key_id` and, during an active rotation grace window, `previous_key_id`.
- Pre-shared symmetric keys MUST be at least 32 bytes (256 bits) in length. Shorter keys MUST be rejected at configuration time.

### Unified 401 Error Classification

All authentication errors are classified under HTTP status 401 (`error_category::unauthorized`) for consistency with lease and binding rejection:
- `auth_required`: Required `FLAG_AUTHENTICATED` missing on active SL1 session.
- `unknown_key`: Unknown `key_id` or key unavailable / outside grace window.
- `auth_invalid`: HMAC verification failed (tampered content or wrong secret), or corrupted auth extension.
- `auth_replay`: Sequence number is non-monotonic or replayed ($S_{new} \neq S_{last} + 1$).
- `auth_unexpected`: Authenticated envelope received on non-SL1 connection.
- `auth_seq_exhausted`: Sequence counter reached $2^{32}-1$, re-bind required.

### Normative Verification Precedence

When validating an inbound SL1-authenticated envelope (including `SESSION_BIND`), endpoints evaluate checks in the following normative order:
1. **Authentication Requirement**: Verify `FLAG_AUTHENTICATED` is present on active SL1 sessions (`auth_required`).
2. **Sequence Monotonicity**: Verify sequence number ($S_{new} = S_{last} + 1$; for `SESSION_BIND`, $S = 1$) (`auth_replay`).
3. **Key Validity**: Verify `key_id` is configured and within active rotation window (`unknown_key`).
4. **Integrity / MAC**: Verify HMAC against header and payload (`auth_invalid`).

### Transport Scope & Follow-Up Tracking

- **UDP Control Plane**: Optional signed UDP control datagrams are designated for a future specification increment (**Future / Später**).
- **Downstream Adapter Tracking**:
  - `Mentor82/LiNeP-Ollama`: Formal follow-up issue tracked for Go Ollama adapter SL1 wire framing and verification.
  - `Mentor82/LiNeP-llama.cpp`: Formal follow-up issue tracked for C++ llama.cpp adapter SL1 wire framing and verification.

## Control Plane

The reference control plane uses an 80-byte UDP control datagram with strict semantic validation. The normative lifecycle is:

```text
UNKNOWN → SEEN → INVITED → ACTIVE
                     ↘ DEGRADED
                       COOLING
                       OFFLINE
```

Key invariants:

- only `NODE_HELLO` may introduce an unknown node;
- `INVITE` is scheduler→node and can only be issued from `SEEN`; a same-epoch `NODE_HELLO` of an `INVITED` node gets the same INVITE (same lease) again, so a lost INVITE or LEASE_ACK is recovered by retransmitting `NODE_HELLO`;
- `LEASE_ACK` requires the invited state, matching non-zero lease token, and a ready TCP trunk;
- inbound node→scheduler `INVITE` and `PING` are rejected;
- stale/lower epochs are rejected;
- only `NODE_HELLO` may establish a higher control epoch;
- same-epoch replay/duplicate sequencing is idempotent;
- rejected messages MUST NOT consume sequence, refresh liveness, alter lease state, or mutate routing/capability state;
- same-epoch `NODE_HELLO` MUST NOT downgrade an active/invited incarnation;
- UDP liveness loss does not prove that a running TCP execution stopped.

## Runtime and Security Profiles

The V0.2 baseline defines first-class runtime and security profiles:

### Runtime Profiles
- `PROFILE_GENERATE`
- `PROFILE_CHAT`
- `PROFILE_EMBED`

### Security Profiles
- `PROFILE_SL0`: Baseline unauthenticated plaintext transport.
- `PROFILE_SL1`: Shared-key HMAC-SHA256 authenticated framing, anti-replay, and mutual key confirmation.

Further profiles may be standardized without requiring runtime implementations to share internal architecture.

## Lifecycle and outcomes

`CANCEL_REQUESTED` is non-terminal. The authoritative terminal outcome is exactly one of:

```text
COMPLETED
CANCELLED
FAILED
UNKNOWN
```

Observed runtime outcome wins a cancel race. A disconnect or timeout does not by itself prove remote cancellation or failure; unresolved outcome is `UNKNOWN`.

## Capabilities, availability, authorization

These are independent:

```text
Capability    = runtime can technically perform an operation.
Availability  = runtime can currently accept work.
Authorization = peer is permitted to use it.
```

**Capability ≠ Availability ≠ Authorization.**

## Embeddings

Equal vector dimensions do not imply compatible embedding spaces. `embedding_space_id` is part of vector-space identity; implementations must also preserve required model/revision, normalization, metric, dimensions, and related metadata defined by the profile.

## Conformance

A V0.2 adapter is expected to conform to the manual and executable conformance suite. Wire compatibility alone is insufficient: state-machine, replay, lease, lifecycle, backpressure, failure and dual-plane semantics are part of protocol conformance.

See [`IMPLEMENTER_CHECKLIST.md`](./IMPLEMENTER_CHECKLIST.md).
