# LiNeP V0.2 Implementer Checklist

Use this checklist when implementing or reviewing a LiNeP V0.2 adapter.

## Wire

- [ ] Canonical little-endian encoding
- [ ] Strict magic/version validation
- [ ] Exact header/datagram sizes
- [ ] Reserved fields/bits rejected where required
- [ ] Payload and embedding limits enforced

## Identity

- [ ] `request_id` preserved
- [ ] `execution_id` preserved
- [ ] `output_id` preserved
- [ ] full `(request_id, execution_id, output_id)` used for stream-specific state
- [ ] runtime/control identity kept distinct from transport/security/conversation identity

## Streaming

- [ ] `event_seq` starts at 1
- [ ] `event_seq` is monotonic per logical output stream
- [ ] concurrent streams cannot cross-talk
- [ ] terminal event emitted exactly once
- [ ] required DELTA events are not silently dropped

## TCP Data Plane

- [ ] persistent session/trunk supported
- [ ] logical streams multiplexed safely
- [ ] flow-control/window updates are monotonic and replay-safe
- [ ] bounded buffering/backpressure implemented
- [ ] disconnect does not fabricate a known remote outcome

## UDP Control Plane

- [ ] exact V0.2 control datagram format
- [ ] `NODE_HELLO` semantics implemented
- [ ] inbound/outbound message directions enforced
- [ ] inbound `INVITE` rejected at scheduler/router
- [ ] inbound `PING` rejected; `PONG` handled as defined
- [ ] lower/stale epochs rejected without mutation
- [ ] higher epoch accepted only through `NODE_HELLO`
- [ ] same-epoch replay/duplicate sequence handled idempotently
- [ ] rejected messages mutate no state and refresh no liveness
- [ ] same-epoch HELLO cannot downgrade `INVITED`/`ACTIVE`/`DEGRADED`
- [ ] `INVITE` can only be issued from `SEEN`
- [ ] `LEASE_ACK` requires `INVITED`, matching non-zero token and ready TCP trunk
- [ ] stale/degraded/cooling/offline transitions match the normative state machine

## Dual Plane

- [ ] UDP identity is bound to the TCP session/trunk via `SESSION_BIND` (envelope type 5, exact 36-byte payload)
- [ ] Strict syntactic decode: `request_id = 0`, `execution_id = 0`, `output_id = 0`, `flags = 0`, exact payload length 36 (reject trailing/truncated bytes)
- [ ] Syntactic decode kept separate from semantic authorization (`validate_tcp_session_binding`)
- [ ] Connection state machine implemented (`UNBOUND` -> `BOUND_CURRENT` -> `BOUND_STALE`)
- [ ] `REQUEST` rejected with 401 Unauthorized while `UNBOUND` or `BOUND_STALE`
- [ ] `REQUEST` during `BOUND_STALE` keeps TCP connection OPEN to allow immediate in-band re-bind
- [ ] Duplicate `SESSION_BIND` with same identity, lease, and epoch handled idempotently
- [ ] Identity change on existing connection (`BOUND_CURRENT` or `BOUND_STALE`) rejected with 401 `identity_change_on_existing_connection` and socket closed
- [ ] `control_epoch` checked against control-plane incarnation
- [ ] `lease_token` checked against router active lease
- [ ] Connection-level failures emit terminal event with reserved stream identity `(0, 0, 0)`
- [ ] UDP heartbeat loss does not terminate healthy TCP execution
- [ ] In-flight executions complete across lease rotation while new requests are blocked until re-bound
- [ ] 64-bit `lease_token` treated as logical lease handle, not cryptographic bearer auth (LiNeP-SL provides cryptographic security)
- [ ] new incarnation cannot resurrect old execution state

## Security Layer: Profile SL1

- [ ] `FLAG_AUTHENTICATED` (0x01) asserted in envelope header flags byte 7
- [ ] 24-byte `wire_auth_extension` (`auth_seq: u32`, `key_id: u16`, `reserved: u16`, `mac: [16]u8`) placed immediately after 32-byte header
- [ ] Authenticated `SESSION_BIND` wire size is exactly 92 bytes ($32 + 24 + 36$)
- [ ] HMAC-SHA256 truncated to 16 bytes over canonical 80-byte prefix (header, auth_ext prefix, bound identity/lease, direction) and payload
- [ ] Mutual key confirmation: `SESSION_BIND` is signed (`auth_seq = 1`, client $\to$ server) and confirmed with signed frame (`auth_seq = 1`, server $\to$ client)
- [ ] Inbound and outbound sequence counters strictly monotonic ($S_{new} > S_{last}$) starting at 1
- [ ] Sequence counter overflow protection: fail-closed with 401 (`auth_seq_exhausted`) at $2^{32}-1$, no wrap-around
- [ ] Strict post-bind enforcement: all frames (including error events on `(0, 0, 0)` and `CAPABILITIES`) are signed once SL1 is active
- [ ] Fail-closed immediate socket teardown upon receiving unsigned or tampered frames post-bind
- [ ] Receiver key rotation: accepts `current_key_id` and `previous_key_id` during transition window
- [ ] Key length enforcement: pre-shared symmetric keys rejected if $< 32$ bytes (256 bits)
- [ ] Unified 401 Unauthorized status for all authentication errors (`auth_missing`, `auth_bad_key`, `auth_bad_mac`, `auth_bad_seq`, `auth_seq_exhausted`)

## Cancellation

- [ ] targeted output cancellation is unambiguous
- [ ] execution-wide cancellation is explicitly separate when supported
- [ ] cancel-requested state is non-terminal
- [ ] observed runtime final outcome wins cancel race
- [ ] unresolved outcome becomes `UNKNOWN`

## Capabilities

- [ ] capability kept distinct from availability
- [ ] capability kept distinct from authorization
- [ ] required unsupported capabilities cause explicit rejection
- [ ] optional downgrade occurs only when the capability was explicitly optional
- [ ] capability revision/digest invalidation handled correctly

## Embeddings

- [ ] `embedding_space_id` preserved
- [ ] model/revision metadata preserved where required
- [ ] dimensions enforced within limits
- [ ] normalization and distance metric enum values match the normative registry
- [ ] equal dimensions alone are never treated as vector-space compatibility
- [ ] batch/multi-output ownership is preserved

## Interoperability

- [ ] reference-generated golden frames decode successfully
- [ ] implementation-generated frames decode in the reference implementation
- [ ] live socket interoperability tested
- [ ] tests cover malformed/truncated/trailing data
- [ ] tests cover replay, stale epoch, disconnect, cancel races and multi-output

## Conformance reporting

Report sections independently. Do not collapse protocol conformance into one green checkmark.

```text
Wire Format
TCP Data Plane
Streaming
Lifecycle
Cancellation
Backpressure
Capabilities
UDP Control Plane
Epoch / Replay
Lease Binding
Availability
Dual-Plane Integration
Security Profile (SL1)
Failure Semantics
Cross-language Interop
```
