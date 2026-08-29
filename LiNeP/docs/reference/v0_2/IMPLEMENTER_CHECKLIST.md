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

- [ ] UDP identity is bound to the TCP session/trunk
- [ ] `control_epoch` checked
- [ ] `lease_token` checked
- [ ] UDP heartbeat loss does not terminate healthy TCP execution
- [ ] new incarnation cannot resurrect old execution state

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
Failure Semantics
Cross-language Interop
```
