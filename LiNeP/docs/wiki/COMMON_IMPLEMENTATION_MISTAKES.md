# Common LiNeP Implementation Mistakes

**Applies to:** LiNeP V0.2 — Current normative baseline

These mistakes have a high chance of producing implementations that are wire-compatible but semantically non-conformant.

## Incomplete stream identity

❌ Track only `(request_id, execution_id)`

✅ Track the complete `(request_id, execution_id, output_id)` for stream-specific state.

## Treating control-plane loss as execution failure

❌ `heartbeat missing → running TCP execution failed`

✅ Control-plane liveness and execution outcome are separate. A missing heartbeat does not prove execution termination.

## Mutating state on rejected control messages

❌ Advance sequence, refresh last-seen, or alter lease/cache before semantic authorization.

✅ Rejection is transactional: rejected messages mutate nothing.

## Weak epoch handling

❌ Accept arbitrary higher-epoch STATUS/HEARTBEAT/PING traffic.

✅ Only `NODE_HELLO` may establish a higher control epoch.

## Wrong message direction

❌ Allow a node to inject scheduler→node messages such as `INVITE` or `PING` into the scheduler router.

✅ Enforce protocol direction before state mutation.

## Heartbeat bypasses lease establishment

❌ Allow `HEARTBEAT` to move an `INVITED` node into an active/routable state.

✅ `LEASE_ACK` with matching non-zero token and ready TCP trunk is required.

## Same-epoch HELLO destroys active state

❌ Re-register an active node as `SEEN` on delayed/replayed same-epoch HELLO.

✅ Protect active/invited/degraded state from same-epoch HELLO downgrade.

## Embedding dimensions used as identity

❌ `same dimensions = compatible vectors`

✅ Use `embedding_space_id` and required vector-space metadata. Equal dimensions alone prove nothing about compatibility.

## Capability confused with availability or authorization

❌ `advertised = available = allowed`

✅ Capability, availability, and authorization are independent dimensions.

## Adapter-specific protocol semantics

❌ Change protocol meaning to fit one runtime implementation.

✅ Adapt the runtime to the LiNeP Reference Manual.

## Self-only interoperability testing

❌ Encoder and decoder from the same implementation pass against each other.

✅ Test reference→implementation, implementation→reference, malformed inputs, live sockets, replay, disconnect, cancel races, multi-output, and dual-plane failure isolation.
