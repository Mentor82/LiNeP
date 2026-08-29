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

- `RUNTIME_REQUEST`
- `RUNTIME_EVENT`
- `RUNTIME_CONTROL`
- `RUNTIME_CAPABILITIES`

`event_seq` describes logical runtime event ordering. It is not a TCP packet sequence, UDP `control_seq`, or transport fragment sequence.

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
- `INVITE` is scheduler→node and can only be issued from `SEEN`;
- `LEASE_ACK` requires the invited state, matching non-zero lease token, and a ready TCP trunk;
- inbound node→scheduler `INVITE` and `PING` are rejected;
- stale/lower epochs are rejected;
- only `NODE_HELLO` may establish a higher control epoch;
- same-epoch replay/duplicate sequencing is idempotent;
- rejected messages MUST NOT consume sequence, refresh liveness, alter lease state, or mutate routing/capability state;
- same-epoch `NODE_HELLO` MUST NOT downgrade an active/invited incarnation;
- UDP liveness loss does not prove that a running TCP execution stopped.

## Runtime profiles

The V0.2 baseline defines first-class runtime profiles including:

- `PROFILE_GENERATE`
- `PROFILE_CHAT`
- `PROFILE_EMBED`

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
