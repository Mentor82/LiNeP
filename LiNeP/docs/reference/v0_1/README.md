# LiNeP V0.1 Reference

**Status: FROZEN**

LiNeP V0.1 is the historical normative baseline for the original worker-oriented protocol. No new semantics are added to V0.1. Only correctness fixes, clarifications, and documentation repairs are permitted.

## Architecture

```text
Mainworker → Scheduler    HTTP
Scheduler → Coworker     LiNeP

UDP Control Plane
- heartbeat
- status
- score / routing telemetry
- invite
- invite_ack

TCP Data Plane
- register / register_ack
- task / task_ack
- result
- embedding
- similarity
- consensus
- error
```

V0.1 uses UDP and TCP as parallel planes: UDP provides lightweight liveness/status/invitation control while TCP carries task/result payloads.

## Node lifecycle

```text
UNKNOWN
  ↓ heartbeat
SEEN
  ↓ invite
INVITED
  ↓ invite_ack
ACTIVE

Additional states: DEGRADED, COOLING, OFFLINE
```

A missed INVITE_ACK does not by itself mark a node offline. Offline state is derived from stale/liveness timeout. Running TCP work is not implicitly terminated by a single missed heartbeat.

## Frozen-baseline rule

V0.2 concepts such as the V0.2 runtime envelope families, full `(request_id, execution_id, output_id)` stream identity, `event_seq`, V0.2 control epochs, V0.2 lease binding, or V0.2 runtime profiles MUST NOT be retroactively described as V0.1 semantics.

Existing V0.1 protocol documents remain the detailed source for its exact message IDs and wire formats. This page is the stable version entry point.
