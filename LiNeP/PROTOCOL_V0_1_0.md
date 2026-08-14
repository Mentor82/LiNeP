# LiNeP Protocol Baseline V0.1.0

This document defines the new non-compatible baseline for test-to-product evolution.
Backward compatibility with previous test formats is intentionally not required.

## 1. Scope

1. Mainworker to Scheduler transport: HTTP.
2. Scheduler to Coworker transport: LiNeP over UDP and TCP.
3. UDP purpose: liveness, status, score, invitation/ack control.
4. TCP purpose: task payload and result payload.

### 1.1 Implementation Targets

This baseline applies to all runtime layers, not only Python.

1. Primary implementation: C/C++ core as shared dynamic library (DLL/.so/.dylib).
2. Stable external boundary: C ABI exported by the dynamic library.
3. Python package: binding layer on top of the same C ABI.
4. Any future language binding must follow this same baseline wire format and ABI contract.

## 2. Versioning Model

Baseline identifier:

- V0.1.0-(HEXDEC Timestamp MM,DD,HH,MI,SS)

Rules:

1. Protocol baseline starts at V0.1.0.
2. Year marker is fixed to 1 for this baseline family.
3. Counter starts from the current year baseline and increments by release.
4. Timestamp fields are encoded as hexadecimal byte values.

Timestamp byte order:

1. MM: month (01..0C)
2. DD: day (01..1F)
3. HH: hour UTC (00..17)
4. MI: minute (00..3B)
5. SS: second (00..3B)

Example:

- 03 May 2026, 14:09:55 UTC -> 05 03 0E 09 37

## 3. Control/Data Planes

### 3.1 UDP Control Plane

Coworker periodically broadcasts or unicasts heartbeat to Scheduler.

Minimum heartbeat cadence:

1. Interval target: 1000 ms.
2. Allowed jitter: plus/minus 10 percent.
3. Stale timeout at Scheduler: 5 seconds without valid heartbeat.

### 3.2 TCP Data Plane

1. Scheduler sends task frames to selected coworker.
2. Coworker returns result frames.
3. Task timeout and retry policy are handled by Scheduler.

## 4. State Machine

Scheduler-side slot state:

1. UNKNOWN
2. SEEN
3. INVITED
4. ACTIVE
5. DEGRADED
6. COOLING
7. OFFLINE

Transitions:

1. UNKNOWN -> SEEN: first valid heartbeat observed.
2. SEEN -> INVITED: scheduler sends acceptance/ok.
3. INVITED -> ACTIVE: coworker registration and tcp-ready confirmed.
4. ACTIVE -> DEGRADED: score or telemetry below threshold.
5. ACTIVE/DEGRADED -> COOLING: repeated timeout or error policy trigger.
6. ACTIVE/DEGRADED/COOLING -> OFFLINE: stale timeout exceeded.
7. OFFLINE -> SEEN: new valid heartbeat appears.

## 5. Heartbeat Frame V0.1.0

Transport: UDP

Fields:

1. magic_u16
2. version_u8
3. msg_type_u8
4. worker_id_u16
5. slot_id_u8
6. slot_flags_u8
7. load_u8
8. queue_depth_u8
9. sequence_u8
10. worker_score_u16
11. timestamp_mm_u8
12. timestamp_dd_u8
13. timestamp_hh_u8
14. timestamp_mi_u8
15. timestamp_ss_u8
16. crc8_u8

Semantics:

1. worker_score is computed by coworker from local telemetry.
2. Scheduler validates score range and delta rate.
3. Sequence detects reordering/replay.
4. CRC protects frame integrity.

## 6. Score Policy

Two-score model:

1. Worker-proposed score: from coworker telemetry.
2. Scheduler-derived score: from observed behavior and queue health.

Final routing score:

`S_final = alpha * S_worker + (1 - alpha) * S_scheduler + penalties`

Recommended alpha for baseline:

- alpha = 0.35

Hard filters before scoring:

1. not alive
2. not ready
3. error
4. thermal limit
5. model loading
6. stale heartbeat
7. cooldown active

## 7. Invitation and Ping-Pong

Required behavior:

1. Coworker sends heartbeat: "I am here".
2. Scheduler responds with invitation/ok (UDP control ack).
3. Coworker transitions to waiting-for-task over TCP.
4. Both sides continue heartbeat ping-pong in parallel.

Failure handling:

1. Missing ack does not block heartbeat stream.
2. Registration retries with exponential backoff.
3. Running tcp tasks are not dropped immediately on single heartbeat miss.

### 7.1 UDP Control Messages (Explicit Format)

Control-plane message IDs reserved in V0.1.0:

1. HEARTBEAT = 0x01 (coworker -> scheduler)
2. REGISTER = 0x02 (tcp)
3. REGISTER_ACK = 0x03 (tcp)
4. BYE = 0x04
5. INVITE = 0x05 (scheduler -> coworker, udp)
6. INVITE_ACK = 0x06 (coworker -> scheduler, udp)
7. HEARTBEAT_ACK = 0x07 (scheduler -> coworker, udp)

INVITE payload (udp):

1. invite_seq_u8
2. worker_id_u16
3. slot_id_u8
4. lease_ttl_ms_u32
5. session_token_u32
6. crc8_u8

INVITE_ACK payload (udp):

1. invite_seq_u8
2. worker_id_u16
3. slot_id_u8
4. accepted_u8 (0 or 1)
5. session_token_u32
6. crc8_u8

HEARTBEAT_ACK payload (udp):

1. heartbeat_seq_u8
2. worker_id_u16
3. slot_id_u8
4. scheduler_time_sec_u32
5. crc8_u8

### 7.2 Retry and Timeout Policy (Normative)

Scheduler side (INVITE):

1. Send INVITE immediately after first valid heartbeat in UNKNOWN/SEEN state.
2. Wait up to 1200 ms for INVITE_ACK.
3. Retry up to 3 times with backoff: 300 ms, 700 ms, 1500 ms.
4. If no INVITE_ACK after retries: keep slot in SEEN, continue listening to heartbeat.

Coworker side (INVITE_ACK):

1. Must reply INVITE_ACK within 200 ms of receiving INVITE.
2. Duplicate INVITE with same invite_seq must return the same INVITE_ACK (idempotent).
3. Invalid token or malformed invite must be acknowledged with accepted=0.

Heartbeat ping-pong:

1. Coworker continues HEARTBEAT every 1000 ms regardless of ACK loss.
2. Scheduler sends HEARTBEAT_ACK best-effort; missing ACK never blocks scheduling.
3. Slot transitions to OFFLINE only on stale timeout rule (5 s), not on single ACK miss.

## 8. Control-Plane Message ID Freeze (V0.1.0)

The following IDs are frozen for V0.1.0 and must not be reassigned:

1. 0x01 HEARTBEAT
2. 0x02 REGISTER
3. 0x03 REGISTER_ACK
4. 0x04 BYE
5. 0x05 INVITE
6. 0x06 INVITE_ACK
7. 0x07 HEARTBEAT_ACK
8. 0x10 TASK
9. 0x11 TASK_ACK
10. 0x12 RESULT
11. 0x13 MSG_ERROR
12. 0x20 STATUS_REQUEST
13. 0x21 STATUS_RESPONSE
14. 0x30 EMBED_REQUEST
15. 0x31 EMBED_RESPONSE
16. 0x32 SIMILARITY_REQUEST
17. 0x33 SIMILARITY_RESPONSE
18. 0x40 CONSENSUS_REQUEST
19. 0x41 CONSENSUS_RESPONSE
20. 0xF0 PING
21. 0xF1 PONG

## 9. Security and Validity

Minimum checks:

1. crc8 verification on every heartbeat.
2. sequence monotonicity window per worker/slot.
3. score clamping and outlier rejection.
4. source identity binding to worker_id policy.

Recommended extension for production:

1. hmac tag for heartbeat authenticity.
2. rotating session token after invitation.

## 10. Implementation Notes for Current Repo

1. Existing scheduler and coworker test paths should adopt this as the single source of truth.
2. Compatibility adapters to previous formats are intentionally out of scope.
3. Tests should be updated first for heartbeat shape and score semantics.
4. Runtime path should then align with updated UDP frame and scheduler state machine.

## 11. Acceptance Criteria

1. Coworker heartbeat includes worker_score and timestamp bytes in required order.
2. Scheduler state machine transitions according to section 4.
3. Scheduler slot selection uses S_final and hard filters.
4. Offline/stale detection triggers exactly at configured timeout window.
5. Integration test validates UDP control plus TCP task flow end-to-end.
6. INVITE/INVITE_ACK retry semantics are implemented exactly as in section 7.2.
