# LiNeP V0.1.0 TODO Checklist

Use this checklist to track the V0.1.0 rollout end-to-end.

## Protocol and Framing

- [x] Define V0.1.0 baseline document
- [x] Introduce 19-byte heartbeat with worker_score and UTC timestamp bytes
- [x] Update CRC coverage and heartbeat validation rules
- [x] Add explicit UDP invite/ack message format and retry policy
- [x] Freeze message ID allocation table for control-plane extensions

## C/C++ Core (Dynamic Library)

- [x] Update C++ heartbeat structs and framing implementation
- [x] Update scheduler slot ingestion for worker_score
- [x] Blend worker_score into scheduler scoring
- [x] Keep C ABI structs and functions aligned with new heartbeat layout
- [x] Add ABI version constant export for runtime compatibility checks
- [x] Add integration test: scheduler state machine SEEN -> INVITED -> ACTIVE

## Python Bindings

- [x] Update cffi declarations for new heartbeat fields
- [x] Update Python HeartbeatCompact dataclass and serialization size
- [x] Update python tests for heartbeat roundtrip and UDP loopback
- [x] Add high-level Python helper for worker_score calculation parity with C++

## Test and Validation

- [x] Build all CMake targets successfully
- [x] Pass full C++ ctest suite
- [x] Pass targeted Python heartbeat tests
- [x] Add end-to-end multi-process test: coworker UDP heartbeat + TCP task flow
- [x] Add fuzz/negative tests for malformed timestamp and score ranges

## Packaging and Delivery

- [ ] Produce release note for V0.1.0 wire-format break
- [ ] Tag baseline snapshot and archive protocol docs
- [ ] Validate Windows dynamic library loading path in clean environment
- [ ] Validate Linux shared library loading path in clean environment
- [ ] Run Mac partner sync via scripts/build-mac.ps1 (or build-targets.sh on Mac) and collect report template

## Docs

- [x] Link protocol baseline from README
- [x] Add Mac reference for C/C++ dynamic library and Python bindings
- [x] Add architecture diagram for HTTP (mainworker) and LiNeP UDP/TCP (scheduler-coworker)
- [x] Add C/C++ and Python quickstart snippets side by side
