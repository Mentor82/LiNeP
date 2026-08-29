# LiNeP V0.2 Runtime Baseline Documentation

Welcome to the **LiNeP V0.2 Runtime Baseline** specification and verification index.

## Documents

1. [**`RUNTIME_CONTRACT.md`**](RUNTIME_CONTRACT.md): Full specification of V0.2 envelope families, canonical 32-byte header, identity scopes, lifecycle state machine, and flow control.
2. [**`CONFORMANCE.md`**](CONFORMANCE.md): Conformance runner specification, standardized test suites, and profile evaluation rules.
3. [**`AUDIT_V0_2.md`**](AUDIT_V0_2.md): Multi-platform audit report across Windows Host x64 and Debian 13 WSL.

## Test Suites

- `test_v02_envelopes`: Envelope serialization, canonical little-endian framing, tampered buffer protection.
- `test_v02_session`: Persistent session multiplexing, stream isolation, sequencing invariants.
- `test_v02_socket_multiplexing`: Real TCP socket persistent multiplexing, interleaving, and disconnect recovery.
- `test_v02_lifecycle_cancel_backpressure`: End-to-end socket cancellation, race resolution, hybrid backpressure, and fair send scheduler.
- `test_v02_conformance`: Standardized 9-suite conformance verification and edge mode failure tests.
