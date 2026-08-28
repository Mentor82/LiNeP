# LiNeP V0.2 Documentation & Verification Audits

Tracking: [Issue #10](https://github.com/Mentor82/LiNeP/issues/10)

This directory contains specifications, runtime contracts, and audit reports for the testable V0.2 runtime baseline.

V0.1 remains frozen. Documents here must not retroactively redefine V0.1 behavior.

## Audits & Verification Evidence

- [`AUDIT_V0_2.md`](./AUDIT_V0_2.md) — Comprehensive audit report, wire-level specifications, invariant matrices, and raw multi-platform test execution logs for Phase A (Contract Types & Envelopes), Phase B (Persistent Session & TCP Multiplexing), and Phase C (Lifecycle, End-to-End Cancel & Hybrid Flow Control).

## Planned Specifications

- `PROTOCOL_V0_2_DRAFT.md` — candidate wire/envelope contract
- `RUNTIME_CONTRACT.md` — lifecycle, identity, streaming, cancel, terminal semantics
- `CONFORMANCE.md` — executable profile requirements and evidence rules
