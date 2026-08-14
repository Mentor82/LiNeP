# LiNeP-SL V0.1 — Implementation Roadmap

This roadmap exists so implementation agents do not redesign LiNeP-SL from scratch.

## Read before coding

1. `LiNeP-SL/README.md`
2. `LiNeP-SL/SPEC_V0_1_RECONSTRUCTED.md`
3. current LiNeP V0.2 protocol/docs/tests under `LiNeP/`

## Ground rules

- Do not build a second transport.
- Do not silently downgrade security.
- Preserve LiNeP V0.2 streaming, sequence, cancellation, correlation, telemetry, and consensus invariants.
- Reuse existing LiNeP sequence/correlation semantics for replay/session binding where possible.
- Keep crypto/provider choices behind interfaces.
- Deny by default for authorization.
- Do not log raw secrets or sensitive payloads.

## Phase 0 — Compatibility analysis only

Before modifying code:

- map current LiNeP V0.2 frame/header extension points
- map C++ public API, C-ABI, Python bindings, scheduler/task receiver paths
- identify the smallest SL1 integration seam
- determine whether authentication metadata fits existing header extensions or requires an explicitly versioned security extension
- verify current TLS assumptions/deployment behavior instead of assuming TLS is universal
- identify streaming/cancellation paths that must bind to one security session
- propose negative/fuzz tests before implementation

**Deliverable:** short implementation plan. No broad refactor.

## Phase 1 — SL1 lightweight authentication

Implement minimal low-latency internal authentication.

Target properties:

- session context (`session_id`, subject/worker binding, key id)
- MAC/HMAC or equivalent authenticated-frame mechanism
- constant-time verification
- sequence/session binding
- fail-closed rejection before task execution
- explicit security-level/algorithm versioning
- C++ API + C-ABI + Python parity where exposed

Tests:

- valid authentication
- wrong key
- wrong worker/session binding
- modified header/payload
- duplicate/replay
- stream fragment authentication
- cancel frame authentication
- cross-language golden vectors

## Phase 2 — SL2 identity & key management

Add strong peer identity and session-key lifecycle behind interfaces.

Scope:

- mutual identity verification
- mTLS and/or Noise-style provider implementation behind abstraction
- session-key establishment
- rotation/revocation/expiry
- trust-domain binding
- explicit no-downgrade negotiation

Tests:

- valid mutual auth
- unknown/revoked identity
- expired key/session
- rotation without task corruption
- downgrade attempt rejected
- reconnect/re-authentication

## Phase 3 — SL3 capabilities & replay protection

Add authorization and freshness controls.

Scope:

- capability model
- deny-by-default authorizer
- action/resource constraints
- sequence-window replay protection
- TTL/expiry
- protected critical actions

Tests:

- allow/deny by capability
- stale/duplicate/reordered protected messages
- unauthorized MODEL_LOAD / ADMIN / KEY_ROTATE style operations
- streaming replay/reorder behavior

## Phase 4 — SL4 policy, audit & federation

Add governance-facing trust controls without contaminating low-level framing.

Scope:

- policy engine interface
- trust-domain/federation model
- policy version/reason codes
- audit sink
- optional attestation hooks
- payload digest rather than raw sensitive content

Tests:

- policy allow/deny
- cross-domain federation decision
- policy version changes
- audit completeness
- sensitive-payload non-disclosure

## Phase 5 — Hardening

- fuzz malformed security extensions
- oversized security metadata bounds
- socket/session teardown under protected streams
- concurrent session rotation
- long-running replay-window tests
- cross-platform C++/Python parity
- performance benchmark versus SL0 baseline

## Definition of done for V0.1

- SL0–SL4 architecture documented and implemented in separable layers
- SL1 usable for low-latency internal clusters
- no silent downgrade
- protected streaming/cancellation preserves LiNeP V0.2 semantics
- replay protection tested
- authorization deny-by-default
- security failures fail closed where the selected profile requires protection
- C++/Python exposed contracts agree on wire/authentication semantics
- audit omits raw secrets/sensitive payloads
- performance impact measured

## Recommended first prompt for an implementation agent

> Read `LiNeP-SL/README.md`, `LiNeP-SL/SPEC_V0_1_RECONSTRUCTED.md`, and `LiNeP-SL/TODO_V0_1.md`. Treat them as the architecture baseline. Do not redesign SL0–SL4. First perform Phase 0 only: inspect current LiNeP V0.2 and propose the smallest safe SL1 integration seam, preserving streaming/sequence/cancellation invariants and preventing silent downgrade. Do not implement until the compatibility plan is explicit.