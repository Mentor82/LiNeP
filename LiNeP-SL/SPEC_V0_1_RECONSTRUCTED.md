# LiNeP-SL — Reconstructed Specification V0.1

This document reconstructs the intended LiNeP-SL architecture from earlier LiNeP design discussions and turns it into an implementation-ready baseline.

## Status and historical caution

The **layered Security Layers concept (SL0–SL4)** and the direction of the mechanisms are established design intent. Some exact assignments inside SL2–SL4 were not previously frozen as a normative wire specification. Therefore:

- Treat the layer boundaries and invariants as the current architecture baseline.
- Treat specific cryptographic/provider choices as implementation decisions unless explicitly standardized later.
- Do not claim historical certainty for details that are documented here as reconstruction.

## 1. Purpose

LiNeP must remain a fast, deterministic neural transport/protocol for Scheduler ↔ Worker and AI-to-AI communication. LiNeP-SL adds security progressively according to trust boundary and risk.

```text
LiNeP    = communication
LiNeP-SL = trust + security of that communication
```

LiNeP-SL MUST NOT become a replacement transport, VPN, or parallel framing protocol.

## 2. Layer model

### SL0 — Baseline

Scope:
- TLS where the deployment profile requires it
- frame/header validation
- CRC/integrity checks
- protocol/version checks
- worker/slot identifiers
- sequence/correlation invariants
- malformed-frame rejection

Guarantee: transport/frame integrity baseline only.

### SL1 — Lightweight internal authentication

Goal: authenticate internal LiNeP peers with minimal latency and minimal framing overhead.

Candidate session context:

```text
session_id
subject / worker_id
sequence
nonce (if required by profile)
key_id
MAC/HMAC
```

Logical binding:

```text
MAC = Auth(frame_header || protected_extensions || payload || session_id || sequence)
```

Requirements:
- session-bound keying
- worker/subject binding
- sequence binding
- constant-time MAC verification
- reject-before-execution on authentication failure
- explicit algorithm/version identifier if multiple suites are supported
- no plaintext long-lived secret on the wire

### SL2 — Cryptographic identity & key management

Goal: establish strong peer identity and fresh session keys across machines/trust boundaries.

Capabilities:
- mutual authentication
- mTLS or Noise-style authenticated key exchange
- node/worker cryptographic identity
- trust-domain membership
- session-key negotiation
- rotation and revocation
- re-authentication
- key identifiers and bounded key lifetime

Requirements:
- session keys are ephemeral/rotatable
- peer identity is cryptographically bound to the session
- downgrade to weaker identity/auth mode is rejected unless explicitly permitted by deployment policy
- key-management logic remains separate from LiNeP task semantics

### SL3 — Authorization, capabilities & replay protection

Goal: determine what an authenticated principal may do and ensure protected messages are fresh.

Capabilities:
- RBAC / ABAC / capability tokens
- deny-by-default authorization
- action/resource constraints
- replay protection
- TTL/expiry
- sequence window
- optional critical-message signature/MAC
- optional message-level payload protection

Recommended capability model:

```text
Capability {
  subject
  action
  resource
  constraints
  issued_at
  expires_at
  issuer
  policy_version
}
```

Example actions:

```text
TASK_CODE
TASK_VALIDATE
EMBED_REQUEST
CONSENSUS_REQUEST
MODEL_LOAD
WORKER_REGISTER
ADMIN_COMMAND
KEY_ROTATE
```

Replay tuple should align with LiNeP V0.2 sequence semantics:

```text
session_id + sequence + timestamp/ttl + optional nonce + authenticator
```

Requirements:
- duplicate/replayed protected frames are rejected
- a valid identity does not imply authorization
- critical actions are explicitly scoped
- streaming fragments remain ordered and replay-safe without breaking LiNeP V0.2 fragment semantics

### SL4 — Governance, audit & federation

Goal: make high-level trust decisions policy-driven, explainable, and auditable across trust domains.

Capabilities:
- policy engine
- trust zones/levels
- external/federated LiNeP domains
- attestation hooks
- policy versioning
- anomaly/risk signals
- explainable allow/deny reason codes
- audit trail

Recommended audit record:

```text
timestamp
session_id
subject
peer
trust_domain
msg_type
correlation_id
action
policy_id
policy_version
decision
reason_code
security_level
payload_digest
```

Audit MUST NOT require storing full sensitive payloads.

## 3. Negotiation

Peers may advertise support and minimum requirement:

```text
supported_sl = SL0..SL3
required_sl  = SL2
```

Effective security is valid only if the negotiated result satisfies both sides' minimum requirements and the governing policy.

### Downgrade invariant

A stronger requested/required security level MUST NOT silently fall back to a weaker level.

Failure to satisfy the required level must fail closed.

## 4. Session lifecycle

Reference flow:

```text
Connection / Discovery
        │
        ▼
SL0 transport established
        │
        ▼
SL1 lightweight authentication
        │
        ▼
SL2 identity verification + session key establishment
        │
        ▼
SL3 capability/authorization + replay context
        │
        ▼
SL4 policy/trust evaluation when required
        │
        ▼
LiNeP TASK / RESULT / EMBED / CONSENSUS / STREAM
```

Profiles may stop at a lower layer when policy allows it.

## 5. Integration with LiNeP V0.2

LiNeP-SL must preserve current V0.2 behavior:

- `FLAG_FRAGMENTED`
- `FLAG_FINAL_FRAGMENT`
- `TASK_CANCEL`
- monotone fragment sequence checks
- duplicate rejection
- cancellation semantics
- correlation IDs
- normalized scheduler telemetry/scoring
- consensus request/response flow

Security context should bind to these existing invariants instead of duplicating them.

### Streaming rule

For a protected stream, every fragment must be attributable to the same authenticated session/correlation context. Missing, reordered, duplicated, unauthenticated, or post-cancel fragments must be rejected according to the selected security profile.

## 6. Suggested architecture interfaces

Implementation should prefer narrow abstractions, e.g.:

```text
ISecuritySession
IAuthenticator
IIdentityProvider
IKeyManager
IAuthorizer
IReplayProtector
IPolicyEngine
IAuditSink
```

LiNeP core should depend only on the smallest necessary seam, especially for SL1.

Avoid coupling the public protocol contract to one crypto library.

## 7. Failure behavior

Security failures should be explicit and fail closed for protected profiles.

Categories should distinguish at least:

```text
AUTH_FAILED
IDENTITY_REJECTED
SECURITY_LEVEL_UNSUPPORTED
DOWNGRADE_REJECTED
REPLAY_DETECTED
CAPABILITY_DENIED
POLICY_DENIED
KEY_EXPIRED
SESSION_EXPIRED
```

Do not leak secrets, raw keys, certificate internals, or sensitive policy details in protocol errors.

## 8. Test expectations

Minimum test families:

- valid SL1 authentication
- invalid MAC/HMAC
- wrong session/worker binding
- modified payload/header after authentication
- duplicate/replayed frame
- stale/expired session
- downgrade attempt
- unsupported security level
- capability allow/deny
- cross-trust-domain rejection
- streaming fragment replay/reorder/duplicate
- cancellation under protected stream
- key rotation/session renewal
- audit event emitted without raw sensitive payload

Cross-language parity is required where C++ and Python both expose security/framing functions.

## 9. Non-goals for V0.1

- inventing a new transport
- replacing LiNeP framing
- putting governance policy into every low-level frame parser
- hardwiring one vendor crypto stack into the public contract
- making all deployments pay SL4 overhead

## 10. Definition

**LiNeP-SL (Liara Neural Protocol Security Layers) is the layered security framework for LiNeP. It augments the low-latency LiNeP transport with progressively stronger authentication, cryptographic identity, authorization, replay protection, policy enforcement, auditability, and zero-trust federation while preserving LiNeP's deterministic and lightweight core.**

---

## 11. Normative Issue References & Implementation History

- **Issue #1**: [`fix(linep-sl): restore normative SL0–SL4 layer boundaries`](https://github.com/Mentor82/LiNeP/issues/1) (Commit `e39d693`)
- **Issue #2**: [`hardening(linep-sl/sl1): canonicalize MAC input`](https://github.com/Mentor82/LiNeP/issues/2) (Commit `e39d693`)
- **Issue #3**: [`feat(linep-sl/sl2): implement cryptographic identity & session key management`](https://github.com/Mentor82/LiNeP/issues/3) (Commits `268bb73`, `03f3496`)
- **Issue #4**: [`test(linep-sl): validate SL2 interoperability on real Windows ↔ Debian 13 peers`](https://github.com/Mentor82/LiNeP/issues/4) (Commits `634c350`, `7244583`, `bb6625f`, `bbbca74`)
- **Issue #6**: [`feat(linep-sl/sl4): implement governance, audit, zero-trust and federation semantics`](https://github.com/Mentor82/LiNeP/issues/6) (Commits `d9b89e0`, `8c8d16d`, `024ebde`, `f2ac035`, `fc0e0c6`, `6d57fd5`)
- **Issue #7**: [`test(linep-sl): validate SL security invariants over LiNeP UDP heartbeat transport`](https://github.com/Mentor82/LiNeP/issues/7) (Commits `5f47dee`, `c1d23cc`, `f2ac035`, `fc0e0c6`, `6d57fd5`)