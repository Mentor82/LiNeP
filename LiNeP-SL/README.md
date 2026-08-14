# LiNeP-SL — Security Layers

LiNeP-SL is the layered security framework for LiNeP. It augments the low-latency LiNeP transport with progressively stronger authentication, cryptographic identity, authorization, replay protection, policy enforcement, auditability, and zero-trust federation while preserving LiNeP's deterministic and lightweight core.

> Status: reconstructed architecture baseline from prior LiNeP design discussions. Treat the layer model and architectural boundaries below as the current design baseline. Where details are still marked for validation, do not silently invent incompatible semantics.

## Core boundary

- **LiNeP = communication / transport / scheduling / streaming / consensus.**
- **LiNeP-SL = trust + security for that communication.**
- LiNeP-SL is **not** a second transport and must not reimplement TCP/UDP.
- Security must be additive and layered; no silent downgrade.
- Keep the LiNeP core lightweight and deterministic.

## Security layers

### SL0 — LiNeP baseline security
Part of the LiNeP baseline: TLS where configured, frame/header validation, CRC/integrity checks, protocol/version validation, worker/slot identity fields, sequence/correlation invariants, structured rejection of malformed frames.

SL0 is transport/frame hygiene, not a complete identity or authorization model.

### SL1 — Lightweight internal authentication
Low-overhead authentication intended for trusted/internal LiNeP clusters. Candidate mechanisms: shared secret, HMAC/MAC binding over frame/session/sequence, authenticated worker identity, session identifier, nonce/sequence binding, optional short-lived session key.

Primary question: **Did this frame really come from an authenticated member of this LiNeP trust domain?**

SL1 may require a minimal integration seam in the LiNeP core, but remains conceptually part of LiNeP-SL.

### SL2 — Cryptographic identity & key management
Strong peer identity and key lifecycle: mTLS or Noise-style authenticated handshake, node/worker cryptographic identities, session-key negotiation, rotation, revocation, re-authentication, trust-domain membership.

Primary question: **Who are you cryptographically, and what keys/trust domain apply to this session?**

### SL3 — Authorization, capabilities & replay protection
Authorization and message-freshness controls: RBAC/ABAC/capabilities, deny-by-default policy, action/resource constraints, replay protection, monotone/rolling sequence windows, nonce/TTL binding, optional message-level MAC/signature and payload protection for critical operations.

Primary question: **May this authenticated identity perform this operation now, and is the message fresh and unmodified?**

### SL4 — Governance, audit & zero-trust federation
Highest trust/governance layer: policy engine, audit trail, trust levels/zones, federation between LiNeP domains, attestation, policy versioning, anomaly signals, explainable allow/deny decisions.

Primary question: **Is this communication legitimate under the governing security policy, and can that decision be audited later?**

## Cumulative model

```text
SL4  Governance / Audit / Zero Trust / Federation
 ↑
SL3  Authorization / Capabilities / Replay Protection
 ↑
SL2  Cryptographic Identity / Key Management
 ↑
SL1  Lightweight Internal Authentication
 ↑
SL0  LiNeP Baseline / TLS / Frame Integrity
 ↑
LiNeP Transport
```

Example deployment profiles:

```text
Local Scheduler ↔ Worker        SL0 + SL1
Remote Worker                   SL0 + SL1 + SL2
Privileged Tool Worker          SL0 + SL1 + SL2 + SL3
External/Federated Trust Domain SL0 + SL1 + SL2 + SL3 + SL4
```

## Non-negotiable invariants

1. No second transport stack.
2. No silent security downgrade.
3. No breaking LiNeP V0.2 streaming/sequence/cancellation invariants without an explicit protocol decision.
4. Prefer session-bound authentication over per-feature ad-hoc secrets.
5. Replay protection must reuse/align with LiNeP sequence semantics where possible.
6. Authorization is deny-by-default.
7. Audit must avoid duplicating sensitive payloads; use metadata + payload digest where possible.
8. Keep cryptographic/provider choices behind narrow interfaces so the wire/security contract is not coupled to one library.

## Start here for implementation

Read in this order:

1. `README.md` — architecture boundary and layer model
2. `SPEC_V0_1_RECONSTRUCTED.md` — reconstructed detailed specification
3. `TODO_V0_1.md` — phased implementation plan

For the first implementation pass, **do not redesign SL0–SL4**. Analyze current LiNeP V0.2 compatibility first, then propose the smallest safe SL1 integration seam.