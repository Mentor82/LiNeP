# LiNeP-SL — Security Layers

LiNeP-SL is the layered security framework for LiNeP. It augments the low-latency LiNeP transport with progressively stronger authentication, cryptographic identity, authorization, replay protection, policy enforcement, auditability, and zero-trust federation while preserving LiNeP's deterministic and lightweight core.

> **Naming note:** `SL` normatively means **Security Layers**. Within LIARA's neural-system architecture, it also carries a deliberate secondary analogy to **Synaptic Layers**: LiNeP transports the signal; LiNeP-SL governs the synapse — which peers may connect, under which identity, capability, policy, trust, revocation, and audit conditions. This analogy is descriptive only and does not define a second protocol or an alternative SL specification.

> **Architecture mnemonic:** **LiNeP transports the signal. LiNeP-SL governs the synapse.**

> Status: Fully implemented & audited V0.1 architecture baseline. All layer boundaries, identity stores, governance policy engines, audit sinks, and transport security invariants across TCP & UDP are verified.

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

### SL2 — Cryptographic identity & key management
Strong peer identity and key lifecycle: mTLS or Noise-style authenticated key exchange, node/worker cryptographic identities, session-key negotiation, rotation, revocation, re-authentication, trust-domain membership.

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

## Documentation & Issue Tracking

* 📚 **[Library Reference & API Guide](./LIBRARY_REFERENCE.md)**
* 📜 **[Reconstructed Security Specification V0.1](./SPEC_V0_1_RECONSTRUCTED.md)**
* 📊 **[Micro-Benchmark & Security Overhead Audit Report](./AUDIT_PERFORMANCE_SL0_VS_SL4.md)**
* 🌐 **[Windows ↔ Debian 13 Interoperability Report](./INTEROP_WINDOWS_DEBIAN13.md)**
* 📋 **[LiNeP-SL Implementation Roadmap](./TODO_V0_1.md)**

### Implementation Issues & Verification:
- **Issue #1**: [`fix(linep-sl): restore normative SL0–SL4 layer boundaries`](https://github.com/Mentor82/LiNeP/issues/1)
- **Issue #2**: [`hardening(linep-sl/sl1): canonicalize MAC input`](https://github.com/Mentor82/LiNeP/issues/2)
- **Issue #3**: [`feat(linep-sl/sl2): implement cryptographic identity & session key management`](https://github.com/Mentor82/LiNeP/issues/3)
- **Issue #4**: [`test(linep-sl): validate SL2 interoperability on real Windows ↔ Debian 13 peers`](https://github.com/Mentor82/LiNeP/issues/4)
- **Issue #6**: [`feat(linep-sl/sl4): implement governance, audit, zero-trust and federation semantics`](https://github.com/Mentor82/LiNeP/issues/6)
- **Issue #7**: [`test(linep-sl): validate SL security invariants over LiNeP UDP heartbeat transport`](https://github.com/Mentor82/LiNeP/issues/7)