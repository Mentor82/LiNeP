# LiNeP-SL Migration Guide: V0.1 to V0.2

This document guides integrators, developers, and operators migrating from LiNeP Security Layer (LiNeP-SL) V0.1 to V0.2.

---

## 1. Executive Summary & Architectural Overview

LiNeP-SL V0.1 provided basic point-to-point symmetric MAC protection across unified transport streams. 
LiNeP V0.2 introduces a strict separation between:
- **UDP Control Plane** (stateless node discovery, liveness, capability advertisements, and lease renewal)
- **TCP Data Plane** (multiplexed streaming requests, delta events, and flow control windows)
- **LiNeP-SL Security Session Layer** (multi-level cryptographic authentication, fine-grained capability authorization, and tamper-evident governance)

In V0.2, LiNeP-SL couples the logical TCP `SESSION_BIND` state machine directly to authenticated LiNeP-SL security sessions, eliminating cross-plane desynchronization, session confusion, and unauthorized cross-domain escalation.

---

## 2. Breaking Wire & Protocol Changes

### 2.1 Transport Session Binding (`SESSION_BIND`)
- **Protocol Frame**: Data plane frames now require a 36-byte payload `SESSION_BIND` envelope (total 68-byte frame) before executing any requests.
- **Cryptographic Coupling**: A connection's transport binding must be authenticated against the active LiNeP-SL `session_record` via `validate_transport_session_binding()`.
- **Bidirectional Stream Traffic**: Transport session binding validates the peer's connection role (`session_participant_role::initiator` or `session_participant_role::responder`). Once bound, requests and streaming response deltas flow bidirectionally over the connection without per-direction re-binding.
- **Fail-Closed Timestamps**: Validation requires a non-zero timestamp (`now_us > 0`).

### 2.2 Canonical Domain Separators
Canonical authenticator inputs now enforce strict protocol domain prefixes:
- Control Plane & Data Plane canonical input: `LNS2`
- Security Negotiation transcript: `LNS2NEG`

---

## 3. Security Level (SL) Taxonomy & Profile Mappings

LiNeP-SL V0.2 codifies 5 discrete security levels with monotonic precedence:

| Level | Identifier | Description | Required Boundary Profile |
| :--- | :--- | :--- | :--- |
| **SL0** | `sl0_baseline` | Raw, unauthenticated transport (development only) | Rejected in production |
| **SL1** | `sl1_authenticated` | HMAC-SHA256 authenticated control/data plane frames | `intranet_cluster` |
| **SL2** | `sl2_identity` | Cryptographic peer endpoint identity & lease binding | `dmz_gateway` |
| **SL3** | `sl3_authorized` | Fine-grained subject/role capability enforcement | `federated_external` |
| **SL4** | `sl4_governed` | Hardware TPM/Token attestation & tamper-evident audit | `zero_trust_strict` |

---

## 4. Fine-Grained Authorization & Policy Scoping

### 4.1 Domain-Scoped Subjects and Roles
In V0.1, subject IDs and role names were global strings/integers. In V0.2:
- Policies are strictly keyed by `(trust_domain_id, subject_id)` and `(trust_domain_id, role_name)`.
- Roles registered under one trust domain cannot be assumed by callers from another trust domain.

### 4.2 Resource Match Invariants & Explicit Superuser Grant
- Resource matching enforces matching `resource_kind` (e.g. `{model, "*"}` matches only model resources, never tools or system controls).
- **Normative Administrative Superuser Grant**: Only `{resource_kind::system, "*"}` matches universally across all resource kinds (`model`, `embedding_space`, `tool`, `runtime`, `system`).

### 4.3 Execution Constraints & Non-Finite Numbers
- Constraint validation rejects non-finite floats (`NaN`, `Inf`) with `"temperature_non_finite"`.
- If a runtime advertises an empty `supported_models` list, it is treated as a dynamic/wildcard backend (e.g. Ollama adapters), permitting authorized model requests.

---

## 5. Governance, Federation & Tamper-Evident Audit

### 5.1 Fail-Closed Attestation Verifier
Under `federated_external` and `zero_trust_strict` profiles:
- If an attestation verifier is not configured (`nullptr`), admission evaluation fails closed with `"attestation_verifier_missing"`.
- Missing or malformed evidence results in `"federation_attestation_required"` or `"zero_trust_attestation_missing"`.

### 5.2 Strictly Monotonic Revisions
- Calls to `update_policy_revision(rev)` and `update_federation_revision(rev)` require `rev > current_rev`. Duplicate or backwards revisions return `false`.

### 5.3 Cryptographic Hash Chaining for Audit Records
All `audit_record_v02` entries contain:
- Monotonic sequence number: `audit_seq` (1, 2, 3...)
- Previous record digest: `prev_record_digest` (SHA-256 of prior record, empty for genesis)
- Canonical record digest: `record_digest` (SHA-256 of this record's canonical fields)

---

## 6. Migration Checklist

1. [ ] **Update Connection Handshake**:
   - Ensure clients issue `SESSION_BIND` immediately after opening TCP connections.
   - Set `session_participant_role::initiator` or `session_participant_role::responder` when invoking `validate_transport_session_binding()`.
   - Provide a valid, non-zero microsecond timestamp `now_us`.

2. [ ] **Scope Roles by Trust Domain**:
   - Update `role_policy` declarations to set `trust_domain_id` matching your cluster or tenant domain.

3. [ ] **Configure Minimum Security Levels**:
   - Set `trust_boundary_profile` appropriately:
     - Internal node clusters: `intranet_cluster` (SL1+)
     - Ingress DMZ: `dmz_gateway` (SL2+)
     - Partner federation: `federated_external` (SL3+)
     - Zero-Trust environments: `zero_trust_strict` (SL4)

4. [ ] **Supply Attestation Verifier**:
   - When deploying under `federated_external` or `zero_trust_strict`, always provide an `attestation_verifier` instance before handling peer requests.

5. [ ] **Verify Audit Chaining**:
   - Ingest `audit_record_v02` streams via `iaudit_sink_v02` and verify hash chains using `prev_record_digest`.
