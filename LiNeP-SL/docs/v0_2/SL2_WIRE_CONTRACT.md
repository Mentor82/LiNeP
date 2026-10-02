# LiNeP-SL V0.2 Wire Contract: SL2 Remote Worker Profile

Status: **Phase C Specification Baseline** (Issue #30).  
Governing Standard: `equorus-value-v1`, LiNeP V0.2 Protocol Specifications, RFC 8446 (TLS 1.3 transcript binding principles), RFC 5869 (HKDF), RFC 7539 / RFC 8439 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM).

---

## 1. Overview & Architectural Role

LiNeP-SL Level 2 (`SL2_IDENTITY`) establishes an authenticated, confidential, forward-secret, replay-protected session between two LiNeP endpoints over an untrusted, firewalled, or routed transport (e.g. Tailscale, NAT, remote edge gateway).

### Concrete Deployment Target: Remote NPU Worker (VINOX)
- A remote workstation/laptop running VINOX (Intel NPU) dials out to a L.I.A.R.A. cluster edge gateway (`linepd`).
- The dial-out connection cannot accept inbound connections (DHCP / NAT).
- The cluster-internal trunk operates with SL1; cluster keys must never leave the cluster boundaries.
- The remote laptop authenticates with an individual per-device cryptographic identity (Ed25519) and negotiates an ephemeral session key (X25519 ECDH + HKDF-SHA-256 + AEAD).
- After the SL2 handshake completes, the connection is bound via `SESSION_BIND`, and the worker registers itself as a runtime via `RUNTIME_REGISTER` (Issue #31) to serve authorized models (`PROFILE_CHAT`, `PROFILE_GENERATE`, `PROFILE_EMBED`).

---

## 2. Separation of Roles: Transport vs. Application

To avoid cryptographic reflection, key confusion, or privilege inversion, transport roles and application roles are strictly separated:

| Role Dimension | Initiator (`0x01`) | Responder (`0x02`) |
| :--- | :--- | :--- |
| **TCP / Transport** | Dials TCP connection (Remote Worker) | Listens / Accepts TCP connection (Gateway / Router) |
| **SL2 Cryptography** | `initiator_traffic_key`, `initiator_iv` | `responder_traffic_key`, `responder_iv` |
| **Application Layer** | Worker / Runtime (serves inference/embeddings) | Router / Scheduler (submits requests) |
| **Data Envelopes** | Sends `RUNTIME_REGISTER`, sends `EVENT`, receives `REQUEST` | Receives `RUNTIME_REGISTER`, sends `REQUEST`, receives `EVENT` |
| **SL1 / Wire Labels** | `initiator_to_responder` (Worker $\rightarrow$ Router) | `responder_to_initiator` (Router $\rightarrow$ Worker) |

> [!IMPORTANT]
> Symmetric AEAD keys and IVs are derived strictly from the **TCP transport roles** (`initiator` vs `responder`). Direction tags in message authentication inputs prevent reflection attacks unconditionally.

---

## 3. Cryptographic Primitives & Suite Definitions

In accordance with `negotiation.hpp`, SL2 mandates vetted, non-invented cryptographic primitives:

1. **Key Exchange (KEM / ECDH):**
   - **X25519** (RFC 7748): 32-byte ephemeral private and public keys. Ephemeral keys are strictly single-use per TCP connection (Perfect Forward Secrecy).
2. **Device Identity & Signatures:**
   - **Ed25519** (RFC 8032): 32-byte public key, 64-byte signature.
3. **Key Derivation:**
   - **HKDF-SHA-256** (RFC 5869): Extract-and-Expand with strict domain-separated labels.
4. **Symmetric AEAD Ciphers:**
   - Suite `0x0002`: `x25519_ed25519_hkdf_sha256_aes256_gcm` (AES-256-GCM, NIST SP 800-38D).
   - Suite `0x0003`: `x25519_ed25519_hkdf_sha256_chacha20_poly1305` (ChaCha20-Poly1305, RFC 8439).

---

## 4. Handshake Wire Carriage & Frame Format

Handshake messages travel in LiNeP V0.2 framing with a dedicated envelope type:

### Envelope Header (32 bytes Little-Endian)
- `magic`: `LINEP_V02_MAGIC` (`0x504E4C32` / `'2LNP'`)
- `version_major`: `0`
- `version_minor`: `2`
- `envelope_type`: `7` (`sl2_handshake`)
- `flags`: `0` (unauthenticated during initial handshake exchange; subsequent data frames use authenticated flag)
- `request_id`: `0` (connection-level)
- `execution_id`: `0` (connection-level)
- `output_id`: `0` (connection-level)
- `payload_len`: length of the handshake payload

### Handshake Message Types
Inside the envelope payload, the first byte identifies the handshake step:

| ID | Message Name | Direction | Purpose |
| :--- | :--- | :--- | :--- |
| `0x01` | `ClientHello` | Initiator $\rightarrow$ Responder | Initiator Offer, Ephemeral X25519 PubKey, Device Identity, Signature |
| `0x02` | `ServerHello` | Responder $\rightarrow$ Initiator | Responder Offer, Ephemeral X25519 PubKey, Gateway Identity, Negotiation Result, Signature |
| `0x03` | `ClientFinished` | Initiator $\rightarrow$ Responder | AEAD/HMAC verification of the complete mutual transcript |
| `0x04` | `ServerFinished` | Responder $\rightarrow$ Initiator | AEAD/HMAC verification confirming session activation |

Until `ServerFinished` is successfully verified, the connection is in state `HANDSHAKE`. Any data frame (types 1..6) received while in state `HANDSHAKE` is a fatal protocol error that immediately terminates the connection (Fail-Closed).

---

## 5. Handshake Transcript & Key Derivation Specification

### A. Transcript Accumulation ($H$)
Transcript hashing follows RFC 8446 principles:
1. Initialize:
   $$H_0 = \text{SHA-256}(\text{"LNS2-SL2-TRANSCRIPT-V0.2"})$$
2. After encoding `ClientHello` (payload bytes $M_1$):
   $$H_1 = \text{SHA-256}(H_0 \parallel M_1)$$
3. After encoding `ServerHello` (payload bytes $M_2$):
   $$H_2 = \text{SHA-256}(H_1 \parallel M_2)$$
4. The negotiation transcript `LNS2NEG` from Phase B (`encode_negotiation_transcript()`) is computed from the mutual `negotiation_offer` structs and result:
   $$H_{\text{neg}} = \text{SHA-256}(H_2 \parallel \text{LNS2NEG\_BYTES})$$

### B. Device Signature Contract (Proof of Possession)
Both peers must prove possession of their respective long-term Ed25519 identity keys:

$$\text{SigInput}_{\text{client}} = \text{"LNS2-SIG-CLIENT-V1"} \parallel \text{uint32\_le}(\text{trust\_domain\_id}) \parallel \text{uint64\_le}(\text{subject\_id}) \parallel H_1$$

$$\text{SigInput}_{\text{server}} = \text{"LNS2-SIG-SERVER-V1"} \parallel \text{uint32\_le}(\text{trust\_domain\_id}) \parallel \text{uint64\_le}(\text{subject\_id}) \parallel H_2$$

The peer verifies the 64-byte Ed25519 signature against the sender's authenticated device public key before proceeding.

### C. Shared Secret & Key Schedule
1. **Diffie-Hellman Exchange:**
   $$SS = \text{X25519}(\text{priv}_{\text{ephem}}, \text{pub}_{\text{peer\_ephem}})$$
   If $SS$ is all zeros (contributory behavior check), the handshake aborts immediately.

2. **Early Key Derivation:**
   $$PRK = \text{HKDF-Extract}(\text{salt} = H_{\text{neg}}, \text{IKM} = SS)$$

3. **Key Expansion (`HKDF-Expand` with labels):**
   - `initiator_traffic_key` (32 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.key.init"}, 32)$$
   - `responder_traffic_key` (32 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.key.resp"}, 32)$$
   - `initiator_iv` (12 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.iv.init"}, 12)$$
   - `responder_iv` (12 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.iv.resp"}, 12)$$
   - `initiator_finished_key` (32 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.fin.init"}, 32)$$
   - `responder_finished_key` (32 bytes):
     $$\text{HKDF-Expand}(PRK, \text{"lns2.fin.resp"}, 32)$$

### D. Finished Verification
- `ClientFinished` payload:
  $$\text{VerifyData}_{\text{client}} = \text{HMAC-SHA256}(\text{initiator\_finished\_key}, H_2)$$
- Update transcript: $H_3 = \text{SHA-256}(H_2 \parallel \text{VerifyData}_{\text{client}})$
- `ServerFinished` payload:
  $$\text{VerifyData}_{\text{server}} = \text{HMAC-SHA256}(\text{responder\_finished\_key}, H_3)$$
- Update transcript: $H_4 = \text{SHA-256}(H_3 \parallel \text{VerifyData}_{\text{server}})$

Upon successful verification of `ServerFinished`, the security session is marked `active` in the local `session_registry`.

---

## 6. Nonce Construction, Replay Protection & Rekeying

### A. AEAD Nonce Construction
For each direction, messages maintain a monotonically increasing 64-bit sequence counter $N_{\text{seq}}$, initialized to $0$ upon session activation:

$$\text{Nonce}_{96} = \text{BaseIV}_{96} \oplus (\text{0x00}_{32} \parallel \text{uint64\_be}(N_{\text{seq}}))$$

### B. Invariants
1. $N_{\text{seq}}$ increments strictly by 1 for each transmitted AEAD envelope.
2. If $N_{\text{seq}} = 2^{64} - 1$, the connection terminates immediately without wrapping.
3. On TCP streams, received sequence numbers must equal the expected monotonic sequence (`monotonic_stream_tracker`). Any gap or duplicate terminates the connection.

### C. Rekeying (Key Rotation)
To comply with cryptographic limits for GCM and Poly1305:
- **Triggers:**
  - After $2^{24}$ AEAD frames (~16,777,216 messages).
  - After 1 GiB of encrypted payload data.
  - When remaining credential validity falls below $20\%$.
- **Mechanism:**
  - Key rotation invokes `session_registry::rotate()`:
    $$PRK_{\text{new}} = \text{HKDF-Expand}(PRK_{\text{current}}, \text{"lns2.rekey"}, 32)$$
  - Epoch bumps: $\text{security\_epoch} \leftarrow \text{security\_epoch} + 1$, $\text{key\_id} \leftarrow \text{key\_id} + 1$.
  - Nonce sequence resets to $N_{\text{seq}} = 0$.

### D. Reconnect Policy
- Every reconnect over TCP creates an entirely new connection.
- Key reuse across reconnects is **strictly prohibited**.
- A new connection must run a fresh handshake, draw fresh nonces, generate fresh X25519 pairs, and receive a new `session_id`.

---

## 7. Device Identity, Trust Anchor & Revocation Enforcement

### A. Device Credential Structure
Device authorization is verified by `identity_verifier`:
1. `trust_domain_id` (uint32): Cluster identifier (e.g. `100`).
2. `subject_id` (uint64): Unique device identifier.
3. `node_id` (uint64): LiNeP endpoint identifier.
4. `device_pubkey` (32 bytes Ed25519).
5. `valid_from_us` / `valid_to_us`: Unix epoch microseconds validity window.
6. `ca_signature`: Cluster Root CA signature over fields (1..5).

### B. Instant Isolation & Revocation
When a device is revoked or `session_registry::revoke(session_id)` is invoked:
1. `session_record::state` is transitioned to `session_state::revoked`.
2. The active socket is closed immediately (`connection.close()`).
3. All in-flight execution streams are cancelled and failed (`terminal_outcome::failed`, `error_category::unauthorized`).
4. Ephemeral keys in RAM are zeroized (`OPENSSL_cleanse`).
5. Subsequent handshake attempts presenting this `subject_id` or key are rejected at the `identity_verifier` stage.

---

## 8. Integration with SESSION_BIND and RUNTIME_REGISTER

Once the SL2 session is active:
1. **SESSION_BIND (Envelope 5):**
   - Transmitted under the established SL2 session.
   - The Gateway checks:
     ```cpp
     validate_transport_session_binding(
         session,
         session_participant_role::initiator,
         binding,
         now_us
     ) == verification_status::ok
     ```
2. **RUNTIME_REGISTER (Envelope 6 - Issue #31):**
   - The worker declares its available concurrent slots and capabilities (`PROFILE_CHAT`, `PROFILE_GENERATE`, `PROFILE_EMBED`).
   - The router authorizer checks the bound credential against `authorization.hpp`:
     - Checks if `subject_id` has role `"runtime"`.
     - Validates that every advertised model ID in `supported_models` and `supported_embedding_spaces` is explicitly authorized in the device's policy grant.
   - If unauthorized, the router replies with `RESULT` status `403` ("runtime_not_authorized").
   - If authorized, the router replies with `RESULT` status `200` ("accepted").

---

## 9. Conformance Test Matrix (Negative & Positive Vectors)

The SL2 conformance test profile must verify the following scenarios deterministically:

| ID | Test Scenario | Expected Outcome |
| :--- | :--- | :--- |
| `SL2-POS-01` | Full roundtrip handshake with ChaCha20-Poly1305 | Session active, valid finished keys, bidirectional traffic decrypts |
| `SL2-POS-02` | Full roundtrip handshake with AES-256-GCM | Session active, valid finished keys, bidirectional traffic decrypts |
| `SL2-POS-03` | Key rotation after limit threshold | Epoch incremented, keys rotated, communication continues without drop |
| `SL2-NEG-01` | Single-bit flip in `LNS2NEG` transcript | Handshake verification fails closed (`signature_invalid` or `finished_mismatch`) |
| `SL2-NEG-02` | Untrusted or mismatched `trust_domain_id` | Handshake fails closed at `identity_verifier` |
| `SL2-NEG-03` | Expired device credential (`now_us > valid_to_us`) | Handshake fails closed with `session_inactive` |
| `SL2-NEG-04` | Revoked device identity | Handshake fails closed with `revoked` |
| `SL2-NEG-05` | Downgrade attack: offer manipulated to force SL1 when policy requires SL2 | Handshake fails with `downgrade_rejected` |
| `SL2-NEG-06` | Nonce replay / re-used ClientHello nonce | Fails closed |
| `SL2-NEG-07` | Premature `RUNTIME_REGISTER` or `REQUEST` sent before handshake completes | Protocol violation, connection terminated immediately |
| `SL2-NEG-08` | Sequence regression or replayed AEAD frame | Monotonic tracker rejects frame, connection closed |
| `SL2-NEG-09` | Tampered AEAD ciphertext or invalid auth tag | Decryption fails, immediate socket close |
| `SL2-NEG-10` | Dial-out worker attempts to register unapproved model | Router authorizer returns 403, registration denied |
