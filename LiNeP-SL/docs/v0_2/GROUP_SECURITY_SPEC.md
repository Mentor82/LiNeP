# LiNeP-SL V0.2 Group Security & Cryptographic Execution Groups

## 1. Executive Summary

This specification defines the provider-neutral, MLS-compatible (RFC 9420) group security architecture in `linep::sl::v0_2`.

In L.I.A.R.A. Cluster OS, distributed task execution involves dynamic sets of heterogeneous worker nodes (primary execution, redundant verification, quorum consensus, and failover). LiNeP-SL Group Security provides cryptographic context isolation, anti-impersonation, confidentiality and forward secrecy so task payloads and intermediate stream deltas are visible and authenticatable only to active, authorized members of the cryptographic execution group.

---

## 2. Responsibility Split

```text
LiNeP / Cluster OS Scheduler
    --> Decides WHO works (resource placement, load balancing, health)

LiNeP Consensus / Validator
    --> Decides WHICH result is accepted (majority voting, deterministic proof)

LiNeP-SL Authorization
    --> Decides WHO may perform WHICH action (capabilities, policies)

LiNeP-SL Group Security (MLS-compatible)
    --> Decides WHO can cryptographically send, verify and decrypt group traffic
```

### Critical Security Invariants

1. **Epoch Separation**:
   $$\text{control\_epoch} \neq \text{security\_group\_epoch}$$
   - `control_epoch` tracks node incarnation in the UDP Control Plane (`ULNP`).
   - `security_group_epoch` tracks cryptographic membership state and key generation of the group context.
2. **Identity Separation**:
   $$\text{task\_id} \neq \text{execution\_id} \neq \text{security\_group\_id} \neq \text{security\_session\_id}$$
3. **No Authorization Shortcut**:
   Cryptographic group membership grants confidentiality/integrity over group traffic, but does **not** bypass action-level authorization checks.
4. **Forward Secrecy & Fresh Entropy Eviction**:
   When a node is evicted, fresh commit entropy is injected into the KDF. Removed members holding all epoch $N$ keys cannot compute epoch $N+1$ keys.
5. **Post-Compromise Security (PCS)**:
   When a healing rekey occurs with fresh update entropy, compromise of epoch $N$ state does not expose traffic in epoch $N+1$.
6. **Per-Sender Anti-Impersonation**:
   Messages are authenticated using per-sender private leaf keys; active members cannot forge messages under another member's identity.

---

## 3. RFC 9420 Ciphersuite Registry (16-Bit)

| Value | Name | DHKEM | AEAD | Hash | Signature |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0x0001` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | X25519 | AES-128-GCM | SHA-256 | Ed25519 |
| `0x0002` | `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` | P-256 | AES-128-GCM | SHA-256 | ECDSA-P256 |
| `0x0003` | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` | X25519 | ChaCha20Poly1305 | SHA-256 | Ed25519 |
| `0x0004` | `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` | X448 | AES-256-GCM | SHA-512 | Ed448 |
| `0x0005` | `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` | P-384 | AES-256-GCM | SHA-384 | ECDSA-P384 |
| `0x0006` | `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` | P-521 | AES-256-GCM | SHA-512 | ECDSA-P521 |
| `0x0007` | `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` | X448 | ChaCha20Poly1305 | SHA-512 | Ed448 |

---

## 4. Public State vs. Private Secrets Hygiene

- `group_context` contains **only public authenticated state** (RFC 9420 Section 6.1 `GroupContext`):
  - `group_id`, `group_epoch`, `type`, `ciphersuite`, `state`, `created_at_us`, `epoch_advanced_at_us`
  - `members` (public endpoint identities and public keys)
  - `execution_group_state_hash`, `tree_hash`, `confirmed_transcript_hash`
- **Secret state** (epoch secrets, leaf secrets, sender signing keys, encryption streams) is kept opaque inside `group_crypto_provider` and is never exposed through public inspection APIs.

---

## 5. Group Message Authenticator Binding (`LNS2_GROUP`)

The canonical little-endian byte representation for group message signatures:

```text
Offset  Size  Field
-------------------------------------------------------------
0x00    8     Magic: "LNS2GRP\0" (0x4C, 0x4E, 0x53, 0x32, 0x47, 0x52, 0x50, 0x00)
0x08    1     Version Major (0x00)
0x09    1     Version Minor (0x02)
0x0A    8     group_id (uint64 LE)
0x12    8     group_epoch (uint64 LE)
0x1A    8     sender_node_id (uint64 LE)
0x22    8     sender_runtime_id (uint64 LE)
0x2A    4     sender_endpoint_id (uint32 LE)
0x2E    4     sender_trust_domain_id (uint32 LE)
0x32    8     sender_subject_id (uint64 LE)
0x3A    1     message_class (uint8: 1=request, 2=event, 3=control)
0x3B    1     digest_algorithm (uint8: 1=SHA-256, 2=SHA-512)
0x3C    8     message_seq (uint64 LE - Application sequence)
0x44    4     ratchet_generation (uint32 LE - Cryptographic ratchet)
0x48    2     content_digest_len (uint16 LE)
0x4A    N     content_digest (N bytes)
```

---

## 6. Protection Modes

1. **`authenticated_only`** (`group_protection_mode::authenticated_only`):
   - Corresponds to MLS `PublicMessage` semantics.
   - Payload is transmitted as plaintext with anti-impersonation sender authentication tag.
2. **`confidential_and_authenticated`** (`group_protection_mode::confidential_and_authenticated`):
   - Corresponds to MLS `PrivateMessage` semantics.
   - Payload is encrypted on the wire; decrypted only by active members possessing epoch keys.
