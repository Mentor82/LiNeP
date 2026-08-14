# LiNeP & LiNeP-SL Library Reference

This reference manual documents all core components, structures, functions, C-ABI entry points, and Python bindings across **LiNeP (Core Transport)** and **LiNeP-SL (Security Layers)** with concise explanations.

---

## 1. Architecture Overview & Component Boundaries

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        LiNeP Core Transport                           │
│  (Header Packing, Frame Validation, Scheduling, Streaming, Consensus) │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   LiNeP-SL Layered Security Stack                      │
│                                                                        │
│   SL4: Governance, Policy Engine, Audit Trail & Federation            │
│   SL3: Capability Tokens, Replay Protection & Action Authorization     │
│   SL2: Ephemeral Session Keys, TTL Freshness & Domain Identities       │
│   SL1: HMAC-SHA256 Frame Authentication & Integrity Checks            │
│   SL0: Baseline Frame Hygiene, Version Validation & Error Handling     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. LiNeP Core Transport Library (`<linep/types.hpp>`)

### `linep::Header`
The 24-byte binary wire header prefix prepended to all network frames.
- `uint16_t magic`: Protocol magic identifier (`0x4E4C` = `"NL"`).
- `uint8_t version`: Protocol version number (default `0x01`).
- `uint8_t msg_type`: Category identifier (`TASK`, `RESULT`, `STREAM_CHUNK`, `TASK_CANCEL`, `UDP_HEARTBEAT`).
- `uint32_t payload_len`: Byte length of payload body following header.
- `uint32_t session_id`: Unique session identifier.
- `uint32_t sequence`: Monotonic frame sequence number.
- `uint32_t correlation_id`: Task or stream tracking correlation ID.
- `uint16_t flags`: Control bitmask (`FLAG_FRAGMENTED`, `FLAG_FINAL_FRAGMENT`, `FLAG_SECURITY_EXT`).

### `linep::MessageType`
Enumeration of normative message categories:
- `TASK` (`0x01`): Execution request task payload.
- `RESULT` (`0x02`): Task completion payload.
- `STREAM_CHUNK` (`0x03`): Streaming payload fragment.
- `TASK_CANCEL` (`0x04`): Task cancellation request.
- `UDP_HEARTBEAT` (`0x05`): Lightweight datagram heartbeat.
- `CONSENSUS_REQ` (`0x06`): Peer consensus message.

---

## 3. LiNeP-SL Security Layer C++ API (`namespace linep::sl`)

### 3.1. SL1 — Lightweight Frame Authentication (`<linep_sl/sl1.hpp>`)

#### `compute_sl1_mac(...)`
```cpp
void compute_sl1_mac(
    const uint8_t* secret_key, size_t key_len,
    const linep::Header& header, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, size_t payload_len,
    uint8_t out_mac[16]) noexcept;
```
- **Explanation**: Computes a 16-byte HMAC-SHA256 signature binding the header, session ID, key ID, sequence, and payload.

#### `verify_sl1_mac(...)`
```cpp
bool verify_sl1_mac(
    const uint8_t* secret_key, size_t key_len,
    const linep::Header& header, const AuthExtension& auth_ext,
    const uint8_t* payload, size_t payload_len) noexcept;
```
- **Explanation**: Performs constant-time MAC verification. Returns `true` if valid, `false` otherwise (fail-closed).

---

### 3.2. SL2 — Identity & Key Lifecycle (`<linep_sl/sl2.hpp>`)

#### `DomainNodeKey`
```cpp
struct DomainNodeKey {
    uint32_t trust_domain_id;
    uint16_t node_id;
};
```
- **Explanation**: Domain-scoped key tuple ensuring that a peer identity is strictly bound to its specific trust domain `(trust_domain_id, node_id)`.

#### `MemoryIdentityProvider`
```cpp
class MemoryIdentityProvider : public IdentityProvider {
public:
    explicit MemoryIdentityProvider(uint32_t trust_domain_id);
    void register_peer(uint16_t node_id, const uint8_t pubkey[32]);
    void register_peer_for_domain(uint32_t trust_domain_id, uint16_t node_id, const uint8_t pubkey[32]);
    void revoke_peer(uint16_t node_id);
    bool is_peer_trusted(const PeerIdentity& peer, uint32_t expected_trust_domain) const noexcept override;
};
```
- **Explanation**: In-memory domain-scoped identity store backing cryptographic public key lookups and revocation checks.

#### `derive_session_key(...)`
```cpp
bool derive_session_key(
    const uint8_t* master_secret, size_t master_len,
    uint32_t session_id, uint16_t key_id, uint16_t node_id,
    uint64_t ttl_sec, uint64_t current_time_sec,
    SessionKey& out_key) noexcept;
```
- **Explanation**: Derives an ephemeral 256-bit symmetric session key via HKDF/HMAC-SHA256 with temporal validity limits (`expires_at_sec = current_time_sec + ttl_sec`).

#### `verify_session_key_freshness(...)`
```cpp
bool verify_session_key_freshness(const SessionKey& key, uint64_t current_time_sec) noexcept;
```
- **Explanation**: Validates if `current_time_sec` falls strictly within the session key's valid lifetime `[established_at_sec, expires_at_sec]`.

#### `SessionStore`
```cpp
class SessionStore;
```
- **Explanation**: Persistent session store manager tracking active key generations (`key_id`), enforcing key rotation grace periods, and rejecting expired or revoked session keys.

---

### 3.3. SL3 — Capabilities & Replay Protection (`<linep_sl/sl3.hpp>`)

#### `CapFlags`
Bitmask capabilities restricting authorized operations:
- `CAP_NONE` (`0x00`): No capabilities granted.
- `CAP_INFERENCE_READ` (`0x01`): Read/query inference models.
- `CAP_INFERENCE_WRITE` (`0x02`): Submit tasks / write model weights.
- `CAP_ADMIN` (`0x04`): Administrative & key rotation actions.
- `CAP_SLOT_MANAGE` (`0x08`): Manage worker scheduling slots.
- `CAP_METRICS_READ` (`0x10`): Access telemetry metrics.
- `CAP_HEARTBEAT_EMIT` (`0x20`): Emit UDP heartbeat datagrams.

#### `create_capability_token(...)`
```cpp
CapabilityToken create_capability_token(
    const uint8_t* secret_key, uint32_t session_id,
    CapFlags granted_caps, uint64_t expires_at_sec) noexcept;
```
- **Explanation**: Generates a 16-byte HMAC-SHA256 signed capability token bound to a session and expiry timestamp.

#### `verify_capability_token(...)`
```cpp
bool verify_capability_token(
    const uint8_t* secret_key, const CapabilityToken& token,
    uint32_t expected_session_id, uint64_t current_time_sec,
    CapFlags required_capability) noexcept;
```
- **Explanation**: Verifies capability signature, checks expiration time, and asserts that `required_capability` is granted by the token bitmask.

---

### 3.4. SL4 — Governance, Audit & Federation (`<linep_sl/sl4.hpp>`)

#### `GovernancePolicy`
```cpp
struct GovernancePolicy {
    std::string policy_id = "default-policy";
    uint32_t policy_revision = 1;
    uint64_t allowed_capabilities;
    bool allow_cross_domain = false;
};
```
- **Explanation**: Governed security policy defining permitted capabilities, revision indices, and cross-domain access controls.

#### `SecurityDecisionEngine`
```cpp
class SecurityDecisionEngine {
public:
    explicit SecurityDecisionEngine(uint32_t local_trust_domain_id);
    void register_peer(uint16_t node_id, const uint8_t pubkey[32], uint32_t trust_domain_id);
    void set_policy(const GovernancePolicy& policy);
    void add_federation(uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps, uint32_t revision = 1);
    DecisionResult evaluate(const DecisionContext& ctx) noexcept;
};
```
- **Explanation**: Zero-Trust decision engine enforcing 3-Gate checks:
  1. Security Level check (`negotiated_sl >= SL2_IDENTITY`).
  2. Domain-Scoped Peer Identity verification via `IdentityProvider`.
  3. Policy & Federation capability bounds. Emits structured, secret-free audit events.

---

## 4. C-ABI Interface (`<linep_sl/cabi_sl.h>`)

| C-ABI Function | Description |
|---|---|
| `linep_sl1_compute_mac(...)` | Compute SL1 HMAC-SHA256 MAC. |
| `linep_sl1_verify_mac(...)` | Verify SL1 MAC in constant-time. |
| `linep_sl2_negotiate_level(...)` | Negotiate security level (fails closed on downgrade). |
| `linep_sl2_validate_peer_identity(...)` | Validate structural peer identity format. |
| `linep_sl2_derive_session_key(...)` | Derive 256-bit symmetric session key with TTL. |
| `linep_sl2_verify_session_key_freshness(...)` | Check session key timestamp freshness. |
| `linep_sl3_create_cap_token(...)` | Sign capability authorization token. |
| `linep_sl3_verify_cap_token(...)` | Verify capability token signature and scope. |
| `linep_sl4_engine_create(...)` | Instantiate persistent SL4 decision engine. |
| `linep_sl4_engine_register_peer_for_domain(...)` | Register domain-scoped peer identity `(domain, node, pubkey)`. |
| `linep_sl4_engine_set_policy(...)` | Register active governance policy revision. |
| `linep_sl4_engine_add_federation(...)` | Register cross-domain federation agreement. |
| `linep_sl4_engine_evaluate(...)` | Evaluate Zero-Trust decision context and emit audit trail. |
| `linep_sl4_engine_free(...)` | Free decision engine handle. |

---

## 5. Python CFFI Bindings (`import linep_sl`)

### Classes & Functions
```python
import linep_sl

# 1. SL1 MAC Authentication
mac = linep_sl.compute_sl1_mac(secret_key, hdr_bytes, session_id, key_id, auth_seq, payload)
is_valid = linep_sl.verify_sl1_mac(secret_key, hdr_bytes, session_id, key_id, auth_seq, mac, payload)

# 2. SL2 Session Key Lifecycle
session = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, ttl_sec, current_time)
is_fresh = linep_sl.verify_session_key_freshness(session, current_time)

# 3. SL3 Capability Authorization
token = linep_sl.create_capability_token(secret_key, session_id, linep_sl.CapFlags.INFERENCE_READ, expires_at)
is_authorized = linep_sl.verify_capability_token(secret_key, token, session_id, current_time, linep_sl.CapFlags.INFERENCE_READ)

# 4. SL4 Governance Engine
engine = linep_sl.SecurityDecisionEngine(local_trust_domain_id=0x4C4E5031)
engine.register_peer(node_id=20, pubkey_32bytes=pubkey_bytes, trust_domain_id=0x4C4E5031)
policy = linep_sl.GovernancePolicy(policy_id="default-policy", policy_revision=1, allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ)
engine.set_policy(policy)

decision, reason = engine.evaluate(
    trust_domain_id=0x4C4E5031,
    session_id=0x1001,
    key_id=1,
    local_node_id=1,
    remote_node_id=20,
    remote_trust_domain_id=0x4C4E5031,
    remote_revoked=False,
    negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
    requested_cap=linep_sl.CapFlags.INFERENCE_READ,
    remote_pubkey_32bytes=pubkey_bytes,
)
```

---

## 6. Normative References & Issue Tracking

- **GitHub Issue #1**: [`fix(linep-sl): restore normative SL0–SL4 layer boundaries`](https://github.com/Mentor82/LiNeP/issues/1)
- **GitHub Issue #2**: [`hardening(linep-sl/sl1): canonicalize MAC input`](https://github.com/Mentor82/LiNeP/issues/2)
- **GitHub Issue #3**: [`feat(linep-sl/sl2): implement cryptographic identity & session key management`](https://github.com/Mentor82/LiNeP/issues/3)
- **GitHub Issue #4**: [`test(linep-sl): validate SL2 interoperability on real Windows ↔ Debian 13 peers`](https://github.com/Mentor82/LiNeP/issues/4)
- **GitHub Issue #6**: [`feat(linep-sl/sl4): implement governance, audit, zero-trust and federation semantics`](https://github.com/Mentor82/LiNeP/issues/6)
- **GitHub Issue #7**: [`test(linep-sl): validate SL security invariants over LiNeP UDP heartbeat transport`](https://github.com/Mentor82/LiNeP/issues/7)
