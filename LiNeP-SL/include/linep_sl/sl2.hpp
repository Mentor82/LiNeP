#ifndef LINEP_SL_SL2_HPP
#define LINEP_SL_SL2_HPP

#include "security_types.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linep::sl {

// Security Level Enum (SL0..SL4)
enum class SecurityLevel : uint8_t {
    SL0_NONE         = 0,
    SL1_AUTH         = 1,
    SL2_IDENTITY     = 2,
    SL3_CAPABILITIES = 3,
    SL4_GOVERNANCE   = 4
};

// Security Policy configuration
struct SecurityPolicy {
    SecurityLevel supported_sl = SecurityLevel::SL2_IDENTITY;
    SecurityLevel required_sl  = SecurityLevel::SL2_IDENTITY;
};

// Security Negotiation Result
struct NegotiationResult {
    bool          success = false;
    SecurityLevel negotiated_sl = SecurityLevel::SL0_NONE;
    const char*   error_reason = nullptr;
};

// Negotiate security level between peers and policy (fails closed on downgrade attempts)
NegotiationResult negotiate_security_level(
    SecurityLevel peer_supported,
    SecurityLevel local_supported,
    SecurityLevel local_required) noexcept;

// Peer Identity
struct PeerIdentity {
    uint32_t trust_domain_id; // Trust domain ID
    uint16_t node_id;         // Unique node ID
    uint8_t  pubkey[32];      // Public key bytes
    bool     revoked;         // Revocation flag
};

// Abstract Identity Provider Interface
class IdentityProvider {
public:
    virtual ~IdentityProvider() = default;
    virtual bool is_peer_trusted(const PeerIdentity& peer, uint32_t expected_trust_domain) const noexcept = 0;
    virtual bool is_node_revoked(uint16_t node_id) const noexcept = 0;
};

// Memory-backed Identity Provider implementation
class MemoryIdentityProvider : public IdentityProvider {
public:
    explicit MemoryIdentityProvider(uint32_t trust_domain_id)
        : trust_domain_id_(trust_domain_id) {}

    void register_peer(uint16_t node_id, const uint8_t pubkey[32]);
    void revoke_peer(uint16_t node_id);

    bool is_peer_trusted(const PeerIdentity& peer, uint32_t expected_trust_domain) const noexcept override;
    bool is_node_revoked(uint16_t node_id) const noexcept override;

private:
    uint32_t trust_domain_id_;
    std::unordered_map<uint16_t, std::vector<uint8_t>> trusted_nodes_;
    std::unordered_set<uint16_t> revoked_nodes_;
};

// Session Key
struct SessionKey {
    uint32_t session_id;         // Session ID
    uint16_t key_id;             // Key generation index
    uint64_t established_at_sec; // Creation timestamp (sec)
    uint64_t expires_at_sec;     // Expiration timestamp (sec)
    uint8_t  secret_key[32];     // Derived 256-bit symmetric session key
};

// Session Store managing key rotation boundaries and grace periods
class SessionStore {
public:
    SessionStore(uint32_t session_id, uint16_t node_id, uint64_t ttl_sec)
        : session_id_(session_id), node_id_(node_id), ttl_sec_(ttl_sec) {}

    bool initialize(const uint8_t* master_secret, size_t master_len, uint64_t current_time_sec) noexcept;
    bool rotate_key(const uint8_t* master_secret, size_t master_len, uint64_t current_time_sec) noexcept;
    bool get_active_key(SessionKey& out_key) const noexcept;
    bool is_key_valid(uint16_t key_id, const uint8_t secret_key[32], uint64_t current_time_sec) const noexcept;

private:
    uint32_t session_id_;
    uint16_t node_id_;
    uint64_t ttl_sec_;
    SessionKey current_key_{};
    SessionKey previous_key_{};
    bool initialized_ = false;
    bool has_previous_ = false;
};

// Standalone functions
bool validate_peer_identity(const PeerIdentity& peer, uint32_t expected_trust_domain) noexcept;

bool derive_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    uint32_t       session_id,
    uint16_t       key_id,
    uint16_t       node_id,
    uint64_t       ttl_sec,
    uint64_t       current_time_sec,
    SessionKey&    out_key) noexcept;

bool verify_session_key_freshness(const SessionKey& key, uint64_t current_time_sec) noexcept;

bool rotate_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    SessionKey&    key,
    uint64_t       current_time_sec,
    uint64_t       new_ttl_sec) noexcept;

} // namespace linep::sl

#endif // LINEP_SL_SL2_HPP
