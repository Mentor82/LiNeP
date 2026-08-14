#ifndef LINEP_SL_SL2_HPP
#define LINEP_SL_SL2_HPP

#include "security_types.hpp"
#include <cstddef>
#include <cstdint>

namespace linep::sl {

// SL2: Cryptographic Identity & Key Management
struct PeerIdentity {
    uint32_t trust_domain_id; // Trust domain ID (must match expected cluster domain)
    uint16_t node_id;         // Unique cryptographic node ID
    uint8_t  pubkey[32];      // Ed25519 or Curve25519 public key bytes
    bool     revoked;         // Revocation status (true if identity has been revoked)
};

struct SessionKey {
    uint32_t session_id;         // Established session ID
    uint16_t key_id;             // Active key generation index
    uint64_t established_at_sec; // Creation timestamp (seconds since Unix epoch)
    uint64_t expires_at_sec;     // Expiration timestamp (seconds since Unix epoch)
    uint8_t  secret_key[32];     // Derived 256-bit symmetric session key
};

// Validates peer identity against trust domain and revocation list
bool validate_peer_identity(const PeerIdentity& peer, uint32_t expected_trust_domain) noexcept;

// Derives a fresh 256-bit session key using HMAC-SHA256(Master, Domain || SessionID || KeyID || NodeID)
bool derive_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    uint32_t       session_id,
    uint16_t       key_id,
    uint16_t       node_id,
    uint64_t       ttl_sec,
    uint64_t       current_time_sec,
    SessionKey&    out_key) noexcept;

// Verifies if a session key is non-zero and within its valid TTL window
bool verify_session_key_freshness(const SessionKey& key, uint64_t current_time_sec) noexcept;

// Rotates session key to key_id + 1 and derives new secret key
bool rotate_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    SessionKey&    key,
    uint64_t       current_time_sec,
    uint64_t       new_ttl_sec) noexcept;

} // namespace linep::sl

#endif // LINEP_SL_SL2_HPP
