#ifndef LINEP_SL_SL2_HPP
#define LINEP_SL_SL2_HPP

#include "security_types.hpp"
#include <cstddef>
#include <cstdint>

namespace linep::sl {

// SL2: Cryptographic Identity & Key Management
struct PeerIdentity {
    uint32_t trust_domain_id;
    uint16_t node_id;
    uint8_t  pubkey[32];
};

struct SessionKey {
    uint32_t session_id;
    uint16_t key_id;
    uint64_t established_at_sec;
    uint64_t expires_at_sec;
    uint8_t  secret_key[32];
};

bool validate_peer_identity(const PeerIdentity& peer) noexcept;

} // namespace linep::sl

#endif // LINEP_SL_SL2_HPP
