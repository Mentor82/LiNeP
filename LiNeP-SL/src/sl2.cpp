#include <linep_sl/sl2.hpp>
#include <linep_sl/sl1.hpp>
#include "sha256.hpp"
#include <cstring>
#include <algorithm>

namespace linep::sl {

namespace {

inline void write_u16_le(uint8_t* dst, uint16_t val) noexcept {
    dst[0] = static_cast<uint8_t>(val & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
}

inline void write_u32_le(uint8_t* dst, uint32_t val) noexcept {
    dst[0] = static_cast<uint8_t>(val & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

} // namespace

NegotiationResult negotiate_security_level(
    SecurityLevel peer_supported,
    SecurityLevel local_supported,
    SecurityLevel local_required) noexcept
{
    NegotiationResult res;
    // Calculate negotiated level as min(peer_supported, local_supported)
    auto peer_val = static_cast<uint8_t>(peer_supported);
    auto local_val = static_cast<uint8_t>(local_supported);
    auto req_val = static_cast<uint8_t>(local_required);

    uint8_t min_val = (peer_val < local_val) ? peer_val : local_val;
    res.negotiated_sl = static_cast<SecurityLevel>(min_val);

    // Fail closed if negotiated level is lower than local required level
    if (min_val < req_val) {
        res.success = false;
        res.error_reason = "Downgrade rejected: Negotiated security level is lower than required security level";
        return res;
    }

    res.success = true;
    res.error_reason = nullptr;
    return res;
}

bool validate_peer_identity(const PeerIdentity& peer, uint32_t expected_trust_domain) noexcept {
    if (peer.revoked) {
        return false; // Revoked identity -> fail closed
    }
    if (peer.trust_domain_id == 0 || peer.trust_domain_id != expected_trust_domain) {
        return false; // Trust-domain mismatch -> fail closed
    }
    if (peer.node_id == 0) {
        return false; // Invalid node ID -> fail closed
    }

    uint8_t mask = 0;
    for (size_t i = 0; i < 32; ++i) {
        mask |= peer.pubkey[i];
    }
    return mask != 0;
}

void MemoryIdentityProvider::register_peer(uint16_t node_id, const uint8_t pubkey[32]) {
    if (node_id == 0 || !pubkey) return;
    std::vector<uint8_t> pk(pubkey, pubkey + 32);
    trusted_nodes_[node_id] = pk;
    revoked_nodes_.erase(node_id);
}

void MemoryIdentityProvider::revoke_peer(uint16_t node_id) {
    if (node_id == 0) return;
    revoked_nodes_.insert(node_id);
}

bool MemoryIdentityProvider::is_node_revoked(uint16_t node_id) const noexcept {
    return revoked_nodes_.find(node_id) != revoked_nodes_.end();
}

bool MemoryIdentityProvider::is_peer_trusted(const PeerIdentity& peer, uint32_t expected_trust_domain) const noexcept {
    if (peer.revoked || is_node_revoked(peer.node_id)) {
        return false;
    }
    if (!validate_peer_identity(peer, expected_trust_domain)) {
        return false;
    }
    auto it = trusted_nodes_.find(peer.node_id);
    if (it == trusted_nodes_.end()) {
        return false; // Unknown node -> fail closed
    }

    // Check pubkey match
    return std::memcmp(it->second.data(), peer.pubkey, 32) == 0;
}

bool MemoryIdentityProvider::get_peer_identity(uint16_t node_id, uint32_t trust_domain_id, PeerIdentity& out_peer) const noexcept {
    if (node_id == 0) return false;
    auto it = trusted_nodes_.find(node_id);
    if (it == trusted_nodes_.end()) return false;

    out_peer.node_id = node_id;
    out_peer.trust_domain_id = trust_domain_id;
    out_peer.revoked = is_node_revoked(node_id);
    std::memcpy(out_peer.pubkey, it->second.data(), 32);
    return true;
}

bool derive_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    uint32_t       session_id,
    uint16_t       key_id,
    uint16_t       node_id,
    uint64_t       ttl_sec,
    uint64_t       current_time_sec,
    SessionKey&    out_key) noexcept
{
    if (!master_secret || master_len == 0 || session_id == 0 || node_id == 0) {
        return false;
    }

    static const uint8_t kdf_label[7] = {'S', 'L', '2', '_', 'K', 'D', 'F'};
    uint8_t kdf_info[7 + 4 + 2 + 2];
    std::memcpy(kdf_info, kdf_label, 7);
    write_u32_le(kdf_info + 7, session_id);
    write_u16_le(kdf_info + 11, key_id);
    write_u16_le(kdf_info + 13, node_id);

    out_key.session_id = session_id;
    out_key.key_id = key_id;
    out_key.established_at_sec = current_time_sec;
    out_key.expires_at_sec = current_time_sec + ttl_sec;

    crypto::hmac_sha256(master_secret, master_len, kdf_info, sizeof(kdf_info), out_key.secret_key);
    return true;
}

bool verify_session_key_freshness(const SessionKey& key, uint64_t current_time_sec) noexcept {
    if (key.session_id == 0) return false;
    if (current_time_sec < key.established_at_sec) return false;
    if (current_time_sec > key.expires_at_sec) return false;

    uint8_t mask = 0;
    for (size_t i = 0; i < 32; ++i) {
        mask |= key.secret_key[i];
    }
    return mask != 0;
}

bool rotate_session_key(
    const uint8_t* master_secret,
    size_t         master_len,
    SessionKey&    key,
    uint64_t       current_time_sec,
    uint64_t       new_ttl_sec) noexcept
{
    const uint16_t next_key_id = key.key_id + 1;
    const uint32_t session_id = key.session_id;
    const uint16_t dummy_node_id = 1;

    return derive_session_key(master_secret, master_len, session_id, next_key_id, dummy_node_id, new_ttl_sec, current_time_sec, key);
}

bool SessionStore::initialize(const uint8_t* master_secret, size_t master_len, uint64_t current_time_sec) noexcept {
    if (!derive_session_key(master_secret, master_len, session_id_, 1, node_id_, ttl_sec_, current_time_sec, current_key_)) {
        return false;
    }
    initialized_ = true;
    has_previous_ = false;
    return true;
}

bool SessionStore::rotate_key(const uint8_t* master_secret, size_t master_len, uint64_t current_time_sec) noexcept {
    if (!initialized_) return false;
    previous_key_ = current_key_;
    has_previous_ = true;

    uint16_t next_key_id = current_key_.key_id + 1;
    return derive_session_key(master_secret, master_len, session_id_, next_key_id, node_id_, ttl_sec_, current_time_sec, current_key_);
}

bool SessionStore::get_active_key(SessionKey& out_key) const noexcept {
    if (!initialized_) return false;
    out_key = current_key_;
    return true;
}

bool SessionStore::is_key_valid(uint16_t key_id, const uint8_t secret_key[32], uint64_t current_time_sec) const noexcept {
    if (!initialized_ || !secret_key) return false;

    // Check active key
    if (current_key_.key_id == key_id) {
        if (!verify_session_key_freshness(current_key_, current_time_sec)) return false;
        return std::memcmp(current_key_.secret_key, secret_key, 32) == 0;
    }

    // Check previous key during rotation grace window (if key_id matches previous_key)
    if (has_previous_ && previous_key_.key_id == key_id) {
        if (!verify_session_key_freshness(previous_key_, current_time_sec)) return false;
        return std::memcmp(previous_key_.secret_key, secret_key, 32) == 0;
    }

    // Old key past rotation boundary -> rejected!
    return false;
}

} // namespace linep::sl
