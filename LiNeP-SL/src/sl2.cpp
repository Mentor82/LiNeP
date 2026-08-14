#include <linep_sl/sl2.hpp>
#include "sha256.hpp"
#include <cstring>

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

    // Ensure pubkey is not all zeroes
    uint8_t mask = 0;
    for (size_t i = 0; i < 32; ++i) {
        mask |= peer.pubkey[i];
    }
    return mask != 0;
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

    // Derivation transcript: "SL2_KDF" || session_id (4B LE) || key_id (2B LE) || node_id (2B LE)
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
    if (current_time_sec < key.established_at_sec) return false; // Clock skew anomaly
    if (current_time_sec > key.expires_at_sec) return false;     // Key expired -> fail closed

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
    const uint16_t dummy_node_id = 1; // Default rotation binding

    return derive_session_key(master_secret, master_len, session_id, next_key_id, dummy_node_id, new_ttl_sec, current_time_sec, key);
}

} // namespace linep::sl
