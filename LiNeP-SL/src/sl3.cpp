#include <linep_sl/sl3.hpp>
#include <linep_sl/sl1.hpp>
#include "sha256.hpp"
#include <cstring>
#include <vector>

namespace linep::sl {

void compute_cap_token_mac(
    const uint8_t* secret_key,
    size_t         key_len,
    uint32_t       session_id,
    uint64_t       granted_caps,
    uint64_t       expires_at_sec,
    uint8_t        out_mac[16]) noexcept
{
    uint8_t buf[sizeof(session_id) + sizeof(granted_caps) + sizeof(expires_at_sec)];
    size_t off = 0;

    std::memcpy(buf + off, &session_id, sizeof(session_id));
    off += sizeof(session_id);

    std::memcpy(buf + off, &granted_caps, sizeof(granted_caps));
    off += sizeof(granted_caps);

    std::memcpy(buf + off, &expires_at_sec, sizeof(expires_at_sec));
    off += sizeof(expires_at_sec);

    uint8_t full_mac[32];
    crypto::hmac_sha256(secret_key, key_len, buf, sizeof(buf), full_mac);
    std::memcpy(out_mac, full_mac, 16);
}

bool verify_cap_token(
    const uint8_t*                 secret_key,
    size_t                         key_len,
    const linep::sl::HeaderCapExt& cap_ext,
    uint32_t                       expected_session_id,
    uint64_t                       current_time_sec,
    CapFlags                       required_capability) noexcept
{
    // 1. Session ID check
    if (cap_ext.session_id != expected_session_id) {
        return false;
    }

    // 2. TTL Expiration check
    if (current_time_sec > cap_ext.expires_at_sec) {
        return false; // Expired capability token -> fail closed
    }

    // 3. Required Capability check
    if (!has_capability(cap_ext.granted_caps, required_capability)) {
        return false; // Missing required capability -> fail closed
    }

    // 4. HMAC signature check over token payload
    uint8_t expected_mac[16];
    compute_cap_token_mac(secret_key, key_len, cap_ext.session_id, cap_ext.granted_caps, cap_ext.expires_at_sec, expected_mac);
    return constant_time_memcmp16(expected_mac, cap_ext.cap_mac);
}

} // namespace linep::sl
