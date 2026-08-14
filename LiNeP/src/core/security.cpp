#include "security.hpp"
#include "sha256.hpp"
#include <cstring>
#include <iostream>
#include <vector>

namespace linep::core {

bool constant_time_memcmp16(const uint8_t* a, const uint8_t* b) noexcept {
    if (!a || !b) return false;
    uint8_t result = 0;
    for (size_t i = 0; i < 16; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return (result == 0);
}

void compute_sl1_mac(
    const uint8_t*       secret_key,
    size_t               key_len,
    const linep::Header& header,
    uint32_t             session_id,
    uint16_t             key_id,
    uint32_t             auth_seq,
    const uint8_t*       payload,
    uint32_t             payload_len,
    uint8_t              out_mac[16]) noexcept
{
    if (!secret_key || key_len == 0 || !out_mac) {
        std::memset(out_mac, 0, 16);
        return;
    }

    // Buffer layout to sign:
    // [24 bytes Header] [4 bytes session_id] [2 bytes key_id] [4 bytes auth_seq] [payload...]
    const size_t prefix_len = sizeof(linep::Header) + sizeof(session_id) + sizeof(key_id) + sizeof(auth_seq);
    std::vector<uint8_t> buf(prefix_len + payload_len);

    std::memcpy(buf.data(), &header, sizeof(linep::Header));
    size_t off = sizeof(linep::Header);

    std::memcpy(buf.data() + off, &session_id, sizeof(session_id));
    off += sizeof(session_id);

    std::memcpy(buf.data() + off, &key_id, sizeof(key_id));
    off += sizeof(key_id);

    std::memcpy(buf.data() + off, &auth_seq, sizeof(auth_seq));
    off += sizeof(auth_seq);

    if (payload && payload_len > 0) {
        std::memcpy(buf.data() + off, payload, payload_len);
    }

    uint8_t full_mac[32];
    hmac_sha256(secret_key, key_len, buf.data(), buf.size(), full_mac);
    std::memcpy(out_mac, full_mac, 16); // Truncate to 16 bytes for HeaderAuthExt
}

bool verify_sl1_mac(
    const uint8_t*             secret_key,
    size_t                     key_len,
    const linep::Header&       header,
    const linep::HeaderAuthExt& auth_ext,
    const uint8_t*             payload,
    uint32_t                   payload_len) noexcept
{
    uint8_t expected_mac[16];
    compute_sl1_mac(secret_key, key_len, header, auth_ext.session_id, auth_ext.key_id, auth_ext.auth_seq, payload, payload_len, expected_mac);
    return constant_time_memcmp16(expected_mac, auth_ext.mac);
}

} // namespace linep::core
