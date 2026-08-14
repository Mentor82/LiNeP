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

    // Canonical 34-byte header+ext prefix + payload
    const size_t prefix_len = 34;
    std::vector<uint8_t> buf(prefix_len + payload_len);

    // 1. Header (24 bytes Little-Endian)
    write_u16_le(buf.data() + 0, header.magic);
    buf[2] = header.version;
    buf[3] = header.msg_type;
    write_u16_le(buf.data() + 4, header.header_len);
    write_u16_le(buf.data() + 6, header.flags);
    write_u32_le(buf.data() + 8, header.payload_len);
    write_u32_le(buf.data() + 12, header.sequence);
    write_u32_le(buf.data() + 16, header.correlation_id);
    write_u16_le(buf.data() + 20, header.worker_id);
    buf[22] = header.slot_id;
    buf[23] = header.header_crc;

    // 2. Auth Extension fields (10 bytes Little-Endian)
    write_u32_le(buf.data() + 24, session_id);
    write_u16_le(buf.data() + 28, key_id);
    write_u32_le(buf.data() + 30, auth_seq);

    // 3. Payload
    if (payload && payload_len > 0) {
        std::memcpy(buf.data() + prefix_len, payload, payload_len);
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
