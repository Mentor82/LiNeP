#pragma once
#include <linep/export.h>
#include <linep/messages.hpp>
#include <linep/types.hpp>
#include <cstddef>
#include <cstdint>

namespace linep::core {

// Constant-time 16-byte memory comparison (prevents timing attacks)
LINEP_API bool constant_time_memcmp16(const uint8_t* a, const uint8_t* b) noexcept;

// Compute SL1 16-byte HMAC MAC tag over (header_base || session_id || key_id || auth_seq || payload)
LINEP_API void compute_sl1_mac(
    const uint8_t*       secret_key,
    size_t               key_len,
    const linep::Header& header,
    uint32_t             session_id,
    uint16_t             key_id,
    uint32_t             auth_seq,
    const uint8_t*       payload,
    uint32_t             payload_len,
    uint8_t              out_mac[16]) noexcept;

// Verify SL1 MAC tag
LINEP_API bool verify_sl1_mac(
    const uint8_t*             secret_key,
    size_t                     key_len,
    const linep::Header&       header,
    const linep::HeaderAuthExt& auth_ext,
    const uint8_t*             payload,
    uint32_t                   payload_len) noexcept;

} // namespace linep::core
