#ifndef LINEP_SL_SL1_HPP
#define LINEP_SL_SL1_HPP

#include "security_types.hpp"
#include <linep/types.hpp>
#include <cstddef>
#include <cstdint>

namespace linep::sl {

void compute_sl1_mac(
    const uint8_t*       secret_key,
    size_t               key_len,
    const linep::Header& header,
    uint32_t             session_id,
    uint16_t             key_id,
    uint32_t             auth_seq,
    const uint8_t*       payload,
    uint32_t             payload_len,
    uint8_t              out_mac[16]) noexcept;

bool constant_time_memcmp16(const uint8_t a[16], const uint8_t b[16]) noexcept;

bool verify_sl1_mac(
    const uint8_t*             secret_key,
    size_t                     key_len,
    const linep::Header&       header,
    const linep::sl::HeaderAuthExt& auth_ext,
    const uint8_t*             payload,
    uint32_t                   payload_len) noexcept;

} // namespace linep::sl

#endif // LINEP_SL_SL1_HPP
