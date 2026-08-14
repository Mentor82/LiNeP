#ifndef LINEP_SL_SL3_HPP
#define LINEP_SL_SL3_HPP

#include "security_types.hpp"
#include <cstddef>
#include <cstdint>

namespace linep::sl {

void compute_cap_token_mac(
    const uint8_t* secret_key,
    size_t         key_len,
    uint32_t       session_id,
    uint64_t       granted_caps,
    uint64_t       expires_at_sec,
    uint8_t        out_mac[16]) noexcept;

bool verify_cap_token(
    const uint8_t*          secret_key,
    size_t                  key_len,
    const linep::sl::HeaderCapExt& cap_ext,
    uint32_t                expected_session_id,
    uint64_t                current_time_sec,
    CapFlags                required_capability) noexcept;

} // namespace linep::sl

#endif // LINEP_SL_SL3_HPP
