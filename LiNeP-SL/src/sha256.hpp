#ifndef LINEP_SL_SHA256_HPP
#define LINEP_SL_SHA256_HPP

#include <cstddef>
#include <cstdint>

namespace linep::sl::crypto {

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) noexcept;

void hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[32]) noexcept;

} // namespace linep::sl::crypto

#endif // LINEP_SL_SHA256_HPP
