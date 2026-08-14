#pragma once
#include <cstddef>
#include <cstdint>

namespace linep::core {

struct SHA256_CTX {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
};

void sha256_init(SHA256_CTX* ctx) noexcept;
void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) noexcept;
void sha256_final(SHA256_CTX* ctx, uint8_t hash[32]) noexcept;

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out_mac[32]) noexcept;

} // namespace linep::core
