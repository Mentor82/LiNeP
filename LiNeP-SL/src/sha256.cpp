#include "sha256.hpp"
#include <cstring>

namespace linep::sl::crypto {

namespace {

static constexpr uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t rotr(uint32_t x, uint32_t n) noexcept {
    return (x >> n) | (x << (32u - n));
}

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
};

void sha256_init(Sha256Ctx& ctx) noexcept {
    ctx.state[0] = 0x6a09e667u;
    ctx.state[1] = 0xbb67ae85u;
    ctx.state[2] = 0x3c6ef372u;
    ctx.state[3] = 0xa54ff53au;
    ctx.state[4] = 0x510e527fu;
    ctx.state[5] = 0x9b05688cu;
    ctx.state[6] = 0x1f83d9abu;
    ctx.state[7] = 0x5be0cd19u;
    ctx.count = 0;
}

void sha256_transform(Sha256Ctx& ctx, const uint8_t data[64]) noexcept {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (size_t i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx.state[0];
    uint32_t b = ctx.state[1];
    uint32_t c = ctx.state[2];
    uint32_t d = ctx.state[3];
    uint32_t e = ctx.state[4];
    uint32_t f = ctx.state[5];
    uint32_t g = ctx.state[6];
    uint32_t h = ctx.state[7];

    for (size_t i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    ctx.state[5] += f;
    ctx.state[6] += g;
    ctx.state[7] += h;
}

void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) noexcept {
    for (size_t i = 0; i < len; ++i) {
        ctx.buffer[ctx.count % 64] = data[i];
        ctx.count++;
        if (ctx.count % 64 == 0) {
            sha256_transform(ctx, ctx.buffer);
        }
    }
}

void sha256_final(Sha256Ctx& ctx, uint8_t out[32]) noexcept {
    uint8_t bits[8];
    const uint64_t bit_count = ctx.count * 8;
    for (size_t i = 0; i < 8; ++i) {
        bits[i] = static_cast<uint8_t>(bit_count >> (56 - i * 8));
    }

    const size_t pad_len = (ctx.count % 64 < 56) ? (56 - ctx.count % 64) : (120 - ctx.count % 64);
    static const uint8_t padding[64] = { 0x80 };
    sha256_update(ctx, padding, 1);
    if (pad_len > 1) {
        static const uint8_t zeroes[64] = { 0 };
        sha256_update(ctx, zeroes, pad_len - 1);
    }
    sha256_update(ctx, bits, 8);

    for (size_t i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<uint8_t>(ctx.state[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(ctx.state[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(ctx.state[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(ctx.state[i]);
    }
}

} // namespace

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) noexcept {
    Sha256Ctx ctx;
    sha256_init(ctx);
    if (data && len > 0) {
        sha256_update(ctx, data, len);
    }
    sha256_final(ctx, out);
}

void hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out[32]) noexcept
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];

    std::memset(k_ipad, 0, sizeof(k_ipad));
    std::memset(k_opad, 0, sizeof(k_opad));

    if (key_len > 64) {
        sha256(key, key_len, tk);
        std::memcpy(k_ipad, tk, 32);
        std::memcpy(k_opad, tk, 32);
    } else if (key && key_len > 0) {
        std::memcpy(k_ipad, key, key_len);
        std::memcpy(k_opad, key, key_len);
    }

    for (size_t i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    Sha256Ctx inner;
    sha256_init(inner);
    sha256_update(inner, k_ipad, 64);
    if (data && data_len > 0) {
        sha256_update(inner, data, data_len);
    }
    uint8_t inner_hash[32];
    sha256_final(inner, inner_hash);

    Sha256Ctx outer;
    sha256_init(outer);
    sha256_update(outer, k_opad, 64);
    sha256_update(outer, inner_hash, 32);
    sha256_final(outer, out);
}

} // namespace linep::sl::crypto
