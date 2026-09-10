#include <linep_sl/v0_2/authenticator.hpp>
#include "../sha256.hpp"

namespace linep::sl::v0_2 {

bool constant_time_equals(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) noexcept {
    if (!a || !b) {
        return false;
    }
    volatile std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool compute_sha256_digest(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out_digest) noexcept {
    if (!data && size > 0) {
        out_digest.clear();
        return false;
    }
    out_digest.resize(32);
    linep::sl::crypto::sha256(data ? data : reinterpret_cast<const std::uint8_t*>(""), size, out_digest.data());
    return true;
}

hmac_sha256_authenticator::hmac_sha256_authenticator(crypto_suite suite) noexcept
    : suite_(suite), tag_size_(16) {
    if (suite == crypto_suite::hmac_sha256_128) {
        tag_size_ = 16;
    } else {
        tag_size_ = 32;
    }
}

bool hmac_sha256_authenticator::sign(
    const std::vector<std::uint8_t>& authenticator_input,
    const std::vector<std::uint8_t>& key,
    std::vector<std::uint8_t>& out_tag) const noexcept {
    if (key.empty() || authenticator_input.empty()) {
        out_tag.clear();
        return false;
    }

    std::uint8_t full_mac[32]{};
    linep::sl::crypto::hmac_sha256(
        key.data(), key.size(),
        authenticator_input.data(), authenticator_input.size(),
        full_mac);

    out_tag.assign(full_mac, full_mac + tag_size_);
    return true;
}

bool hmac_sha256_authenticator::verify(
    const std::vector<std::uint8_t>& authenticator_input,
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& tag) const noexcept {
    if (tag.size() != tag_size_) {
        return false;
    }

    std::vector<std::uint8_t> expected_tag;
    if (!sign(authenticator_input, key, expected_tag)) {
        return false;
    }

    return constant_time_equals(tag.data(), expected_tag.data(), tag_size_);
}

std::unique_ptr<message_authenticator> create_authenticator(crypto_suite suite) noexcept {
    if (suite == crypto_suite::hmac_sha256_128) {
        return std::make_unique<hmac_sha256_authenticator>(suite);
    }
    return nullptr;
}

} // namespace linep::sl::v0_2
