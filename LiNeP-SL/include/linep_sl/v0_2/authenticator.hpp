#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <linep_sl/v0_2/negotiation.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

namespace linep::sl::v0_2 {

// Constant-time memory comparison to protect against timing side-channel attacks
bool constant_time_equals(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) noexcept;

// Content digest calculation helpers
bool compute_sha256_digest(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out_digest) noexcept;

// Provider-neutral message authenticator interface for LNS2 canonical signatures
class message_authenticator {
public:
    virtual ~message_authenticator() = default;

    virtual crypto_suite suite() const noexcept = 0;
    virtual std::size_t tag_size() const noexcept = 0;

    virtual bool sign(
        const std::vector<std::uint8_t>& authenticator_input,
        const std::vector<std::uint8_t>& key,
        std::vector<std::uint8_t>& out_tag) const noexcept = 0;

    virtual bool verify(
        const std::vector<std::uint8_t>& authenticator_input,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& tag) const noexcept = 0;
};

// Built-in reference HMAC-SHA256 authenticator supporting truncated (128-bit) and full (256-bit) tags
class hmac_sha256_authenticator : public message_authenticator {
public:
    explicit hmac_sha256_authenticator(crypto_suite suite = crypto_suite::hmac_sha256_128) noexcept;

    crypto_suite suite() const noexcept override { return suite_; }
    std::size_t tag_size() const noexcept override { return tag_size_; }

    bool sign(
        const std::vector<std::uint8_t>& authenticator_input,
        const std::vector<std::uint8_t>& key,
        std::vector<std::uint8_t>& out_tag) const noexcept override;

    bool verify(
        const std::vector<std::uint8_t>& authenticator_input,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& tag) const noexcept override;

private:
    crypto_suite suite_;
    std::size_t tag_size_;
};

// Factory to construct appropriate authenticator for a negotiated suite
std::unique_ptr<message_authenticator> create_authenticator(crypto_suite suite) noexcept;

} // namespace linep::sl::v0_2
