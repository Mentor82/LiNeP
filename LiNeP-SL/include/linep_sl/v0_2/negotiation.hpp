#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <linep/v0_2/control_plane.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

namespace linep::sl::v0_2 {

constexpr std::size_t negotiation_nonce_bytes = 32;
constexpr std::size_t max_negotiated_suites = 16;

enum class crypto_suite : std::uint16_t {
    none = 0,
    hmac_sha256_128 = 1,
    x25519_ed25519_hkdf_sha256_aes256_gcm = 2,
    x25519_ed25519_hkdf_sha256_chacha20_poly1305 = 3,
};

enum class negotiation_status : std::uint8_t {
    not_negotiated = 0,
    accepted = 1,
    invalid_offer = 2,
    invalid_policy = 3,
    version_mismatch = 4,
    no_common_level = 5,
    no_common_suite = 6,
    downgrade_rejected = 7,
};

struct negotiation_offer {
    std::uint8_t version_major{contract_version_major};
    std::uint8_t version_minor{contract_version_minor};
    security_level minimum_level{security_level::unknown};
    security_level maximum_level{security_level::unknown};
    std::vector<crypto_suite> supported_suites;
    linep::v0_2::node_endpoint_identity endpoint;
    std::uint64_t control_epoch{0};
    std::uint64_t lease_token{0};
    std::array<std::uint8_t, negotiation_nonce_bytes> nonce{};

    bool is_structurally_valid() const noexcept;
};

struct negotiation_policy {
    security_level required_level{security_level::unknown};
    std::vector<crypto_suite> preferred_suites;

    bool is_valid() const noexcept;
};

struct negotiation_result {
    negotiation_status status{negotiation_status::not_negotiated};
    security_level required_level{security_level::unknown};
    security_level negotiated_level{security_level::unknown};
    crypto_suite suite{crypto_suite::none};

    bool accepted() const noexcept {
        return status == negotiation_status::accepted;
    }
};

negotiation_result negotiate(
    const negotiation_offer& initiator,
    const negotiation_offer& responder,
    const negotiation_policy& policy) noexcept;

bool encode_negotiation_transcript(
    const negotiation_offer& initiator,
    const negotiation_offer& responder,
    const negotiation_result& result,
    std::vector<std::uint8_t>& out);

} // namespace linep::sl::v0_2
