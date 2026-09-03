#include <linep_sl/v0_2/negotiation.hpp>

#include <algorithm>
#include <type_traits>

namespace linep::sl::v0_2 {
namespace {

template <typename T>
void append_le(std::vector<std::uint8_t>& out, T value) {
    static_assert(std::is_integral_v<T>, "transcript fields must be integral");
    using unsigned_t = std::make_unsigned_t<T>;
    const auto unsigned_value = static_cast<unsigned_t>(value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>(unsigned_value >> (i * 8)));
    }
}

template <typename T>
bool contains_duplicate(const std::vector<T>& values) noexcept {
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (std::find(values.begin() + static_cast<std::ptrdiff_t>(i + 1),
                      values.end(), values[i]) != values.end()) {
            return true;
        }
    }
    return false;
}

bool contains_suite(const std::vector<crypto_suite>& suites, crypto_suite suite) noexcept {
    return std::find(suites.begin(), suites.end(), suite) != suites.end();
}

bool known_suite(crypto_suite suite) noexcept {
    return suite == crypto_suite::hmac_sha256_128 ||
           suite == crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm ||
           suite == crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
}

bool known_level(security_level level) noexcept {
    return level >= security_level::sl0_baseline &&
           level <= security_level::sl4_governed;
}

bool suite_supports_level(crypto_suite suite, security_level level) noexcept {
    if (suite == crypto_suite::hmac_sha256_128) {
        return level == security_level::sl1_authenticated;
    }
    return (suite == crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm ||
            suite == crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305) &&
           level >= security_level::sl2_identity &&
           level <= security_level::sl4_governed;
}

bool nonce_is_nonzero(
    const std::array<std::uint8_t, negotiation_nonce_bytes>& nonce) noexcept {
    return std::any_of(nonce.begin(), nonce.end(), [](std::uint8_t byte) {
        return byte != 0;
    });
}

void append_offer(
    std::vector<std::uint8_t>& out,
    std::uint8_t role,
    const negotiation_offer& offer) {
    append_le(out, role);
    append_le(out, offer.version_major);
    append_le(out, offer.version_minor);
    append_le(out, static_cast<std::uint8_t>(offer.minimum_level));
    append_le(out, static_cast<std::uint8_t>(offer.maximum_level));
    append_le(out, offer.endpoint.node_id);
    append_le(out, offer.endpoint.runtime_id);
    append_le(out, offer.endpoint.endpoint_id);
    append_le(out, offer.control_epoch);
    append_le(out, offer.lease_token);
    append_le(out, static_cast<std::uint8_t>(offer.supported_suites.size()));
    for (const auto suite : offer.supported_suites) {
        append_le(out, static_cast<std::uint16_t>(suite));
    }
    out.insert(out.end(), offer.nonce.begin(), offer.nonce.end());
}

} // namespace

bool negotiation_offer::is_structurally_valid() const noexcept {
    const auto minimum = static_cast<std::uint8_t>(minimum_level);
    const auto maximum = static_cast<std::uint8_t>(maximum_level);
    if (!known_level(minimum_level) || !known_level(maximum_level) || minimum > maximum ||
        supported_suites.empty() || supported_suites.size() > max_negotiated_suites ||
        contains_duplicate(supported_suites) ||
        !std::all_of(supported_suites.begin(), supported_suites.end(), known_suite)) {
        return false;
    }
    return endpoint.node_id != 0 && endpoint.runtime_id != 0 &&
           endpoint.endpoint_id != 0 && control_epoch != 0 && lease_token != 0 &&
           nonce_is_nonzero(nonce);
}

bool negotiation_policy::is_valid() const noexcept {
    return known_level(required_level) && !preferred_suites.empty() &&
           preferred_suites.size() <= max_negotiated_suites &&
           !contains_duplicate(preferred_suites) &&
           std::all_of(preferred_suites.begin(), preferred_suites.end(), known_suite);
}

negotiation_result negotiate(
    const negotiation_offer& initiator,
    const negotiation_offer& responder,
    const negotiation_policy& policy) noexcept {
    negotiation_result result;
    if (!initiator.is_structurally_valid() || !responder.is_structurally_valid()) {
        result.status = negotiation_status::invalid_offer;
        return result;
    }
    if (!policy.is_valid()) {
        result.status = negotiation_status::invalid_policy;
        return result;
    }
    if (initiator.version_major != contract_version_major ||
        initiator.version_minor != contract_version_minor ||
        responder.version_major != contract_version_major ||
        responder.version_minor != contract_version_minor) {
        result.status = negotiation_status::version_mismatch;
        return result;
    }

    const auto common_maximum = std::min(
        static_cast<std::uint8_t>(initiator.maximum_level),
        static_cast<std::uint8_t>(responder.maximum_level));
    const auto peer_minimum = std::max(
        static_cast<std::uint8_t>(initiator.minimum_level),
        static_cast<std::uint8_t>(responder.minimum_level));
    if (common_maximum < peer_minimum) {
        result.status = negotiation_status::no_common_level;
        return result;
    }
    if (common_maximum < static_cast<std::uint8_t>(policy.required_level)) {
        result.status = negotiation_status::downgrade_rejected;
        return result;
    }

    const auto required = std::max(
        peer_minimum, static_cast<std::uint8_t>(policy.required_level));

    for (const auto suite : policy.preferred_suites) {
        if (contains_suite(initiator.supported_suites, suite) &&
            contains_suite(responder.supported_suites, suite) &&
            suite_supports_level(suite, static_cast<security_level>(common_maximum))) {
            result.status = negotiation_status::accepted;
            result.required_level = static_cast<security_level>(required);
            result.negotiated_level = static_cast<security_level>(common_maximum);
            result.suite = suite;
            return result;
        }
    }

    result.status = negotiation_status::no_common_suite;
    return result;
}

bool encode_negotiation_transcript(
    const negotiation_offer& initiator,
    const negotiation_offer& responder,
    const negotiation_result& result,
    std::vector<std::uint8_t>& out) {
    if (!initiator.is_structurally_valid() || !responder.is_structurally_valid() ||
        initiator.version_major != contract_version_major ||
        initiator.version_minor != contract_version_minor ||
        responder.version_major != contract_version_major ||
        responder.version_minor != contract_version_minor || !result.accepted() ||
        !known_level(result.required_level) || !known_level(result.negotiated_level) ||
        static_cast<std::uint8_t>(result.negotiated_level) <
            static_cast<std::uint8_t>(result.required_level) ||
        static_cast<std::uint8_t>(result.negotiated_level) !=
            std::min(static_cast<std::uint8_t>(initiator.maximum_level),
                     static_cast<std::uint8_t>(responder.maximum_level)) ||
        static_cast<std::uint8_t>(result.required_level) <
            std::max(static_cast<std::uint8_t>(initiator.minimum_level),
                     static_cast<std::uint8_t>(responder.minimum_level)) ||
        !known_suite(result.suite) ||
        !suite_supports_level(result.suite, result.negotiated_level) ||
        !contains_suite(initiator.supported_suites, result.suite) ||
        !contains_suite(responder.supported_suites, result.suite)) {
        out.clear();
        return false;
    }

    out.clear();
    out.insert(out.end(), {'L', 'N', 'S', '2', 'N', 'E', 'G'});
    append_offer(out, 1, initiator);
    append_offer(out, 2, responder);
    append_le(out, static_cast<std::uint8_t>(result.status));
    append_le(out, static_cast<std::uint8_t>(result.required_level));
    append_le(out, static_cast<std::uint8_t>(result.negotiated_level));
    append_le(out, static_cast<std::uint16_t>(result.suite));
    return true;
}

} // namespace linep::sl::v0_2
