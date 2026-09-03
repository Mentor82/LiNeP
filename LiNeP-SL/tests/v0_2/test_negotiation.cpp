#include <linep_sl/v0_2/negotiation.hpp>

#include <cassert>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

negotiation_offer offer(std::uint64_t node, std::uint8_t nonce_byte) {
    negotiation_offer value;
    value.minimum_level = security_level::sl1_authenticated;
    value.maximum_level = security_level::sl4_governed;
    value.supported_suites = {
        crypto_suite::hmac_sha256_128,
        crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305,
    };
    value.endpoint = {node, node + 1000, 1};
    value.control_epoch = 7;
    value.lease_token = node + 9000;
    value.nonce.fill(nonce_byte);
    return value;
}

} // namespace

int main() {
    auto initiator = offer(10, 0x11);
    auto responder = offer(20, 0x22);
    responder.maximum_level = security_level::sl3_authorized;

    negotiation_policy policy;
    policy.required_level = security_level::sl2_identity;
    policy.preferred_suites = {
        crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305,
        crypto_suite::hmac_sha256_128,
    };

    const auto accepted = negotiate(initiator, responder, policy);
    assert(accepted.accepted());
    assert(accepted.required_level == security_level::sl2_identity);
    assert(accepted.negotiated_level == security_level::sl3_authorized);
    assert(accepted.suite ==
           crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305);

    std::vector<std::uint8_t> transcript;
    assert(encode_negotiation_transcript(initiator, responder, accepted, transcript));
    assert(transcript.size() > 7);
    assert(transcript[0] == 'L' && transcript[1] == 'N' && transcript[2] == 'S' &&
           transcript[3] == '2' && transcript[4] == 'N');
    const auto canonical = transcript;

    responder.lease_token++;
    assert(encode_negotiation_transcript(initiator, responder, accepted, transcript));
    assert(transcript != canonical);
    responder.lease_token--;

    policy.required_level = security_level::sl4_governed;
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::downgrade_rejected);

    policy.required_level = security_level::sl2_identity;
    initiator.maximum_level = security_level::sl2_identity;
    responder.minimum_level = security_level::sl3_authorized;
    responder.maximum_level = security_level::sl4_governed;
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::no_common_level);
    initiator = offer(10, 0x11);
    responder = offer(20, 0x22);

    responder.supported_suites = {crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm};
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::no_common_suite);
    responder = offer(20, 0x22);

    responder.supported_suites = {crypto_suite::hmac_sha256_128};
    initiator.supported_suites = {crypto_suite::hmac_sha256_128};
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::no_common_suite);
    initiator = offer(10, 0x11);
    responder = offer(20, 0x22);

    responder.version_minor = 1;
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::version_mismatch);
    responder.version_minor = contract_version_minor;

    responder.nonce.fill(0);
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::invalid_offer);

    responder = offer(20, 0x22);
    responder.supported_suites = {static_cast<crypto_suite>(999)};
    assert(negotiate(initiator, responder, policy).status ==
           negotiation_status::invalid_offer);

    return 0;
}
