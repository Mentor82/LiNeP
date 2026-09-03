#include <linep_sl/v0_2/session.hpp>

#include <cassert>

using namespace linep::sl::v0_2;

namespace {

negotiation_offer offer(std::uint64_t node, std::uint8_t nonce_byte) {
    negotiation_offer value;
    value.minimum_level = security_level::sl2_identity;
    value.maximum_level = security_level::sl3_authorized;
    value.supported_suites = {
        crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305,
    };
    value.endpoint = {node, node + 1000, 1};
    value.control_epoch = node + 10;
    value.lease_token = node + 20;
    value.nonce.fill(nonce_byte);
    return value;
}

authenticated_peer peer(
    const negotiation_offer& source,
    std::uint32_t domain,
    std::uint64_t subject) {
    authenticated_peer value;
    value.endpoint = source.endpoint;
    value.trust_domain_id = domain;
    value.subject_id = subject;
    value.credential_revision = 1;
    value.authenticated_at_us = 900;
    value.credential_expires_at_us = 5000;
    return value;
}

} // namespace

int main() {
    const auto initiator_offer = offer(10, 0x11);
    const auto responder_offer = offer(20, 0x22);
    negotiation_policy policy{
        security_level::sl2_identity,
        {crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305},
    };
    const auto negotiated = negotiate(initiator_offer, responder_offer, policy);
    assert(negotiated.accepted());

    const auto initiator = peer(initiator_offer, 100, 1001);
    const auto responder = peer(responder_offer, 200, 2001);
    session_registry sessions;
    assert(sessions.establish(
        initiator_offer, responder_offer, policy, negotiated, initiator, responder,
        7001, 1, 1, 1000, 3000));

    session_record record;
    assert(sessions.get(7001, record));
    assert(record.is_active_at(1000));
    assert(record.initiator_control_epoch == initiator_offer.control_epoch);
    assert(record.responder_lease_token == responder_offer.lease_token);
    assert(!record.negotiation_transcript.empty());

    security_session_identity sender;
    assert(sessions.make_sender_identity(
        7001, message_direction::initiator_to_responder, 1100, sender));
    assert(sender.trust_domain_id == 100 && sender.subject_id == 1001);
    assert(sessions.make_sender_identity(
        7001, message_direction::responder_to_initiator, 1100, sender));
    assert(sender.trust_domain_id == 200 && sender.subject_id == 2001);

    assert(!sessions.rotate(7001, 1, 2, 1200, 3500));
    assert(!sessions.rotate(7001, 2, 1, 1200, 3500));
    assert(sessions.rotate(7001, 2, 2, 1200, 3500));
    assert(sessions.make_sender_identity(
        7001, message_direction::initiator_to_responder, 1300, sender));
    assert(sender.security_epoch == 2 && sender.key_id == 2);
    assert(sessions.get(7001, record));
    assert(record.established_at_us == 1000);
    assert(record.key_activated_at_us == 1200);

    assert(!sessions.establish(
        initiator_offer, responder_offer, policy, negotiated, initiator, responder,
        7001, 1, 1, 1300, 3000));

    assert(sessions.expire(3600) == 1);
    assert(!sessions.make_sender_identity(
        7001, message_direction::initiator_to_responder, 3600, sender));
    assert(sender.session_id == 0);
    assert(!sessions.rotate(7001, 3, 3, 3600, 4000));

    assert(sessions.establish(
        initiator_offer, responder_offer, policy, negotiated, initiator, responder,
        7002, 1, 1, 1000, 3000));
    assert(sessions.revoke(7002));
    assert(!sessions.revoke(7002));
    assert(!sessions.make_sender_identity(
        7002, message_direction::initiator_to_responder, 1100, sender));
    assert(sessions.close(7002));
    assert(!sessions.close(7002));

    auto mismatched_peer = initiator;
    mismatched_peer.endpoint.node_id++;
    assert(!sessions.establish(
        initiator_offer, responder_offer, policy, negotiated, mismatched_peer, responder,
        7003, 1, 1, 1000, 3000));

    auto short_credential = responder;
    short_credential.credential_expires_at_us = 2000;
    assert(!sessions.establish(
        initiator_offer, responder_offer, policy, negotiated, initiator, short_credential,
        7004, 1, 1, 1000, 3000));

    auto forged = negotiated;
    forged.required_level = security_level::sl1_authenticated;
    assert(!sessions.establish(
        initiator_offer, responder_offer, policy, forged, initiator, responder,
        7005, 1, 1, 1000, 3000));

    return 0;
}
