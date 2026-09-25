#include <linep_sl/v0_2/authorization.hpp>
#include <linep_sl/v0_2/governance.hpp>
#include <linep_sl/v0_2/negotiation.hpp>
#include <linep_sl/v0_2/plane_authenticator.hpp>
#include <linep_sl/v0_2/replay_window.hpp>
#include <linep_sl/v0_2/security_contract.hpp>
#include <linep_sl/v0_2/session.hpp>

#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

session_record create_conformance_session(
    std::uint64_t session_id = 9001,
    security_level level = security_level::sl3_authorized,
    crypto_suite suite = crypto_suite::hmac_sha256_128) {
    session_record s;
    s.session_id = session_id;
    s.security_epoch = 1;
    s.key_id = 101;
    s.negotiated_level = level;
    s.suite = suite;
    s.state = session_state::active;
    s.established_at_us = 1000000;
    s.key_activated_at_us = 1000000;
    s.expires_at_us = 5000000;

    s.initiator.endpoint = {10, 100, 1};
    s.initiator.trust_domain_id = 1;
    s.initiator.subject_id = 501;
    s.initiator.credential_revision = 1;
    s.initiator.authenticated_at_us = 1000000;
    s.initiator.credential_expires_at_us = 5000000;
    s.initiator.revoked = false;
    s.initiator_control_epoch = 1;
    s.initiator_lease_token = 0xAA11BB22CC33DD44ULL;

    s.responder.endpoint = {20, 200, 2};
    s.responder.trust_domain_id = 1;
    s.responder.subject_id = 502;
    s.responder.credential_revision = 1;
    s.responder.authenticated_at_us = 1000000;
    s.responder.credential_expires_at_us = 5000000;
    s.responder.revoked = false;
    s.responder_control_epoch = 1;
    s.responder_lease_token = 0x5566778899AABBCCULL;

    return s;
}

std::vector<std::uint8_t> make_conformance_key() {
    return {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
}

} // namespace

void test_cross_layer_full_pipeline() {
    std::cout << "[Test 1] Cross-Layer Full Pipeline (Binding + Auth + Gov + Stream)..." << std::endl;

    auto session = create_conformance_session();
    auto key = make_conformance_key();
    std::uint64_t now_us = 2000000;

    // 1. Core TCP SESSION_BIND validation (Issue #15 & #16)
    linep::v0_2::session_bind_envelope bind_env;
    bind_env.identity = session.initiator.endpoint;
    bind_env.control_epoch = session.initiator_control_epoch;
    bind_env.lease_token = session.initiator_lease_token;
    assert(bind_env.is_valid());

    assert(validate_transport_session_binding(
        session, message_direction::initiator_to_responder,
        bind_env, now_us) == verification_status::ok);

    // 2. Policy Authorizer setup (Phase D / SL3)
    policy_authorizer authorizer;
    subject_policy sub_pol;
    sub_pol.subject_id = session.initiator.subject_id;
    sub_pol.trust_domain_id = session.initiator.trust_domain_id;
    sub_pol.capabilities = capability_flags::chat | capability_flags::stream_output;
    sub_pol.allowed_resources.push_back({resource_kind::model, "linep-conformance-model-v02"});
    authorizer.add_subject_policy(sub_pol);

    linep::v0_2::runtime_capabilities_descriptor rt_caps;
    rt_caps.supported_models = {"linep-conformance-model-v02"};
    rt_caps.supported_profiles = {linep::v0_2::runtime_profile::chat};
    rt_caps.supports_streaming = true;

    // 3. Authorization check
    authorization_request auth_req;
    auth_req.trust_domain_id = session.initiator.trust_domain_id;
    auth_req.subject_id = session.initiator.subject_id;
    auth_req.action = security_action::execute;
    auth_req.profile = linep::v0_2::runtime_profile::chat;
    auth_req.resource = {resource_kind::model, "linep-conformance-model-v02"};
    auth_req.streaming_requested = true;

    authorization_decision auth_dec;
    assert(authorizer.validate_against_advertised_capabilities(auth_req, rt_caps, auth_dec));
    assert(auth_dec.is_allowed());

    // 4. Governance Engine & Audit Sink setup (Phase E / SL4)
    governance_engine gov(1, "linep-gov-v02", 1, 1);
    auto audit_sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(audit_sink);

    // 5. Data Plane Request protection (Phase C / SL2-SL3)
    linep::v0_2::request_envelope req_env;
    req_env.stream = {101, 1001, 0};
    req_env.profile = linep::v0_2::runtime_profile::chat;
    req_env.model_id = "linep-conformance-model-v02";
    req_env.payload = "Hello secure LiNeP";
    req_env.stream_requested = true;

    std::vector<std::uint8_t> req_raw;
    linep::v0_2::encode_request(req_env, req_raw);

    std::vector<std::uint8_t> req_tag;
    assert(sign_request(
        session, key, message_direction::initiator_to_responder,
        security_level::sl3_authorized, security_action::execute,
        req_env, req_raw, req_tag));

    assert(verify_request(
        session, key, message_direction::initiator_to_responder,
        security_level::sl3_authorized, security_action::execute,
        req_env, req_raw, req_tag, now_us) == verification_status::ok);

    // Emit request audit
    std::vector<std::uint8_t> req_digest;
    compute_sha256_digest(req_raw.data(), req_raw.size(), req_digest);
    gov.emit_audit_event(
        audit_event_type_v02::authorization_allowed,
        session.session_id, session.initiator.subject_id,
        session.responder.trust_domain_id, security_action::execute,
        req_env.model_id, authorization_outcome::allow, "ok",
        req_digest, now_us);

    // 6. Streaming event verification with monotonic tracker
    monotonic_stream_tracker stream_tracker;
    for (std::uint64_t seq = 1; seq <= 5; ++seq) {
        linep::v0_2::event_envelope evt;
        evt.stream = req_env.stream;
        evt.event_seq = seq;
        evt.event_type = (seq == 5) ? linep::v0_2::runtime_event_type::completed : linep::v0_2::runtime_event_type::content_delta;
        evt.payload = "chunk";
        if (seq == 5) evt.outcome = linep::v0_2::terminal_outcome::completed;

        std::vector<std::uint8_t> evt_raw;
        linep::v0_2::encode_event(evt, evt_raw);

        std::vector<std::uint8_t> evt_tag;
        assert(sign_event(
            session, key, message_direction::responder_to_initiator,
            security_level::sl3_authorized, security_action::emit_output,
            evt, evt_raw, 0, false, evt_tag));

        assert(verify_event(
            session, key, message_direction::responder_to_initiator,
            security_level::sl3_authorized, security_action::emit_output,
            evt, evt_raw, 0, false, evt_tag,
            stream_tracker, now_us) == verification_status::ok);
    }

    assert(audit_sink->size() == 1);
    std::cout << "  -> Cross-Layer Full Pipeline PASSED" << std::endl;
}

void test_golden_vectors_and_canonical_invariants() {
    std::cout << "[Test 2] Canonical Golden Vectors & Invariant Hardening..." << std::endl;

    control_plane_binding cp_bind;
    cp_bind.common.session = {1001, 1, 42, 10, 501};
    cp_bind.common.direction = message_direction::initiator_to_responder;
    cp_bind.common.negotiated_level = security_level::sl2_identity;
    cp_bind.common.required_level = security_level::sl2_identity;
    cp_bind.common.action = security_action::report_liveness;
    cp_bind.common.digest = digest_algorithm::sha256;
    cp_bind.common.content_digest.assign(32, 0xEE);

    cp_bind.endpoint = {1, 101, 1001};
    cp_bind.control_epoch = 1;
    cp_bind.control_seq = 42;
    cp_bind.lease_token = 0xC0FFEE;
    cp_bind.lease_bound = true;

    assert(cp_bind.is_valid());

    std::vector<std::uint8_t> canonical_bytes;
    assert(encode_authenticator_input(cp_bind, canonical_bytes));
    // Verify domain separator 'LNS2'
    assert(canonical_bytes.size() > 4);
    assert(canonical_bytes[0] == 'L' && canonical_bytes[1] == 'N' &&
           canonical_bytes[2] == 'S' && canonical_bytes[3] == '2');

    // Tampered canonical input fails verification
    auto key = make_conformance_key();
    auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
    assert(auth != nullptr);

    std::vector<std::uint8_t> sig;
    assert(auth->sign(canonical_bytes, key, sig));
    assert(auth->verify(canonical_bytes, key, sig));

    // 1-bit corruption in canonical input fails verification
    std::vector<std::uint8_t> corrupted_bytes = canonical_bytes;
    corrupted_bytes[10] ^= 0x01;
    assert(!auth->verify(corrupted_bytes, key, sig));

    std::cout << "  -> Canonical Golden Vectors PASSED" << std::endl;
}

void test_active_stream_revocation_fail_closed() {
    std::cout << "[Test 3] Active-Stream Revocation & Fail-Closed Invariants..." << std::endl;

    auto session = create_conformance_session();
    auto key = make_conformance_key();
    std::uint64_t now_us = 2000000;

    monotonic_stream_tracker tracker;

    linep::v0_2::event_envelope evt1;
    evt1.stream = {10, 20, 0};
    evt1.event_seq = 1;
    evt1.payload = "delta 1";

    std::vector<std::uint8_t> raw1;
    linep::v0_2::encode_event(evt1, raw1);
    std::vector<std::uint8_t> tag1;
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, raw1, 0, false, tag1));

    // Seq 1 succeeds
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, raw1, 0, false, tag1, tracker, now_us) == verification_status::ok);

    // Now revoke session mid-stream!
    session.state = session_state::revoked;

    linep::v0_2::event_envelope evt2;
    evt2.stream = {10, 20, 0};
    evt2.event_seq = 2;
    evt2.payload = "delta 2";

    std::vector<std::uint8_t> raw2;
    linep::v0_2::encode_event(evt2, raw2);
    std::vector<std::uint8_t> tag2;
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2));

    // Seq 2 MUST FAIL CLOSED with session_inactive
    auto status = verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2, tracker, now_us);
    assert(status == verification_status::session_inactive);

    std::cout << "  -> Active-Stream Revocation Fail-Closed PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Phase F Conformance & Hardening Test Suite ===" << std::endl;
    test_cross_layer_full_pipeline();
    test_golden_vectors_and_canonical_invariants();
    test_active_stream_revocation_fail_closed();
    std::cout << "ALL PHASE F CONFORMANCE & HARDENING TESTS PASSED 100%!" << std::endl;
    return 0;
}
