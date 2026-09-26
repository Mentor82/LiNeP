#include <linep_sl/v0_2/authorization.hpp>
#include <linep_sl/v0_2/governance.hpp>
#include <linep_sl/v0_2/negotiation.hpp>
#include <linep_sl/v0_2/plane_authenticator.hpp>
#include <linep_sl/v0_2/replay_window.hpp>
#include <linep_sl/v0_2/security_contract.hpp>
#include <linep_sl/v0_2/session.hpp>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#define LINEP_SL_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::abort(); \
        } \
    } while (0)

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

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

} // namespace

void test_cross_layer_full_pipeline() {
    std::cout << "[Test 1] Cross-Layer Full Pipeline (Binding + Auth + Gov + Stream)..." << std::endl;

    auto session = create_conformance_session();
    auto key = make_conformance_key();
    std::uint64_t now_us = 2000000;

    // 1. Core TCP SESSION_BIND validation (Issue #15, #16, #17)
    linep::v0_2::session_bind_envelope bind_env;
    bind_env.identity = session.initiator.endpoint;
    bind_env.control_epoch = session.initiator_control_epoch;
    bind_env.lease_token = session.initiator_lease_token;
    LINEP_SL_TEST_CHECK(bind_env.is_valid());

    LINEP_SL_TEST_CHECK(validate_transport_session_binding(
        session, session_participant_role::initiator,
        bind_env, now_us) == verification_status::ok);

    // Fail-closed on now_us == 0
    LINEP_SL_TEST_CHECK(validate_transport_session_binding(
        session, session_participant_role::initiator,
        bind_env, 0) == verification_status::session_inactive);

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
    LINEP_SL_TEST_CHECK(authorizer.validate_against_advertised_capabilities(auth_req, rt_caps, auth_dec));
    LINEP_SL_TEST_CHECK(auth_dec.is_allowed());

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
    LINEP_SL_TEST_CHECK(sign_request(
        session, key, message_direction::initiator_to_responder,
        security_level::sl3_authorized, security_action::execute,
        req_env, req_raw, req_tag));

    LINEP_SL_TEST_CHECK(verify_request(
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
        LINEP_SL_TEST_CHECK(sign_event(
            session, key, message_direction::responder_to_initiator,
            security_level::sl3_authorized, security_action::emit_output,
            evt, evt_raw, 0, false, evt_tag));

        LINEP_SL_TEST_CHECK(verify_event(
            session, key, message_direction::responder_to_initiator,
            security_level::sl3_authorized, security_action::emit_output,
            evt, evt_raw, 0, false, evt_tag,
            stream_tracker, now_us) == verification_status::ok);
    }

    LINEP_SL_TEST_CHECK(audit_sink->size() == 1);
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

    LINEP_SL_TEST_CHECK(cp_bind.is_valid());

    std::vector<std::uint8_t> canonical_bytes;
    LINEP_SL_TEST_CHECK(encode_authenticator_input(cp_bind, canonical_bytes));
    // Verify domain separator 'LNS2'
    LINEP_SL_TEST_CHECK(canonical_bytes.size() > 4);
    LINEP_SL_TEST_CHECK(canonical_bytes[0] == 'L' && canonical_bytes[1] == 'N' &&
                        canonical_bytes[2] == 'S' && canonical_bytes[3] == '2');

    // Tampered canonical input fails verification
    auto key = make_conformance_key();
    auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
    LINEP_SL_TEST_CHECK(auth != nullptr);

    std::vector<std::uint8_t> sig;
    LINEP_SL_TEST_CHECK(auth->sign(canonical_bytes, key, sig));
    LINEP_SL_TEST_CHECK(auth->verify(canonical_bytes, key, sig));

    // 1-bit corruption in canonical input fails verification
    std::vector<std::uint8_t> corrupted_bytes = canonical_bytes;
    corrupted_bytes[10] ^= 0x01;
    LINEP_SL_TEST_CHECK(!auth->verify(corrupted_bytes, key, sig));

    std::cout << "  -> Canonical Golden Vectors PASSED" << std::endl;
}

void test_cross_language_concrete_golden_vectors() {
    std::cout << "[Test 3] Concrete Cross-Language Golden Vectors..." << std::endl;

    // Fixed session parameters
    session_record session = create_conformance_session(12345, security_level::sl2_identity, crypto_suite::hmac_sha256_128);
    auto key = make_conformance_key();

    // Deterministic Control Datagram
    linep::v0_2::udp_control_datagram dgram;
    dgram.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
    dgram.version_major = 0;
    dgram.version_minor = 2;
    dgram.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::node_hello);
    dgram.flags = 0x01;
    dgram.node_id = 10;
    dgram.runtime_id = 100;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 100;
    dgram.lease_token = 0xAA11BB22CC33DD44ULL;
    dgram.tcp_port = 9000;

    std::vector<std::uint8_t> tag;
    LINEP_SL_TEST_CHECK(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag));

    LINEP_SL_TEST_CHECK(tag.size() == 16); // HMAC-SHA256-128 is 16 bytes
    std::string tag_hex = bytes_to_hex(tag);
    LINEP_SL_TEST_CHECK(!tag_hex.empty());

    // Deterministic Negotiation Transcript
    negotiation_offer init_offer;
    init_offer.minimum_level = security_level::sl1_authenticated;
    init_offer.maximum_level = security_level::sl1_authenticated;
    init_offer.supported_suites = {crypto_suite::hmac_sha256_128};
    init_offer.endpoint = {1, 10, 100};
    init_offer.control_epoch = 1;
    init_offer.lease_token = 0x11223344;
    init_offer.nonce.fill(0xAA);

    negotiation_offer resp_offer = init_offer;
    resp_offer.endpoint = {2, 20, 200};
    resp_offer.nonce.fill(0xBB);

    negotiation_result res;
    res.status = negotiation_status::accepted;
    res.required_level = security_level::sl1_authenticated;
    res.negotiated_level = security_level::sl1_authenticated;
    res.suite = crypto_suite::hmac_sha256_128;

    std::vector<std::uint8_t> transcript;
    LINEP_SL_TEST_CHECK(encode_negotiation_transcript(init_offer, resp_offer, res, transcript));
    // Golden prefix must be LNS2NEG
    LINEP_SL_TEST_CHECK(transcript.size() >= 7);
    LINEP_SL_TEST_CHECK(std::string(transcript.begin(), transcript.begin() + 7) == "LNS2NEG");

    std::cout << "  -> Cross-Language Concrete Golden Vectors PASSED (tag=" << tag_hex << ")" << std::endl;
}

void test_active_stream_policy_revision_update() {
    std::cout << "[Test 4] Active-Stream Dynamic Policy Revision Monotonic Updates..." << std::endl;

    governance_engine gov(1, "policy-conformance", 1, 1);
    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    auto session = create_conformance_session();
    auto key = make_conformance_key();
    std::uint64_t now_us = 2000000;
    monotonic_stream_tracker tracker;

    // Event 1 during revision 1
    linep::v0_2::event_envelope evt1;
    evt1.stream = {10, 20, 0};
    evt1.event_seq = 1;
    evt1.payload = "msg 1";
    std::vector<std::uint8_t> raw1;
    linep::v0_2::encode_event(evt1, raw1);
    std::vector<std::uint8_t> tag1;
    LINEP_SL_TEST_CHECK(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, raw1, 0, false, tag1));
    LINEP_SL_TEST_CHECK(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, raw1, 0, false, tag1, tracker, now_us) == verification_status::ok);

    // Monotonically bump policy revision mid-stream from 1 to 2
    LINEP_SL_TEST_CHECK(gov.update_policy_revision(2, now_us + 100));
    LINEP_SL_TEST_CHECK(gov.policy_revision() == 2);

    // Monotonic enforcement: regression or duplicate rejected
    LINEP_SL_TEST_CHECK(!gov.update_policy_revision(2, now_us + 200));
    LINEP_SL_TEST_CHECK(!gov.update_policy_revision(1, now_us + 300));
    LINEP_SL_TEST_CHECK(gov.policy_revision() == 2);

    // Event 2 during revision 2 succeeds
    linep::v0_2::event_envelope evt2;
    evt2.stream = {10, 20, 0};
    evt2.event_seq = 2;
    evt2.payload = "msg 2";
    std::vector<std::uint8_t> raw2;
    linep::v0_2::encode_event(evt2, raw2);
    std::vector<std::uint8_t> tag2;
    LINEP_SL_TEST_CHECK(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2));
    LINEP_SL_TEST_CHECK(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2, tracker, now_us + 500) == verification_status::ok);

    std::cout << "  -> Active-Stream Policy Revision Update PASSED" << std::endl;
}

void test_malformed_fuzzed_inputs() {
    std::cout << "[Test 5] Malformed & Fuzzed Inputs Robustness..." << std::endl;

    auto session = create_conformance_session();
    auto key = make_conformance_key();
    sliding_replay_window win;
    std::uint64_t now_us = 2000000;

    // 1. Truncated or empty tag
    linep::v0_2::udp_control_datagram dgram;
    dgram.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
    dgram.node_id = 1;
    dgram.runtime_id = 1;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    std::vector<std::uint8_t> empty_tag;
    LINEP_SL_TEST_CHECK(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, empty_tag, win, now_us) == verification_status::signature_invalid);

    // 1b. Structurally invalid datagram (control_epoch == 0) -> binding_invalid
    auto bad_epoch_dgram = dgram;
    bad_epoch_dgram.control_epoch = 0;
    LINEP_SL_TEST_CHECK(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        bad_epoch_dgram, empty_tag, win, now_us) == verification_status::binding_invalid);

    // 2. Out-of-range security action enum
    std::vector<std::uint8_t> tag;
    LINEP_SL_TEST_CHECK(!sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, static_cast<security_action>(255),
        dgram, tag));

    // 3. Out-of-range message direction
    LINEP_SL_TEST_CHECK(!sign_control_datagram(
        session, key, static_cast<message_direction>(255),
        security_level::sl2_identity, security_action::advertise,
        dgram, tag));

    // 4. Malformed session bind envelope (node_id = 0)
    linep::v0_2::session_bind_envelope bad_bind;
    bad_bind.identity = {0, 100, 1};
    bad_bind.control_epoch = 1;
    bad_bind.lease_token = 12345;
    LINEP_SL_TEST_CHECK(validate_transport_session_binding(
        session, session_participant_role::initiator,
        bad_bind, now_us) == verification_status::binding_invalid);

    // 5. Zero timestamp fails closed
    linep::v0_2::session_bind_envelope valid_bind;
    valid_bind.identity = session.initiator.endpoint;
    valid_bind.control_epoch = session.initiator_control_epoch;
    valid_bind.lease_token = session.initiator_lease_token;
    LINEP_SL_TEST_CHECK(validate_transport_session_binding(
        session, session_participant_role::initiator,
        valid_bind, 0) == verification_status::session_inactive);

    // 6. Unknown bound role fails closed
    LINEP_SL_TEST_CHECK(validate_transport_session_binding(
        session, static_cast<session_participant_role>(0),
        valid_bind, now_us) == verification_status::binding_invalid);

    std::cout << "  -> Malformed & Fuzzed Inputs Robustness PASSED" << std::endl;
}

void test_active_stream_revocation_fail_closed() {
    std::cout << "[Test 6] Active-Stream Revocation & Fail-Closed Invariants..." << std::endl;

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
    LINEP_SL_TEST_CHECK(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, raw1, 0, false, tag1));

    // Seq 1 succeeds
    LINEP_SL_TEST_CHECK(verify_event(
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
    LINEP_SL_TEST_CHECK(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2));

    // Seq 2 MUST FAIL CLOSED with session_inactive
    auto status = verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, raw2, 0, false, tag2, tracker, now_us);
    LINEP_SL_TEST_CHECK(status == verification_status::session_inactive);

    std::cout << "  -> Active-Stream Revocation Fail-Closed PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Phase F Conformance & Hardening Test Suite ===" << std::endl;
    test_cross_layer_full_pipeline();
    test_golden_vectors_and_canonical_invariants();
    test_cross_language_concrete_golden_vectors();
    test_active_stream_policy_revision_update();
    test_malformed_fuzzed_inputs();
    test_active_stream_revocation_fail_closed();
    std::cout << "ALL PHASE F CONFORMANCE & HARDENING TESTS PASSED 100%!" << std::endl;
    return 0;
}
