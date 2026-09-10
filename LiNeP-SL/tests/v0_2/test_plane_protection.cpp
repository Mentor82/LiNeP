#include <linep_sl/v0_2/plane_authenticator.hpp>

#include <cassert>
#include <iostream>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

session_record make_test_session(
    std::uint64_t session_id = 1001,
    security_level level = security_level::sl2_identity,
    crypto_suite suite = crypto_suite::hmac_sha256_128,
    std::uint64_t lease_duration_us = 3600000000ULL) {
    session_record s;
    s.session_id = session_id;
    s.security_epoch = 1;
    s.negotiated_level = level;
    s.suite = suite;
    s.key_id = 42;
    s.state = session_state::active;
    s.established_at_us = 1000000ULL;
    s.key_activated_at_us = 1000000ULL;
    s.expires_at_us = 1000000ULL + lease_duration_us;

    s.initiator.endpoint = {1, 101, 1001};
    s.initiator.trust_domain_id = 1;
    s.initiator.subject_id = 101;
    s.initiator.credential_revision = 1;
    s.initiator.authenticated_at_us = 1000000ULL;
    s.initiator.credential_expires_at_us = s.expires_at_us;
    s.initiator.revoked = false;

    s.responder.endpoint = {1, 202, 2002};
    s.responder.trust_domain_id = 1;
    s.responder.subject_id = 202;
    s.responder.credential_revision = 1;
    s.responder.authenticated_at_us = 1000000ULL;
    s.responder.credential_expires_at_us = s.expires_at_us;
    s.responder.revoked = false;

    return s;
}

std::vector<std::uint8_t> make_test_key() {
    return {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };
}

} // namespace

void test_udp_control_plane_protection() {
    std::cout << "[Test 1] UDP Control Plane Datagram Protection & Replay Windows..." << std::endl;

    auto session = make_test_session();
    auto key = make_test_key();
    sliding_replay_window win;
    std::uint64_t now_us = 2000000ULL;

    linep::v0_2::udp_control_datagram dgram;
    dgram.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
    dgram.version_major = 0;
    dgram.version_minor = 2;
    dgram.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::node_hello);
    dgram.flags = 0x01;
    dgram.node_id = 1;
    dgram.runtime_id = 101;
    dgram.endpoint_id = 1001;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    dgram.lease_token = 555;
    dgram.tcp_port = 8080;

    // 1. Sign datagram
    std::vector<std::uint8_t> tag;
    bool sign_ok = sign_control_datagram(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::advertise,
        dgram,
        tag);
    assert(sign_ok);
    assert(!tag.empty());

    // 2. Verify valid datagram
    auto status = verify_control_datagram(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::advertise,
        dgram,
        tag,
        win,
        now_us);
    assert(status == verification_status::ok);
    assert(win.highest_seq() == 1);

    // 3. Replay attack rejection (same seq = 1)
    status = verify_control_datagram(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::advertise,
        dgram,
        tag,
        win,
        now_us);
    assert(status == verification_status::replay_rejected);

    // 4. In-window out-of-order sequence progression
    dgram.control_seq = 5;
    std::vector<std::uint8_t> tag5;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag5));
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag5, win, now_us) == verification_status::ok);
    assert(win.highest_seq() == 5);

    // Seq 3 arrived late (within window)
    dgram.control_seq = 3;
    std::vector<std::uint8_t> tag3;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag3));
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag3, win, now_us) == verification_status::ok);

    // Duplicate seq 3 rejected
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag3, win, now_us) == verification_status::replay_rejected);

    // 5. Tampered datagram field fails verification
    dgram.control_seq = 6;
    std::vector<std::uint8_t> tag6;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag6));
    dgram.tcp_port = 9090; // Tamper
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag6, win, now_us) == verification_status::signature_invalid);
    dgram.tcp_port = 8080; // Restore

    // 6. Direction reflection attack rejected
    dgram.control_seq = 7;
    std::vector<std::uint8_t> tag7;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag7));
    // Attacker sends datagram claiming responder_to_initiator
    assert(verify_control_datagram(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag7, win, now_us) == verification_status::signature_invalid);

    // 7. Expired lease fails with session_inactive
    dgram.control_seq = 8;
    std::vector<std::uint8_t> tag8;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag8));
    std::uint64_t expired_time = session.expires_at_us + 1000ULL;
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag8, win, expired_time) == verification_status::session_inactive);

    // 8. Level downgrade attack rejected
    session.negotiated_level = security_level::sl1_authenticated; // SL1
    dgram.control_seq = 9;
    std::vector<std::uint8_t> tag9;
    assert(sign_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl1_authenticated, security_action::advertise,
        dgram, tag9));
    // Receiver requires SL2 (sl2_identity) but session only negotiated SL1
    assert(verify_control_datagram(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::advertise,
        dgram, tag9, win, now_us) == verification_status::level_insufficient);

    std::cout << "  -> UDP Control Plane Datagram Protection PASSED" << std::endl;
}

void test_tcp_data_plane_request_protection() {
    std::cout << "[Test 2] TCP Data Plane Request Protection..." << std::endl;

    auto session = make_test_session();
    auto key = make_test_key();
    std::uint64_t now_us = 2000000ULL;

    linep::v0_2::request_envelope req;
    req.stream = {10, 20, 30};
    req.profile = linep::v0_2::runtime_profile::generate;
    req.model_id = "mock-model";
    req.temperature = 0.7f;
    req.has_options = true;
    req.options.seed = 42;

    std::vector<std::uint8_t> raw_payload = {'{', '"', 'm', 's', 'g', '"', ':', '"', 'h', 'i', '"', '}'};

    std::vector<std::uint8_t> tag;
    assert(sign_request(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::execute,
        req,
        raw_payload,
        tag));
    assert(!tag.empty());

    // Valid verify
    auto status = verify_request(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::execute,
        req,
        raw_payload,
        tag,
        now_us);
    assert(status == verification_status::ok);

    // Tampered payload fails verification
    std::vector<std::uint8_t> bad_payload = raw_payload;
    bad_payload.push_back('!');
    assert(verify_request(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::execute,
        req,
        bad_payload,
        tag,
        now_us) == verification_status::signature_invalid);

    // Tampered stream fails verification
    linep::v0_2::request_envelope bad_req = req;
    bad_req.stream.request_id = 999;
    assert(verify_request(
        session,
        key,
        message_direction::initiator_to_responder,
        security_level::sl2_identity,
        security_action::execute,
        bad_req,
        raw_payload,
        tag,
        now_us) == verification_status::signature_invalid);

    std::cout << "  -> TCP Data Plane Request Protection PASSED" << std::endl;
}

void test_tcp_data_plane_event_protection() {
    std::cout << "[Test 3] TCP Data Plane Event Protection & Monotonic Stream Tracker..." << std::endl;

    auto session = make_test_session();
    auto key = make_test_key();
    monotonic_stream_tracker tracker;
    std::uint64_t now_us = 2000000ULL;

    linep::v0_2::event_envelope evt1;
    evt1.stream = {10, 20, 30};
    evt1.event_seq = 1;
    evt1.event_type = linep::v0_2::runtime_event_type::content_delta;
    std::vector<std::uint8_t> payload1 = {'d', 'a', 't', 'a', '1'};

    std::vector<std::uint8_t> tag1;
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, payload1, 0, false, tag1));

    // Verify Event 1
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, payload1, 0, false, tag1, tracker, now_us) == verification_status::ok);
    assert(tracker.last_event_seq() == 1);

    // Event 1 duplicate rejected by monotonic tracker
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt1, payload1, 0, false, tag1, tracker, now_us) == verification_status::sequence_regression);

    // Event 2
    linep::v0_2::event_envelope evt2;
    evt2.stream = {10, 20, 30};
    evt2.event_seq = 2;
    evt2.event_type = linep::v0_2::runtime_event_type::content_delta;
    std::vector<std::uint8_t> payload2 = {'d', 'a', 't', 'a', '2'};

    std::vector<std::uint8_t> tag2;
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, payload2, 0, false, tag2));
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, payload2, 0, false, tag2, tracker, now_us) == verification_status::ok);
    assert(tracker.last_event_seq() == 2);

    // Fragmented Event 3: frag 0, 1
    linep::v0_2::event_envelope evt3;
    evt3.stream = {10, 20, 30};
    evt3.event_seq = 3;
    evt3.event_type = linep::v0_2::runtime_event_type::content_delta;
    std::vector<std::uint8_t> payload3_0 = {'p', 'a', 'r', 't', '1'};
    std::vector<std::uint8_t> payload3_1 = {'p', 'a', 'r', 't', '2'};

    std::vector<std::uint8_t> tag3_0, tag3_1;
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt3, payload3_0, 0, true, tag3_0));
    assert(sign_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt3, payload3_1, 1, true, tag3_1));

    // Verify frag 0
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt3, payload3_0, 0, true, tag3_0, tracker, now_us) == verification_status::ok);

    // Verify frag 1
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt3, payload3_1, 1, true, tag3_1, tracker, now_us) == verification_status::ok);

    // Duplicate frag 1 rejected
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt3, payload3_1, 1, true, tag3_1, tracker, now_us) == verification_status::sequence_regression);

    // Event sequence regression (trying event 2 again) rejected
    assert(verify_event(
        session, key, message_direction::responder_to_initiator,
        security_level::sl2_identity, security_action::emit_output,
        evt2, payload2, 0, false, tag2, tracker, now_us) == verification_status::sequence_regression);

    std::cout << "  -> TCP Data Plane Event Protection PASSED" << std::endl;
}

void test_tcp_data_plane_control_protection() {
    std::cout << "[Test 4] TCP Data Plane Control Protection..." << std::endl;

    auto session = make_test_session();
    auto key = make_test_key();
    std::uint64_t now_us = 2000000ULL;

    linep::v0_2::control_envelope ctrl;
    ctrl.stream = {10, 20, 30};
    ctrl.control_type = linep::v0_2::runtime_control_type::window_update;
    ctrl.ack_offset_bytes = 65536;

    std::vector<std::uint8_t> payload = {0x00, 0x01, 0x00, 0x00};

    std::vector<std::uint8_t> tag;
    assert(sign_control(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::cancel,
        ctrl, payload, tag));
    assert(!tag.empty());

    assert(verify_control(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::cancel,
        ctrl, payload, tag, now_us) == verification_status::ok);

    // Tampered payload fails
    std::vector<std::uint8_t> bad_payload = payload;
    bad_payload[0] = 0xFF;
    assert(verify_control(
        session, key, message_direction::initiator_to_responder,
        security_level::sl2_identity, security_action::cancel,
        ctrl, bad_payload, tag, now_us) == verification_status::signature_invalid);

    std::cout << "  -> TCP Data Plane Control Protection PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Plane Protection & Replay Verification Suite ===" << std::endl;
    test_udp_control_plane_protection();
    test_tcp_data_plane_request_protection();
    test_tcp_data_plane_event_protection();
    test_tcp_data_plane_control_protection();
    std::cout << "ALL PLANE PROTECTION TESTS PASSED 100%!" << std::endl;
    return 0;
}
