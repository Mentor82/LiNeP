#include <linep_sl/v0_2/plane_authenticator.hpp>

namespace linep::sl::v0_2 {
namespace {

security_session_identity extract_session_identity(
    const session_record& session,
    message_direction direction) noexcept {
    security_session_identity id;
    id.session_id = session.session_id;
    id.security_epoch = session.security_epoch;
    id.key_id = session.key_id;

    if (direction == message_direction::initiator_to_responder) {
        id.trust_domain_id = session.initiator.trust_domain_id;
        id.subject_id = session.initiator.subject_id;
    } else {
        id.trust_domain_id = session.responder.trust_domain_id;
        id.subject_id = session.responder.subject_id;
    }
    return id;
}

} // namespace

bool sign_control_datagram(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::udp_control_datagram& dgram,
    std::vector<std::uint8_t>& out_tag) noexcept {
    out_tag.clear();

    std::vector<std::uint8_t> raw_dgram;
    linep::v0_2::encode_control_datagram(dgram, raw_dgram);

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_dgram.data(), raw_dgram.size(), content_digest)) {
        return false;
    }

    control_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.endpoint = {dgram.node_id, dgram.runtime_id, dgram.endpoint_id};
    binding.control_epoch = dgram.control_epoch;
    binding.control_seq = dgram.control_seq;
    binding.lease_token = dgram.lease_token;
    binding.lease_bound = (dgram.lease_token != 0);

    if (!binding.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return false;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return false;
    }

    return auth->sign(auth_input, key, out_tag);
}

verification_status verify_control_datagram(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::udp_control_datagram& dgram,
    const std::vector<std::uint8_t>& tag,
    sliding_replay_window& replay_window,
    std::uint64_t now_us) noexcept {
    if (!session.is_active_at(now_us)) {
        return verification_status::session_inactive;
    }

    if (static_cast<std::uint8_t>(session.negotiated_level) <
        static_cast<std::uint8_t>(required_level)) {
        return verification_status::level_insufficient;
    }

    if (replay_window.check(dgram.control_seq) != replay_status::accepted) {
        return verification_status::replay_rejected;
    }

    std::vector<std::uint8_t> raw_dgram;
    linep::v0_2::encode_control_datagram(dgram, raw_dgram);

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_dgram.data(), raw_dgram.size(), content_digest)) {
        return verification_status::digest_failed;
    }

    control_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.endpoint = {dgram.node_id, dgram.runtime_id, dgram.endpoint_id};
    binding.control_epoch = dgram.control_epoch;
    binding.control_seq = dgram.control_seq;
    binding.lease_token = dgram.lease_token;
    binding.lease_bound = (dgram.lease_token != 0);

    if (!binding.is_valid()) {
        return verification_status::binding_invalid;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return verification_status::binding_invalid;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return verification_status::suite_unsupported;
    }

    if (!auth->verify(auth_input, key, tag)) {
        return verification_status::signature_invalid;
    }

    replay_window.update(dgram.control_seq);
    return verification_status::ok;
}

bool sign_request(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::request_envelope& req,
    const std::vector<std::uint8_t>& raw_payload,
    std::vector<std::uint8_t>& out_tag) noexcept {
    out_tag.clear();

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return false;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::request;
    binding.stream = req.stream;
    binding.event_seq = 0;
    binding.fragment_seq = 0;
    binding.has_fragment_seq = false;

    if (!binding.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return false;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return false;
    }

    return auth->sign(auth_input, key, out_tag);
}

verification_status verify_request(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::request_envelope& req,
    const std::vector<std::uint8_t>& raw_payload,
    const std::vector<std::uint8_t>& tag,
    std::uint64_t now_us) noexcept {
    if (!session.is_active_at(now_us)) {
        return verification_status::session_inactive;
    }

    if (static_cast<std::uint8_t>(session.negotiated_level) <
        static_cast<std::uint8_t>(required_level)) {
        return verification_status::level_insufficient;
    }

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return verification_status::digest_failed;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::request;
    binding.stream = req.stream;
    binding.event_seq = 0;
    binding.fragment_seq = 0;
    binding.has_fragment_seq = false;

    if (!binding.is_valid()) {
        return verification_status::binding_invalid;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return verification_status::binding_invalid;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return verification_status::suite_unsupported;
    }

    if (!auth->verify(auth_input, key, tag)) {
        return verification_status::signature_invalid;
    }

    return verification_status::ok;
}

bool sign_event(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::event_envelope& evt,
    const std::vector<std::uint8_t>& raw_payload,
    std::uint64_t fragment_seq,
    bool has_fragment_seq,
    std::vector<std::uint8_t>& out_tag) noexcept {
    out_tag.clear();

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return false;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::event;
    binding.stream = evt.stream;
    binding.event_seq = evt.event_seq;
    binding.fragment_seq = fragment_seq;
    binding.has_fragment_seq = has_fragment_seq;

    if (!binding.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return false;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return false;
    }

    return auth->sign(auth_input, key, out_tag);
}

verification_status verify_event(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::event_envelope& evt,
    const std::vector<std::uint8_t>& raw_payload,
    std::uint64_t fragment_seq,
    bool has_fragment_seq,
    const std::vector<std::uint8_t>& tag,
    monotonic_stream_tracker& stream_tracker,
    std::uint64_t now_us) noexcept {
    if (!session.is_active_at(now_us)) {
        return verification_status::session_inactive;
    }

    if (static_cast<std::uint8_t>(session.negotiated_level) <
        static_cast<std::uint8_t>(required_level)) {
        return verification_status::level_insufficient;
    }

    if (!stream_tracker.check_and_advance(evt.event_seq, fragment_seq, has_fragment_seq)) {
        return verification_status::sequence_regression;
    }

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return verification_status::digest_failed;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::event;
    binding.stream = evt.stream;
    binding.event_seq = evt.event_seq;
    binding.fragment_seq = fragment_seq;
    binding.has_fragment_seq = has_fragment_seq;

    if (!binding.is_valid()) {
        return verification_status::binding_invalid;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return verification_status::binding_invalid;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return verification_status::suite_unsupported;
    }

    if (!auth->verify(auth_input, key, tag)) {
        return verification_status::signature_invalid;
    }

    return verification_status::ok;
}

bool sign_control(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::control_envelope& ctrl,
    const std::vector<std::uint8_t>& raw_payload,
    std::vector<std::uint8_t>& out_tag) noexcept {
    out_tag.clear();

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return false;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::control;
    binding.stream = ctrl.stream;
    binding.event_seq = 0;
    binding.fragment_seq = 0;
    binding.has_fragment_seq = false;

    if (!binding.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return false;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return false;
    }

    return auth->sign(auth_input, key, out_tag);
}

verification_status verify_control(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::control_envelope& ctrl,
    const std::vector<std::uint8_t>& raw_payload,
    const std::vector<std::uint8_t>& tag,
    std::uint64_t now_us) noexcept {
    if (!session.is_active_at(now_us)) {
        return verification_status::session_inactive;
    }

    if (static_cast<std::uint8_t>(session.negotiated_level) <
        static_cast<std::uint8_t>(required_level)) {
        return verification_status::level_insufficient;
    }

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(raw_payload.data(), raw_payload.size(), content_digest)) {
        return verification_status::digest_failed;
    }

    data_plane_binding binding;
    binding.common.session = extract_session_identity(session, direction);
    binding.common.direction = direction;
    binding.common.negotiated_level = session.negotiated_level;
    binding.common.required_level = required_level;
    binding.common.action = action;
    binding.common.digest = digest_algorithm::sha256;
    binding.common.content_digest = std::move(content_digest);

    binding.message_class = data_message_class::control;
    binding.stream = ctrl.stream;
    binding.event_seq = 0;
    binding.fragment_seq = 0;
    binding.has_fragment_seq = false;

    if (!binding.is_valid()) {
        return verification_status::binding_invalid;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_authenticator_input(binding, auth_input)) {
        return verification_status::binding_invalid;
    }

    auto auth = create_authenticator(session.suite);
    if (!auth) {
        return verification_status::suite_unsupported;
    }

    if (!auth->verify(auth_input, key, tag)) {
        return verification_status::signature_invalid;
    }

    return verification_status::ok;
}

} // namespace linep::sl::v0_2
