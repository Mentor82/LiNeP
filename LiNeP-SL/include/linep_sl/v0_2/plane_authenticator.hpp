#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <linep/v0_2/control_plane.hpp>
#include <linep/v0_2/envelopes.hpp>
#include <linep_sl/v0_2/authenticator.hpp>
#include <linep_sl/v0_2/replay_window.hpp>
#include <linep_sl/v0_2/security_contract.hpp>
#include <linep_sl/v0_2/session.hpp>

namespace linep::sl::v0_2 {

enum class verification_status : std::uint8_t {
    ok = 0,
    session_inactive = 1,
    level_insufficient = 2,
    suite_unsupported = 3,
    digest_failed = 4,
    signature_invalid = 5,
    replay_rejected = 6,
    sequence_regression = 7,
    direction_mismatch = 8,
    epoch_lease_mismatch = 9,
    binding_invalid = 10,
};

// High-level helper functions for UDP Control Plane message protection
bool sign_control_datagram(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::udp_control_datagram& dgram,
    std::vector<std::uint8_t>& out_tag) noexcept;

verification_status verify_control_datagram(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::udp_control_datagram& dgram,
    const std::vector<std::uint8_t>& tag,
    sliding_replay_window& replay_window,
    std::uint64_t now_us) noexcept;

// High-level helper functions for TCP Data Plane message protection
bool sign_request(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::request_envelope& req,
    const std::vector<std::uint8_t>& raw_payload,
    std::vector<std::uint8_t>& out_tag) noexcept;

verification_status verify_request(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::request_envelope& req,
    const std::vector<std::uint8_t>& raw_payload,
    const std::vector<std::uint8_t>& tag,
    std::uint64_t now_us) noexcept;

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
    std::vector<std::uint8_t>& out_tag) noexcept;

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
    std::uint64_t now_us) noexcept;

bool sign_control(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::control_envelope& ctrl,
    const std::vector<std::uint8_t>& raw_payload,
    std::vector<std::uint8_t>& out_tag) noexcept;

verification_status verify_control(
    const session_record& session,
    const std::vector<std::uint8_t>& key,
    message_direction direction,
    security_level required_level,
    security_action action,
    const linep::v0_2::control_envelope& ctrl,
    const std::vector<std::uint8_t>& raw_payload,
    const std::vector<std::uint8_t>& tag,
    std::uint64_t now_us) noexcept;

} // namespace linep::sl::v0_2
