#pragma once
#include <linep/types.hpp>
#include <linep/export.h>
#include <cstdint>

namespace linep::core {

// ── HeartbeatCompact ─────────────────────────────────────────────────────────

// Build a HeartbeatCompact frame and compute its CRC-8.
LINEP_API linep::HeartbeatCompact make_heartbeat_compact(
    uint16_t worker_id,
    uint8_t  slot_id,
    uint8_t  slot_flags,
    uint8_t  load,
    uint8_t  queue_depth,
    uint8_t  sequence,
    uint16_t worker_score,
    uint8_t  ts_month,
    uint8_t  ts_day,
    uint8_t  ts_hour,
    uint8_t  ts_minute,
    uint8_t  ts_second) noexcept;

// Validate magic, version, msg_type, CRC-8, and timestamp ranges.
LINEP_API bool validate_heartbeat_compact(
    const linep::HeartbeatCompact& f) noexcept;

// ── UDP Control Frames (V0.1.0 Baseline) ─────────────────────────────────────

LINEP_API linep::UdpInviteFrame make_udp_invite(
    uint8_t  invite_seq,
    uint16_t worker_id,
    uint8_t  slot_id,
    uint32_t lease_ttl_ms,
    uint32_t session_token) noexcept;

LINEP_API bool validate_udp_invite(
    const linep::UdpInviteFrame& f) noexcept;

LINEP_API linep::UdpInviteAckFrame make_udp_invite_ack(
    uint8_t  invite_seq,
    uint16_t worker_id,
    uint8_t  slot_id,
    uint8_t  accepted,
    uint32_t session_token) noexcept;

LINEP_API bool validate_udp_invite_ack(
    const linep::UdpInviteAckFrame& f) noexcept;

LINEP_API linep::UdpHeartbeatAckFrame make_udp_heartbeat_ack(
    uint8_t  heartbeat_seq,
    uint16_t worker_id,
    uint8_t  slot_id,
    uint32_t scheduler_time_sec) noexcept;

LINEP_API bool validate_udp_heartbeat_ack(
    const linep::UdpHeartbeatAckFrame& f) noexcept;

// ── Common Header ─────────────────────────────────────────────────────────────

// Build a Header and compute its CRC-8.
LINEP_API linep::Header make_header(
    uint8_t  msg_type,
    uint16_t flags,
    uint32_t payload_len,
    uint32_t sequence,
    uint32_t correlation_id,
    uint16_t worker_id,
    uint8_t  slot_id) noexcept;

// Build-time extension helpers (v1.1).
LINEP_API linep::HeaderBuildTimeExt make_build_time_ext_from_build() noexcept;

// Mutates header to include build-time extension metadata and recomputes CRC.
LINEP_API void apply_build_time_extension(linep::Header& h) noexcept;

// Parse extension bytes (if present) into HeaderBuildTimeExt.
LINEP_API bool try_parse_build_time_ext(const uint8_t* ext,
                              uint16_t ext_len,
                              linep::HeaderBuildTimeExt& out) noexcept;

// Validate magic, version, header_len and CRC-8.
LINEP_API bool validate_header(const linep::Header& h) noexcept;

} // namespace linep::core
