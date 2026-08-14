#include "framing.hpp"
#include "crc.hpp"
#include <linep/messages.hpp>
#include <cstring>

#ifndef LINEP_BUILD_YEAR_2D
#define LINEP_BUILD_YEAR_2D 0
#endif
#ifndef LINEP_BUILD_MONTH
#define LINEP_BUILD_MONTH 1
#endif
#ifndef LINEP_BUILD_DAY
#define LINEP_BUILD_DAY 1
#endif
#ifndef LINEP_BUILD_HOUR
#define LINEP_BUILD_HOUR 0
#endif
#ifndef LINEP_BUILD_MINUTE
#define LINEP_BUILD_MINUTE 0
#endif
#ifndef LINEP_BUILD_SECOND
#define LINEP_BUILD_SECOND 0
#endif

namespace linep::core {

// ── HeartbeatCompact ─────────────────────────────────────────────────────────

linep::HeartbeatCompact make_heartbeat_compact(
    uint16_t worker_id, uint8_t slot_id,
    uint8_t  slot_flags, uint8_t load,
    uint8_t  queue_depth, uint8_t sequence,
    uint16_t worker_score,
    uint8_t  ts_month, uint8_t ts_day,
    uint8_t  ts_hour, uint8_t ts_minute,
    uint8_t  ts_second) noexcept
{
    linep::HeartbeatCompact f{};
    f.magic       = linep::MAGIC;
    f.version     = linep::VERSION;
    f.msg_type    = static_cast<uint8_t>(linep::MsgType::HEARTBEAT);
    f.worker_id   = worker_id;
    f.slot_id     = slot_id;
    f.slot_flags  = slot_flags;
    f.load        = load;
    f.queue_depth = queue_depth;
    f.sequence    = sequence;
    f.worker_score = worker_score;
    f.ts_month     = ts_month;
    f.ts_day       = ts_day;
    f.ts_hour      = ts_hour;
    f.ts_minute    = ts_minute;
    f.ts_second    = ts_second;
    // CRC-8 covers bytes [0..17] (all fields except crc8 itself)
    f.crc8 = crc8(reinterpret_cast<const uint8_t*>(&f), 18u);
    return f;
}

bool validate_heartbeat_compact(
    const linep::HeartbeatCompact& f) noexcept
{
    if (f.magic    != linep::MAGIC)   return false;
    if (f.version  != linep::VERSION) return false;
    if (f.msg_type != static_cast<uint8_t>(linep::MsgType::HEARTBEAT)) return false;
    if (f.ts_month == 0u || f.ts_month > 12u) return false;
    if (f.ts_day == 0u || f.ts_day > 31u) return false;
    if (f.ts_hour > 23u) return false;
    if (f.ts_minute > 59u) return false;
    if (f.ts_second > 59u) return false;
    const uint8_t expected = crc8(reinterpret_cast<const uint8_t*>(&f), 18u);
    return f.crc8 == expected;
}

// ── UDP Control Frames (V0.1.0 Baseline) ─────────────────────────────────────

linep::UdpInviteFrame make_udp_invite(
    uint8_t invite_seq, uint16_t worker_id, uint8_t slot_id,
    uint32_t lease_ttl_ms, uint32_t session_token) noexcept
{
    linep::UdpInviteFrame f{};
    f.msg_type      = static_cast<uint8_t>(linep::MsgType::INVITE);
    f.invite_seq    = invite_seq;
    f.worker_id     = worker_id;
    f.slot_id       = slot_id;
    f.lease_ttl_ms  = lease_ttl_ms;
    f.session_token = session_token;
    f.crc8          = crc8(reinterpret_cast<const uint8_t*>(&f), 13u);
    return f;
}

bool validate_udp_invite(const linep::UdpInviteFrame& f) noexcept {
    if (f.msg_type != static_cast<uint8_t>(linep::MsgType::INVITE)) return false;
    const uint8_t expected = crc8(reinterpret_cast<const uint8_t*>(&f), 13u);
    return f.crc8 == expected;
}

linep::UdpInviteAckFrame make_udp_invite_ack(
    uint8_t invite_seq, uint16_t worker_id, uint8_t slot_id,
    uint8_t accepted, uint32_t session_token) noexcept
{
    linep::UdpInviteAckFrame f{};
    f.msg_type      = static_cast<uint8_t>(linep::MsgType::INVITE_ACK);
    f.invite_seq    = invite_seq;
    f.worker_id     = worker_id;
    f.slot_id       = slot_id;
    f.accepted      = (accepted != 0u) ? 1u : 0u;
    f.session_token = session_token;
    f.crc8          = crc8(reinterpret_cast<const uint8_t*>(&f), 10u);
    return f;
}

bool validate_udp_invite_ack(const linep::UdpInviteAckFrame& f) noexcept {
    if (f.msg_type != static_cast<uint8_t>(linep::MsgType::INVITE_ACK)) return false;
    if (f.accepted > 1u) return false;
    const uint8_t expected = crc8(reinterpret_cast<const uint8_t*>(&f), 10u);
    return f.crc8 == expected;
}

linep::UdpHeartbeatAckFrame make_udp_heartbeat_ack(
    uint8_t heartbeat_seq, uint16_t worker_id, uint8_t slot_id,
    uint32_t scheduler_time_sec) noexcept
{
    linep::UdpHeartbeatAckFrame f{};
    f.msg_type           = static_cast<uint8_t>(linep::MsgType::HEARTBEAT_ACK);
    f.heartbeat_seq      = heartbeat_seq;
    f.worker_id          = worker_id;
    f.slot_id            = slot_id;
    f.scheduler_time_sec = scheduler_time_sec;
    f.crc8               = crc8(reinterpret_cast<const uint8_t*>(&f), 9u);
    return f;
}

bool validate_udp_heartbeat_ack(const linep::UdpHeartbeatAckFrame& f) noexcept {
    if (f.msg_type != static_cast<uint8_t>(linep::MsgType::HEARTBEAT_ACK)) return false;
    const uint8_t expected = crc8(reinterpret_cast<const uint8_t*>(&f), 9u);
    return f.crc8 == expected;
}

// ── Common Header ─────────────────────────────────────────────────────────────

linep::Header make_header(
    uint8_t  msg_type, uint16_t flags,
    uint32_t payload_len, uint32_t sequence,
    uint32_t correlation_id, uint16_t worker_id, uint8_t slot_id) noexcept
{
    linep::Header h{};
    h.magic          = linep::MAGIC;
    h.version        = linep::VERSION;
    h.msg_type       = msg_type;
    h.header_len     = static_cast<uint16_t>(sizeof(linep::Header));
    h.flags          = flags;
    h.payload_len    = payload_len;
    h.sequence       = sequence;
    h.correlation_id = correlation_id;
    h.worker_id      = worker_id;
    h.slot_id        = slot_id;
    // CRC-8 covers bytes [0..22] (header_crc is byte 23)
    h.header_crc = crc8(reinterpret_cast<const uint8_t*>(&h), 23u);
    return h;
}

linep::HeaderBuildTimeExt make_build_time_ext_from_build() noexcept {
    linep::HeaderBuildTimeExt ext{};
    ext.year_2d = static_cast<uint8_t>(LINEP_BUILD_YEAR_2D);
    ext.month   = static_cast<uint8_t>(LINEP_BUILD_MONTH);
    ext.day     = static_cast<uint8_t>(LINEP_BUILD_DAY);
    ext.hour    = static_cast<uint8_t>(LINEP_BUILD_HOUR);
    ext.minute  = static_cast<uint8_t>(LINEP_BUILD_MINUTE);
    ext.second  = static_cast<uint8_t>(LINEP_BUILD_SECOND);
    return ext;
}

void apply_build_time_extension(linep::Header& h) noexcept {
    h.flags = static_cast<uint16_t>(h.flags | static_cast<uint16_t>(linep::FLAG_BUILD_TIME));
    h.header_len = static_cast<uint16_t>(linep::HEADER_BASE_LEN + linep::HEADER_BUILD_TIME_LEN);
    h.header_crc = crc8(reinterpret_cast<const uint8_t*>(&h), 23u);
}

bool try_parse_build_time_ext(const uint8_t* ext,
                              uint16_t ext_len,
                              linep::HeaderBuildTimeExt& out) noexcept {
    if (!ext || ext_len < linep::HEADER_BUILD_TIME_LEN) return false;
    std::memcpy(&out, ext, sizeof(linep::HeaderBuildTimeExt));
    return true;
}

bool validate_header(const linep::Header& h) noexcept {
    if (h.magic      != linep::MAGIC)   return false;
    if (h.version    != linep::VERSION) return false;
    if (h.header_len < linep::HEADER_BASE_LEN) return false;
    if (h.header_len > static_cast<uint16_t>(linep::HEADER_BASE_LEN + linep::HEADER_BUILD_TIME_LEN)) return false;
    if (h.payload_len > linep::MAX_PAYLOAD_BYTES) return false;
    const uint8_t expected = crc8(reinterpret_cast<const uint8_t*>(&h), 23u);
    return h.header_crc == expected;
}

} // namespace linep::core
