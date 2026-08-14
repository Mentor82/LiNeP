#pragma once
#include <cstdint>
#include "export.h"

// ── Packed-struct helpers (MSVC / GCC / Clang) ───────────────────────────────
#if defined(_MSC_VER)
#  define LINEP_PACKED_BEGIN  __pragma(pack(push, 1))
#  define LINEP_PACKED_END    __pragma(pack(pop))
#  define LINEP_PACKED
#else
#  define LINEP_PACKED_BEGIN
#  define LINEP_PACKED_END
#  define LINEP_PACKED        __attribute__((packed))
#endif

// ── Wire-format constants ────────────────────────────────────────────────────
namespace linep {

static constexpr uint16_t MAGIC   = 0x4C4E;  // ASCII "LN"
static constexpr uint8_t  VERSION = 0x01;
static constexpr uint16_t HEADER_BASE_LEN       = 24;
static constexpr uint16_t HEADER_BUILD_TIME_LEN = 6;

// ── Endianness ────────────────────────────────────────────────────────────────
// v1 wire format uses host byte order (little-endian).
// All multi-byte header fields are written/read as-is without byte-swapping.
// Cross-endian peers (e.g. big-endian ARM) are NOT supported in v1.
static constexpr uint8_t WIRE_BYTE_ORDER = 0x01; // 0x01 = little-endian

// ── Payload limit ─────────────────────────────────────────────────────────────
// Frames with payload_len > LINEP_MAX_PAYLOAD_BYTES are rejected by
// validate_header() to guard against allocation exhaustion attacks.
static constexpr uint32_t MAX_PAYLOAD_BYTES = 4u * 1024u * 1024u; // 4 MiB

// ── Common Header — base 24 bytes (v1.1 may append extension bytes) ─────────
LINEP_PACKED_BEGIN
struct Header {
    uint16_t magic;           //  0  must be MAGIC
    uint8_t  version;         //  2  must be VERSION
    uint8_t  msg_type;        //  3  linep::MsgType
    uint16_t header_len;      //  4  base=24, may be >24 when extensions follow
    uint16_t flags;           //  6  linep::Flags bitmask
    uint32_t payload_len;     //  8  bytes after header
    uint32_t sequence;        // 12  sender-local counter
    uint32_t correlation_id;  // 16  matches request↔response
    uint16_t worker_id;       // 20
    uint8_t  slot_id;         // 22
    uint8_t  header_crc;      // 23  CRC-8 over bytes [0..22]
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(Header) == HEADER_BASE_LEN,
              "LiNeP Header base must be exactly 24 bytes");

// Optional v1.1 extension payload, appended directly after Header when
// FLAG_BUILD_TIME is set and header_len >= 30.
LINEP_PACKED_BEGIN
struct HeaderBuildTimeExt {
    uint8_t year_2d;  // years since 2000, e.g. 26 = 2026
    uint8_t month;    // 1..12
    uint8_t day;      // 1..31
    uint8_t hour;     // 0..23
    uint8_t minute;   // 0..59
    uint8_t second;   // 0..59
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(HeaderBuildTimeExt) == HEADER_BUILD_TIME_LEN,
              "HeaderBuildTimeExt must be exactly 6 bytes");

// ── Heartbeat Compact Frame — 19 bytes (UDP only, V0.1.0 baseline) ───────────
LINEP_PACKED_BEGIN
struct HeartbeatCompact {
    uint16_t magic;        //  0  MAGIC
    uint8_t  version;      //  2  VERSION
    uint8_t  msg_type;     //  3  MsgType::HEARTBEAT
    uint16_t worker_id;    //  4
    uint8_t  slot_id;      //  6
    uint8_t  slot_flags;   //  7  SlotFlags bitmask
    uint8_t  load;         //  8  0-100 percent, or Load special values
    uint8_t  queue_depth;  //  9  0-254, 255 = overflow
    uint8_t  sequence;     // 10  wraps at 255
    uint16_t worker_score; // 11  coworker-computed score
    uint8_t  ts_month;     // 13  UTC month   (1..12)
    uint8_t  ts_day;       // 14  UTC day     (1..31)
    uint8_t  ts_hour;      // 15  UTC hour    (0..23)
    uint8_t  ts_minute;    // 16  UTC minute  (0..59)
    uint8_t  ts_second;    // 17  UTC second  (0..59)
    uint8_t  crc8;         // 18  CRC-8 over bytes [0..17]
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(HeartbeatCompact) == 19,
              "HeartbeatCompact must be exactly 19 bytes");

// ── UDP Control Frames (V0.1.0 Baseline) ─────────────────────────────────────

LINEP_PACKED_BEGIN
struct UdpInviteFrame {
    uint8_t  msg_type;        //  0  MsgType::INVITE (0x05)
    uint8_t  invite_seq;      //  1  Sequence counter for invites
    uint16_t worker_id;       //  2  Target worker
    uint8_t  slot_id;         //  4  Target slot
    uint32_t lease_ttl_ms;    //  5  Lease duration in ms
    uint32_t session_token;   //  9  Assigned session token
    uint8_t  crc8;            // 13  CRC-8 over bytes [0..12]
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(UdpInviteFrame) == 14,
              "UdpInviteFrame must be exactly 14 bytes");

LINEP_PACKED_BEGIN
struct UdpInviteAckFrame {
    uint8_t  msg_type;        //  0  MsgType::INVITE_ACK (0x06)
    uint8_t  invite_seq;      //  1  Matching invite_seq
    uint16_t worker_id;       //  2  Worker ID
    uint8_t  slot_id;         //  4  Slot ID
    uint8_t  accepted;        //  5  1 = accepted, 0 = rejected
    uint32_t session_token;   //  6  Matching session token
    uint8_t  crc8;            // 10  CRC-8 over bytes [0..9]
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(UdpInviteAckFrame) == 11,
              "UdpInviteAckFrame must be exactly 11 bytes");

LINEP_PACKED_BEGIN
struct UdpHeartbeatAckFrame {
    uint8_t  msg_type;        //  0  MsgType::HEARTBEAT_ACK (0x07)
    uint8_t  heartbeat_seq;   //  1  Matching sequence from HeartbeatCompact
    uint16_t worker_id;       //  2  Worker ID
    uint8_t  slot_id;         //  4  Slot ID
    uint32_t scheduler_time_sec; // 5 UTC unix timestamp from Scheduler
    uint8_t  crc8;            //  9  CRC-8 over bytes [0..8]
} LINEP_PACKED;
LINEP_PACKED_END

static_assert(sizeof(UdpHeartbeatAckFrame) == 10,
              "UdpHeartbeatAckFrame must be exactly 10 bytes");

// ── Flags (16-bit) ───────────────────────────────────────────────────────────
enum Flags : uint16_t {
    FLAG_ACK_REQUIRED   = 1u << 0,   // reserved in v1 — not evaluated by any receiver
    FLAG_IS_ACK         = 1u << 1,   // reserved in v1 — not evaluated by any receiver
    FLAG_ERROR          = 1u << 2,
    FLAG_COMPRESSED     = 1u << 3,   // reserved in v1
    FLAG_ENCRYPTED      = 1u << 4,   // reserved in v1
    FLAG_FRAGMENTED     = 1u << 5,
    FLAG_FINAL_FRAGMENT = 1u << 6,
    FLAG_PRIORITY       = 1u << 7,
    FLAG_DEGRADED       = 1u << 8,
    FLAG_RETRY          = 1u << 9,
    FLAG_BUILD_TIME     = 1u << 10,  // v1.1: HeaderBuildTimeExt follows Header
};

// ── Slot Flags (8-bit, in HeartbeatCompact.slot_flags) ───────────────────────
enum SlotFlags : uint8_t {
    SLOT_ALIVE         = 1u << 0,
    SLOT_READY         = 1u << 1,
    SLOT_BUSY          = 1u << 2,
    SLOT_DEGRADED      = 1u << 3,
    SLOT_ERROR         = 1u << 4,
    SLOT_THERMAL_LIMIT = 1u << 5,
    SLOT_MODEL_LOADING = 1u << 6,
};

// ── Load byte special values ─────────────────────────────────────────────────
enum Load : uint8_t {
    LOAD_IDLE    =   0,
    LOAD_UNKNOWN = 200,
    LOAD_OFFLINE = 250,
    LOAD_INVALID = 255,
};

} // namespace linep
