/*
 * linep/cabi.h — C-ABI for LiNeP (Python/cffi, ctypes, and plain C callers)
 *
 * All functions use C linkage (extern "C") and plain POD types only.
 * No C++ headers or STL types appear here.
 *
 * Packed-struct layout
 * --------------------
 * linep_header_t and linep_heartbeat_compact_t carry the exact same byte
 * layout as the C++ linep::Header / linep::HeartbeatCompact structs.
 * GCC/Clang: __attribute__((__packed__)) is used.
 * MSVC:       #pragma pack(push,1) / pop is used.
 * cffi: parse this header with the GCC/Clang path (cffi understands
 *       __attribute__((__packed__))).
 *
 * Typical Python/cffi usage
 * -------------------------
 *   from cffi import FFI
 *   ffi = FFI()
 *   ffi.cdef(open("include/linep/cabi.h").read())   # or inline subset
 *   lib = ffi.dlopen("linep.so")  # or linep.dll
 *   lib.linep_net_init()
 *   s = lib.linep_sender_create()
 *   ...
 *   lib.linep_net_cleanup()
 */

#pragma once
#include <stdint.h>
#include "export.h"

/* ── Error / return codes ──────────────────────────────────────────────────── */
#define LINEP_C_OK              0
#define LINEP_C_ERR_ARG        -1   /* NULL pointer or illegal field value     */
#define LINEP_C_ERR_TIMEOUT    -2   /* TCP send_task timed out                 */
#define LINEP_C_ERR_CONNECT    -3   /* TCP connection refused / unreachable     */
#define LINEP_C_ERR_SEND       -4   /* TCP send failed                         */
#define LINEP_C_ERR_RECV       -5   /* TCP recv failed or connection closed     */
#define LINEP_C_ERR_BAD_FRAME  -6   /* CRC mismatch or invalid magic/version   */
#define LINEP_C_ERR_PORT       -7   /* Port already in use (receiver start)    */
#define LINEP_C_ERR_INTERNAL   -8   /* Unexpected internal error               */
#define LINEP_C_ERR_BUF_SMALL  -9   /* Caller result_buf too small             */

/* ── ABI versioning ───────────────────────────────────────────────────────── */
/* Encoded as MAJOR<<16 | MINOR<<8 | PATCH (for V0.1.0 => 0x00000100). */
#define LINEP_C_ABI_VERSION_V0_1_0 0x00000100u

/* ── Wire-format structs ───────────────────────────────────────────────────── */

#if defined(_MSC_VER)
#  pragma pack(push, 1)
#endif

/* Common header — 24 bytes (base). */
typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint16_t magic;           /*  0  must be 0x4C4E ("LN")             */
    uint8_t  version;         /*  2  must be 0x01                       */
    uint8_t  msg_type;        /*  3  linep_msg_type_t                   */
    uint16_t header_len;      /*  4  24 base, >=30 when ext present     */
    uint16_t flags;           /*  6  linep_flags_t bitmask              */
    uint32_t payload_len;     /*  8  bytes after the full header        */
    uint32_t sequence;        /* 12  sender-local monotone counter      */
    uint32_t correlation_id;  /* 16  ties request to response           */
    uint16_t worker_id;       /* 20                                     */
    uint8_t  slot_id;         /* 22                                     */
    uint8_t  header_crc;      /* 23  CRC-8 over bytes [0..22]           */
} linep_header_t;

/* Heartbeat compact frame — 19 bytes (UDP, V0.1.0 baseline). */
typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint16_t magic;        /*  0  0x4C4E                */
    uint8_t  version;      /*  2  0x01                  */
    uint8_t  msg_type;     /*  3  0x01 (HEARTBEAT)      */
    uint16_t worker_id;    /*  4                        */
    uint8_t  slot_id;      /*  6                        */
    uint8_t  slot_flags;   /*  7  linep_slot_flags_t    */
    uint8_t  load;         /*  8  0-100 %, 200=unknown, 250=offline */
    uint8_t  queue_depth;  /*  9  0-254, 255=overflow   */
    uint8_t  sequence;     /* 10  wraps at 255          */
    uint16_t worker_score; /* 11  coworker score        */
    uint8_t  ts_month;     /* 13  UTC month             */
    uint8_t  ts_day;       /* 14  UTC day               */
    uint8_t  ts_hour;      /* 15  UTC hour              */
    uint8_t  ts_minute;    /* 16  UTC minute            */
    uint8_t  ts_second;    /* 17  UTC second            */
    uint8_t  crc8;         /* 18  CRC-8 over [0..17]    */
} linep_heartbeat_compact_t;

/* Optional v1.1 build-time extension — 6 bytes (appended after header). */
typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint8_t year_2d; /* years since 2000 (e.g. 26 = 2026) */
    uint8_t month;   /* 1..12  */
    uint8_t day;     /* 1..31  */
    uint8_t hour;    /* 0..23  */
    uint8_t minute;  /* 0..59  */
    uint8_t second;  /* 0..59  */
} linep_build_time_ext_t;

/* UDP Control Frames (V0.1.0 Baseline) */
typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint8_t  msg_type;      /*  0  0x05 (INVITE)        */
    uint8_t  invite_seq;    /*  1                       */
    uint16_t worker_id;     /*  2                       */
    uint8_t  slot_id;       /*  4                       */
    uint32_t lease_ttl_ms;  /*  5                       */
    uint32_t session_token; /*  9                       */
    uint8_t  crc8;          /* 13                       */
} linep_udp_invite_t;

typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint8_t  msg_type;      /*  0  0x06 (INVITE_ACK)    */
    uint8_t  invite_seq;    /*  1                       */
    uint16_t worker_id;     /*  2                       */
    uint8_t  slot_id;       /*  4                       */
    uint8_t  accepted;      /*  5                       */
    uint32_t session_token; /*  6                       */
    uint8_t  crc8;          /* 10                       */
} linep_udp_invite_ack_t;

typedef struct
#if !defined(_MSC_VER)
    __attribute__((__packed__))
#endif
{
    uint8_t  msg_type;           /*  0  0x07 (HEARTBEAT_ACK) */
    uint8_t  heartbeat_seq;      /*  1                      */
    uint16_t worker_id;          /*  2                      */
    uint8_t  slot_id;            /*  4                      */
    uint32_t scheduler_time_sec;/*  5                      */
    uint8_t  crc8;               /*  9                      */
} linep_udp_heartbeat_ack_t;

#if defined(_MSC_VER)
#  pragma pack(pop)
#endif

/* ── Message-type constants (mirrors linep::MsgType) ─────────────────────── */
#define LINEP_MSG_HEARTBEAT          0x01u
#define LINEP_MSG_REGISTER           0x02u
#define LINEP_MSG_REGISTER_ACK       0x03u
#define LINEP_MSG_BYE                0x04u
#define LINEP_MSG_INVITE             0x05u
#define LINEP_MSG_INVITE_ACK         0x06u
#define LINEP_MSG_HEARTBEAT_ACK      0x07u
#define LINEP_MSG_TASK               0x10u
#define LINEP_MSG_TASK_ACK           0x11u
#define LINEP_MSG_RESULT             0x12u
#define LINEP_MSG_ERROR              0x13u
#define LINEP_MSG_TASK_CANCEL        0x14u
#define LINEP_MSG_STATUS_REQUEST     0x20u
#define LINEP_MSG_STATUS_RESPONSE    0x21u
#define LINEP_MSG_EMBED_REQUEST      0x30u
#define LINEP_MSG_EMBED_RESPONSE     0x31u
#define LINEP_MSG_SIMILARITY_REQUEST 0x32u
#define LINEP_MSG_SIMILARITY_RESPONSE 0x33u
#define LINEP_MSG_CONSENSUS_REQUEST  0x40u
#define LINEP_MSG_CONSENSUS_RESPONSE 0x41u
#define LINEP_MSG_PING               0xF0u
#define LINEP_MSG_PONG               0xF1u

/* ── Task-type constants (mirrors linep::TaskType) ───────────────────────── */
#define LINEP_TASK_INSTRUCT       0x01u
#define LINEP_TASK_CODE           0x02u
#define LINEP_TASK_SUMMARIZE      0x03u
#define LINEP_TASK_CLASSIFY       0x04u
#define LINEP_TASK_VALIDATE       0x05u
#define LINEP_TASK_EDGE_TEXT_EVAL 0x06u

/* ── Result-status constants (mirrors linep::ResultStatus) ───────────────── */
#define LINEP_RESULT_OK            0x00u
#define LINEP_RESULT_REJECTED      0x01u
#define LINEP_RESULT_TIMEOUT       0x02u
#define LINEP_RESULT_MODEL_ERROR   0x03u
#define LINEP_RESULT_INVALID_INPUT 0x04u
#define LINEP_RESULT_DEGRADED      0x05u

/* ── Slot-flag bit constants (mirrors linep::SlotFlags) ─────────────────── */
#define LINEP_SLOT_ALIVE         0x01u
#define LINEP_SLOT_READY         0x02u
#define LINEP_SLOT_BUSY          0x04u
#define LINEP_SLOT_DEGRADED      0x08u
#define LINEP_SLOT_ERROR         0x10u
#define LINEP_SLOT_THERMAL_LIMIT 0x20u
#define LINEP_SLOT_MODEL_LOADING 0x40u

/* ── Header-flag bit constants (mirrors linep::Flags) ───────────────────── */
#define LINEP_FLAG_ACK_REQUIRED   0x0001u
#define LINEP_FLAG_IS_ACK         0x0002u
#define LINEP_FLAG_ERROR          0x0004u
#define LINEP_FLAG_COMPRESSED     0x0008u
#define LINEP_FLAG_ENCRYPTED      0x0010u
#define LINEP_FLAG_FRAGMENTED     0x0020u
#define LINEP_FLAG_FINAL_FRAGMENT 0x0040u
#define LINEP_FLAG_PRIORITY       0x0080u
#define LINEP_FLAG_DEGRADED       0x0100u
#define LINEP_FLAG_RETRY          0x0200u
#define LINEP_FLAG_BUILD_TIME     0x0400u  /* v1.1 extension present */

/* ── Opaque handle types ─────────────────────────────────────────────────── */
typedef struct linep_sender_s   linep_sender_t;
typedef struct linep_receiver_s linep_receiver_t;

/* ── Task callback (server-side, matches linep::tcp::ITcpTaskReceiver::TaskCallback) */
/*
 * Called once per TASK frame accepted by the receiver.
 *
 * task_type      : one of LINEP_TASK_* constants.
 * correlation_id : echoed back in the RESULT header.
 * worker_id      : from the inbound TASK header.
 * slot_id        : from the inbound TASK header.
 * payload        : raw task body (caller must NOT free).
 * payload_len    : bytes in payload.
 * result_buf     : write the result body here (max result_cap bytes).
 * result_cap     : capacity of result_buf.
 * result_len     : set *result_len to bytes actually written.
 * user_data      : pointer passed to linep_receiver_start().
 *
 * Returns: one of the LINEP_RESULT_* constants.
 */
typedef uint8_t (*linep_task_cb_t)(
    uint8_t        task_type,
    uint32_t       correlation_id,
    uint16_t       worker_id,
    uint8_t        slot_id,
    const uint8_t* payload,
    uint32_t       payload_len,
    uint8_t*       result_buf,
    uint32_t       result_cap,
    uint32_t*      result_len,
    void*          user_data);

#ifdef __cplusplus
extern "C" {
#endif

/* ── Network lifecycle ───────────────────────────────────────────────────── */

/* Must be called once before any TCP/UDP operations (WSAStartup on Windows). */
LINEP_API void linep_net_init(void);

/* Returns C ABI version as MAJOR<<16 | MINOR<<8 | PATCH. */
LINEP_API uint32_t linep_get_abi_version(void);

/* Call once at shutdown to release network resources. */
LINEP_API void linep_net_cleanup(void);

/* ── Low-level CRC ───────────────────────────────────────────────────────── */

/* CRC-8 (poly=0x07, init=0x00, no reflection) over len bytes. */
LINEP_API uint8_t linep_crc8(const uint8_t* data, uint32_t len);

/* ── Framing — Header ────────────────────────────────────────────────────── */

/*
 * Build a linep_header_t and fill out->header_crc.
 * Returns LINEP_C_OK or LINEP_C_ERR_ARG if out is NULL.
 */
LINEP_API int linep_make_header(
    uint8_t         msg_type,
    uint16_t        flags,
    uint32_t        payload_len,
    uint32_t        sequence,
    uint32_t        correlation_id,
    uint16_t        worker_id,
    uint8_t         slot_id,
    linep_header_t* out);

/*
 * Apply the v1.1 build-time extension to an already-built header.
 * Sets FLAG_BUILD_TIME, bumps header_len to 30, recomputes header_crc.
 * Fills ext_out with the 6 extension bytes to append after the header.
 * Returns LINEP_C_OK or LINEP_C_ERR_ARG.
 */
LINEP_API int linep_apply_build_time_ext(
    linep_header_t*         header,
    linep_build_time_ext_t* ext_out);

/*
 * Validate magic, version, header_len and CRC-8.
 * Returns LINEP_C_OK if the frame is well-formed, LINEP_C_ERR_BAD_FRAME otherwise.
 */
LINEP_API int linep_validate_header(const linep_header_t* h);

/* ── Framing — HeartbeatCompact ─────────────────────────────────────────── */

/*
 * Build a HeartbeatCompact frame and compute its CRC-8.
 * Returns LINEP_C_OK or LINEP_C_ERR_ARG if out is NULL.
 */
LINEP_API int linep_make_heartbeat_compact(
    uint16_t                    worker_id,
    uint8_t                     slot_id,
    uint8_t                     slot_flags,
    uint8_t                     load,
    uint8_t                     queue_depth,
    uint8_t                     sequence,
    uint16_t                    worker_score,
    uint8_t                     ts_month,
    uint8_t                     ts_day,
    uint8_t                     ts_hour,
    uint8_t                     ts_minute,
    uint8_t                     ts_second,
    linep_heartbeat_compact_t*  out);

/*
 * Validate magic, version, msg_type and CRC-8 of a HeartbeatCompact frame.
 * Returns LINEP_C_OK or LINEP_C_ERR_BAD_FRAME.
 */
LINEP_API int linep_validate_heartbeat_compact(
    const linep_heartbeat_compact_t* h);

/* ── Framing — UDP Control Frames ────────────────────────────────────────── */

LINEP_API int linep_make_udp_invite(
    uint8_t             invite_seq,
    uint16_t            worker_id,
    uint8_t             slot_id,
    uint32_t            lease_ttl_ms,
    uint32_t            session_token,
    linep_udp_invite_t* out);

LINEP_API int linep_validate_udp_invite(const linep_udp_invite_t* f);

LINEP_API int linep_make_udp_invite_ack(
    uint8_t                 invite_seq,
    uint16_t                worker_id,
    uint8_t                 slot_id,
    uint8_t                 accepted,
    uint32_t                session_token,
    linep_udp_invite_ack_t* out);

LINEP_API int linep_validate_udp_invite_ack(const linep_udp_invite_ack_t* f);

LINEP_API int linep_make_udp_heartbeat_ack(
    uint8_t                    heartbeat_seq,
    uint16_t                   worker_id,
    uint8_t                    slot_id,
    uint32_t                   scheduler_time_sec,
    linep_udp_heartbeat_ack_t* out);

LINEP_API int linep_validate_udp_heartbeat_ack(const linep_udp_heartbeat_ack_t* f);

/* ── TCP Task Sender ─────────────────────────────────────────────────────── */

/* Allocate a sender handle.  Returns NULL on allocation failure. */
LINEP_API linep_sender_t* linep_sender_create(void);

/* Free a sender handle created by linep_sender_create(). */
LINEP_API void linep_sender_destroy(linep_sender_t* s);

/*
 * Connect to host:port, send a TASK frame, wait for RESULT.
 * Opens a fresh TCP connection per call (stateless).
 *
 * task_type      : one of LINEP_TASK_* constants.
 * correlation_id : request identifier, echoed in RESULT header.
 * worker_id      : routed worker id (placed in TASK header).
 * slot_id        : target slot on the worker.
 * payload        : raw task body bytes.
 * payload_len    : length of payload in bytes.
 * result_buf     : caller-allocated output buffer.
 * result_len     : [in]  capacity of result_buf.
 *                  [out] bytes written on LINEP_C_OK.
 * timeout_ms     : per-call timeout (default 5000 ms).
 *
 * Returns: LINEP_C_OK on success, or one of the LINEP_C_ERR_* codes.
 *          On LINEP_C_OK the leading byte of result_buf is the
 *          LINEP_RESULT_* status sent by the worker.
 */
LINEP_API int linep_sender_send_task(
    linep_sender_t* s,
    const char*     host,
    uint16_t        port,
    uint8_t         task_type,
    uint32_t        correlation_id,
    uint16_t        worker_id,
    uint8_t         slot_id,
    const uint8_t*  payload,
    uint32_t        payload_len,
    uint8_t*        result_buf,
    uint32_t*       result_len,
    uint32_t        timeout_ms);

LINEP_API int linep_sender_set_sl1_session(
    linep_sender_t* s,
    uint32_t        session_id,
    uint16_t        key_id,
    const uint8_t*  secret_key,
    uint32_t        key_len);

LINEP_API void linep_sender_clear_sl1_session(linep_sender_t* s);

/* ── TCP Task Receiver ───────────────────────────────────────────────────── */

/* Allocate a receiver handle.  Returns NULL on allocation failure. */
LINEP_API linep_receiver_t* linep_receiver_create(void);

/* Free a receiver handle.  Calls linep_receiver_stop() if still running. */
LINEP_API void linep_receiver_destroy(linep_receiver_t* r);

/*
 * Bind to port and start accepting TASK frames.
 * cb is called once per accepted task from a background thread.
 * Returns LINEP_C_OK or LINEP_C_ERR_PORT if the port cannot be bound.
 */
LINEP_API int linep_receiver_start(
    linep_receiver_t* r,
    uint16_t          port,
    linep_task_cb_t   cb,
    void*             user_data);

LINEP_API int linep_receiver_set_sl1_session(
    linep_receiver_t* r,
    uint32_t        session_id,
    uint16_t        key_id,
    const uint8_t*  secret_key,
    uint32_t        key_len,
    int             require_auth);

LINEP_API void linep_receiver_clear_sl1_session(linep_receiver_t* r);

/*
 * Stop accepting new connections and wait for active handlers to finish.
 * Safe to call from any thread.  No-op if not running.
 */
LINEP_API void linep_receiver_stop(linep_receiver_t* r);

#ifdef __cplusplus
} /* extern "C" */
#endif
