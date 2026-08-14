"""
linep._cabi
-----------
Raw cffi layer — not part of the public API.

This module loads ``liblinep`` (``linep.dll`` on Windows, ``liblinep.so`` on
Linux) and exposes the C-ABI functions declared in ``include/linep/cabi.h``.

Library discovery order
~~~~~~~~~~~~~~~~~~~~~~~
1. ``LINEP_LIB_PATH`` environment variable (full path to the shared library).
2. Directory of this file (useful when a wheel bundles the compiled library).
3. Standard OS library search paths (``PATH`` on Windows, ``LD_LIBRARY_PATH``
   / ``/usr/local/lib`` etc. on Linux/macOS).

All higher-level modules import ``ffi`` and ``lib`` from here::

    from linep._cabi import ffi, lib
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cffi import FFI

# ---------------------------------------------------------------------------
# cffi type / function declarations
# ---------------------------------------------------------------------------
# This is a clean subset of include/linep/cabi.h suitable for ffi.cdef():
# no preprocessor directives, no C++ comments, no #pragma.
# Integer constants are expressed as anonymous enums so cffi makes them
# accessible as lib.LINEP_C_OK, lib.LINEP_MSG_TASK etc.
# ---------------------------------------------------------------------------

_CDEF = """
/* ── Error / return codes ─────────────────────────────────────────────── */
enum {
    LINEP_C_OK            =  0,
    LINEP_C_ERR_ARG       = -1,
    LINEP_C_ERR_TIMEOUT   = -2,
    LINEP_C_ERR_CONNECT   = -3,
    LINEP_C_ERR_SEND      = -4,
    LINEP_C_ERR_RECV      = -5,
    LINEP_C_ERR_BAD_FRAME = -6,
    LINEP_C_ERR_PORT      = -7,
    LINEP_C_ERR_INTERNAL  = -8,
    LINEP_C_ERR_BUF_SMALL = -9
};

enum {
    LINEP_C_ABI_VERSION_V0_1_0 = 0x00000100
};

/* ── Message-type constants ───────────────────────────────────────────── */
enum {
    LINEP_MSG_HEARTBEAT           = 0x01,
    LINEP_MSG_REGISTER            = 0x02,
    LINEP_MSG_REGISTER_ACK        = 0x03,
    LINEP_MSG_BYE                 = 0x04,
    LINEP_MSG_INVITE              = 0x05,
    LINEP_MSG_INVITE_ACK          = 0x06,
    LINEP_MSG_HEARTBEAT_ACK       = 0x07,
    LINEP_MSG_TASK                = 0x10,
    LINEP_MSG_TASK_ACK            = 0x11,
    LINEP_MSG_RESULT              = 0x12,
    LINEP_MSG_ERROR               = 0x13,
    LINEP_MSG_TASK_CANCEL         = 0x14,
    LINEP_MSG_STATUS_REQUEST      = 0x20,
    LINEP_MSG_STATUS_RESPONSE     = 0x21,
    LINEP_MSG_EMBED_REQUEST       = 0x30,
    LINEP_MSG_EMBED_RESPONSE      = 0x31,
    LINEP_MSG_SIMILARITY_REQUEST  = 0x32,
    LINEP_MSG_SIMILARITY_RESPONSE = 0x33,
    LINEP_MSG_CONSENSUS_REQUEST   = 0x40,
    LINEP_MSG_CONSENSUS_RESPONSE  = 0x41,
    LINEP_MSG_PING                = 0xF0,
    LINEP_MSG_PONG                = 0xF1
};

/* ── Task-type constants ──────────────────────────────────────────────── */
enum {
    LINEP_TASK_INSTRUCT       = 0x01,
    LINEP_TASK_CODE           = 0x02,
    LINEP_TASK_SUMMARIZE      = 0x03,
    LINEP_TASK_CLASSIFY       = 0x04,
    LINEP_TASK_VALIDATE       = 0x05,
    LINEP_TASK_EDGE_TEXT_EVAL = 0x06
};

/* ── Result-status constants ─────────────────────────────────────────── */
enum {
    LINEP_RESULT_OK            = 0x00,
    LINEP_RESULT_REJECTED      = 0x01,
    LINEP_RESULT_TIMEOUT       = 0x02,
    LINEP_RESULT_MODEL_ERROR   = 0x03,
    LINEP_RESULT_INVALID_INPUT = 0x04,
    LINEP_RESULT_DEGRADED      = 0x05
};

/* ── Slot-flag bit constants ─────────────────────────────────────────── */
enum {
    LINEP_SLOT_ALIVE         = 0x01,
    LINEP_SLOT_READY         = 0x02,
    LINEP_SLOT_BUSY          = 0x04,
    LINEP_SLOT_DEGRADED      = 0x08,
    LINEP_SLOT_ERROR         = 0x10,
    LINEP_SLOT_THERMAL_LIMIT = 0x20,
    LINEP_SLOT_MODEL_LOADING = 0x40
};

/* ── Header-flag bit constants ───────────────────────────────────────── */
enum {
    LINEP_FLAG_ACK_REQUIRED   = 0x0001,
    LINEP_FLAG_IS_ACK         = 0x0002,
    LINEP_FLAG_ERROR          = 0x0004,
    LINEP_FLAG_COMPRESSED     = 0x0008,
    LINEP_FLAG_ENCRYPTED      = 0x0010,
    LINEP_FLAG_FRAGMENTED     = 0x0020,
    LINEP_FLAG_FINAL_FRAGMENT = 0x0040,
    LINEP_FLAG_PRIORITY       = 0x0080,
    LINEP_FLAG_DEGRADED       = 0x0100,
    LINEP_FLAG_RETRY          = 0x0200,
    LINEP_FLAG_BUILD_TIME     = 0x0400
};

/* ── Packed structs ──────────────────────────────────────────────────── */
typedef struct {
    uint16_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t header_len;
    uint16_t flags;
    uint32_t payload_len;
    uint32_t sequence;
    uint32_t correlation_id;
    uint16_t worker_id;
    uint8_t  slot_id;
    uint8_t  header_crc;
} linep_header_t;

typedef struct {
    uint16_t magic;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t worker_id;
    uint8_t  slot_id;
    uint8_t  slot_flags;
    uint8_t  load;
    uint8_t  queue_depth;
    uint8_t  sequence;
    uint16_t worker_score;
    uint8_t  ts_month;
    uint8_t  ts_day;
    uint8_t  ts_hour;
    uint8_t  ts_minute;
    uint8_t  ts_second;
    uint8_t  crc8;
} linep_heartbeat_compact_t;

typedef struct {
    uint8_t year_2d;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
} linep_build_time_ext_t;

typedef struct {
    uint8_t  msg_type;
    uint8_t  invite_seq;
    uint16_t worker_id;
    uint8_t  slot_id;
    uint32_t lease_ttl_ms;
    uint32_t session_token;
    uint8_t  crc8;
} linep_udp_invite_t;

typedef struct {
    uint8_t  msg_type;
    uint8_t  invite_seq;
    uint16_t worker_id;
    uint8_t  slot_id;
    uint8_t  accepted;
    uint32_t session_token;
    uint8_t  crc8;
} linep_udp_invite_ack_t;

typedef struct {
    uint8_t  msg_type;
    uint8_t  heartbeat_seq;
    uint16_t worker_id;
    uint8_t  slot_id;
    uint32_t scheduler_time_sec;
    uint8_t  crc8;
} linep_udp_heartbeat_ack_t;

/* ── Opaque handles ──────────────────────────────────────────────────── */
typedef struct linep_sender_s   linep_sender_t;
typedef struct linep_receiver_s linep_receiver_t;

/* ── Task callback ───────────────────────────────────────────────────── */
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

/* ── Functions ───────────────────────────────────────────────────────── */
void    linep_net_init(void);
uint32_t linep_get_abi_version(void);
void    linep_net_cleanup(void);

uint8_t linep_crc8(const uint8_t* data, uint32_t len);

int     linep_make_header(
            uint8_t msg_type, uint16_t flags, uint32_t payload_len,
            uint32_t sequence, uint32_t correlation_id,
            uint16_t worker_id, uint8_t slot_id,
            linep_header_t* out);

int     linep_apply_build_time_ext(
            linep_header_t* header, linep_build_time_ext_t* ext_out);

int     linep_validate_header(const linep_header_t* h);

int     linep_make_heartbeat_compact(
            uint16_t worker_id, uint8_t slot_id, uint8_t slot_flags,
            uint8_t load, uint8_t queue_depth, uint8_t sequence,
            uint16_t worker_score,
            uint8_t ts_month, uint8_t ts_day, uint8_t ts_hour,
            uint8_t ts_minute, uint8_t ts_second,
            linep_heartbeat_compact_t* out);

int     linep_validate_heartbeat_compact(const linep_heartbeat_compact_t* h);

int     linep_make_udp_invite(
            uint8_t invite_seq, uint16_t worker_id, uint8_t slot_id,
            uint32_t lease_ttl_ms, uint32_t session_token,
            linep_udp_invite_t* out);

int     linep_validate_udp_invite(const linep_udp_invite_t* f);

int     linep_make_udp_invite_ack(
            uint8_t invite_seq, uint16_t worker_id, uint8_t slot_id,
            uint8_t accepted, uint32_t session_token,
            linep_udp_invite_ack_t* out);

int     linep_validate_udp_invite_ack(const linep_udp_invite_ack_t* f);

int     linep_make_udp_heartbeat_ack(
            uint8_t heartbeat_seq, uint16_t worker_id, uint8_t slot_id,
            uint32_t scheduler_time_sec,
            linep_udp_heartbeat_ack_t* out);

int     linep_validate_udp_heartbeat_ack(const linep_udp_heartbeat_ack_t* f);

linep_sender_t*   linep_sender_create(void);
void              linep_sender_destroy(linep_sender_t* s);

int               linep_sender_send_task(
                      linep_sender_t* s,
                      const char* host, uint16_t port,
                      uint8_t task_type, uint32_t correlation_id,
                      uint16_t worker_id, uint8_t slot_id,
                      const uint8_t* payload, uint32_t payload_len,
                      uint8_t* result_buf, uint32_t* result_len,
                      uint32_t timeout_ms);

linep_receiver_t* linep_receiver_create(void);
void              linep_receiver_destroy(linep_receiver_t* r);

int               linep_receiver_start(
                      linep_receiver_t* r,
                      uint16_t port,
                      linep_task_cb_t cb,
                      void* user_data);

void              linep_receiver_stop(linep_receiver_t* r);
"""

# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

ffi = FFI()
ffi.cdef(_CDEF, packed=True)


def _candidate_libraries() -> list[str]:
    """Return candidate shared-library paths in priority order.

    Development builds are preferred over bundled package binaries so code
    changes are picked up without manually setting LINEP_LIB_PATH every time.
    """
    candidates: list[str] = []

    # 1. Explicit override via environment variable.
    env_path = os.environ.get("LINEP_LIB_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return [str(p)]
        raise OSError(
            f"LINEP_LIB_PATH is set to '{env_path}' but the file does not exist."
        )

    # 2. Repository build outputs (dev workflow).
    repo_root = Path(__file__).resolve().parents[2]
    if sys.platform == "win32":
        candidates.extend([
            str(repo_root / "build" / "liblinep.dll"),
            str(repo_root / "build" / "linep.dll"),
            str(repo_root / "build-win-x64" / "liblinep.dll"),
            str(repo_root / "build-win-x64" / "linep.dll"),
        ])
    elif sys.platform == "darwin":
        candidates.extend([
            str(repo_root / "build" / "liblinep.dylib"),
            str(repo_root / "build-macos-arm64" / "liblinep.dylib"),
            str(repo_root / "build-macos-x64" / "liblinep.dylib"),
            str(repo_root / "build-macos-universal" / "liblinep.dylib"),
        ])
    else:
        candidates.extend([
            str(repo_root / "build" / "liblinep.so"),
            str(repo_root / "build" / "liblinep.so.1"),
            str(repo_root / "build-linux-x64" / "liblinep.so"),
            str(repo_root / "build-linux-arm64" / "liblinep.so"),
        ])

    # 3. Alongside this file (wheel bundles the compiled library next to _cabi.py).
    pkg_dir = Path(__file__).parent
    if sys.platform == "win32":
        candidates.extend([str(pkg_dir / "linep.dll"), str(pkg_dir / "liblinep.dll")])
    elif sys.platform == "darwin":
        candidates.extend([str(pkg_dir / "liblinep.dylib"), str(pkg_dir / "liblinep.1.dylib")])
    else:
        candidates.extend([str(pkg_dir / "liblinep.so"), str(pkg_dir / "liblinep.so.1")])

    existing = [c for c in candidates if Path(c).is_file()]
    if existing:
        return existing

    # 4. OS search path fallback — let loader resolve it.
    if sys.platform == "win32":
        return ["linep.dll", "liblinep.dll"]
    if sys.platform == "darwin":
        return ["liblinep.dylib", "liblinep.1.dylib"]
    return ["liblinep.so.1", "liblinep.so"]


def _load_library():
    """Load the first working shared library from candidate list."""
    errors: list[str] = []
    for candidate in _candidate_libraries():
        try:
            return ffi.dlopen(candidate)
        except Exception as exc:  # noqa: BLE001 - keep trying fallbacks
            errors.append(f"{candidate}: {exc}")
    joined = "\n".join(errors)
    raise OSError(f"Could not load LiNeP shared library from candidates:\n{joined}")


# On Windows, add the package directory to the DLL search path so that
# bundled runtime DLLs (libstdc++-6.dll, libgcc_s_seh-1.dll) are found
# when loading liblinep.dll.  os.add_dll_directory is available on Python 3.8+.
if sys.platform == "win32":
    import os
    _pkg_dir = str(Path(__file__).parent)
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_pkg_dir)

lib = _load_library()
