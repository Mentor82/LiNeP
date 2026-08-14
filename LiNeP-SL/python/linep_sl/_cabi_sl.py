from __future__ import annotations

import os
import sys
from pathlib import Path
from cffi import FFI

_CDEF = """
typedef struct {
    uint32_t session_id;
    uint16_t key_id;
    uint32_t auth_seq;
    uint8_t  mac[16];
} linep_sl_auth_ext_t;

typedef struct {
    uint32_t session_id;
    uint64_t granted_caps;
    uint64_t expires_at_sec;
    uint8_t  cap_mac[16];
} linep_sl_cap_ext_t;

int linep_sl1_compute_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, uint32_t payload_len,
    uint8_t out_mac[16]);

int linep_sl1_verify_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, const linep_sl_auth_ext_t* auth_ext,
    const uint8_t* payload, uint32_t payload_len);

int linep_sl3_create_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    uint32_t session_id, uint64_t granted_caps,
    uint64_t expires_at_sec, linep_sl_cap_ext_t* out_token);

int linep_sl3_verify_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    const linep_sl_cap_ext_t* cap_token,
    uint32_t expected_session_id,
    uint64_t current_time_sec,
    uint64_t required_capability);
"""

ffi = FFI()
ffi.cdef(_CDEF, packed=True)


def _candidate_libraries() -> list[str]:
    env_path = os.environ.get("LINEP_SL_LIB_PATH")
    if env_path:
        return [env_path]

    repo_root = Path(__file__).resolve().parents[2]
    build_dir = repo_root / "build" / "src"

    names = ["liblinep_sl.dll", "linep_sl.dll", "liblinep_sl.so", "liblinep_sl.dylib"]
    candidates = []
    for name in names:
        p = build_dir / name
        if p.is_file():
            candidates.append(str(p))

    pkg_dir = Path(__file__).parent
    for name in names:
        p = pkg_dir / name
        if p.is_file():
            candidates.append(str(p))

    return candidates


lib = None
_load_error = None

for path in _candidate_libraries():
    if os.path.exists(path):
        if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
            parent_dir = str(Path(path).parent)
            try:
                os.add_dll_directory(parent_dir)
            except Exception:
                pass
            gcc_dir = r"C:\Strawberry\c\bin"
            if os.path.exists(gcc_dir):
                try:
                    os.add_dll_directory(gcc_dir)
                except Exception:
                    pass

        try:
            lib = ffi.dlopen(path)
            break
        except Exception as e:
            _load_error = e

if lib is None:
    class DummyLib:
        def __getattr__(self, name):
            raise RuntimeError(
                f"liblinep_sl shared library is not loaded. Build LiNeP-SL first or set LINEP_SL_LIB_PATH. Error: {_load_error}"
            )
    lib = DummyLib()
