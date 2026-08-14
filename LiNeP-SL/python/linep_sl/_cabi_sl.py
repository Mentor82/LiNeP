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

typedef struct {
    uint32_t trust_domain_id;
    uint16_t node_id;
    uint8_t  pubkey[32];
    uint8_t  revoked;
} linep_sl2_peer_identity_t;

typedef struct {
    uint32_t session_id;
    uint16_t key_id;
    uint64_t established_at_sec;
    uint64_t expires_at_sec;
    uint8_t  secret_key[32];
} linep_sl2_session_key_t;

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

int linep_sl2_negotiate_level(
    uint8_t peer_supported,
    uint8_t local_supported,
    uint8_t local_required,
    uint8_t* out_negotiated);

int linep_sl2_validate_peer_identity(
    const linep_sl2_peer_identity_t* peer,
    uint32_t expected_trust_domain);

int linep_sl2_derive_session_key(
    const uint8_t* master_secret, uint32_t master_len,
    uint32_t session_id, uint16_t key_id,
    uint16_t node_id, uint64_t ttl_sec,
    uint64_t current_time_sec,
    linep_sl2_session_key_t* out_key);

int linep_sl2_verify_session_key_freshness(
    const linep_sl2_session_key_t* key,
    uint64_t current_time_sec);

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

typedef struct linep_sl4_engine linep_sl4_engine_t;

typedef struct {
    uint32_t trust_domain_id;
    uint32_t session_id;
    uint16_t key_id;
    uint16_t local_node_id;
    uint16_t remote_node_id;
    uint32_t remote_trust_domain_id;
    uint8_t  remote_revoked;
    uint8_t  negotiated_sl;
    uint64_t requested_cap;
    uint8_t  msg_type;
    uint32_t correlation_id;
    const char* policy_id;
    uint32_t established_policy_revision;
    uint64_t timestamp_sec;
} linep_sl4_decision_context_t;

linep_sl4_engine_t* linep_sl4_engine_create(uint32_t local_trust_domain_id);
void linep_sl4_engine_free(linep_sl4_engine_t* engine);

int linep_sl4_engine_register_peer(
    linep_sl4_engine_t* engine, uint16_t node_id, const uint8_t* pubkey_32bytes);

int linep_sl4_engine_set_policy(
    linep_sl4_engine_t* engine, const char* policy_id, uint32_t revision, uint64_t allowed_caps, uint8_t allow_cross_domain);

int linep_sl4_engine_add_federation(
    linep_sl4_engine_t* engine, uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps, uint32_t revision);

int linep_sl4_engine_revoke_federation(
    linep_sl4_engine_t* engine, uint32_t local_domain, uint32_t remote_domain);

int linep_sl4_engine_evaluate(
    linep_sl4_engine_t* engine,
    uint32_t trust_domain_id,
    uint32_t session_id,
    uint16_t key_id,
    uint16_t local_node_id,
    uint16_t remote_node_id,
    uint32_t remote_trust_domain_id,
    const uint8_t* remote_pubkey_32bytes,
    uint8_t  remote_revoked,
    uint8_t  negotiated_sl,
    uint64_t requested_cap,
    uint8_t  msg_type,
    uint32_t correlation_id,
    const char* policy_id,
    uint32_t established_policy_revision,
    uint64_t timestamp_sec,
    uint8_t* out_decision,
    char* out_reason_buf,
    uint32_t reason_buf_len);

uint32_t linep_sl4_engine_get_audit_count(linep_sl4_engine_t* engine);

int linep_sl4_evaluate_decision(
    uint32_t trust_domain_id,
    uint32_t session_id,
    uint16_t key_id,
    uint16_t remote_node_id,
    uint32_t remote_trust_domain_id,
    uint8_t  remote_revoked,
    uint8_t  negotiated_sl,
    uint64_t requested_cap,
    const char* policy_id,
    uint8_t* out_decision,
    char* out_reason_buf,
    uint32_t reason_buf_len);
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
