from __future__ import annotations

from linep_sl._cabi_sl import ffi, lib
from linep_sl.constants import CapFlags


class CapabilityToken:
    __slots__ = ("session_id", "granted_caps", "expires_at_sec", "mac")

    def __init__(
        self,
        session_id: int,
        granted_caps: CapFlags | int,
        expires_at_sec: int,
        mac: bytes,
    ) -> None:
        self.session_id = session_id
        self.granted_caps = CapFlags(granted_caps)
        self.expires_at_sec = expires_at_sec
        self.mac = mac


def create_capability_token(
    secret_key: bytes,
    session_id: int,
    granted_caps: CapFlags | int,
    expires_at_sec: int,
) -> CapabilityToken:
    c_secret = ffi.from_buffer(bytes(secret_key))
    token_struct = ffi.new("linep_sl_cap_ext_t *")

    rc = lib.linep_sl3_create_cap_token(
        c_secret,
        len(secret_key),
        session_id,
        int(granted_caps),
        expires_at_sec,
        token_struct,
    )
    if rc != 1:
        raise RuntimeError("linep_sl3_create_cap_token failed")

    mac = bytes(ffi.buffer(token_struct.cap_mac, 16))
    return CapabilityToken(
        session_id=token_struct.session_id,
        granted_caps=token_struct.granted_caps,
        expires_at_sec=token_struct.expires_at_sec,
        mac=mac,
    )


def verify_capability_token(
    secret_key: bytes,
    token: CapabilityToken,
    expected_session_id: int,
    current_time_sec: int,
    required_capability: CapFlags | int,
) -> bool:
    c_secret = ffi.from_buffer(bytes(secret_key))
    token_struct = ffi.new("linep_sl_cap_ext_t *")
    token_struct.session_id = token.session_id
    token_struct.granted_caps = int(token.granted_caps)
    token_struct.expires_at_sec = token.expires_at_sec
    ffi.memmove(token_struct.cap_mac, token.mac, 16)

    rc = lib.linep_sl3_verify_cap_token(
        c_secret,
        len(secret_key),
        token_struct,
        expected_session_id,
        current_time_sec,
        int(required_capability),
    )
    return rc == 1
