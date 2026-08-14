from __future__ import annotations

from linep_sl._cabi_sl import ffi, lib


def compute_sl1_mac(
    secret_key: bytes,
    header_bytes: bytes,
    session_id: int,
    key_id: int,
    auth_seq: int,
    payload: bytes = b"",
) -> bytes:
    if not secret_key:
        raise ValueError("secret_key must not be empty")
    if len(header_bytes) < 24:
        raise ValueError("header_bytes must be at least 24 bytes")

    c_secret = ffi.from_buffer(bytes(secret_key))
    c_hdr = ffi.from_buffer(bytes(header_bytes))
    c_payload = ffi.from_buffer(bytes(payload)) if payload else ffi.NULL
    out_mac = ffi.new("uint8_t[16]")

    rc = lib.linep_sl1_compute_mac(
        c_secret,
        len(secret_key),
        c_hdr,
        session_id,
        key_id,
        auth_seq,
        c_payload,
        len(payload),
        out_mac,
    )
    if rc != 1:
        raise RuntimeError("linep_sl1_compute_mac failed")
    return bytes(ffi.buffer(out_mac, 16))


def verify_sl1_mac(
    secret_key: bytes,
    header_bytes: bytes,
    session_id: int,
    key_id: int,
    auth_seq: int,
    mac: bytes,
    payload: bytes = b"",
) -> bool:
    if len(mac) != 16:
        return False

    auth_ext = ffi.new("linep_sl_auth_ext_t *")
    auth_ext.session_id = session_id
    auth_ext.key_id = key_id
    auth_ext.auth_seq = auth_seq
    ffi.memmove(auth_ext.mac, mac, 16)

    c_secret = ffi.from_buffer(bytes(secret_key))
    c_hdr = ffi.from_buffer(bytes(header_bytes))
    c_payload = ffi.from_buffer(bytes(payload)) if payload else ffi.NULL

    rc = lib.linep_sl1_verify_mac(
        c_secret,
        len(secret_key),
        c_hdr,
        auth_ext,
        c_payload,
        len(payload),
    )
    return rc == 1
