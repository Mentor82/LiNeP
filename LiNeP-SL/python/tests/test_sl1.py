from __future__ import annotations

import os
from pathlib import Path
import pytest


def _ensure_linep_sl_lib_path() -> None:
    if os.environ.get("LINEP_SL_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "build" / "src" / "liblinep_sl.dll"
    if candidate.exists():
        os.environ["LINEP_SL_LIB_PATH"] = str(candidate)


def test_sl1_mac_python():
    _ensure_linep_sl_lib_path()
    import linep_sl

    secret = b"SECRET_KEY_12345"
    hdr = b"LN\x01\x10\x38\x00\x08\x00\x08\x00\x00\x00\x64\x00\x00\x00\x2a\x00\x00\x00\x01\x00\x00\xab"
    session_id = 0x12345678
    key_id = 1
    auth_seq = 100
    payload = b"TESTDATA"

    mac = linep_sl.compute_sl1_mac(secret, hdr, session_id, key_id, auth_seq, payload)
    assert len(mac) == 16

    ok = linep_sl.verify_sl1_mac(secret, hdr, session_id, key_id, auth_seq, mac, payload)
    assert ok is True

    # Tampered payload check
    tampered_ok = linep_sl.verify_sl1_mac(secret, hdr, session_id, key_id, auth_seq, mac, b"XESTDATA")
    assert tampered_ok is False

    # Wrong secret key check
    wrong_key_ok = linep_sl.verify_sl1_mac(b"WRONGKEY00000000000", hdr, session_id, key_id, auth_seq, mac, payload)
    assert wrong_key_ok is False
