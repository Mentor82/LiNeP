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


def test_sl2_capability_token_python():
    _ensure_linep_sl_lib_path()
    import linep_sl

    secret = b"SL2_SECRET_KEY_99999"
    session_id = 0xCAFE0001
    granted_caps = linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.METRICS_READ
    expires_at = 2000000000

    token = linep_sl.create_capability_token(secret, session_id, granted_caps, expires_at)
    assert token.session_id == session_id
    assert token.granted_caps == granted_caps
    assert len(token.mac) == 16

    current_time = 1700000000
    # 1. Valid capability check
    read_ok = linep_sl.verify_capability_token(secret, token, session_id, current_time, linep_sl.CapFlags.INFERENCE_READ)
    assert read_ok is True

    # 2. Reject ungranted capability (ADMIN)
    admin_ok = linep_sl.verify_capability_token(secret, token, session_id, current_time, linep_sl.CapFlags.ADMIN)
    assert admin_ok is False

    # 3. Reject expired token
    expired_time = 2000000001
    expired_ok = linep_sl.verify_capability_token(secret, token, session_id, expired_time, linep_sl.CapFlags.INFERENCE_READ)
    assert expired_ok is False
