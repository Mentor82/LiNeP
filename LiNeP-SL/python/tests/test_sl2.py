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


def test_sl2_identity_and_kdf_python():
    _ensure_linep_sl_lib_path()
    import linep_sl

    trust_domain = 0x4C4E5031
    valid_peer = linep_sl.PeerIdentity(
        trust_domain_id=trust_domain,
        node_id=42,
        pubkey=b"\xab" * 32,
        revoked=False,
    )

    # 1. Valid peer identity check
    assert linep_sl.validate_peer_identity(valid_peer, trust_domain) is True

    # 2. Reject revoked identity
    revoked_peer = linep_sl.PeerIdentity(
        trust_domain_id=trust_domain,
        node_id=42,
        pubkey=b"\xab" * 32,
        revoked=True,
    )
    assert linep_sl.validate_peer_identity(revoked_peer, trust_domain) is False

    # 3. Session key derivation and freshness check
    master_secret = b"MASTER_SECRET_01"
    now = 1700000000
    ttl = 3600

    sk = linep_sl.derive_session_key(master_secret, session_id=0x1001, key_id=1, node_id=42, ttl_sec=ttl, current_time_sec=now)
    assert sk.session_id == 0x1001
    assert sk.key_id == 1
    assert len(sk.secret_key) == 32

    assert linep_sl.verify_session_key_freshness(sk, now + 100) is True
    assert linep_sl.verify_session_key_freshness(sk, now + ttl + 1) is False
