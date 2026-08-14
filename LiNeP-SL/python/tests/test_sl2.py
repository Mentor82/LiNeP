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
    pubkey_a = b"\xab" * 32

    provider = linep_sl.MemoryIdentityProvider(trust_domain)
    provider.register_peer(42, pubkey_a)

    valid_peer = linep_sl.PeerIdentity(
        trust_domain_id=trust_domain,
        node_id=42,
        pubkey=pubkey_a,
        revoked=False,
    )

    # 1. Valid peer identity check
    assert provider.is_peer_trusted(valid_peer, trust_domain) is True

    # 2. Reject revoked identity
    provider.revoke_peer(42)
    assert provider.is_peer_trusted(valid_peer, trust_domain) is False

    # 3. Security Level Negotiation & Downgrade Protection
    ok, sl = linep_sl.negotiate_security_level(
        linep_sl.SecurityLevel.SL2_IDENTITY,
        linep_sl.SecurityLevel.SL3_CAPABILITIES,
        linep_sl.SecurityLevel.SL2_IDENTITY,
    )
    assert ok is True
    assert sl == linep_sl.SecurityLevel.SL2_IDENTITY

    # Downgrade rejected
    ok_downgrade, sl_downgrade = linep_sl.negotiate_security_level(
        linep_sl.SecurityLevel.SL1_AUTH, # Peer supports SL1
        linep_sl.SecurityLevel.SL3_CAPABILITIES,
        linep_sl.SecurityLevel.SL2_IDENTITY, # Required SL2
    )
    assert ok_downgrade is False
    assert sl_downgrade == linep_sl.SecurityLevel.SL1_AUTH

    # 4. Session key derivation and freshness check
    master_secret = b"MASTER_SECRET_01"
    now = 1700000000
    ttl = 3600

    sk = linep_sl.derive_session_key(master_secret, session_id=0x1001, key_id=1, node_id=42, ttl_sec=ttl, current_time_sec=now)
    assert sk.session_id == 0x1001
    assert sk.key_id == 1
    assert len(sk.secret_key) == 32

    assert linep_sl.verify_session_key_freshness(sk, now + 100) is True
    assert linep_sl.verify_session_key_freshness(sk, now + ttl + 1) is False
