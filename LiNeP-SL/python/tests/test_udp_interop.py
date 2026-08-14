from __future__ import annotations

import os
import sys
import time
from pathlib import Path
import pytest


def _ensure_linep_sl_lib_path() -> None:
    if os.environ.get("LINEP_SL_LIB_PATH"):
        return
    repo_root = Path(__file__).resolve().parents[2]
    if sys.platform == "win32":
        candidate = repo_root / "build" / "src" / "liblinep_sl.dll"
    else:
        candidate = repo_root / "build_linux" / "src" / "liblinep_sl.so"
    if candidate.exists():
        os.environ["LINEP_SL_LIB_PATH"] = str(candidate)


def test_udp_heartbeat_security_invariants():
    _ensure_linep_sl_lib_path()
    import linep_sl

    domain_a = 0x4C4E5031
    domain_b = 0x4C4E5032
    master_secret = b"\x11\x22\x33\x44" * 8
    pubkey_node10 = b"\xbb" * 32

    now = int(time.time())
    session_id = 0x5001
    key_id = 1
    node_id = 10

    # Derive SL2 session key
    session_key = linep_sl.derive_session_key(master_secret, session_id, key_id, node_id, 3600, now)
    assert session_key is not None

    # Setup SL4 Security Decision Engine
    engine = linep_sl.SecurityDecisionEngine(domain_a)
    engine.register_peer(node_id, pubkey_node10)

    # Set policy with HEARTBEAT_EMIT capability
    pol = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=1,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ | linep_sl.CapFlags.HEARTBEAT_EMIT,
        allow_cross_domain=False,
    )
    engine.set_policy(pol)

    # Create capability token for HEARTBEAT_EMIT
    cap_token = linep_sl.create_capability_token(
        session_key.secret_key, session_id, linep_sl.CapFlags.HEARTBEAT_EMIT, now + 3600
    )

    # 1. Valid UDP Heartbeat capability token verification -> True
    ok_cap = linep_sl.verify_capability_token(
        session_key.secret_key, cap_token, session_id, now, linep_sl.CapFlags.HEARTBEAT_EMIT
    )
    assert ok_cap is True

    # 2. Valid SL4 Governance Evaluation for Heartbeat -> ALLOW
    dec1, reason1 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=session_id,
        key_id=key_id,
        local_node_id=1,
        remote_node_id=node_id,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.HEARTBEAT_EMIT,
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
    )
    assert dec1 == linep_sl.Decision.ALLOW
    assert reason1 == "GOVERNANCE_POLICY_ALLOWED"

    # 3. Heartbeat without HEARTBEAT_EMIT Capability -> DENIED
    dec3, reason3 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=session_id,
        key_id=key_id,
        local_node_id=1,
        remote_node_id=node_id,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.ADMIN,
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
    )
    assert dec3 == linep_sl.Decision.DENY
    assert reason3 == "GOVERNANCE_POLICY_CAPABILITY_DENIED"

    # 4. Cross-Domain Heartbeat without Federation -> DENIED
    dec4, reason4 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=session_id,
        key_id=key_id,
        local_node_id=1,
        remote_node_id=node_id,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.HEARTBEAT_EMIT,
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
    )
    assert dec4 == linep_sl.Decision.DENY
    assert reason4 == "CROSS_DOMAIN_FEDERATION_DENIED"
