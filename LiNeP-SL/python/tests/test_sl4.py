from __future__ import annotations

import os
import sys
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


def test_sl4_persistent_security_engine():
    _ensure_linep_sl_lib_path()
    import linep_sl

    domain_a = 0x4C4E5031
    domain_b = 0x4C4E5032
    pubkey = b"\xaa" * 32

    # Instantiate persistent engine
    engine = linep_sl.SecurityDecisionEngine(domain_a)
    engine.register_peer(10, pubkey)

    # 1. Same-Domain Valid Request -> ALLOW
    dec1, reason1 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec1 == linep_sl.Decision.ALLOW
    assert reason1 == "GOVERNANCE_POLICY_ALLOWED"

    # 2. Cross-Domain without Federation -> DENY
    dec2, reason2 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec2 == linep_sl.Decision.DENY
    assert reason2 == "CROSS_DOMAIN_FEDERATION_DENIED"

    # 3. Add Federation Trust BUT policy allow_cross_domain is False -> DENY
    engine.add_federation(domain_a, domain_b, linep_sl.CapFlags.INFERENCE_READ)
    dec3, reason3 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec3 == linep_sl.Decision.DENY
    assert reason3 == "GOVERNANCE_POLICY_CROSS_DOMAIN_DENIED"

    # 4. Enable allow_cross_domain in policy -> ALLOW!
    pol = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=2,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ,
        allow_cross_domain=True,
    )
    engine.set_policy(pol)

    dec4, reason4 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
        established_policy_revision=2,
    )
    assert dec4 == linep_sl.Decision.ALLOW
    assert reason4 == "GOVERNANCE_POLICY_ALLOWED"
    assert engine.get_audit_count() >= 5
