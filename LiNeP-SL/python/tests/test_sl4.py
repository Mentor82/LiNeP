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


def test_sl4_persistent_security_engine_with_real_identity():
    _ensure_linep_sl_lib_path()
    import linep_sl

    domain_a = 0x4C4E5031
    domain_b = 0x4C4E5032
    pubkey_node10 = b"\xbb" * 32  # Real distinct pubkey!

    # Instantiate persistent engine and register REAL peer pubkey
    engine = linep_sl.SecurityDecisionEngine(domain_a)
    engine.register_peer(10, pubkey_node10)

    # 1. Same-Domain Valid Request passing real pubkey -> ALLOW
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
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
    )
    assert dec1 == linep_sl.Decision.ALLOW
    assert reason1 == "GOVERNANCE_POLICY_ALLOWED"

    # 2. Same-Domain Valid Request WITHOUT explicit pubkey (auto-resolved from provider) -> ALLOW
    dec2, reason2 = engine.evaluate(
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
    assert dec2 == linep_sl.Decision.ALLOW
    assert reason2 == "GOVERNANCE_POLICY_ALLOWED"

    # 3. Same-Domain Request with WRONG pubkey -> MUST BE DENIED!
    wrong_pubkey = b"\xcc" * 32
    dec3, reason3 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        remote_pubkey_32bytes=wrong_pubkey,
        policy_id="default-policy",
    )
    assert dec3 == linep_sl.Decision.DENY
    assert reason3 == "SAME_DOMAIN_IDENTITY_UNTRUSTED"

    # 4. Cross-Domain without Federation -> DENY
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
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
    )
    assert dec4 == linep_sl.Decision.DENY
    assert reason4 == "CROSS_DOMAIN_FEDERATION_DENIED"

    # 5. Add Federation Trust AND enable allow_cross_domain -> ALLOW!
    engine.add_federation(domain_a, domain_b, linep_sl.CapFlags.INFERENCE_READ)
    pol = linep_sl.GovernancePolicy(
        policy_id="default-policy",
        policy_revision=2,
        allowed_capabilities=linep_sl.CapFlags.INFERENCE_READ,
        allow_cross_domain=True,
    )
    engine.set_policy(pol)

    dec5, reason5 = engine.evaluate(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        local_node_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        remote_pubkey_32bytes=pubkey_node10,
        policy_id="default-policy",
        established_policy_revision=2,
    )
    assert dec5 == linep_sl.Decision.ALLOW
    assert reason5 == "GOVERNANCE_POLICY_ALLOWED"
    assert engine.get_audit_count() >= 5
