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


def test_sl4_governance_decision():
    _ensure_linep_sl_lib_path()
    import linep_sl

    domain_a = 0x4C4E5031
    domain_b = 0x4C4E5032

    # 1. Valid Same-Domain Zero-Trust Request -> ALLOW
    dec, reason = linep_sl.evaluate_governance_decision(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec == linep_sl.Decision.ALLOW
    assert reason == "GOVERNANCE_POLICY_ALLOWED"

    # 2. Unauthorized ADMIN Capability -> DENY
    dec_admin, reason_admin = linep_sl.evaluate_governance_decision(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.ADMIN,
        policy_id="default-policy",
    )
    assert dec_admin == linep_sl.Decision.DENY
    assert reason_admin == "GOVERNANCE_POLICY_CAPABILITY_DENIED"

    # 3. Insufficient Security Level -> DENY
    dec_sl1, reason_sl1 = linep_sl.evaluate_governance_decision(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_a,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL1_AUTH,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec_sl1 == linep_sl.Decision.DENY
    assert reason_sl1 == "INSUFFICIENT_SECURITY_LEVEL"

    # 4. Cross-Domain without Federation -> DENY
    dec_cross, reason_cross = linep_sl.evaluate_governance_decision(
        trust_domain_id=domain_a,
        session_id=0x1001,
        key_id=1,
        remote_node_id=10,
        remote_trust_domain_id=domain_b,
        remote_revoked=False,
        negotiated_sl=linep_sl.SecurityLevel.SL2_IDENTITY,
        requested_cap=linep_sl.CapFlags.INFERENCE_READ,
        policy_id="default-policy",
    )
    assert dec_cross == linep_sl.Decision.DENY
    assert reason_cross == "CROSS_DOMAIN_FEDERATION_DENIED"
