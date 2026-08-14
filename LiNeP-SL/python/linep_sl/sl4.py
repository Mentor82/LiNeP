from __future__ import annotations

from enum import IntEnum
from linep_sl._cabi_sl import ffi, lib
from linep_sl.constants import CapFlags
from linep_sl.sl2 import PeerIdentity, SecurityLevel


class Decision(IntEnum):
    ALLOW         = 0
    DENY          = 1
    INDETERMINATE = 2


class AuditEventType(IntEnum):
    SESSION_ADMITTED        = 0
    SESSION_REJECTED        = 1
    DOWNGRADE_REJECTED      = 2
    CAPABILITY_DENIED       = 3
    GOVERNANCE_DENIED       = 4
    FEDERATION_DENIED       = 5
    FEDERATION_ADMITTED     = 6
    POLICY_REVISION_CHANGED = 7
    SESSION_INVALIDATED     = 8


class GovernancePolicy:
    def __init__(
        self,
        policy_id: str = "default-policy",
        policy_revision: int = 1,
        allowed_capabilities: CapFlags | int = (CapFlags.INFERENCE_READ | CapFlags.INFERENCE_WRITE | CapFlags.METRICS_READ),
        allow_cross_domain: bool = False,
    ) -> None:
        self.policy_id = policy_id
        self.policy_revision = policy_revision
        self.allowed_capabilities = CapFlags(allowed_capabilities)
        self.allow_cross_domain = allow_cross_domain


def evaluate_governance_decision(
    trust_domain_id: int,
    session_id: int,
    key_id: int,
    remote_node_id: int,
    remote_trust_domain_id: int,
    remote_revoked: bool,
    negotiated_sl: SecurityLevel | int,
    requested_cap: CapFlags | int,
    policy_id: str = "default-policy",
) -> tuple[Decision, str]:
    out_dec = ffi.new("uint8_t *")
    out_reason = ffi.new("char[128]")

    rc = lib.linep_sl4_evaluate_decision(
        trust_domain_id,
        session_id,
        key_id,
        remote_node_id,
        remote_trust_domain_id,
        1 if remote_revoked else 0,
        int(negotiated_sl),
        int(requested_cap),
        policy_id.encode("utf-8"),
        out_dec,
        out_reason,
        128,
    )

    reason = ffi.string(out_reason).decode("utf-8")
    return Decision(out_dec[0]), reason
