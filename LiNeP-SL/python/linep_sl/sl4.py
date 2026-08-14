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


class SecurityDecisionEngine:
    def __init__(self, local_trust_domain_id: int) -> None:
        self._handle = lib.linep_sl4_engine_create(local_trust_domain_id)

    def __del__(self) -> None:
        if hasattr(self, "_handle") and self._handle:
            lib.linep_sl4_engine_free(self._handle)
            self._handle = None

    def register_peer(self, node_id: int, pubkey_32bytes: bytes, trust_domain_id: int | None = None) -> None:
        if len(pubkey_32bytes) != 32:
            raise ValueError("Pubkey must be exactly 32 bytes")
        if trust_domain_id is not None:
            lib.linep_sl4_engine_register_peer_for_domain(self._handle, trust_domain_id, node_id, pubkey_32bytes)
        else:
            lib.linep_sl4_engine_register_peer(self._handle, node_id, pubkey_32bytes)

    def set_policy(self, policy: GovernancePolicy) -> None:
        lib.linep_sl4_engine_set_policy(
            self._handle,
            policy.policy_id.encode("utf-8"),
            policy.policy_revision,
            int(policy.allowed_capabilities),
            1 if policy.allow_cross_domain else 0,
        )

    def add_federation(self, local_domain: int, remote_domain: int, max_caps: CapFlags | int, revision: int = 1) -> None:
        lib.linep_sl4_engine_add_federation(self._handle, local_domain, remote_domain, int(max_caps), revision)

    def revoke_federation(self, local_domain: int, remote_domain: int) -> None:
        lib.linep_sl4_engine_revoke_federation(self._handle, local_domain, remote_domain)

    def evaluate(
        self,
        trust_domain_id: int,
        session_id: int,
        key_id: int,
        local_node_id: int,
        remote_node_id: int,
        remote_trust_domain_id: int,
        remote_revoked: bool,
        negotiated_sl: SecurityLevel | int,
        requested_cap: CapFlags | int,
        remote_pubkey_32bytes: bytes | None = None,
        policy_id: str = "default-policy",
        established_policy_revision: int = 0,
    ) -> tuple[Decision, str]:
        out_dec = ffi.new("uint8_t *")
        out_reason = ffi.new("char[128]")

        pub_cdata = ffi.NULL
        if remote_pubkey_32bytes is not None:
            if len(remote_pubkey_32bytes) != 32:
                raise ValueError("remote_pubkey_32bytes must be 32 bytes")
            pub_cdata = ffi.new("uint8_t[32]", remote_pubkey_32bytes)

        lib.linep_sl4_engine_evaluate(
            self._handle,
            trust_domain_id,
            session_id,
            key_id,
            local_node_id,
            remote_node_id,
            remote_trust_domain_id,
            pub_cdata,
            1 if remote_revoked else 0,
            int(negotiated_sl),
            int(requested_cap),
            0, # msg_type
            0, # correlation_id
            policy_id.encode("utf-8"),
            established_policy_revision,
            1700000000, # timestamp_sec
            out_dec,
            out_reason,
            128,
        )
        reason = ffi.string(out_reason).decode("utf-8")
        return Decision(out_dec[0]), reason

    def get_audit_count(self) -> int:
        return lib.linep_sl4_engine_get_audit_count(self._handle)


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

    lib.linep_sl4_evaluate_decision(
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
