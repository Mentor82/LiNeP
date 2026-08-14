#include <linep_sl/sl4.hpp>
#include <cstring>
#include <iostream>

namespace linep::sl {

// MemoryAuditSink implementation
bool MemoryAuditSink::log_event(const AuditEvent& event) noexcept {
    if (fail_closed_mode_) {
        return false; // Simulate audit sink failure for fail-closed testing
    }
    try {
        events_.push_back(event);
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<AuditEvent> MemoryAuditSink::get_events() const {
    return events_;
}

void MemoryAuditSink::clear() {
    events_.clear();
}

// MemoryGovernancePolicyProvider implementation
MemoryGovernancePolicyProvider::MemoryGovernancePolicyProvider() {
    GovernancePolicy def;
    def.policy_id = "default-policy";
    def.policy_revision = 1;
    def.allowed_capabilities = static_cast<uint64_t>(CapFlags::CAP_INFERENCE_READ | CapFlags::CAP_INFERENCE_WRITE | CapFlags::CAP_METRICS_READ);
    def.allow_cross_domain = false;
    policies_[def.policy_id] = def;
}

void MemoryGovernancePolicyProvider::set_policy(const GovernancePolicy& policy) {
    policies_[policy.policy_id] = policy;
}

bool MemoryGovernancePolicyProvider::get_policy(const std::string& policy_id, GovernancePolicy& out_policy) const noexcept {
    auto it = policies_.find(policy_id);
    if (it == policies_.end()) {
        return false;
    }
    out_policy = it->second;
    return true;
}

// MemoryFederationTrustProvider implementation
void MemoryFederationTrustProvider::add_federation(uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps, uint32_t revision) {
    DomainPairKey k{local_domain, remote_domain};
    FederationTrust ft;
    ft.local_domain_id = local_domain;
    ft.federated_domain_id = remote_domain;
    ft.federation_revision = revision;
    ft.max_granted_caps = max_caps;
    ft.active = true;
    trusts_[k] = ft;
}

void MemoryFederationTrustProvider::revoke_federation(uint32_t local_domain, uint32_t remote_domain) {
    DomainPairKey k{local_domain, remote_domain};
    auto it = trusts_.find(k);
    if (it != trusts_.end()) {
        it->second.active = false;
    }
}

bool MemoryFederationTrustProvider::is_federation_trusted(uint32_t local_domain, uint32_t remote_domain, FederationTrust& out_trust) const noexcept {
    DomainPairKey k{local_domain, remote_domain};
    auto it = trusts_.find(k);
    if (it == trusts_.end() || !it->second.active) {
        return false;
    }
    out_trust = it->second;
    return true;
}

// SecurityDecisionEngine implementation
SecurityDecisionEngine::SecurityDecisionEngine(
    std::shared_ptr<IGovernancePolicyProvider> policy_provider,
    std::shared_ptr<IdentityProvider>          identity_provider,
    std::shared_ptr<IFederationTrustProvider>  federation_provider,
    std::shared_ptr<IAuditSink>                 audit_sink)
    : policy_provider_(std::move(policy_provider)),
      identity_provider_(std::move(identity_provider)),
      federation_provider_(std::move(federation_provider)),
      audit_sink_(std::move(audit_sink))
{}

void SecurityDecisionEngine::register_policy(const GovernancePolicy& policy) {
    if (policy_provider_) {
        policy_provider_->set_policy(policy);
        if (audit_sink_) {
            AuditEvent evt{};
            evt.event_type = AuditEventType::POLICY_REVISION_CHANGED;
            evt.policy_id = policy.policy_id;
            evt.policy_revision = policy.policy_revision;
            evt.decision = Decision::ALLOW;
            evt.reason_code = "POLICY_REVISION_UPDATED";
            audit_sink_->log_event(evt);
        }
    }
}

DecisionResult SecurityDecisionEngine::evaluate(const DecisionContext& ctx) noexcept {
    DecisionResult res;
    res.decision = Decision::INDETERMINATE;
    res.reason_code = "UNINITIALIZED";

    AuditEvent audit_evt{};
    audit_evt.timestamp_sec = ctx.timestamp_sec;
    audit_evt.session_id = ctx.session_id;
    audit_evt.key_id = ctx.key_id;
    audit_evt.local_node_id = ctx.local_peer.node_id;
    audit_evt.remote_node_id = ctx.remote_peer.node_id;
    audit_evt.local_trust_domain_id = ctx.trust_domain_id;
    audit_evt.remote_trust_domain_id = ctx.remote_peer.trust_domain_id;
    audit_evt.policy_id = ctx.policy_id;
    audit_evt.requested_cap = static_cast<uint64_t>(ctx.requested_cap);
    audit_evt.msg_type = ctx.msg_type;
    audit_evt.correlation_id = ctx.correlation_id;

    // Helper lambda to emit full audit record and return result
    auto emit_result = [&](Decision dec, const char* reason, AuditEventType evt_type) -> DecisionResult {
        res.decision = dec;
        res.reason_code = reason;
        audit_evt.decision = dec;
        audit_evt.event_type = evt_type;
        audit_evt.reason_code = reason;
        audit_evt.policy_revision = res.policy_revision;
        audit_evt.federation_revision = res.federation_revision;

        if (audit_sink_) {
            bool audit_ok = audit_sink_->log_event(audit_evt);
            if (!audit_ok) {
                // FAIL CLOSED: If mandatory audit logging fails, override decision to DENY!
                res.decision = Decision::DENY;
                res.reason_code = "AUDIT_LOG_COMMIT_FAILED_FAIL_CLOSED";
            }
        }
        return res;
    };

    // 0. Check for INDETERMINATE evaluation path (e.g. CAP_NONE / unspecified capability)
    if (ctx.requested_cap == CapFlags::CAP_NONE) {
        return emit_result(Decision::INDETERMINATE, "INDETERMINATE_NO_CAPABILITY_SPECIFIED", AuditEventType::CAPABILITY_DENIED);
    }

    // 1. Fetch Governance Policy
    GovernancePolicy policy;
    if (!policy_provider_ || !policy_provider_->get_policy(ctx.policy_id, policy)) {
        return emit_result(Decision::DENY, "MISSING_GOVERNANCE_POLICY_FAIL_CLOSED", AuditEventType::GOVERNANCE_DENIED);
    }
    res.policy_id = policy.policy_id;
    res.policy_revision = policy.policy_revision;

    // 2. Check Security Level Invariant (SL4 requires SL2+ negotiated level)
    if (ctx.negotiated_sl < SecurityLevel::SL2_IDENTITY) {
        return emit_result(Decision::DENY, "INSUFFICIENT_SECURITY_LEVEL", AuditEventType::DOWNGRADE_REJECTED);
    }

    // 3. Zero-Trust Peer Identity & Cryptographic Pubkey Verification (MANDATORY for SAME-DOMAIN & CROSS-DOMAIN!)
    if (ctx.remote_peer.node_id == 0 || ctx.remote_peer.revoked) {
        return emit_result(Decision::DENY, "IDENTITY_REVOKED_OR_INVALID", AuditEventType::SESSION_REJECTED);
    }
    if (!validate_peer_identity(ctx.remote_peer, ctx.remote_peer.trust_domain_id)) {
        return emit_result(Decision::DENY, "PEER_IDENTITY_VALIDATION_FAILED", AuditEventType::SESSION_REJECTED);
    }
    if (identity_provider_ && identity_provider_->is_node_revoked(ctx.remote_peer.node_id)) {
        return emit_result(Decision::DENY, "IDENTITY_REVOKED_IN_PROVIDER", AuditEventType::SESSION_REJECTED);
    }

    // 4. Policy Revision Invalidation Check for Active Sessions
    bool is_same_domain = (ctx.remote_peer.trust_domain_id == ctx.trust_domain_id);
    if (ctx.established_policy_revision > 0 && policy.policy_revision > ctx.established_policy_revision) {
        if (!has_capability(policy.allowed_capabilities, ctx.requested_cap) || (!is_same_domain && !policy.allow_cross_domain)) {
            return emit_result(Decision::DENY, "SESSION_INVALIDATED_BY_POLICY_REVISION", AuditEventType::SESSION_INVALIDATED);
        }
    }

    // 5. Cross-Domain vs Same-Domain Federation Evaluation
    if (!is_same_domain) {
        // Gate A: Check explicit Federation Trust exists
        FederationTrust fed_trust;
        if (!federation_provider_ || !federation_provider_->is_federation_trusted(ctx.trust_domain_id, ctx.remote_peer.trust_domain_id, fed_trust)) {
            return emit_result(Decision::DENY, "CROSS_DOMAIN_FEDERATION_DENIED", AuditEventType::FEDERATION_DENIED);
        }
        res.federation_revision = fed_trust.federation_revision;

        // Gate B: Governing policy MUST explicitly allow cross-domain traffic (policy.allow_cross_domain == true)
        if (!policy.allow_cross_domain) {
            return emit_result(Decision::DENY, "GOVERNANCE_POLICY_CROSS_DOMAIN_DENIED", AuditEventType::GOVERNANCE_DENIED);
        }

        // Gate C: Requested capability must fit within BOTH governing policy bounds AND federation trust max caps
        if (!has_capability(fed_trust.max_granted_caps, ctx.requested_cap)) {
            return emit_result(Decision::DENY, "FEDERATION_CAPABILITY_EXCEEDED", AuditEventType::CAPABILITY_DENIED);
        }
    } else {
        // Same-domain -> Check if identity is trusted by identity provider
        if (identity_provider_ && !identity_provider_->is_peer_trusted(ctx.remote_peer, ctx.trust_domain_id)) {
            return emit_result(Decision::DENY, "SAME_DOMAIN_IDENTITY_UNTRUSTED", AuditEventType::SESSION_REJECTED);
        }
    }

    // 6. Governance Policy Capability Filter
    if (!has_capability(policy.allowed_capabilities, ctx.requested_cap)) {
        return emit_result(Decision::DENY, "GOVERNANCE_POLICY_CAPABILITY_DENIED", AuditEventType::CAPABILITY_DENIED);
    }

    // ALL CHECKS PASSED -> ALLOW!
    return emit_result(Decision::ALLOW, "GOVERNANCE_POLICY_ALLOWED", is_same_domain ? AuditEventType::SESSION_ADMITTED : AuditEventType::FEDERATION_ADMITTED);
}

} // namespace linep::sl
