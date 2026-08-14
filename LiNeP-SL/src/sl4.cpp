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
void MemoryFederationTrustProvider::add_federation(uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps) {
    DomainPairKey k{local_domain, remote_domain};
    FederationTrust ft;
    ft.local_domain_id = local_domain;
    ft.federated_domain_id = remote_domain;
    ft.federation_revision = 1;
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

DecisionResult SecurityDecisionEngine::evaluate(const DecisionContext& ctx) noexcept {
    DecisionResult res;
    res.decision = Decision::INDETERMINATE;
    res.reason_code = "UNINITIALIZED";

    AuditEvent audit_evt{};
    audit_evt.timestamp_sec = ctx.timestamp_sec;
    audit_evt.session_id = ctx.session_id;
    audit_evt.key_id = ctx.key_id;
    audit_evt.node_id = ctx.remote_peer.node_id;
    audit_evt.trust_domain_id = ctx.trust_domain_id;

    // Helper lambda to emit audit and return result
    auto emit_result = [&](Decision dec, const char* reason, AuditEventType evt_type) -> DecisionResult {
        res.decision = dec;
        res.reason_code = reason;
        audit_evt.event_type = evt_type;
        audit_evt.reason_code = reason;

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

    // 3. Zero-Trust Identity Check
    if (ctx.remote_peer.node_id == 0 || ctx.remote_peer.revoked) {
        return emit_result(Decision::DENY, "IDENTITY_REVOKED_OR_INVALID", AuditEventType::SESSION_REJECTED);
    }
    if (identity_provider_ && identity_provider_->is_node_revoked(ctx.remote_peer.node_id)) {
        return emit_result(Decision::DENY, "IDENTITY_REVOKED_IN_PROVIDER", AuditEventType::SESSION_REJECTED);
    }

    // 4. Same-Domain vs Federation Trust Evaluation
    bool is_same_domain = (ctx.remote_peer.trust_domain_id == ctx.trust_domain_id);
    if (!is_same_domain) {
        // Cross-domain traffic -> Requires explicit Federation Trust!
        FederationTrust fed_trust;
        if (!federation_provider_ || !federation_provider_->is_federation_trusted(ctx.trust_domain_id, ctx.remote_peer.trust_domain_id, fed_trust)) {
            return emit_result(Decision::DENY, "CROSS_DOMAIN_FEDERATION_DENIED", AuditEventType::FEDERATION_DENIED);
        }
        // Enforce maximum granted capabilities for federated trust
        if (!has_capability(fed_trust.max_granted_caps, ctx.requested_cap)) {
            return emit_result(Decision::DENY, "FEDERATION_CAPABILITY_EXCEEDED", AuditEventType::CAPABILITY_DENIED);
        }
    } else {
        // Same-domain -> Check if identity is trusted
        if (identity_provider_ && !identity_provider_->is_peer_trusted(ctx.remote_peer, ctx.trust_domain_id)) {
            return emit_result(Decision::DENY, "SAME_DOMAIN_IDENTITY_UNTRUSTED", AuditEventType::SESSION_REJECTED);
        }
    }

    // 5. Governance Policy Capability Filter
    if (!has_capability(policy.allowed_capabilities, ctx.requested_cap)) {
        return emit_result(Decision::DENY, "GOVERNANCE_POLICY_CAPABILITY_DENIED", AuditEventType::CAPABILITY_DENIED);
    }

    // ALL CHECKS PASSED -> ALLOW!
    return emit_result(Decision::ALLOW, "GOVERNANCE_POLICY_ALLOWED", is_same_domain ? AuditEventType::SESSION_ADMITTED : AuditEventType::FEDERATION_ADMITTED);
}

} // namespace linep::sl
