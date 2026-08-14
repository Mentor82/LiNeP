#ifndef LINEP_SL_SL4_HPP
#define LINEP_SL_SL4_HPP

#include "security_types.hpp"
#include "sl2.hpp"
#include "sl3.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linep::sl {

// Decision Outcome
enum class Decision : uint8_t {
    ALLOW         = 0,
    DENY          = 1,
    INDETERMINATE = 2
};

// Audit Event Type
enum class AuditEventType : uint8_t {
    SESSION_ADMITTED       = 0,
    SESSION_REJECTED       = 1,
    DOWNGRADE_REJECTED     = 2,
    CAPABILITY_DENIED      = 3,
    GOVERNANCE_DENIED      = 4,
    FEDERATION_DENIED      = 5,
    FEDERATION_ADMITTED    = 6,
    POLICY_REVISION_CHANGED= 7,
    SESSION_INVALIDATED    = 8
};

// Audit Event Record (Zero secrets logged)
struct AuditEvent {
    uint64_t       timestamp_sec;
    AuditEventType event_type;
    uint32_t       session_id;
    uint16_t       key_id;
    uint16_t       node_id;
    uint32_t       trust_domain_id;
    std::string    reason_code;
};

// Abstract Audit Sink Interface
class IAuditSink {
public:
    virtual ~IAuditSink() = default;
    virtual bool log_event(const AuditEvent& event) noexcept = 0;
};

// Memory-backed Audit Sink implementation
class MemoryAuditSink : public IAuditSink {
public:
    bool log_event(const AuditEvent& event) noexcept override;
    std::vector<AuditEvent> get_events() const;
    void clear();
    void set_fail_closed_mode(bool enable) { fail_closed_mode_ = enable; }

private:
    std::vector<AuditEvent> events_;
    bool fail_closed_mode_ = false;
};

// Governance Policy
struct GovernancePolicy {
    std::string policy_id = "default-policy";
    uint32_t    policy_revision = 1;
    uint64_t    allowed_capabilities = static_cast<uint64_t>(CapFlags::CAP_INFERENCE_READ | CapFlags::CAP_INFERENCE_WRITE | CapFlags::CAP_METRICS_READ);
    bool        allow_cross_domain = false;
};

// Abstract Governance Policy Provider
class IGovernancePolicyProvider {
public:
    virtual ~IGovernancePolicyProvider() = default;
    virtual bool get_policy(const std::string& policy_id, GovernancePolicy& out_policy) const noexcept = 0;
};

// Memory-backed Governance Policy Provider
class MemoryGovernancePolicyProvider : public IGovernancePolicyProvider {
public:
    MemoryGovernancePolicyProvider();
    void set_policy(const GovernancePolicy& policy);
    bool get_policy(const std::string& policy_id, GovernancePolicy& out_policy) const noexcept override;

private:
    std::unordered_map<std::string, GovernancePolicy> policies_;
};

// Federation Trust Relationship
struct FederationTrust {
    uint32_t    local_domain_id;
    uint32_t    federated_domain_id;
    uint32_t    federation_revision;
    uint64_t    max_granted_caps;
    bool        active;
};

// Abstract Federation Trust Provider
class IFederationTrustProvider {
public:
    virtual ~IFederationTrustProvider() = default;
    virtual bool is_federation_trusted(uint32_t local_domain, uint32_t remote_domain, FederationTrust& out_trust) const noexcept = 0;
};

// Memory-backed Federation Trust Provider
class MemoryFederationTrustProvider : public IFederationTrustProvider {
public:
    void add_federation(uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps);
    void revoke_federation(uint32_t local_domain, uint32_t remote_domain);
    bool is_federation_trusted(uint32_t local_domain, uint32_t remote_domain, FederationTrust& out_trust) const noexcept override;

private:
    struct DomainPairKey {
        uint32_t local;
        uint32_t remote;
        bool operator==(const DomainPairKey& o) const { return local == o.local && remote == o.remote; }
    };
    struct KeyHash {
        size_t operator()(const DomainPairKey& k) const {
            return (static_cast<size_t>(k.local) << 32) ^ static_cast<size_t>(k.remote);
        }
    };
    std::unordered_map<DomainPairKey, FederationTrust, KeyHash> trusts_;
};

// Decision Context for SL4 Security Engine
struct DecisionContext {
    PeerIdentity    local_peer{};
    PeerIdentity    remote_peer{};
    uint32_t        trust_domain_id = 0;
    uint32_t        session_id = 0;
    uint16_t        key_id = 0;
    SecurityLevel   negotiated_sl = SecurityLevel::SL0_NONE;
    CapFlags        requested_cap = CapFlags::CAP_NONE;
    uint8_t         msg_type = 0;
    uint32_t        correlation_id = 0;
    std::string     policy_id = "default-policy";
    uint64_t        timestamp_sec = 0;
};

// Decision Evaluation Result
struct DecisionResult {
    Decision    decision = Decision::INDETERMINATE;
    std::string reason_code = "UNINITIALIZED";
    std::string policy_id;
    uint32_t    policy_revision = 0;
};

// SL4 Security Decision Engine
class SecurityDecisionEngine {
public:
    SecurityDecisionEngine(
        std::shared_ptr<IGovernancePolicyProvider> policy_provider,
        std::shared_ptr<IdentityProvider>          identity_provider,
        std::shared_ptr<IFederationTrustProvider>  federation_provider,
        std::shared_ptr<IAuditSink>                 audit_sink);

    DecisionResult evaluate(const DecisionContext& ctx) noexcept;

private:
    std::shared_ptr<IGovernancePolicyProvider> policy_provider_;
    std::shared_ptr<IdentityProvider>          identity_provider_;
    std::shared_ptr<IFederationTrustProvider>  federation_provider_;
    std::shared_ptr<IAuditSink>                 audit_sink_;
};

} // namespace linep::sl

#endif // LINEP_SL_SL4_HPP
