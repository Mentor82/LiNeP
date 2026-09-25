#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <linep_sl/v0_2/authorization.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

namespace linep::sl::v0_2 {

enum class trust_boundary_profile : std::uint8_t {
    intranet_cluster = 0,    // Internal cluster within trusted local domain (SL1+)
    dmz_gateway = 1,         // Edge perimeter gateway (SL2+)
    federated_external = 2,  // Cross-domain federation with authenticated domain (SL3+)
    zero_trust_strict = 3,   // Strict zero-trust with mandatory attestation & audit (SL4)
};

enum class audit_event_type_v02 : std::uint8_t {
    session_established = 0,
    session_rotated = 1,
    session_revoked = 2,
    session_expired = 3,
    authorization_allowed = 4,
    authorization_denied = 5,
    attestation_verified = 6,
    attestation_failed = 7,
    federation_admitted = 8,
    federation_denied = 9,
    policy_updated = 10,
    integrity_violation = 11,
};

// Privacy-safe, tamper-evident audit record: zero raw secrets or confidential user payloads!
struct audit_record_v02 {
    std::uint64_t timestamp_us{0};
    audit_event_type_v02 event_type{audit_event_type_v02::authorization_denied};
    std::uint64_t session_id{0};
    std::uint64_t subject_id{0};
    std::uint32_t local_trust_domain_id{0};
    std::uint32_t remote_trust_domain_id{0};
    security_action action{security_action::unknown};
    std::string resource_name;
    authorization_outcome decision{authorization_outcome::deny};
    std::string reason_code;
    std::string policy_id;
    std::uint32_t policy_revision{0};
    std::uint32_t federation_revision{0};
    std::vector<std::uint8_t> payload_digest; // SHA-256 content digest only
};

class iaudit_sink_v02 {
public:
    virtual ~iaudit_sink_v02() = default;
    virtual bool record(const audit_record_v02& entry) noexcept = 0;
};

class in_memory_audit_sink_v02 : public iaudit_sink_v02 {
public:
    bool record(const audit_record_v02& entry) noexcept override;
    std::vector<audit_record_v02> get_events() const;
    void clear() noexcept;
    std::size_t size() const noexcept;

private:
    mutable std::mutex mutex_;
    std::vector<audit_record_v02> events_;
};

enum class attestation_type : std::uint8_t {
    none = 0,
    token = 1,      // Signed identity token (e.g. SPIFFE, OIDC)
    tpm_quote = 2,  // Hardware TPM 2.0 quote
    sgx_quote = 3,  // Intel SGX / TDX quote
    sev_snp = 4,    // AMD SEV-SNP report
    nitro = 5,      // AWS Nitro Enclave attestation
};

struct attestation_evidence {
    attestation_type type{attestation_type::none};
    std::vector<std::uint8_t> evidence_bytes;
    std::uint64_t nonce{0};
    std::uint64_t issued_at_us{0};
};

class attestation_verifier {
public:
    virtual ~attestation_verifier() = default;
    virtual bool verify_attestation(
        std::uint32_t trust_domain_id,
        std::uint64_t subject_id,
        const attestation_evidence& evidence,
        std::uint64_t now_us) noexcept = 0;
};

class governance_engine {
public:
    governance_engine(
        std::uint32_t local_trust_domain_id,
        std::string policy_id,
        std::uint32_t initial_policy_revision = 1,
        std::uint32_t initial_federation_revision = 1);

    std::uint32_t local_trust_domain_id() const noexcept { return local_trust_domain_id_; }
    const std::string& policy_id() const noexcept { return policy_id_; }
    std::uint32_t policy_revision() const noexcept { return policy_revision_; }
    std::uint32_t federation_revision() const noexcept { return federation_revision_; }

    void set_trust_boundary_profile(trust_boundary_profile profile) noexcept;
    trust_boundary_profile current_profile() const noexcept;

    // Federation trust domain management
    void add_federated_domain(std::uint32_t domain_id);
    void remove_federated_domain(std::uint32_t domain_id);
    bool is_federated_domain(std::uint32_t domain_id) const noexcept;

    // Policy and federation lifecycle updates
    void update_policy_revision(std::uint32_t new_revision, std::uint64_t now_us = 0);
    void update_federation_revision(std::uint32_t new_revision, std::uint64_t now_us = 0);

    // Attestation and audit configuration
    void set_attestation_verifier(std::shared_ptr<attestation_verifier> verifier) noexcept;
    void add_audit_sink(std::shared_ptr<iaudit_sink_v02> sink);

    // Evaluate federation boundary admission for incoming peer or request
    bool evaluate_federation_admission(
        std::uint32_t remote_trust_domain_id,
        std::uint64_t remote_subject_id,
        const attestation_evidence* evidence,
        std::uint64_t now_us,
        std::string& out_reason) noexcept;

    // Emit structured audit event through all registered sinks
    void emit_audit_event(
        audit_event_type_v02 type,
        std::uint64_t session_id,
        std::uint64_t subject_id,
        std::uint32_t remote_trust_domain_id,
        security_action action,
        const std::string& resource_name,
        authorization_outcome decision,
        const std::string& reason_code,
        const std::vector<std::uint8_t>& payload_digest,
        std::uint64_t now_us) noexcept;

private:
    std::uint32_t local_trust_domain_id_;
    std::string policy_id_;
    std::uint32_t policy_revision_;
    std::uint32_t federation_revision_;
    trust_boundary_profile profile_{trust_boundary_profile::intranet_cluster};

    mutable std::mutex mutex_;
    std::unordered_set<std::uint32_t> federated_domains_;
    std::shared_ptr<attestation_verifier> attestation_verifier_;
    std::vector<std::shared_ptr<iaudit_sink_v02>> audit_sinks_;
};

} // namespace linep::sl::v0_2
