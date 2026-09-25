#include <linep_sl/v0_2/governance.hpp>

namespace linep::sl::v0_2 {

bool in_memory_audit_sink_v02::record(const audit_record_v02& entry) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(entry);
    return true;
}

std::vector<audit_record_v02> in_memory_audit_sink_v02::get_events() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

void in_memory_audit_sink_v02::clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
}

std::size_t in_memory_audit_sink_v02::size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

governance_engine::governance_engine(
    std::uint32_t local_trust_domain_id,
    std::string policy_id,
    std::uint32_t initial_policy_revision,
    std::uint32_t initial_federation_revision)
    : local_trust_domain_id_(local_trust_domain_id),
      policy_id_(std::move(policy_id)),
      policy_revision_(initial_policy_revision),
      federation_revision_(initial_federation_revision) {}

void governance_engine::set_trust_boundary_profile(trust_boundary_profile profile) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    profile_ = profile;
}

trust_boundary_profile governance_engine::current_profile() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return profile_;
}

void governance_engine::add_federated_domain(std::uint32_t domain_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    federated_domains_.insert(domain_id);
}

void governance_engine::remove_federated_domain(std::uint32_t domain_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    federated_domains_.erase(domain_id);
}

bool governance_engine::is_federated_domain(std::uint32_t domain_id) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return federated_domains_.find(domain_id) != federated_domains_.end();
}

void governance_engine::update_policy_revision(std::uint32_t new_revision, std::uint64_t now_us) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        policy_revision_ = new_revision;
    }
    emit_audit_event(
        audit_event_type_v02::policy_updated,
        0, 0, local_trust_domain_id_,
        security_action::administer, "policy_engine",
        authorization_outcome::allow, "policy_revision_updated",
        {}, now_us);
}

void governance_engine::update_federation_revision(std::uint32_t new_revision, std::uint64_t now_us) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        federation_revision_ = new_revision;
    }
    emit_audit_event(
        audit_event_type_v02::policy_updated,
        0, 0, local_trust_domain_id_,
        security_action::administer, "federation_engine",
        authorization_outcome::allow, "federation_revision_updated",
        {}, now_us);
}

void governance_engine::set_attestation_verifier(std::shared_ptr<attestation_verifier> verifier) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    attestation_verifier_ = std::move(verifier);
}

void governance_engine::add_audit_sink(std::shared_ptr<iaudit_sink_v02> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (sink) {
        audit_sinks_.push_back(std::move(sink));
    }
}

bool governance_engine::evaluate_federation_admission(
    std::uint32_t remote_trust_domain_id,
    std::uint64_t remote_subject_id,
    const attestation_evidence* evidence,
    std::uint64_t now_us,
    std::string& out_reason) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);
    const auto prof = profile_;
    const auto local_td = local_trust_domain_id_;
    const bool federated = (federated_domains_.find(remote_trust_domain_id) != federated_domains_.end());
    auto verifier = attestation_verifier_;
    lock.unlock();

    if (remote_trust_domain_id == local_td) {
        // Intradomain communication
        if (prof == trust_boundary_profile::zero_trust_strict) {
            if (!evidence || evidence->type == attestation_type::none) {
                out_reason = "zero_trust_attestation_missing";
                emit_audit_event(
                    audit_event_type_v02::federation_denied, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            if (!verifier || !verifier->verify_attestation(remote_trust_domain_id, remote_subject_id, *evidence, now_us)) {
                out_reason = "zero_trust_attestation_failed";
                emit_audit_event(
                    audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
        }
        out_reason = "ok";
        emit_audit_event(
            audit_event_type_v02::federation_admitted, 0, remote_subject_id,
            remote_trust_domain_id, security_action::administer, "admission",
            authorization_outcome::allow, out_reason, {}, now_us);
        return true;
    }

    // Cross-domain communication
    if (prof == trust_boundary_profile::intranet_cluster) {
        out_reason = "cross_domain_rejected_on_intranet_profile";
        emit_audit_event(
            audit_event_type_v02::federation_denied, 0, remote_subject_id,
            remote_trust_domain_id, security_action::administer, "admission",
            authorization_outcome::deny, out_reason, {}, now_us);
        return false;
    }

    if (!federated) {
        out_reason = "trust_domain_not_federated";
        emit_audit_event(
            audit_event_type_v02::federation_denied, 0, remote_subject_id,
            remote_trust_domain_id, security_action::administer, "admission",
            authorization_outcome::deny, out_reason, {}, now_us);
        return false;
    }

    if (prof == trust_boundary_profile::federated_external ||
        prof == trust_boundary_profile::zero_trust_strict) {
        if (verifier != nullptr) {
            if (!evidence || evidence->type == attestation_type::none) {
                out_reason = "federation_attestation_required";
                emit_audit_event(
                    audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            if (!verifier->verify_attestation(remote_trust_domain_id, remote_subject_id, *evidence, now_us)) {
                out_reason = "federation_attestation_failed";
                emit_audit_event(
                    audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
        }
    }

    out_reason = "ok";
    emit_audit_event(
        audit_event_type_v02::federation_admitted, 0, remote_subject_id,
        remote_trust_domain_id, security_action::administer, "admission",
        authorization_outcome::allow, out_reason, {}, now_us);
    return true;
}

void governance_engine::emit_audit_event(
    audit_event_type_v02 type,
    std::uint64_t session_id,
    std::uint64_t subject_id,
    std::uint32_t remote_trust_domain_id,
    security_action action,
    const std::string& resource_name,
    authorization_outcome decision,
    const std::string& reason_code,
    const std::vector<std::uint8_t>& payload_digest,
    std::uint64_t now_us) noexcept {
    audit_record_v02 record;
    record.timestamp_us = now_us;
    record.event_type = type;
    record.session_id = session_id;
    record.subject_id = subject_id;
    record.local_trust_domain_id = local_trust_domain_id_;
    record.remote_trust_domain_id = remote_trust_domain_id;
    record.action = action;
    record.resource_name = resource_name;
    record.decision = decision;
    record.reason_code = reason_code;
    record.policy_id = policy_id_;
    record.policy_revision = policy_revision_;
    record.federation_revision = federation_revision_;
    record.payload_digest = payload_digest;

    std::vector<std::shared_ptr<iaudit_sink_v02>> sinks_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sinks_copy = audit_sinks_;
    }

    for (auto& sink : sinks_copy) {
        if (sink) {
            sink->record(record);
        }
    }
}

} // namespace linep::sl::v0_2
