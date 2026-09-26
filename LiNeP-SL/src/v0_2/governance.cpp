#include <linep_sl/v0_2/governance.hpp>
#include <linep_sl/v0_2/authenticator.hpp>
#include <cstring>

namespace linep::sl::v0_2 {

namespace {

void write_u32(std::vector<std::uint8_t>& buf, std::uint32_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

void write_u64(std::vector<std::uint8_t>& buf, std::uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

std::vector<std::uint8_t> compute_record_hash(const audit_record_v02& rec) {
    std::vector<std::uint8_t> buf;
    buf.reserve(256);
    write_u64(buf, rec.audit_seq);
    write_u64(buf, rec.timestamp_us);
    buf.push_back(static_cast<std::uint8_t>(rec.event_type));
    write_u64(buf, rec.session_id);
    write_u64(buf, rec.subject_id);
    write_u32(buf, rec.local_trust_domain_id);
    write_u32(buf, rec.remote_trust_domain_id);
    buf.push_back(static_cast<std::uint8_t>(rec.action));
    buf.push_back(static_cast<std::uint8_t>(rec.decision));
    write_u32(buf, rec.policy_revision);
    write_u32(buf, rec.federation_revision);
    buf.insert(buf.end(), rec.resource_name.begin(), rec.resource_name.end());
    buf.insert(buf.end(), rec.reason_code.begin(), rec.reason_code.end());
    buf.insert(buf.end(), rec.policy_id.begin(), rec.policy_id.end());
    buf.insert(buf.end(), rec.payload_digest.begin(), rec.payload_digest.end());
    buf.insert(buf.end(), rec.prev_record_digest.begin(), rec.prev_record_digest.end());

    std::vector<std::uint8_t> digest;
    compute_sha256_digest(buf.data(), buf.size(), digest);
    return digest;
}

} // namespace

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
      federation_revision_(initial_federation_revision),
      last_audit_digest_(32, 0) {}

std::uint32_t governance_engine::local_trust_domain_id() const noexcept {
    return local_trust_domain_id_;
}

std::string governance_engine::policy_id() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_id_;
}

std::uint32_t governance_engine::policy_revision() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_revision_;
}

std::uint32_t governance_engine::federation_revision() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return federation_revision_;
}

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

bool governance_engine::update_policy_revision(std::uint32_t new_revision, std::uint64_t now_us) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (new_revision <= policy_revision_) {
            return false; // Monotonic requirement: reject backwards revision downgrade
        }
        policy_revision_ = new_revision;
    }
    emit_audit_event(
        audit_event_type_v02::policy_updated,
        0, 0, local_trust_domain_id_,
        security_action::administer, "policy_engine",
        authorization_outcome::allow, "policy_revision_updated",
        {}, now_us);
    return true;
}

bool governance_engine::update_federation_revision(std::uint32_t new_revision, std::uint64_t now_us) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (new_revision <= federation_revision_) {
            return false; // Monotonic requirement: reject backwards revision downgrade
        }
        federation_revision_ = new_revision;
    }
    emit_audit_event(
        audit_event_type_v02::policy_updated,
        0, 0, local_trust_domain_id_,
        security_action::administer, "federation_engine",
        authorization_outcome::allow, "federation_revision_updated",
        {}, now_us);
    return true;
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
    security_level level,
    const attestation_evidence* evidence,
    std::uint64_t now_us,
    std::string& out_reason) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);
    const auto prof = profile_;
    const auto local_td = local_trust_domain_id_;
    const bool federated = (federated_domains_.find(remote_trust_domain_id) != federated_domains_.end());
    auto verifier = attestation_verifier_;
    lock.unlock();

    // Hardening #9: Check minimum security level per boundary profile
    switch (prof) {
        case trust_boundary_profile::intranet_cluster:
            if (static_cast<std::uint8_t>(level) < static_cast<std::uint8_t>(security_level::sl1_authenticated)) {
                out_reason = "security_level_insufficient_for_intranet_profile";
                emit_audit_event(
                    audit_event_type_v02::federation_denied, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            break;
        case trust_boundary_profile::dmz_gateway:
            if (static_cast<std::uint8_t>(level) < static_cast<std::uint8_t>(security_level::sl2_identity)) {
                out_reason = "security_level_insufficient_for_gateway_profile";
                emit_audit_event(
                    audit_event_type_v02::federation_denied, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            break;
        case trust_boundary_profile::federated_external:
            if (static_cast<std::uint8_t>(level) < static_cast<std::uint8_t>(security_level::sl3_authorized)) {
                out_reason = "security_level_insufficient_for_federation_profile";
                emit_audit_event(
                    audit_event_type_v02::federation_denied, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            break;
        case trust_boundary_profile::zero_trust_strict:
            if (static_cast<std::uint8_t>(level) < static_cast<std::uint8_t>(security_level::sl4_governed)) {
                out_reason = "security_level_insufficient_for_zero_trust_profile";
                emit_audit_event(
                    audit_event_type_v02::federation_denied, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            break;
    }

    if (remote_trust_domain_id == local_td) {
        // Intradomain communication
        if (prof == trust_boundary_profile::zero_trust_strict) {
            // Defect #2 fix: Fail-closed if verifier missing under zero_trust_strict
            if (!verifier) {
                out_reason = "attestation_verifier_missing";
                emit_audit_event(
                    audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            if (!evidence || evidence->type == attestation_type::none) {
                out_reason = "zero_trust_attestation_missing";
                emit_audit_event(
                    audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                    remote_trust_domain_id, security_action::administer, "admission",
                    authorization_outcome::deny, out_reason, {}, now_us);
                return false;
            }
            if (!verifier->verify_attestation(remote_trust_domain_id, remote_subject_id, *evidence, now_us)) {
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
        // Defect #2 fix: Fail-closed if verifier missing under federated_external / zero_trust_strict
        if (!verifier) {
            out_reason = "attestation_verifier_missing";
            emit_audit_event(
                audit_event_type_v02::attestation_failed, 0, remote_subject_id,
                remote_trust_domain_id, security_action::administer, "admission",
                authorization_outcome::deny, out_reason, {}, now_us);
            return false;
        }
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
    record.remote_trust_domain_id = remote_trust_domain_id;
    record.action = action;
    record.resource_name = resource_name;
    record.decision = decision;
    record.reason_code = reason_code;
    record.payload_digest = payload_digest;

    std::vector<std::shared_ptr<iaudit_sink_v02>> sinks_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        record.local_trust_domain_id = local_trust_domain_id_;
        record.policy_id = policy_id_;
        record.policy_revision = policy_revision_;
        record.federation_revision = federation_revision_;
        record.audit_seq = ++audit_seq_counter_;
        record.prev_record_digest = last_audit_digest_;

        record.record_digest = compute_record_hash(record);
        last_audit_digest_ = record.record_digest;

        sinks_copy = audit_sinks_;
    }

    for (auto& sink : sinks_copy) {
        if (sink) {
            sink->record(record);
        }
    }
}

} // namespace linep::sl::v0_2
