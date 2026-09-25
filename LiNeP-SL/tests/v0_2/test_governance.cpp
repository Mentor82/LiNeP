#include <linep_sl/v0_2/governance.hpp>

#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

using namespace linep::sl::v0_2;

// Mock Attestation Verifier for testing
class mock_attestation_verifier : public attestation_verifier {
public:
    bool verify_attestation(
        std::uint32_t trust_domain_id,
        std::uint64_t subject_id,
        const attestation_evidence& evidence,
        std::uint64_t now_us) noexcept override {
        (void)trust_domain_id;
        (void)now_us;
        // Accept only TPM or Token attestation with non-empty evidence and valid subject
        if (subject_id == 0) return false;
        if (evidence.type != attestation_type::tpm_quote && evidence.type != attestation_type::token) {
            return false;
        }
        return !evidence.evidence_bytes.empty();
    }
};

void test_intranet_profile_boundaries() {
    std::cout << "[Test 1] Intranet cluster trust boundary profile..." << std::endl;
    governance_engine gov(100, "policy-prod", 1, 1);
    gov.set_trust_boundary_profile(trust_boundary_profile::intranet_cluster);

    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    std::string reason;
    // 1. Same domain (100) -> admitted without attestation
    assert(gov.evaluate_federation_admission(100, 1001, nullptr, 1000000, reason));
    assert(reason == "ok");

    // 2. Cross domain (200) -> rejected on intranet profile
    assert(!gov.evaluate_federation_admission(200, 2001, nullptr, 1000000, reason));
    assert(reason == "cross_domain_rejected_on_intranet_profile");

    assert(sink->size() == 2);
    std::cout << "  -> Intranet cluster profile PASSED" << std::endl;
}

void test_federation_and_attestation() {
    std::cout << "[Test 2] Federation admission and attestation hooks..." << std::endl;
    governance_engine gov(100, "policy-prod", 1, 1);
    gov.set_trust_boundary_profile(trust_boundary_profile::federated_external);

    auto verifier = std::make_shared<mock_attestation_verifier>();
    gov.set_attestation_verifier(verifier);

    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    std::string reason;
    // 1. Non-federated domain (300) -> rejected
    assert(!gov.evaluate_federation_admission(300, 3001, nullptr, 1000000, reason));
    assert(reason == "trust_domain_not_federated");

    // Register domain 300 as federated
    gov.add_federated_domain(300);
    assert(gov.is_federated_domain(300));

    // 2. Federated domain without attestation -> rejected
    assert(!gov.evaluate_federation_admission(300, 3001, nullptr, 1000000, reason));
    assert(reason == "federation_attestation_required");

    // 3. Federated domain with invalid attestation type -> rejected
    attestation_evidence bad_ev;
    bad_ev.type = attestation_type::none;
    assert(!gov.evaluate_federation_admission(300, 3001, &bad_ev, 1000000, reason));
    assert(reason == "federation_attestation_required");

    // 4. Federated domain with valid TPM quote attestation -> admitted
    attestation_evidence good_ev;
    good_ev.type = attestation_type::tpm_quote;
    good_ev.evidence_bytes = {0x01, 0x02, 0x03, 0x04};
    assert(gov.evaluate_federation_admission(300, 3001, &good_ev, 1000000, reason));
    assert(reason == "ok");

    // Remove domain 300 from federation -> rejected again
    gov.remove_federated_domain(300);
    assert(!gov.is_federated_domain(300));
    assert(!gov.evaluate_federation_admission(300, 3001, &good_ev, 1000000, reason));
    assert(reason == "trust_domain_not_federated");

    std::cout << "  -> Federation and attestation PASSED" << std::endl;
}

void test_zero_trust_strict() {
    std::cout << "[Test 3] Zero-trust strict boundary profile..." << std::endl;
    governance_engine gov(100, "policy-zt", 1, 1);
    gov.set_trust_boundary_profile(trust_boundary_profile::zero_trust_strict);

    auto verifier = std::make_shared<mock_attestation_verifier>();
    gov.set_attestation_verifier(verifier);

    std::string reason;
    // Even local domain (100) must supply valid attestation in zero-trust mode!
    assert(!gov.evaluate_federation_admission(100, 1001, nullptr, 1000000, reason));
    assert(reason == "zero_trust_attestation_missing");

    attestation_evidence valid_ev;
    valid_ev.type = attestation_type::token;
    valid_ev.evidence_bytes = {0xAA, 0xBB, 0xCC};
    assert(gov.evaluate_federation_admission(100, 1001, &valid_ev, 1000000, reason));
    assert(reason == "ok");

    std::cout << "  -> Zero-trust strict PASSED" << std::endl;
}

void test_policy_revisions_and_audit_completeness() {
    std::cout << "[Test 4] Policy revisions and privacy-safe audit trail..." << std::endl;
    governance_engine gov(100, "policy-corp", 1, 1);
    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    assert(gov.policy_revision() == 1);
    assert(gov.federation_revision() == 1);

    // Update revisions
    gov.update_policy_revision(2, 2000000);
    assert(gov.policy_revision() == 2);

    gov.update_federation_revision(3, 2000100);
    assert(gov.federation_revision() == 3);

    // Emit custom audit event with SHA-256 digest
    std::vector<std::uint8_t> digest = {0x11, 0x22, 0x33, 0x44};
    gov.emit_audit_event(
        audit_event_type_v02::authorization_allowed,
        5001, 101, 200,
        security_action::execute, "gpt-conformance",
        authorization_outcome::allow, "ok",
        digest, 2000200);

    auto events = sink->get_events();
    assert(events.size() == 3);

    // Verify last event provenance
    const auto& last = events.back();
    assert(last.event_type == audit_event_type_v02::authorization_allowed);
    assert(last.session_id == 5001);
    assert(last.subject_id == 101);
    assert(last.local_trust_domain_id == 100);
    assert(last.remote_trust_domain_id == 200);
    assert(last.action == security_action::execute);
    assert(last.resource_name == "gpt-conformance");
    assert(last.decision == authorization_outcome::allow);
    assert(last.reason_code == "ok");
    assert(last.policy_id == "policy-corp");
    assert(last.policy_revision == 2);
    assert(last.federation_revision == 3);
    assert(last.payload_digest == digest);

    std::cout << "  -> Policy revisions and audit completeness PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Phase E Governance Test Suite ===" << std::endl;
    test_intranet_profile_boundaries();
    test_federation_and_attestation();
    test_zero_trust_strict();
    test_policy_revisions_and_audit_completeness();
    std::cout << "ALL PHASE E GOVERNANCE TESTS PASSED 100%!" << std::endl;
    return 0;
}
