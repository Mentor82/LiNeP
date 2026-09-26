#include <linep_sl/v0_2/governance.hpp>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

#define LINEP_SL_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::abort(); \
        } \
    } while (0)

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

    // Hardening #9: Minimum security level enforcement (intranet requires SL1+)
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        100, 1001, security_level::sl0_baseline, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "security_level_insufficient_for_intranet_profile");

    // 1. Same domain (100) with SL1+ -> admitted without attestation
    LINEP_SL_TEST_CHECK(gov.evaluate_federation_admission(
        100, 1001, security_level::sl1_authenticated, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "ok");

    // 2. Cross domain (200) -> rejected on intranet profile
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        200, 2001, security_level::sl1_authenticated, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "cross_domain_rejected_on_intranet_profile");

    LINEP_SL_TEST_CHECK(sink->size() == 3);
    std::cout << "  -> Intranet cluster profile PASSED" << std::endl;
}

void test_federation_and_attestation() {
    std::cout << "[Test 2] Federation admission, minimum SL3, and attestation hooks..." << std::endl;
    governance_engine gov(100, "policy-prod", 1, 1);
    gov.set_trust_boundary_profile(trust_boundary_profile::federated_external);

    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    std::string reason;

    // Hardening #9: Federation requires minimum SL3
    gov.add_federated_domain(300);
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        300, 3001, security_level::sl2_identity, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "security_level_insufficient_for_federation_profile");

    // Defect #2: Missing verifier must fail-closed with attestation_verifier_missing
    attestation_evidence good_ev;
    good_ev.type = attestation_type::tpm_quote;
    good_ev.evidence_bytes = {0x01, 0x02, 0x03, 0x04};
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        300, 3001, security_level::sl3_authorized, &good_ev, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "attestation_verifier_missing");

    // Now attach verifier
    auto verifier = std::make_shared<mock_attestation_verifier>();
    gov.set_attestation_verifier(verifier);

    // 1. Non-federated domain (400) -> rejected
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        400, 4001, security_level::sl3_authorized, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "trust_domain_not_federated");

    // 2. Federated domain without attestation -> rejected
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        300, 3001, security_level::sl3_authorized, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "federation_attestation_required");

    // 3. Federated domain with invalid attestation type -> rejected
    attestation_evidence bad_ev;
    bad_ev.type = attestation_type::none;
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        300, 3001, security_level::sl3_authorized, &bad_ev, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "federation_attestation_required");

    // 4. Federated domain with valid TPM quote attestation -> admitted
    LINEP_SL_TEST_CHECK(gov.evaluate_federation_admission(
        300, 3001, security_level::sl3_authorized, &good_ev, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "ok");

    // Remove domain 300 from federation -> rejected again
    gov.remove_federated_domain(300);
    LINEP_SL_TEST_CHECK(!gov.is_federated_domain(300));
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        300, 3001, security_level::sl3_authorized, &good_ev, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "trust_domain_not_federated");

    std::cout << "  -> Federation and attestation PASSED" << std::endl;
}

void test_zero_trust_strict() {
    std::cout << "[Test 3] Zero-trust strict boundary profile..." << std::endl;
    governance_engine gov(100, "policy-zt", 1, 1);
    gov.set_trust_boundary_profile(trust_boundary_profile::zero_trust_strict);

    std::string reason;

    // Hardening #9: Zero-trust requires SL4
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        100, 1001, security_level::sl3_authorized, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "security_level_insufficient_for_zero_trust_profile");

    // Defect #2: Fail-closed if verifier missing under zero-trust
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        100, 1001, security_level::sl4_governed, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "attestation_verifier_missing");

    auto verifier = std::make_shared<mock_attestation_verifier>();
    gov.set_attestation_verifier(verifier);

    // Even local domain (100) must supply valid attestation in zero-trust mode!
    LINEP_SL_TEST_CHECK(!gov.evaluate_federation_admission(
        100, 1001, security_level::sl4_governed, nullptr, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "zero_trust_attestation_missing");

    attestation_evidence valid_ev;
    valid_ev.type = attestation_type::token;
    valid_ev.evidence_bytes = {0xAA, 0xBB, 0xCC};
    LINEP_SL_TEST_CHECK(gov.evaluate_federation_admission(
        100, 1001, security_level::sl4_governed, &valid_ev, 1000000, reason));
    LINEP_SL_TEST_CHECK(reason == "ok");

    std::cout << "  -> Zero-trust strict PASSED" << std::endl;
}

void test_policy_revisions_and_audit_completeness() {
    std::cout << "[Test 4] Policy revisions and tamper-evident audit trail..." << std::endl;
    governance_engine gov(100, "policy-corp", 1, 1);
    auto sink = std::make_shared<in_memory_audit_sink_v02>();
    gov.add_audit_sink(sink);

    LINEP_SL_TEST_CHECK(gov.policy_revision() == 1);
    LINEP_SL_TEST_CHECK(gov.federation_revision() == 1);

    // Hardening #7: Monotonic revisions (backwards / duplicate rejected)
    LINEP_SL_TEST_CHECK(gov.update_policy_revision(2, 2000000));
    LINEP_SL_TEST_CHECK(gov.policy_revision() == 2);
    LINEP_SL_TEST_CHECK(!gov.update_policy_revision(2, 2000001)); // duplicate rejected
    LINEP_SL_TEST_CHECK(!gov.update_policy_revision(1, 2000002)); // backwards rejected

    LINEP_SL_TEST_CHECK(gov.update_federation_revision(3, 2000100));
    LINEP_SL_TEST_CHECK(gov.federation_revision() == 3);
    LINEP_SL_TEST_CHECK(!gov.update_federation_revision(3, 2000101)); // duplicate rejected
    LINEP_SL_TEST_CHECK(!gov.update_federation_revision(2, 2000102)); // backwards rejected

    // Emit custom audit event with SHA-256 digest
    std::vector<std::uint8_t> digest = {0x11, 0x22, 0x33, 0x44};
    gov.emit_audit_event(
        audit_event_type_v02::authorization_allowed,
        5001, 101, 200,
        security_action::execute, "gpt-conformance",
        authorization_outcome::allow, "ok",
        digest, 2000200);

    auto events = sink->get_events();
    LINEP_SL_TEST_CHECK(events.size() == 3);

    // Hardening #8: Verify monotonic sequence numbers and hash chaining
    LINEP_SL_TEST_CHECK(events[0].audit_seq == 1);
    LINEP_SL_TEST_CHECK(events[0].prev_record_digest == std::vector<std::uint8_t>(32, 0)); // Genesis record
    LINEP_SL_TEST_CHECK(!events[0].record_digest.empty());

    LINEP_SL_TEST_CHECK(events[1].audit_seq == 2);
    LINEP_SL_TEST_CHECK(events[1].prev_record_digest == events[0].record_digest); // Hash chained
    LINEP_SL_TEST_CHECK(!events[1].record_digest.empty());

    LINEP_SL_TEST_CHECK(events[2].audit_seq == 3);
    LINEP_SL_TEST_CHECK(events[2].prev_record_digest == events[1].record_digest); // Hash chained
    LINEP_SL_TEST_CHECK(!events[2].record_digest.empty());

    // Verify last event provenance
    const auto& last = events.back();
    LINEP_SL_TEST_CHECK(last.event_type == audit_event_type_v02::authorization_allowed);
    LINEP_SL_TEST_CHECK(last.session_id == 5001);
    LINEP_SL_TEST_CHECK(last.subject_id == 101);
    LINEP_SL_TEST_CHECK(last.local_trust_domain_id == 100);
    LINEP_SL_TEST_CHECK(last.remote_trust_domain_id == 200);
    LINEP_SL_TEST_CHECK(last.action == security_action::execute);
    LINEP_SL_TEST_CHECK(last.resource_name == "gpt-conformance");
    LINEP_SL_TEST_CHECK(last.decision == authorization_outcome::allow);
    LINEP_SL_TEST_CHECK(last.reason_code == "ok");
    LINEP_SL_TEST_CHECK(last.policy_id == "policy-corp");
    LINEP_SL_TEST_CHECK(last.policy_revision == 2);
    LINEP_SL_TEST_CHECK(last.federation_revision == 3);
    LINEP_SL_TEST_CHECK(last.payload_digest == digest);

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
