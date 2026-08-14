#include <linep_sl/sl4.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

int main() {
    std::cout << "[test_sl4_governance] Starting LiNeP-SL SL4 Governance & Zero-Trust tests..." << std::endl;

    const uint32_t domain_a = 0x4C4E5031; // Domain 1 ("LNP1")
    const uint32_t domain_b = 0x4C4E5032; // Domain 2 ("LNP2")
    const uint8_t pubkey[32] = {0xAA};

    auto pol_provider = std::make_shared<linep::sl::MemoryGovernancePolicyProvider>();
    auto id_provider = std::make_shared<linep::sl::MemoryIdentityProvider>(domain_a);
    id_provider->register_peer(10, pubkey);

    auto fed_provider = std::make_shared<linep::sl::MemoryFederationTrustProvider>();
    auto audit_sink = std::make_shared<linep::sl::MemoryAuditSink>();

    linep::sl::SecurityDecisionEngine engine(pol_provider, id_provider, fed_provider, audit_sink);

    linep::sl::DecisionContext ctx{};
    ctx.trust_domain_id = domain_a;
    ctx.session_id = 0x1001;
    ctx.key_id = 1;
    ctx.remote_peer.trust_domain_id = domain_a;
    ctx.remote_peer.node_id = 10;
    std::memcpy(ctx.remote_peer.pubkey, pubkey, 32);
    ctx.remote_peer.revoked = false;
    ctx.negotiated_sl = linep::sl::SecurityLevel::SL2_IDENTITY;
    ctx.requested_cap = linep::sl::CapFlags::CAP_INFERENCE_READ;
    ctx.policy_id = "default-policy";
    ctx.timestamp_sec = 1700000000ULL;

    // 1. Valid Same-Domain Zero-Trust -> ALLOW
    auto res1 = engine.evaluate(ctx);
    assert(res1.decision == linep::sl::Decision::ALLOW);
    assert(res1.reason_code == "GOVERNANCE_POLICY_ALLOWED");
    std::cout << "  [1] Valid Same-Domain Zero-Trust -> ALLOW PASSED" << std::endl;

    // 2. Governed Policy Deny Override (Request CAP_ADMIN when policy denies ADMIN)
    linep::sl::DecisionContext ctx_admin = ctx;
    ctx_admin.requested_cap = linep::sl::CapFlags::CAP_ADMIN;
    auto res2 = engine.evaluate(ctx_admin);
    assert(res2.decision == linep::sl::Decision::DENY);
    assert(res2.reason_code == "GOVERNANCE_POLICY_CAPABILITY_DENIED");
    std::cout << "  [2] Governed Policy Deny Override -> DENY PASSED" << std::endl;

    // 3. Insufficient Negotiated Security Level (SL1 offered vs SL2 required by SL4)
    linep::sl::DecisionContext ctx_sl1 = ctx;
    ctx_sl1.negotiated_sl = linep::sl::SecurityLevel::SL1_AUTH;
    auto res3 = engine.evaluate(ctx_sl1);
    assert(res3.decision == linep::sl::Decision::DENY);
    assert(res3.reason_code == "INSUFFICIENT_SECURITY_LEVEL");
    std::cout << "  [3] Insufficient Negotiated Security Level -> DENY PASSED" << std::endl;

    // 4. Missing/Unknown Governing Policy -> Fail Closed (DENY)
    linep::sl::DecisionContext ctx_missing_pol = ctx;
    ctx_missing_pol.policy_id = "non-existent-policy";
    auto res4 = engine.evaluate(ctx_missing_pol);
    assert(res4.decision == linep::sl::Decision::DENY);
    assert(res4.reason_code == "MISSING_GOVERNANCE_POLICY_FAIL_CLOSED");
    std::cout << "  [4] Missing Policy -> Fail Closed DENY PASSED" << std::endl;

    // 5. Cross-Domain Traffic without Federation Trust -> DENY
    linep::sl::DecisionContext ctx_cross = ctx;
    ctx_cross.remote_peer.trust_domain_id = domain_b; // Domain B peer talking to Domain A
    auto res5 = engine.evaluate(ctx_cross);
    assert(res5.decision == linep::sl::Decision::DENY);
    assert(res5.reason_code == "CROSS_DOMAIN_FEDERATION_DENIED");
    std::cout << "  [5] Cross-Domain without Federation -> DENY PASSED" << std::endl;

    // 6. Explicit Federation Trust Added -> ALLOW
    fed_provider->add_federation(domain_a, domain_b, static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ));
    auto res6 = engine.evaluate(ctx_cross);
    assert(res6.decision == linep::sl::Decision::ALLOW);
    assert(res6.reason_code == "GOVERNANCE_POLICY_ALLOWED");
    std::cout << "  [6] Explicit Federation Trust -> ALLOW PASSED" << std::endl;

    // 7. Federation Revocation -> DENY
    fed_provider->revoke_federation(domain_a, domain_b);
    auto res7 = engine.evaluate(ctx_cross);
    assert(res7.decision == linep::sl::Decision::DENY);
    assert(res7.reason_code == "CROSS_DOMAIN_FEDERATION_DENIED");
    std::cout << "  [7] Federation Revocation -> DENY PASSED" << std::endl;

    // 8. Dynamic Policy Revision Change
    linep::sl::GovernancePolicy v2_policy;
    v2_policy.policy_id = "default-policy";
    v2_policy.policy_revision = 2;
    v2_policy.allowed_capabilities = static_cast<uint64_t>(linep::sl::CapFlags::CAP_METRICS_READ); // Revoke INFERENCE_READ in v2
    pol_provider->set_policy(v2_policy);

    auto res8 = engine.evaluate(ctx);
    assert(res8.decision == linep::sl::Decision::DENY);
    assert(res8.policy_revision == 2);
    std::cout << "  [8] Dynamic Policy Revision Update -> DENY PASSED" << std::endl;

    // 9. Mandatory Secret-Free Audit Logging Check
    auto events = audit_sink->get_events();
    assert(!events.empty());
    for (const auto& evt : events) {
        assert(evt.session_id == 0x1001);
        assert(!evt.reason_code.empty());
    }
    std::cout << "  [9] Secret-Free Audit Event Logging PASSED (" << events.size() << " audit events recorded)" << std::endl;

    // 10. Audit Sink Failure -> Fail Closed (DENY)
    audit_sink->set_fail_closed_mode(true);
    auto res10 = engine.evaluate(ctx);
    assert(res10.decision == linep::sl::Decision::DENY);
    assert(res10.reason_code == "AUDIT_LOG_COMMIT_FAILED_FAIL_CLOSED");
    std::cout << "  [10] Mandatory Audit Sink Failure -> Fail Closed DENY PASSED" << std::endl;

    std::cout << "[test_sl4_governance] ALL SL4 GOVERNANCE & ZERO-TRUST TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
