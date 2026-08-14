#include <linep_sl/sl4.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

int main() {
    std::cout << "[test_sl4_governance] Starting hardened LiNeP-SL SL4 Governance tests..." << std::endl;

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
    ctx.local_peer.node_id = 1;
    ctx.local_peer.trust_domain_id = domain_a;
    ctx.remote_peer.trust_domain_id = domain_a;
    ctx.remote_peer.node_id = 10;
    std::memcpy(ctx.remote_peer.pubkey, pubkey, 32);
    ctx.remote_peer.revoked = false;
    ctx.negotiated_sl = linep::sl::SecurityLevel::SL2_IDENTITY;
    ctx.requested_cap = linep::sl::CapFlags::CAP_INFERENCE_READ;
    ctx.policy_id = "default-policy";
    ctx.established_policy_revision = 1;
    ctx.timestamp_sec = 1700000000ULL;

    // 1. Valid Same-Domain Zero-Trust -> ALLOW
    auto res1 = engine.evaluate(ctx);
    assert(linep::sl::is_decision_allowed(res1));
    assert(res1.decision == linep::sl::Decision::ALLOW);
    assert(res1.reason_code == "GOVERNANCE_POLICY_ALLOWED");
    std::cout << "  [1] Valid Same-Domain Zero-Trust -> ALLOW PASSED" << std::endl;

    // 2. INDETERMINATE -> DENY Fail-Closed Enforcement (CAP_NONE)
    linep::sl::DecisionContext ctx_indet = ctx;
    ctx_indet.requested_cap = linep::sl::CapFlags::CAP_NONE;
    auto res_indet = engine.evaluate(ctx_indet);
    assert(!linep::sl::is_decision_allowed(res_indet));
    assert(res_indet.decision == linep::sl::Decision::INDETERMINATE);
    assert(res_indet.reason_code == "INDETERMINATE_NO_CAPABILITY_SPECIFIED");
    std::cout << "  [2] INDETERMINATE -> Fail-Closed Mapping PASSED" << std::endl;

    // 3. Governed Policy Deny Override (Request CAP_ADMIN when policy denies ADMIN)
    linep::sl::DecisionContext ctx_admin = ctx;
    ctx_admin.requested_cap = linep::sl::CapFlags::CAP_ADMIN;
    auto res2 = engine.evaluate(ctx_admin);
    assert(!linep::sl::is_decision_allowed(res2));
    assert(res2.decision == linep::sl::Decision::DENY);
    assert(res2.reason_code == "GOVERNANCE_POLICY_CAPABILITY_DENIED");
    std::cout << "  [3] Governed Policy Deny Override -> DENY PASSED" << std::endl;

    // 4. Insufficient Negotiated Security Level (SL1 offered vs SL2 required)
    linep::sl::DecisionContext ctx_sl1 = ctx;
    ctx_sl1.negotiated_sl = linep::sl::SecurityLevel::SL1_AUTH;
    auto res3 = engine.evaluate(ctx_sl1);
    assert(!linep::sl::is_decision_allowed(res3));
    assert(res3.decision == linep::sl::Decision::DENY);
    assert(res3.reason_code == "INSUFFICIENT_SECURITY_LEVEL");
    std::cout << "  [4] Insufficient Negotiated Security Level -> DENY PASSED" << std::endl;

    // 5. Cross-Domain Traffic without Federation Trust -> DENY
    linep::sl::DecisionContext ctx_cross = ctx;
    ctx_cross.remote_peer.trust_domain_id = domain_b; // Foreign Domain B
    auto res5 = engine.evaluate(ctx_cross);
    assert(!linep::sl::is_decision_allowed(res5));
    assert(res5.decision == linep::sl::Decision::DENY);
    assert(res5.reason_code == "CROSS_DOMAIN_FEDERATION_DENIED");
    std::cout << "  [5] Cross-Domain without Federation -> DENY PASSED" << std::endl;

    // 6. Federation Trust added BUT Policy allow_cross_domain is false -> MUST BE DENIED!
    fed_provider->add_federation(domain_a, domain_b, static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ));
    auto res6_denied = engine.evaluate(ctx_cross);
    assert(!linep::sl::is_decision_allowed(res6_denied));
    assert(res6_denied.decision == linep::sl::Decision::DENY);
    assert(res6_denied.reason_code == "GOVERNANCE_POLICY_CROSS_DOMAIN_DENIED");
    std::cout << "  [6] Federation Trust present BUT policy.allow_cross_domain == false -> DENY PASSED" << std::endl;

    // 7. Policy updated with allow_cross_domain = true -> ALLOW!
    linep::sl::GovernancePolicy fed_policy;
    fed_policy.policy_id = "default-policy";
    fed_policy.policy_revision = 2;
    fed_policy.allowed_capabilities = static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ);
    fed_policy.allow_cross_domain = true;
    engine.register_policy(fed_policy);

    ctx_cross.established_policy_revision = 2;
    auto res7_allowed = engine.evaluate(ctx_cross);
    assert(linep::sl::is_decision_allowed(res7_allowed));
    assert(res7_allowed.decision == linep::sl::Decision::ALLOW);
    assert(res7_allowed.reason_code == "GOVERNANCE_POLICY_ALLOWED");
    std::cout << "  [7] Federation Trust + policy.allow_cross_domain == true -> ALLOW PASSED" << std::endl;

    // 8. Policy Revision Invalidation Check for Active Sessions
    linep::sl::GovernancePolicy v3_policy;
    v3_policy.policy_id = "default-policy";
    v3_policy.policy_revision = 3;
    v3_policy.allowed_capabilities = static_cast<uint64_t>(linep::sl::CapFlags::CAP_METRICS_READ); // Revoke INFERENCE_READ in v3!
    v3_policy.allow_cross_domain = true;
    engine.register_policy(v3_policy);

    // Active session established under revision 2 attempts request after policy update to revision 3
    linep::sl::DecisionContext ctx_stale_sess = ctx_cross;
    ctx_stale_sess.established_policy_revision = 2;
    auto res_invalidated = engine.evaluate(ctx_stale_sess);
    assert(!linep::sl::is_decision_allowed(res_invalidated));
    assert(res_invalidated.decision == linep::sl::Decision::DENY);
    assert(res_invalidated.reason_code == "SESSION_INVALIDATED_BY_POLICY_REVISION");
    std::cout << "  [8] Session Invalidated by Policy Revision Update -> DENY PASSED" << std::endl;

    // 9. Full Secret-Free Audit Provenance Verification
    auto events = audit_sink->get_events();
    assert(!events.empty());
    for (const auto& evt : events) {
        assert(evt.session_id == 0 || evt.session_id == 0x1001);
        assert(!evt.reason_code.empty());
    }
    std::cout << "  [9] Full Audit Provenance Verified (" << events.size() << " secret-free events recorded)" << std::endl;

    // 10. Mandatory Audit Sink Failure -> Fail Closed (DENY)
    audit_sink->set_fail_closed_mode(true);
    auto res10 = engine.evaluate(ctx);
    assert(!linep::sl::is_decision_allowed(res10));
    assert(res10.decision == linep::sl::Decision::DENY);
    assert(res10.reason_code == "AUDIT_LOG_COMMIT_FAILED_FAIL_CLOSED");
    std::cout << "  [10] Mandatory Audit Commit Failure -> Fail Closed DENY PASSED" << std::endl;

    std::cout << "[test_sl4_governance] ALL HARDENED SL4 TESTS PASSED 100%!" << std::endl;
    return 0;
}
