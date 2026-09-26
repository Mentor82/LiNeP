#include <linep_sl/v0_2/authorization.hpp>

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>

#define LINEP_SL_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::abort(); \
        } \
    } while (0)

using namespace linep::sl::v0_2;

void test_deny_by_default() {
    std::cout << "[Test 1] Deny by default invariants..." << std::endl;
    policy_authorizer auth;

    // Unknown action -> deny
    authorization_request req1;
    req1.trust_domain_id = 1;
    req1.subject_id = 100;
    req1.action = security_action::unknown;
    auto dec1 = auth.authorize(req1);
    LINEP_SL_TEST_CHECK(!dec1.is_allowed());
    LINEP_SL_TEST_CHECK(dec1.reason_code == "action_unknown");

    // Unauthenticated subject -> deny
    authorization_request req2;
    req2.trust_domain_id = 0;
    req2.subject_id = 0;
    req2.action = security_action::execute;
    auto dec2 = auth.authorize(req2);
    LINEP_SL_TEST_CHECK(!dec2.is_allowed());
    LINEP_SL_TEST_CHECK(dec2.reason_code == "unauthenticated_subject");

    // Valid action & subject, but no policy registered -> deny
    authorization_request req3;
    req3.trust_domain_id = 1;
    req3.subject_id = 100;
    req3.action = security_action::execute;
    req3.profile = linep::v0_2::runtime_profile::chat;
    req3.resource = {resource_kind::model, "test-model"};
    auto dec3 = auth.authorize(req3);
    LINEP_SL_TEST_CHECK(!dec3.is_allowed());
    LINEP_SL_TEST_CHECK(dec3.reason_code == "no_policy_found");

    std::cout << "  -> Deny by default PASSED" << std::endl;
}

void test_subject_and_role_authorization() {
    std::cout << "[Test 2] Subject and role authorization..." << std::endl;
    policy_authorizer auth;

    // Register subject policy: chat + generate on "model-alpha"
    subject_policy sub;
    sub.subject_id = 1001;
    sub.trust_domain_id = 10;
    sub.capabilities = capability_flags::chat | capability_flags::generate | capability_flags::stream_output;
    sub.allowed_resources.push_back({resource_kind::model, "model-alpha"});
    auth.add_subject_policy(sub);

    // 1. Authorized chat request on model-alpha
    authorization_request req_ok;
    req_ok.trust_domain_id = 10;
    req_ok.subject_id = 1001;
    req_ok.action = security_action::execute;
    req_ok.profile = linep::v0_2::runtime_profile::chat;
    req_ok.resource = {resource_kind::model, "model-alpha"};
    req_ok.streaming_requested = true;
    auto dec_ok = auth.authorize(req_ok);
    LINEP_SL_TEST_CHECK(dec_ok.is_allowed());
    LINEP_SL_TEST_CHECK(dec_ok.reason_code == "ok");

    // 2. Resource denied (model-beta not permitted)
    authorization_request req_bad_res = req_ok;
    req_bad_res.resource = {resource_kind::model, "model-beta"};
    auto dec_bad_res = auth.authorize(req_bad_res);
    LINEP_SL_TEST_CHECK(!dec_bad_res.is_allowed());
    LINEP_SL_TEST_CHECK(dec_bad_res.reason_code == "resource_not_permitted");

    // 3. Capability missing (subject lacks embed capability)
    authorization_request req_embed = req_ok;
    req_embed.profile = linep::v0_2::runtime_profile::embed;
    req_embed.resource = {resource_kind::embedding_space, "emb-space-1"};
    auto dec_embed = auth.authorize(req_embed);
    LINEP_SL_TEST_CHECK(!dec_embed.is_allowed());
    LINEP_SL_TEST_CHECK(dec_embed.reason_code == "capability_missing");

    // 4. Role policy scoped to trust_domain_id = 10 granting embed capability & wildcard resource
    role_policy role_embed;
    role_embed.trust_domain_id = 10;
    role_embed.role_name = "embedder";
    role_embed.capabilities = capability_flags::embed;
    role_embed.allowed_resources.push_back({resource_kind::embedding_space, "*"});
    auth.add_role_policy(role_embed);

    req_embed.roles.push_back("embedder");
    auto dec_embed_role = auth.authorize(req_embed);
    LINEP_SL_TEST_CHECK(dec_embed_role.is_allowed());
    LINEP_SL_TEST_CHECK(dec_embed_role.reason_code == "ok");

    // 5. Cross-domain role isolation (Hardening #3):
    // Register role in domain 20; caller from domain 10 must NOT inherit permissions
    role_policy role_domain20;
    role_domain20.trust_domain_id = 20;
    role_domain20.role_name = "admin_d20";
    role_domain20.capabilities = capability_flags::administer;
    role_domain20.allowed_resources.push_back({resource_kind::system, "*"});
    auth.add_role_policy(role_domain20);

    authorization_request req_cross_domain = req_ok;
    req_cross_domain.action = security_action::administer;
    req_cross_domain.resource = {resource_kind::system, "cluster"};
    req_cross_domain.roles = {"admin_d20"};
    auto dec_cross = auth.authorize(req_cross_domain);
    LINEP_SL_TEST_CHECK(!dec_cross.is_allowed()); // Denied because domain 10 cannot access domain 20's role

    std::cout << "  -> Subject and role authorization PASSED" << std::endl;
}

void test_protected_actions() {
    std::cout << "[Test 3] Protected actions & superuser grants..." << std::endl;
    policy_authorizer auth;

    // Normal user: chat only
    subject_policy normal_user;
    normal_user.subject_id = 2001;
    normal_user.trust_domain_id = 1;
    normal_user.capabilities = capability_flags::chat;
    normal_user.allowed_resources.push_back({resource_kind::model, "*"});
    auth.add_subject_policy(normal_user);

    // Power user: tool invoke + cancel
    subject_policy power_user;
    power_user.subject_id = 2002;
    power_user.trust_domain_id = 1;
    power_user.capabilities = capability_flags::chat | capability_flags::tool_invoke | capability_flags::cancel;
    power_user.allowed_resources.push_back({resource_kind::model, "*"});
    power_user.allowed_resources.push_back({resource_kind::tool, "calculator"});
    auth.add_subject_policy(power_user);

    // Superuser Admin: administer + metrics with {system, "*"}
    subject_policy admin_user;
    admin_user.subject_id = 2003;
    admin_user.trust_domain_id = 1;
    admin_user.capabilities = capability_flags::all;
    admin_user.allowed_resources.push_back({resource_kind::system, "*"});
    auth.add_subject_policy(admin_user);

    // Normal user trying to cancel -> denied
    authorization_request req_cancel;
    req_cancel.trust_domain_id = 1;
    req_cancel.subject_id = 2001;
    req_cancel.action = security_action::cancel;
    req_cancel.resource = {resource_kind::model, "any"};
    LINEP_SL_TEST_CHECK(!auth.authorize(req_cancel).is_allowed());

    // Power user cancelling -> allowed
    req_cancel.subject_id = 2002;
    LINEP_SL_TEST_CHECK(auth.authorize(req_cancel).is_allowed());

    // Normal user invoking tool -> denied
    authorization_request req_tool;
    req_tool.trust_domain_id = 1;
    req_tool.subject_id = 2001;
    req_tool.action = security_action::invoke_tool;
    req_tool.resource = {resource_kind::tool, "calculator"};
    LINEP_SL_TEST_CHECK(!auth.authorize(req_tool).is_allowed());

    // Power user invoking calculator -> allowed
    req_tool.subject_id = 2002;
    LINEP_SL_TEST_CHECK(auth.authorize(req_tool).is_allowed());

    // Power user invoking unauthorized tool -> denied
    req_tool.resource = {resource_kind::tool, "system_shell"};
    LINEP_SL_TEST_CHECK(!auth.authorize(req_tool).is_allowed());

    // Normal user reading metrics -> denied
    authorization_request req_metrics;
    req_metrics.trust_domain_id = 1;
    req_metrics.subject_id = 2001;
    req_metrics.action = security_action::read_metrics;
    req_metrics.resource = {resource_kind::system, "telemetry"};
    LINEP_SL_TEST_CHECK(!auth.authorize(req_metrics).is_allowed());

    // Admin reading metrics -> allowed
    req_metrics.subject_id = 2003;
    LINEP_SL_TEST_CHECK(auth.authorize(req_metrics).is_allowed());

    // Hardening #4: Explicit superuser grant {system, "*"} matches any resource kind
    authorization_request req_admin_model;
    req_admin_model.trust_domain_id = 1;
    req_admin_model.subject_id = 2003;
    req_admin_model.action = security_action::execute;
    req_admin_model.profile = linep::v0_2::runtime_profile::generate;
    req_admin_model.resource = {resource_kind::model, "sensitive-model-xyz"};
    LINEP_SL_TEST_CHECK(auth.authorize(req_admin_model).is_allowed());

    authorization_request req_admin_tool;
    req_admin_tool.trust_domain_id = 1;
    req_admin_tool.subject_id = 2003;
    req_admin_tool.action = security_action::invoke_tool;
    req_admin_tool.resource = {resource_kind::tool, "arbitrary_privileged_tool"};
    LINEP_SL_TEST_CHECK(auth.authorize(req_admin_tool).is_allowed());

    // Contrast: {model, "*"} does NOT match a tool resource kind
    authorization_request req_power_tool;
    req_power_tool.trust_domain_id = 1;
    req_power_tool.subject_id = 2002; // has {model, "*"} and {tool, "calculator"}
    req_power_tool.action = security_action::invoke_tool;
    req_power_tool.resource = {resource_kind::tool, "other_tool"};
    LINEP_SL_TEST_CHECK(!auth.authorize(req_power_tool).is_allowed());

    std::cout << "  -> Protected actions PASSED" << std::endl;
}

void test_execution_constraints() {
    std::cout << "[Test 4] Execution policy constraints..." << std::endl;
    policy_authorizer auth;

    subject_policy sub;
    sub.subject_id = 3001;
    sub.trust_domain_id = 1;
    sub.capabilities = capability_flags::generate | capability_flags::chat | capability_flags::stream_output | capability_flags::reasoning;
    sub.allowed_resources.push_back({resource_kind::model, "*"});
    sub.constraints.max_allowed_tokens = 512;
    sub.constraints.max_allowed_temperature = 1.0f;
    sub.constraints.disallow_reasoning = true;
    auth.add_subject_policy(sub);

    // 1. Within token limit
    authorization_request req;
    req.trust_domain_id = 1;
    req.subject_id = 3001;
    req.action = security_action::execute;
    req.profile = linep::v0_2::runtime_profile::generate;
    req.resource = {resource_kind::model, "model-x"};
    req.requested_tokens = 256;
    req.requested_temperature = 0.7f;
    LINEP_SL_TEST_CHECK(auth.authorize(req).is_allowed());

    // 2. Token limit exceeded
    req.requested_tokens = 1024;
    auto dec_tokens = auth.authorize(req);
    LINEP_SL_TEST_CHECK(!dec_tokens.is_allowed());
    LINEP_SL_TEST_CHECK(dec_tokens.reason_code == "max_tokens_exceeded");

    // 3. Temperature exceeded
    req.requested_tokens = 256;
    req.requested_temperature = 1.5f;
    auto dec_temp = auth.authorize(req);
    LINEP_SL_TEST_CHECK(!dec_temp.is_allowed());
    LINEP_SL_TEST_CHECK(dec_temp.reason_code == "temperature_exceeded");

    // 4. Hardening #5: Non-finite temperature rejection (NaN / Inf)
    req.requested_temperature = std::numeric_limits<float>::quiet_NaN();
    auto dec_nan = auth.authorize(req);
    LINEP_SL_TEST_CHECK(!dec_nan.is_allowed());
    LINEP_SL_TEST_CHECK(dec_nan.reason_code == "temperature_non_finite");

    req.requested_temperature = std::numeric_limits<float>::infinity();
    auto dec_inf = auth.authorize(req);
    LINEP_SL_TEST_CHECK(!dec_inf.is_allowed());
    LINEP_SL_TEST_CHECK(dec_inf.reason_code == "temperature_non_finite");

    // 5. Reasoning disallowed by constraint
    req.requested_temperature = 0.7f;
    req.reasoning_requested = true;
    auto dec_reason = auth.authorize(req);
    LINEP_SL_TEST_CHECK(!dec_reason.is_allowed());
    LINEP_SL_TEST_CHECK(dec_reason.reason_code == "reasoning_disallowed");

    std::cout << "  -> Execution policy constraints PASSED" << std::endl;
}

void test_advertised_capability_mapping() {
    std::cout << "[Test 5] Advertised runtime capabilities validation (never direct grants)..." << std::endl;
    policy_authorizer auth;

    // Caller 1 is authorized for chat and generate on "model-foo" and "any-model"
    subject_policy caller1;
    caller1.subject_id = 4001;
    caller1.trust_domain_id = 1;
    caller1.capabilities = capability_flags::chat | capability_flags::generate | capability_flags::stream_output;
    caller1.allowed_resources.push_back({resource_kind::model, "model-foo"});
    caller1.allowed_resources.push_back({resource_kind::model, "dynamic-model"});
    auth.add_subject_policy(caller1);

    linep::v0_2::runtime_capabilities_descriptor rt_desc;
    rt_desc.supported_models = {"model-foo", "model-bar"};
    rt_desc.supported_profiles = {linep::v0_2::runtime_profile::chat};
    rt_desc.supports_streaming = true;
    rt_desc.supports_cancellation = true;
    rt_desc.supports_reasoning_deltas = false;

    // 1. Authorized caller requests supported model + profile -> succeeds
    authorization_request req1;
    req1.trust_domain_id = 1;
    req1.subject_id = 4001;
    req1.action = security_action::execute;
    req1.profile = linep::v0_2::runtime_profile::chat;
    req1.resource = {resource_kind::model, "model-foo"};
    req1.streaming_requested = true;
    authorization_decision dec1;
    LINEP_SL_TEST_CHECK(auth.validate_against_advertised_capabilities(req1, rt_desc, dec1));
    LINEP_SL_TEST_CHECK(dec1.is_allowed());

    // 2. Authorized caller requests unsupported profile on runtime (generate) -> rejected
    authorization_request req2 = req1;
    req2.profile = linep::v0_2::runtime_profile::generate;
    authorization_decision dec2;
    LINEP_SL_TEST_CHECK(!auth.validate_against_advertised_capabilities(req2, rt_desc, dec2));
    LINEP_SL_TEST_CHECK(!dec2.is_allowed());
    LINEP_SL_TEST_CHECK(dec2.reason_code == "profile_not_supported_by_runtime");

    // 3. Authorized caller requests unsupported model on runtime ("model-baz") -> rejected
    authorization_request req3 = req1;
    req3.resource = {resource_kind::model, "model-baz"};
    authorization_decision dec3;
    LINEP_SL_TEST_CHECK(!auth.validate_against_advertised_capabilities(req3, rt_desc, dec3));
    LINEP_SL_TEST_CHECK(!dec3.is_allowed());

    // 4. Hardening #6: Empty supported_models acts as dynamic wildcard (e.g. Ollama backend)
    linep::v0_2::runtime_capabilities_descriptor rt_desc_dynamic = rt_desc;
    rt_desc_dynamic.supported_models.clear(); // Dynamic/wildcard

    authorization_request req_dynamic = req1;
    req_dynamic.resource = {resource_kind::model, "dynamic-model"};
    authorization_decision dec_dyn;
    LINEP_SL_TEST_CHECK(auth.validate_against_advertised_capabilities(req_dynamic, rt_desc_dynamic, dec_dyn));
    LINEP_SL_TEST_CHECK(dec_dyn.is_allowed());

    // 5. Unauthorized caller requests model-foo:
    // Even though runtime descriptor advertises model-foo and chat,
    // the unprivileged caller MUST BE REJECTED (advertised caps NEVER grant access)!
    authorization_request req_unauth;
    req_unauth.trust_domain_id = 1;
    req_unauth.subject_id = 9999; // unknown subject
    req_unauth.action = security_action::execute;
    req_unauth.profile = linep::v0_2::runtime_profile::chat;
    req_unauth.resource = {resource_kind::model, "model-foo"};
    authorization_decision dec_unauth;
    LINEP_SL_TEST_CHECK(!auth.validate_against_advertised_capabilities(req_unauth, rt_desc, dec_unauth));
    LINEP_SL_TEST_CHECK(!dec_unauth.is_allowed());
    LINEP_SL_TEST_CHECK(dec_unauth.reason_code == "no_policy_found");

    std::cout << "  -> Advertised runtime capabilities validation PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Phase D Authorization Test Suite ===" << std::endl;
    test_deny_by_default();
    test_subject_and_role_authorization();
    test_protected_actions();
    test_execution_constraints();
    test_advertised_capability_mapping();
    std::cout << "ALL PHASE D AUTHORIZATION TESTS PASSED 100%!" << std::endl;
    return 0;
}
