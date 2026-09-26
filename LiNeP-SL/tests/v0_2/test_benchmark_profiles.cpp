#include <linep_sl/v0_2/authorization.hpp>
#include <linep_sl/v0_2/governance.hpp>
#include <linep_sl/v0_2/plane_authenticator.hpp>
#include <linep_sl/v0_2/replay_window.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

session_record make_bench_session() {
    session_record s;
    s.session_id = 7001;
    s.security_epoch = 1;
    s.key_id = 1;
    s.negotiated_level = security_level::sl4_governed;
    s.suite = crypto_suite::hmac_sha256_128;
    s.state = session_state::active;
    s.established_at_us = 1000000;
    s.key_activated_at_us = 1000000;
    s.expires_at_us = 9999999999ULL;

    s.initiator.endpoint = {10, 100, 1};
    s.initiator.trust_domain_id = 1;
    s.initiator.subject_id = 101;
    s.initiator.credential_revision = 1;
    s.initiator.authenticated_at_us = 1000000;
    s.initiator.credential_expires_at_us = s.expires_at_us;
    s.initiator_control_epoch = 1;
    s.initiator_lease_token = 0x11223344;

    s.responder.endpoint = {20, 200, 2};
    s.responder.trust_domain_id = 1;
    s.responder.subject_id = 202;
    s.responder.credential_revision = 1;
    s.responder.authenticated_at_us = 1000000;
    s.responder.credential_expires_at_us = s.expires_at_us;
    s.responder_control_epoch = 1;
    s.responder_lease_token = 0x55667788;
    return s;
}

std::vector<std::uint8_t> make_bench_key() {
    return std::vector<std::uint8_t>(32, 0x42);
}

} // namespace

int main() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "     LiNeP-SL V0.2 Security Level Performance Profile Benchmark                " << std::endl;
    std::cout << "================================================================================" << std::endl;

    constexpr int iterations = 50000;
    auto session = make_bench_session();
    auto key = make_bench_key();
    std::uint64_t now_us = 2000000;

    // 1. SL1 Benchmark: UDP Control Plane Datagram Protection
    {
        linep::v0_2::udp_control_datagram dgram;
        dgram.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
        dgram.node_id = 10;
        dgram.runtime_id = 100;
        dgram.endpoint_id = 1;
        dgram.control_epoch = 1;
        dgram.control_seq = 1;
        dgram.lease_token = 0x11223344;

        sliding_replay_window win;
        std::vector<std::uint8_t> tag;
        sign_control_datagram(session, key, message_direction::initiator_to_responder,
                              security_level::sl1_authenticated, security_action::advertise,
                              dgram, tag);

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            dgram.control_seq = static_cast<std::uint32_t>(i + 1);
            sign_control_datagram(session, key, message_direction::initiator_to_responder,
                                  security_level::sl1_authenticated, security_action::advertise,
                                  dgram, tag);
            verify_control_datagram(session, key, message_direction::initiator_to_responder,
                                    security_level::sl1_authenticated, security_action::advertise,
                                    dgram, tag, win, now_us);
        }
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double ops_per_sec = (iterations / (elapsed_ms / 1000.0));
        double us_per_op = (elapsed_ms * 1000.0) / iterations;

        std::cout << "Profile SL1 (Control Datagram Auth + Replay):" << std::endl;
        std::cout << "  Iterations: " << iterations << " | Elapsed: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms" << std::endl;
        std::cout << "  Throughput: " << static_cast<long>(ops_per_sec) << " ops/sec | Latency: " << std::setprecision(3) << us_per_op << " us/op\n" << std::endl;
    }

    // 2. SL2 Benchmark: TCP Data Plane Request + Session Bind
    {
        linep::v0_2::session_bind_envelope bind;
        bind.identity = session.initiator.endpoint;
        bind.control_epoch = session.initiator_control_epoch;
        bind.lease_token = session.initiator_lease_token;

        linep::v0_2::request_envelope req;
        req.stream = {1, 100, 0};
        req.model_id = "bench-model";
        std::vector<std::uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
        std::vector<std::uint8_t> tag;

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            validate_transport_session_binding(session, session_participant_role::initiator, bind, now_us);
            sign_request(session, key, message_direction::initiator_to_responder,
                         security_level::sl2_identity, security_action::execute,
                         req, payload, tag);
            verify_request(session, key, message_direction::initiator_to_responder,
                           security_level::sl2_identity, security_action::execute,
                           req, payload, tag, now_us);
        }
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double ops_per_sec = (iterations / (elapsed_ms / 1000.0));
        double us_per_op = (elapsed_ms * 1000.0) / iterations;

        std::cout << "Profile SL2 (TCP Session Binding + Request Auth):" << std::endl;
        std::cout << "  Iterations: " << iterations << " | Elapsed: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms" << std::endl;
        std::cout << "  Throughput: " << static_cast<long>(ops_per_sec) << " ops/sec | Latency: " << std::setprecision(3) << us_per_op << " us/op\n" << std::endl;
    }

    // 3. SL3 Benchmark: Fine-grained Authorization
    {
        policy_authorizer auth;
        subject_policy sub;
        sub.subject_id = 101;
        sub.trust_domain_id = 1;
        sub.capabilities = capability_flags::chat | capability_flags::generate;
        sub.allowed_resources.push_back({resource_kind::model, "bench-model"});
        auth.add_subject_policy(sub);

        linep::v0_2::runtime_capabilities_descriptor rt;
        rt.supported_models = {"bench-model"};
        rt.supported_profiles = {linep::v0_2::runtime_profile::chat};

        authorization_request req;
        req.trust_domain_id = 1;
        req.subject_id = 101;
        req.action = security_action::execute;
        req.profile = linep::v0_2::runtime_profile::chat;
        req.resource = {resource_kind::model, "bench-model"};

        auto start = std::chrono::high_resolution_clock::now();
        authorization_decision dec;
        for (int i = 0; i < iterations; ++i) {
            auth.validate_against_advertised_capabilities(req, rt, dec);
        }
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double ops_per_sec = (iterations / (elapsed_ms / 1000.0));
        double us_per_op = (elapsed_ms * 1000.0) / iterations;

        std::cout << "Profile SL3 (Fine-grained Authorization Decisions):" << std::endl;
        std::cout << "  Iterations: " << iterations << " | Elapsed: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms" << std::endl;
        std::cout << "  Throughput: " << static_cast<long>(ops_per_sec) << " ops/sec | Latency: " << std::setprecision(3) << us_per_op << " us/op\n" << std::endl;
    }

    // 4. SL4 Benchmark: Tamper-Evident Hash Chained Audit Pipeline
    {
        governance_engine gov(1, "policy-bench", 1, 1);
        auto sink = std::make_shared<in_memory_audit_sink_v02>();
        gov.add_audit_sink(sink);

        std::vector<std::uint8_t> digest = {1, 2, 3, 4};

        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            gov.emit_audit_event(audit_event_type_v02::authorization_allowed,
                                 session.session_id, session.initiator.subject_id,
                                 session.responder.trust_domain_id, security_action::execute,
                                 "bench-model", authorization_outcome::allow, "ok",
                                 digest, now_us);
        }
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double ops_per_sec = (iterations / (elapsed_ms / 1000.0));
        double us_per_op = (elapsed_ms * 1000.0) / iterations;

        std::cout << "Profile SL4 (Tamper-evident Hash-chained Audit Events):" << std::endl;
        std::cout << "  Iterations: " << iterations << " | Elapsed: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms" << std::endl;
        std::cout << "  Throughput: " << static_cast<long>(ops_per_sec) << " ops/sec | Latency: " << std::setprecision(3) << us_per_op << " us/op\n" << std::endl;
    }

    std::cout << "ALL BENCHMARKS COMPLETED SUCCESSFULLY!" << std::endl;
    return 0;
}
