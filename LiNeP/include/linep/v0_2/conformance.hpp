#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/transport.hpp"
#include "linep/v0_2/lease.hpp"

namespace linep::v0_2 {

struct test_result {
    std::string test_name;
    bool passed{false};
    std::string details;
    std::uint64_t duration_ms{0};
};

struct profile_conformance_status {
    runtime_profile profile{runtime_profile::unspecified};
    std::string profile_name;
    bool conformant{false};
    std::vector<std::string> passed_suites;
    std::vector<std::string> failed_suites;
};

struct conformance_report {
    std::string target_endpoint;
    std::size_t total_tests{0};
    std::size_t passed_tests{0};
    std::size_t failed_tests{0};
    std::vector<test_result> results;
    std::vector<profile_conformance_status> profiles;

    bool is_all_passed() const noexcept {
        return total_tests > 0 && failed_tests == 0 && passed_tests == total_tests;
    }
};

class conformance_runner {
public:
    explicit conformance_runner(std::string host, std::uint16_t port);
    ~conformance_runner();

    // UDP control plane (lease issuer) of the endpoint. When set, every suite
    // connection is bound with SESSION_BIND and run_all() adds the dual-plane suites.
    void set_control_endpoint(std::string host, std::uint16_t port);
    bool has_control_endpoint() const noexcept { return control_port_ != 0; }

    // Run all standardized LiNeP V0.2 conformance test suites
    conformance_report run_all();

    // Run conformance for a specific profile (generate, chat, embed)
    conformance_report run_profile(runtime_profile profile);

    // Run only the dual-plane SESSION_BIND suites (needs a control endpoint and an
    // endpoint that requires leases)
    conformance_report run_dual_plane();

    // Standardized test suites:
    test_result test_capabilities_handshake();
    test_result test_basic_chat_streaming();
    test_result test_reasoning_deltas();
    test_result test_embedding_space();
    test_result test_network_cancellation();
    test_result test_window_update_flow_control();
    test_result test_fail_closed_robustness();
    test_result test_content_snapshot_mode();
    test_result test_multi_output_streams();

    // Dual-plane SESSION_BIND suites (lease-enforcing endpoint):
    test_result test_dual_plane_bind_before_lease_ack();
    test_result test_dual_plane_duplicate_bind();
    test_result test_dual_plane_unbound_request();
    test_result test_dual_plane_stale_rebind();
    test_result test_dual_plane_identity_change();
    test_result test_dual_plane_malformed_bind();

    // SL1 MAC authentication credentials. When set, run_all() adds the PROFILE_SL1 suites.
    void set_sl1_credentials(std::uint16_t key_id, std::vector<std::uint8_t> key);
    bool has_sl1() const noexcept { return !sl1_key_.empty(); }

    // Run only the PROFILE_SL1 test suites
    conformance_report run_sl1();

    // Standardized SL1 test suites:
    test_result test_sl1_mutual_handshake();
    test_result test_sl1_authenticated_streaming();
    test_result test_sl1_missing_auth_rejection();
    test_result test_sl1_wrong_key_rejection();
    test_result test_sl1_replay_rejection();

private:
    std::unique_ptr<envelope_connection> create_connection();
    std::unique_ptr<lease_client> make_lease_client() const;
    bool ensure_lease(std::string& out_error);
    void run_dual_plane_suites(conformance_report& rep);
    void run_sl1_suites(conformance_report& rep);

    std::string host_;
    std::uint16_t port_;
    std::string control_host_;
    std::uint16_t control_port_{0};
    std::unique_ptr<lease_client> lease_;
    std::uint16_t sl1_key_id_{1};
    std::vector<std::uint8_t> sl1_key_;
};

} // namespace linep::v0_2
