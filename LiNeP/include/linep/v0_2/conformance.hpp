#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/transport.hpp"

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

    // Run all standardized LiNeP V0.2 conformance test suites
    conformance_report run_all();

    // Run conformance for a specific profile (generate, chat, embed)
    conformance_report run_profile(runtime_profile profile);

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

private:
    std::unique_ptr<envelope_connection> create_connection();

    std::string host_;
    std::uint16_t port_;
};

} // namespace linep::v0_2
