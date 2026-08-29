#include <iostream>
#include <iomanip>
#include <cstdlib>
#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/conformance.hpp"

#define LINEP_TEST_CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAILED: " #expr " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while(0)

int main() {
    std::cout << "=== LiNeP V0.2 Standalone Conformance Test Suite ===" << std::endl;

    // 1. Standard Conformance Run
    linep::v0_2::mock_runtime_config cfg{};
    cfg.model_id = "linep-conformance-model-v02";
    cfg.delay_per_event_ms = 1;
    cfg.default_tokens = 8;
    cfg.enable_reasoning = true;
    cfg.embedding_space_id = "nomic-embed-v1.5";
    cfg.embedding_dimensions = 768;

    linep::v0_2::mock_runtime_server mock_server(cfg);
    LINEP_TEST_CHECK(mock_server.start(0));
    std::uint16_t test_port = mock_server.get_bound_port();
    LINEP_TEST_CHECK(test_port > 0);

    std::cout << "Mock Server listening on 127.0.0.1:" << test_port << std::endl;

    linep::v0_2::conformance_runner runner("127.0.0.1", test_port);
    auto report = runner.run_all();

    std::cout << "\n------------------------------------------------------------" << std::endl;
    std::cout << "CONFORMANCE TEST RESULTS: " << report.passed_tests << "/" << report.total_tests << " SUITES PASSED" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

    for (const auto& res : report.results) {
        std::cout << "[" << (res.passed ? "PASS" : "FAIL") << "] " 
                  << std::left << std::setw(34) << res.test_name 
                  << " (" << res.duration_ms << " ms) -> " << res.details << std::endl;
    }

    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << "PROFILE CONFORMANCE SUMMARY:" << std::endl;
    for (const auto& prof : report.profiles) {
        std::cout << std::left << std::setw(26) << prof.profile_name << " ...... " 
                  << (prof.conformant ? "CONFORMANT" : "NON-CONFORMANT") << std::endl;
    }
    std::cout << "------------------------------------------------------------\n" << std::endl;

    LINEP_TEST_CHECK(report.is_all_passed());
    LINEP_TEST_CHECK(report.total_tests >= 7);
    for (const auto& prof : report.profiles) {
        LINEP_TEST_CHECK(prof.conformant);
    }

    // 2. Edge Case Tests using Mock Runtime Modes:
    // 2.1 Forced Backend Error Mode (fail_after_n = 3)
    {
        std::cout << "[Edge Test 1] Testing Forced Backend Error (fail_after_n = 3)..." << std::endl;
        linep::v0_2::mock_runtime_config fail_cfg = cfg;
        fail_cfg.fail_after_n = 3;
        mock_server.set_config(fail_cfg);

        auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", test_port);
        LINEP_TEST_CHECK(conn != nullptr);

        linep::v0_2::stream_identity id{201, 2001, 0};
        linep::v0_2::request_envelope req{id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Trigger fail"};
        LINEP_TEST_CHECK(conn->send_request(req));

        std::vector<std::uint8_t> raw;
        bool saw_fail = false;
        while (conn->receive_envelope_raw(raw)) {
            linep::v0_2::event_envelope evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), evt));
            if (evt.event_type == linep::v0_2::runtime_event_type::failed) {
                LINEP_TEST_CHECK(evt.outcome == linep::v0_2::terminal_outcome::failed);
                LINEP_TEST_CHECK(evt.error.code == 500);
                saw_fail = true;
                break;
            }
        }
        LINEP_TEST_CHECK(saw_fail);
        std::cout << "  -> Forced Backend Error test PASSED" << std::endl;
    }

    // 2.2 Cancel After Accept (Cancellation before first delta)
    {
        std::cout << "[Edge Test 2] Testing Cancel After Accept (Pre-Delta Cancellation)..." << std::endl;
        linep::v0_2::mock_runtime_config cancel_cfg = cfg;
        cancel_cfg.cancel_after_accept = true;
        mock_server.set_config(cancel_cfg);

        auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", test_port);
        LINEP_TEST_CHECK(conn != nullptr);

        linep::v0_2::stream_identity id{202, 2002, 0};
        linep::v0_2::request_envelope req{id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Trigger immediate cancel"};
        LINEP_TEST_CHECK(conn->send_request(req));

        std::vector<std::uint8_t> raw;
        bool saw_cancel = false;
        while (conn->receive_envelope_raw(raw)) {
            linep::v0_2::event_envelope evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), evt));
            if (evt.event_type == linep::v0_2::runtime_event_type::cancelled) {
                LINEP_TEST_CHECK(evt.outcome == linep::v0_2::terminal_outcome::cancelled);
                LINEP_TEST_CHECK(evt.error.code == 499);
                saw_cancel = true;
                break;
            }
        }
        LINEP_TEST_CHECK(saw_cancel);
        std::cout << "  -> Cancel After Accept test PASSED" << std::endl;
    }

    // 2.3 Batch Embedding (batch_embed_count = 4)
    {
        std::cout << "[Edge Test 3] Testing Batch Embedding (batch_embed_count = 4)..." << std::endl;
        linep::v0_2::mock_runtime_config batch_cfg = cfg;
        batch_cfg.batch_embed_count = 4;
        mock_server.set_config(batch_cfg);

        auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", test_port);
        LINEP_TEST_CHECK(conn != nullptr);

        linep::v0_2::stream_identity id{203, 2003, 0};
        linep::v0_2::request_envelope req{id, linep::v0_2::runtime_profile::embed, "linep-conformance-model-v02", "Batch embed"};
        LINEP_TEST_CHECK(conn->send_request(req));

        std::vector<std::uint8_t> raw;
        std::size_t emb_count = 0;
        bool completed_ok = false;

        while (conn->receive_envelope_raw(raw)) {
            linep::v0_2::event_envelope evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), evt));
            if (evt.event_type == linep::v0_2::runtime_event_type::embedding_result) {
                LINEP_TEST_CHECK(evt.stream.output_id == emb_count);
                emb_count++;
            } else if (evt.event_type == linep::v0_2::runtime_event_type::completed) {
                completed_ok = true;
                break;
            }
        }
        LINEP_TEST_CHECK(emb_count == 4);
        LINEP_TEST_CHECK(completed_ok);
        std::cout << "  -> Batch Embedding test PASSED (4 distinct output_id vectors)" << std::endl;
    }

    mock_server.stop();
    std::cout << "ALL CONFORMANCE AND EDGE MODE TESTS PASSED 100%!" << std::endl;
    return 0;
}
