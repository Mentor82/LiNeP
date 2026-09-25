#include <iostream>
#include <iomanip>
#include <cstdlib>
#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/conformance.hpp"
#include "linep/v0_2/control_plane.hpp"

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

    // 2.4 Dual-Plane TCP Session Binding & Lease Invariants (Issue #15)
    {
        std::cout << "[Edge Test 4] Testing Dual-Plane TCP Session Binding Invariants (Issue #15)..." << std::endl;

        linep::v0_2::control_plane_router router;
        linep::v0_2::udp_control_datagram hello{};
        hello.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
        hello.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::node_hello);
        hello.node_id = 7001;
        hello.runtime_id = 8001;
        hello.endpoint_id = 1;
        hello.control_epoch = 1;
        hello.tcp_port = 11435;
        hello.set_trunk_ready(true);
        LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));

        linep::v0_2::udp_control_datagram invite{};
        LINEP_TEST_CHECK(router.issue_invite(linep::v0_2::node_endpoint_identity{7001, 8001, 1}, 0xC0FFEE1234ULL, invite));

        linep::v0_2::udp_control_datagram ack{};
        ack.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
        ack.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::lease_ack);
        ack.node_id = 7001;
        ack.runtime_id = 8001;
        ack.endpoint_id = 1;
        ack.control_epoch = 1;
        ack.control_seq = 2;
        ack.tcp_port = 11435;
        ack.set_trunk_ready(true);
        ack.lease_token = 0xC0FFEE1234ULL;
        LINEP_TEST_CHECK(router.ingest_datagram(ack, 2000));

        linep::v0_2::mock_runtime_config lease_cfg = cfg;
        lease_cfg.require_lease = true;
        linep::v0_2::mock_runtime_server lease_server(lease_cfg);
        lease_server.set_control_plane_router(&router);
        LINEP_TEST_CHECK(lease_server.start(0));
        std::uint16_t lease_port = lease_server.get_bound_port();

        // 4.1 Missing Bind: Send REQUEST directly without SESSION_BIND -> REJECTED
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::stream_identity id{301, 3001, 0};
            linep::v0_2::request_envelope req{id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Unbound request"};
            LINEP_TEST_CHECK(conn->send_request(req));

            std::vector<std::uint8_t> raw;
            LINEP_TEST_CHECK(conn->receive_envelope_raw(raw));
            linep::v0_2::event_envelope fail_evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), fail_evt));
            LINEP_TEST_CHECK(fail_evt.event_type == linep::v0_2::runtime_event_type::failed);
            LINEP_TEST_CHECK(fail_evt.error.category == linep::v0_2::error_category::unauthorized);
            LINEP_TEST_CHECK(fail_evt.error.code == 401);
        }

        // 4.2 Invalid Bind: Foreign / wrong lease token -> Connection-level terminal EVENT & closed
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::session_bind_envelope bad_bind{};
            bad_bind.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            bad_bind.control_epoch = 1;
            bad_bind.lease_token = 0xDEADBEEFULL; // Wrong token!
            LINEP_TEST_CHECK(conn->send_session_bind(bad_bind));

            std::vector<std::uint8_t> raw;
            LINEP_TEST_CHECK(conn->receive_envelope_raw(raw));
            linep::v0_2::event_envelope term_evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), term_evt));
            LINEP_TEST_CHECK(term_evt.stream.is_connection_level());
            LINEP_TEST_CHECK(term_evt.event_type == linep::v0_2::runtime_event_type::failed);
            LINEP_TEST_CHECK(term_evt.error.category == linep::v0_2::error_category::unauthorized);
            LINEP_TEST_CHECK(term_evt.error.code == 401);
            LINEP_TEST_CHECK(term_evt.error.message == "lease_invalid");
        }

        // 4.2b Malformed / Syntactically broken SESSION_BIND -> 400 invalid_session_bind & closed
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::session_bind_envelope valid_bind{};
            valid_bind.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            valid_bind.control_epoch = 1;
            valid_bind.lease_token = 0xC0FFEE1234ULL;
            std::vector<std::uint8_t> malformed_buf;
            linep::v0_2::encode_session_bind(valid_bind, malformed_buf);
            malformed_buf[7] = 0x01; // dirty flags (byte 7) -> decode_session_bind fails!
            LINEP_TEST_CHECK(conn->send_frame_raw(malformed_buf.data(), malformed_buf.size()));

            std::vector<std::uint8_t> raw;
            LINEP_TEST_CHECK(conn->receive_envelope_raw(raw));
            linep::v0_2::event_envelope term_evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), term_evt));
            LINEP_TEST_CHECK(term_evt.stream.is_connection_level());
            LINEP_TEST_CHECK(term_evt.error.category == linep::v0_2::error_category::bad_request);
            LINEP_TEST_CHECK(term_evt.error.code == 400);
            LINEP_TEST_CHECK(term_evt.error.message == "invalid_session_bind");

            // Connection must be closed
            LINEP_TEST_CHECK(!conn->receive_envelope_raw(raw));
        }

        // 4.3 Valid Bind + Duplicate Bind (idempotent) + Successful REQUEST
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::session_bind_envelope good_bind{};
            good_bind.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            good_bind.control_epoch = 1;
            good_bind.lease_token = 0xC0FFEE1234ULL;
            LINEP_TEST_CHECK(conn->send_session_bind(good_bind));

            // Case: duplicate_bind_same_lease -> idempotent, connection stays alive
            LINEP_TEST_CHECK(conn->send_session_bind(good_bind));

            linep::v0_2::stream_identity id{303, 3003, 0};
            linep::v0_2::request_envelope req{id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Bound request"};
            LINEP_TEST_CHECK(conn->send_request(req));

            std::vector<std::uint8_t> raw;
            bool saw_completed = false;
            while (conn->receive_envelope_raw(raw)) {
                linep::v0_2::event_envelope evt{};
                LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), evt));
                if (evt.event_type == linep::v0_2::runtime_event_type::completed) {
                    saw_completed = true;
                    break;
                }
            }
            LINEP_TEST_CHECK(saw_completed);
        }

        // 4.4 Identity change on existing connection -> Connection-level terminal EVENT & socket closed
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::session_bind_envelope bind_a{};
            bind_a.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            bind_a.control_epoch = 1;
            bind_a.lease_token = 0xC0FFEE1234ULL;
            LINEP_TEST_CHECK(conn->send_session_bind(bind_a));

            // Attempt identity change to Node B on same connection
            linep::v0_2::session_bind_envelope bind_b = bind_a;
            bind_b.identity.node_id = 9999;
            LINEP_TEST_CHECK(conn->send_session_bind(bind_b));

            std::vector<std::uint8_t> raw;
            LINEP_TEST_CHECK(conn->receive_envelope_raw(raw));
            linep::v0_2::event_envelope term_evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw.data(), raw.size(), term_evt));
            LINEP_TEST_CHECK(term_evt.stream.is_connection_level());
            LINEP_TEST_CHECK(term_evt.error.category == linep::v0_2::error_category::unauthorized);
            LINEP_TEST_CHECK(term_evt.error.code == 401);
            LINEP_TEST_CHECK(term_evt.error.message == "identity_change_on_existing_connection");

            // Connection must be closed
            LINEP_TEST_CHECK(!conn->receive_envelope_raw(raw));
        }

        // 4.5 Stale binding: request rejected, connection STAYS OPEN, re-bind succeeds, request completes
        {
            auto conn = linep::v0_2::envelope_connection::connect("127.0.0.1", lease_port);
            LINEP_TEST_CHECK(conn != nullptr);

            linep::v0_2::session_bind_envelope initial_bind{};
            initial_bind.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            initial_bind.control_epoch = 1;
            initial_bind.lease_token = 0xC0FFEE1234ULL;
            LINEP_TEST_CHECK(conn->send_session_bind(initial_bind));

            // Verify initial request succeeds under epoch 1 (ensures server is BOUND_CURRENT)
            linep::v0_2::stream_identity first_id{3031, 3031, 0};
            linep::v0_2::request_envelope first_req{first_id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "First bound request"};
            LINEP_TEST_CHECK(conn->send_request(first_req));

            std::vector<std::uint8_t> raw_first;
            bool saw_first_completed = false;
            while (conn->receive_envelope_raw(raw_first)) {
                linep::v0_2::event_envelope evt{};
                LINEP_TEST_CHECK(linep::v0_2::decode_event(raw_first.data(), raw_first.size(), evt));
                if (evt.event_type == linep::v0_2::runtime_event_type::completed) {
                    saw_first_completed = true;
                    break;
                }
            }
            LINEP_TEST_CHECK(saw_first_completed);

            // Rotate lease on router: epoch 2, new token 0x99887766ULL
            linep::v0_2::udp_control_datagram new_hello{};
            new_hello.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
            new_hello.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::node_hello);
            new_hello.node_id = 7001;
            new_hello.runtime_id = 8001;
            new_hello.endpoint_id = 1;
            new_hello.control_epoch = 2;
            new_hello.control_seq = 1;
            new_hello.tcp_port = 11435;
            new_hello.set_trunk_ready(true);
            LINEP_TEST_CHECK(router.ingest_datagram(new_hello, 3000));

            linep::v0_2::udp_control_datagram inv2{};
            LINEP_TEST_CHECK(router.issue_invite(linep::v0_2::node_endpoint_identity{7001, 8001, 1}, 0x99887766ULL, inv2));

            linep::v0_2::udp_control_datagram ack2{};
            ack2.magic = linep::v0_2::LINEP_V02_UDP_MAGIC;
            ack2.message_type = static_cast<std::uint8_t>(linep::v0_2::control_message_type::lease_ack);
            ack2.node_id = 7001;
            ack2.runtime_id = 8001;
            ack2.endpoint_id = 1;
            ack2.control_epoch = 2;
            ack2.control_seq = 2;
            ack2.tcp_port = 11435;
            ack2.set_trunk_ready(true);
            ack2.lease_token = 0x99887766ULL;
            LINEP_TEST_CHECK(router.ingest_datagram(ack2, 4000));

            // Now previous bind (epoch 1, token 0xC0FFEE1234) is stale on router!
            // When client submits a request with stale binding, server validates against router and rejects,
            // but TCP CONNECTION STAYS OPEN!
            linep::v0_2::stream_identity stale_id{304, 3004, 0};
            linep::v0_2::request_envelope stale_req{stale_id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Request while stale"};
            LINEP_TEST_CHECK(conn->send_request(stale_req));

            std::vector<std::uint8_t> raw_stale;
            LINEP_TEST_CHECK(conn->receive_envelope_raw(raw_stale));
            linep::v0_2::event_envelope stale_evt{};
            LINEP_TEST_CHECK(linep::v0_2::decode_event(raw_stale.data(), raw_stale.size(), stale_evt));
            LINEP_TEST_CHECK(stale_evt.error.code == 401);
            LINEP_TEST_CHECK(stale_evt.error.category == linep::v0_2::error_category::unauthorized);

            // Verify TCP connection is STILL CONNECTED / OPEN!
            LINEP_TEST_CHECK(conn->is_connected());

            // Send new re-bind with rotated epoch 2 & token 0x99887766ULL on the SAME connection!
            linep::v0_2::session_bind_envelope rebind{};
            rebind.identity = linep::v0_2::node_endpoint_identity{7001, 8001, 1};
            rebind.control_epoch = 2;
            rebind.lease_token = 0x99887766ULL;
            LINEP_TEST_CHECK(conn->send_session_bind(rebind));

            // Now submit request again on same connection -> SUCCEEDS!
            linep::v0_2::stream_identity rebound_id{305, 3005, 0};
            linep::v0_2::request_envelope rebound_req{rebound_id, linep::v0_2::runtime_profile::chat, "linep-conformance-model-v02", "Request after re-bind"};
            LINEP_TEST_CHECK(conn->send_request(rebound_req));

            bool saw_completed = false;
            while (conn->receive_envelope_raw(raw_stale)) {
                linep::v0_2::event_envelope evt{};
                LINEP_TEST_CHECK(linep::v0_2::decode_event(raw_stale.data(), raw_stale.size(), evt));
                if (evt.event_type == linep::v0_2::runtime_event_type::completed) {
                    saw_completed = true;
                    break;
                }
            }
            LINEP_TEST_CHECK(saw_completed);
        }

        lease_server.stop();
        std::cout << "  -> Dual-Plane TCP Session Binding tests PASSED (Missing, Invalid, Duplicate, Identity Change & Bound)" << std::endl;
    }

    mock_server.stop();
    std::cout << "ALL CONFORMANCE AND EDGE MODE TESTS PASSED 100%!" << std::endl;
    return 0;
}
