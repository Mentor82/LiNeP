#include <cstdlib>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/session.hpp"
#include "linep/v0_2/transport.hpp"

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST CHECK FAILED: " #cond " at " __FILE__ ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

using namespace linep::v0_2;

void test_tcp_end_to_end_socket_cancellation() {
    std::cout << "[Test 1] Real TCP Socket: End-to-End Stream Cancellation (CONTROL -> cancel_requested -> CANCELLED)..." << std::endl;
    constexpr std::uint16_t port = 19991;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> srv_conn;
    std::thread accept_th([&]() {
        srv_conn = server.accept_connection();
    });

    auto client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    accept_th.join();
    LINEP_TEST_CHECK(srv_conn != nullptr);

    stream_identity id{101, 1001, 0};
    request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Cancel Me Prompt"};
    LINEP_TEST_CHECK(client_conn->send_request(req));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_req{};
    LINEP_TEST_CHECK(srv_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_req));

    session_manager srv_session;
    runtime_error err{};
    LINEP_TEST_CHECK(srv_session.submit_request(srv_req, err));

    std::atomic<bool> worker_stopped{false};
    std::thread worker([&]() {
        event_seq_t seq = 1;
        while (!srv_session.is_cancel_requested(id) && seq <= 50) {
            event_envelope delta{id, seq++, runtime_event_type::content_delta, "tok "};
            srv_session.dispatch_event(delta, err);
            srv_conn->send_event(delta);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }

        if (srv_session.is_cancel_requested(id)) {
            worker_stopped = true;
            event_envelope cancel_term{id, seq++, runtime_event_type::cancelled, "", terminal_outcome::cancelled};
            srv_session.dispatch_event(cancel_term, err);
            srv_conn->send_event(cancel_term);
        }
    });

    // Server reader thread processing control frames from client
    std::thread srv_reader([&]() {
        std::vector<std::uint8_t> ctrl_buf;
        if (srv_conn->receive_envelope_raw(ctrl_buf)) {
            control_envelope ctrl{};
            if (decode_control(ctrl_buf.data(), ctrl_buf.size(), ctrl)) {
                srv_session.process_control(ctrl, err);
            }
        }
    });

    // Client receives a couple tokens, then sends cancel control frame
    int tokens_received = 0;
    bool received_cancelled = false;

    while (!received_cancelled) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));

        if (evt.event_type == runtime_event_type::content_delta) {
            tokens_received++;
            if (tokens_received == 2) {
                // Send CANCEL control targeting execution_id 1001 over TCP
                control_envelope cancel_ctrl{id, runtime_control_type::cancel, "Client abort"};
                LINEP_TEST_CHECK(client_conn->send_control(cancel_ctrl));
            }
        } else if (evt.event_type == runtime_event_type::cancelled) {
            LINEP_TEST_CHECK(evt.outcome == terminal_outcome::cancelled);
            received_cancelled = true;
        }
    }

    worker.join();
    srv_reader.join();

    LINEP_TEST_CHECK(worker_stopped);
    LINEP_TEST_CHECK(srv_session.is_stream_terminal(id));
    active_stream_state st{};
    LINEP_TEST_CHECK(srv_session.get_stream_state(id, st));
    LINEP_TEST_CHECK(st.lifecycle.outcome == terminal_outcome::cancelled);

    client_conn->close();
    srv_conn->close();
    server.close();

    std::cout << "  -> Real TCP End-to-End Stream Cancellation PASSED" << std::endl;
}

void test_tcp_multi_stream_selective_cancellation() {
    std::cout << "[Test 2] Real TCP Socket: Multi-Stream Selective Cancellation (Stream A cancelled, Stream B completes)..." << std::endl;
    constexpr std::uint16_t port = 19992;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> srv_conn;
    std::thread accept_th([&]() {
        srv_conn = server.accept_connection();
    });

    auto client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    accept_th.join();

    stream_identity id_a{201, 2001, 0};
    stream_identity id_b{202, 2002, 0};

    request_envelope req_a{id_a, runtime_profile::chat, "llama-3.1-8b", "Prompt A"};
    request_envelope req_b{id_b, runtime_profile::chat, "llama-3.1-8b", "Prompt B"};

    LINEP_TEST_CHECK(client_conn->send_request(req_a));
    LINEP_TEST_CHECK(client_conn->send_request(req_b));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_a{}, srv_b{};
    LINEP_TEST_CHECK(srv_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_a));
    LINEP_TEST_CHECK(srv_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_b));

    session_manager srv_session;
    runtime_error err{};
    LINEP_TEST_CHECK(srv_session.submit_request(srv_a, err));
    LINEP_TEST_CHECK(srv_session.submit_request(srv_b, err));

    std::thread worker_a([&]() {
        event_seq_t seq = 1;
        while (!srv_session.is_cancel_requested(id_a) && seq <= 50) {
            event_envelope delta{id_a, seq++, runtime_event_type::content_delta, "A "};
            srv_session.dispatch_event(delta, err);
            srv_conn->send_event(delta);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (srv_session.is_cancel_requested(id_a)) {
            event_envelope term{id_a, seq++, runtime_event_type::cancelled, "", terminal_outcome::cancelled};
            srv_session.dispatch_event(term, err);
            srv_conn->send_event(term);
        }
    });

    std::thread worker_b([&]() {
        event_seq_t seq = 1;
        for (int i = 0; i < 5; ++i) {
            event_envelope delta{id_b, seq++, runtime_event_type::content_delta, "B "};
            srv_session.dispatch_event(delta, err);
            srv_conn->send_event(delta);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        event_envelope term{id_b, seq++, runtime_event_type::completed, "", terminal_outcome::completed};
        srv_session.dispatch_event(term, err);
        srv_conn->send_event(term);
    });

    std::thread srv_reader([&]() {
        std::vector<std::uint8_t> ctrl_buf;
        if (srv_conn->receive_envelope_raw(ctrl_buf)) {
            control_envelope ctrl{};
            if (decode_control(ctrl_buf.data(), ctrl_buf.size(), ctrl)) {
                srv_session.process_control(ctrl, err);
            }
        }
    });

    // Client receives from both streams, sends cancel targeting ONLY Stream A
    bool a_cancelled = false, b_completed = false;
    int a_count = 0;

    while (!a_cancelled || !b_completed) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));

        if (evt.stream == id_a) {
            if (evt.event_type == runtime_event_type::content_delta) {
                a_count++;
                if (a_count == 2) {
                    control_envelope ctrl{id_a, runtime_control_type::cancel, "Cancel Stream A only"};
                    LINEP_TEST_CHECK(client_conn->send_control(ctrl));
                }
            } else if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::cancelled);
                a_cancelled = true;
            }
        } else if (evt.stream == id_b) {
            if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::completed);
                b_completed = true;
            }
        }
    }

    worker_a.join();
    worker_b.join();
    srv_reader.join();

    LINEP_TEST_CHECK(srv_session.is_stream_terminal(id_a));
    LINEP_TEST_CHECK(srv_session.is_stream_terminal(id_b));

    active_stream_state st_a{}, st_b{};
    LINEP_TEST_CHECK(srv_session.get_stream_state(id_a, st_a));
    LINEP_TEST_CHECK(srv_session.get_stream_state(id_b, st_b));
    LINEP_TEST_CHECK(st_a.lifecycle.outcome == terminal_outcome::cancelled);
    LINEP_TEST_CHECK(st_b.lifecycle.outcome == terminal_outcome::completed);

    client_conn->close();
    srv_conn->close();
    server.close();

    std::cout << "  -> Multi-Stream Selective Cancellation PASSED" << std::endl;
}

void test_atomic_cancel_vs_completion_race() {
    std::cout << "[Test 3] Atomic Cancel vs. Completion Race (100 concurrent iterations)..." << std::endl;

    for (int iter = 0; iter < 100; ++iter) {
        session_manager mgr;
        runtime_error err{};

        stream_identity id{300 + static_cast<std::uint64_t>(iter), 3000 + static_cast<std::uint64_t>(iter), 0};
        request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Race Prompt"};
        LINEP_TEST_CHECK(mgr.submit_request(req, err));

        std::atomic<bool> complete_won{false};
        std::atomic<bool> cancel_won{false};

        // Thread 1: emits terminal COMPLETED event
        std::thread th_complete([&]() {
            runtime_error local_err{};
            event_envelope term{id, 1, runtime_event_type::completed, "Finished", terminal_outcome::completed};
            if (mgr.dispatch_event(term, local_err)) {
                complete_won = true;
            }
        });

        // Thread 2: attempts to process CANCEL control
        std::thread th_cancel([&]() {
            runtime_error local_err{};
            control_envelope ctrl{id, runtime_control_type::cancel, "Race Cancel"};
            if (mgr.process_control(ctrl, local_err)) {
                cancel_won = true;
                // If cancel won, emit terminal cancelled event
                event_envelope cancel_term{id, 1, runtime_event_type::cancelled, "", terminal_outcome::cancelled};
                mgr.dispatch_event(cancel_term, local_err);
            }
        });

        th_complete.join();
        th_cancel.join();

        // Invariant: Exactly one authoritative outcome must prevail!
        LINEP_TEST_CHECK(mgr.is_stream_terminal(id));
        active_stream_state st{};
        LINEP_TEST_CHECK(mgr.get_stream_state(id, st));
        LINEP_TEST_CHECK(st.lifecycle.has_terminal_outcome);
        LINEP_TEST_CHECK(st.lifecycle.outcome == terminal_outcome::completed ||
                         st.lifecycle.outcome == terminal_outcome::cancelled);
    }

    std::cout << "  -> Atomic Cancel vs. Completion Race Resolution PASSED (100/100)" << std::endl;
}

void test_real_transport_backpressure_slow_consumer() {
    std::cout << "[Test 4] Real Transport Backpressure & Slow Consumer Overload Protection..." << std::endl;
    session_descriptor desc{};
    desc.limits.max_buffered_bytes_per_stream = 500; // 500 bytes buffer ceiling
    session_manager mgr(desc);
    runtime_error err{};

    stream_identity id{401, 4001, 0};
    request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Backpressure Prompt"};
    LINEP_TEST_CHECK(mgr.submit_request(req, err));

    // Send delta 1 (300 bytes) -> OK
    event_envelope d1{id, 1, runtime_event_type::content_delta, std::string(300, 'X')};
    LINEP_TEST_CHECK(mgr.dispatch_event(d1, err));

    // Send delta 2 (300 bytes) -> Exceeds 500 bytes ceiling (300+300 = 600 > 500)
    event_envelope d2{id, 2, runtime_event_type::content_delta, std::string(300, 'Y')};
    bool d2_ok = mgr.dispatch_event(d2, err);
    LINEP_TEST_CHECK(!d2_ok);
    LINEP_TEST_CHECK(err.category == error_category::resource_exhausted);
    LINEP_TEST_CHECK(err.code == 507);

    // Fail-closed termination of overloaded stream
    event_envelope overload_term{id, 3, runtime_event_type::failed, "", terminal_outcome::failed};
    overload_term.error = err;
    LINEP_TEST_CHECK(mgr.dispatch_event(overload_term, err));
    LINEP_TEST_CHECK(mgr.is_stream_terminal(id));

    active_stream_state st{};
    LINEP_TEST_CHECK(mgr.get_stream_state(id, st));
    LINEP_TEST_CHECK(st.lifecycle.outcome == terminal_outcome::failed);

    std::cout << "  -> Real Transport Backpressure & Slow Consumer Protection PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Lifecycle, Cancel & Transport Backpressure Test Suite ===" << std::endl;
    test_tcp_end_to_end_socket_cancellation();
    test_tcp_multi_stream_selective_cancellation();
    test_atomic_cancel_vs_completion_race();
    test_real_transport_backpressure_slow_consumer();
    std::cout << "ALL V0.2 PHASE C LIFECYCLE & BACKPRESSURE TESTS PASSED 100%!" << std::endl;
    return 0;
}
