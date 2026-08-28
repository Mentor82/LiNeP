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
    std::cout << "[Test 1] Real TCP Socket: End-to-End Stream Cancellation (Exact output_id=0 Scope)..." << std::endl;
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

    // Stream with output_id = 0 (primary output)
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

    // Client receives a couple tokens, then sends exact cancel control frame (output_id=0)
    int tokens_received = 0;
    bool received_cancelled = false;

    while (!received_cancelled) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));

        if (evt.event_type == runtime_event_type::content_delta) {
            tokens_received++;
            if (tokens_received == 2) {
                // Send exact stream scope CANCEL targeting request_id 101, execution_id 1001, output_id 0
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
    std::cout << "[Test 3] Atomic Cancel vs. Completion Race & Strict Mutual Exclusion (100 parallel iterations)..." << std::endl;

    for (int iter = 0; iter < 100; ++iter) {
        session_manager mgr;
        runtime_error err{};

        stream_identity id{300 + static_cast<std::uint64_t>(iter), 3000 + static_cast<std::uint64_t>(iter), 0};
        request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Race Prompt"};
        LINEP_TEST_CHECK(mgr.submit_request(req, err));

        std::atomic<bool> complete_won{false};
        std::atomic<bool> cancel_won{false};
        std::atomic<int> complete_err_code{0};
        std::atomic<int> cancel_err_code{0};

        // Thread 1: attempts to dispatch terminal COMPLETED event
        std::thread th_complete([&]() {
            runtime_error local_err{};
            event_envelope term{id, 1, runtime_event_type::completed, "Finished", terminal_outcome::completed};
            if (mgr.dispatch_event(term, local_err)) {
                complete_won = true;
            } else {
                complete_err_code = local_err.code;
            }
        });

        // Thread 2: attempts to dispatch terminal CANCELLED event
        std::thread th_cancel([&]() {
            runtime_error local_err{};
            event_envelope cancel_term{id, 1, runtime_event_type::cancelled, "", terminal_outcome::cancelled};
            if (mgr.dispatch_event(cancel_term, local_err)) {
                cancel_won = true;
            } else {
                cancel_err_code = local_err.code;
            }
        });

        th_complete.join();
        th_cancel.join();

        // 1. Strict Mutual Exclusion: Exactly ONE operation MUST win!
        bool exactly_one_won = (complete_won && !cancel_won) || (!complete_won && cancel_won);
        LINEP_TEST_CHECK(exactly_one_won);

        // 2. Strict Loser Rejection: The losing thread MUST receive error code 410 (stream already terminal)!
        if (complete_won) {
            LINEP_TEST_CHECK(cancel_err_code == 410);
        } else {
            LINEP_TEST_CHECK(complete_err_code == 410);
        }

        // 3. State Invariant: Stream is in immutable terminal state matching the winner
        LINEP_TEST_CHECK(mgr.is_stream_terminal(id));
        active_stream_state st{};
        LINEP_TEST_CHECK(mgr.get_stream_state(id, st));
        LINEP_TEST_CHECK(st.lifecycle.has_terminal_outcome);
        terminal_outcome expected_outcome = complete_won ? terminal_outcome::completed : terminal_outcome::cancelled;
        LINEP_TEST_CHECK(st.lifecycle.outcome == expected_outcome);
    }

    std::cout << "  -> Atomic Cancel vs. Completion Race Resolution PASSED (100/100)" << std::endl;
}

void test_real_transport_backpressure_slow_consumer() {
    std::cout << "[Test 4] Real TCP Transport: Protocol WINDOW_UPDATE Flow Control & Slow Consumer Overload..." << std::endl;
    constexpr std::uint16_t port_fast = 19994;
    constexpr std::uint16_t port_slow = 19995;

    // --- Scenario A: Real TCP Protocol WINDOW_UPDATE Flow Control (Stream 2,000 bytes through 500-byte window) ---
    {
        envelope_server server;
        LINEP_TEST_CHECK(server.listen(port_fast));

        std::unique_ptr<envelope_connection> srv_conn;
        std::thread accept_th([&]() {
            srv_conn = server.accept_connection();
        });

        auto client_conn = envelope_connection::connect("127.0.0.1", port_fast);
        LINEP_TEST_CHECK(client_conn != nullptr);
        accept_th.join();

        session_descriptor desc{};
        desc.limits.max_buffered_bytes_per_stream = 500; // Small 500-byte in-flight window ceiling
        session_manager srv_session(desc);
        runtime_error err{};

        stream_identity id_fast{401, 4001, 0};
        request_envelope req_fast{id_fast, runtime_profile::chat, "llama-3.1-8b", "Fast Prompt"};
        LINEP_TEST_CHECK(srv_session.submit_request(req_fast, err));

        // Server reader thread processing WINDOW_UPDATE control frames from TCP socket
        std::atomic<bool> server_running{true};
        std::thread srv_control_reader([&]() {
            std::vector<std::uint8_t> ctrl_buf;
            while (server_running) {
                if (srv_conn->receive_envelope_raw(ctrl_buf)) {
                    control_envelope ctrl{};
                    if (decode_control(ctrl_buf.data(), ctrl_buf.size(), ctrl)) {
                        srv_session.process_control(ctrl, err);
                    }
                } else {
                    break;
                }
            }
        });

        // Server worker streaming 20 chunks of 100 bytes (2,000 bytes total) through the 500-byte window
        std::thread worker([&]() {
            event_seq_t seq = 1;
            for (int i = 0; i < 20; ++i) {
                event_envelope chunk{id_fast, seq++, runtime_event_type::content_delta, std::string(100, 'X')};
                while (!srv_session.dispatch_event(chunk, err)) {
                    // Window full, wait for client WINDOW_UPDATE
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                srv_conn->send_event(chunk);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            event_envelope term{id_fast, seq++, runtime_event_type::completed, "", terminal_outcome::completed};
            srv_session.dispatch_event(term, err);
            srv_conn->send_event(term);
        });

        // Client receives chunks and sends protocol WINDOW_UPDATE control envelopes back over TCP
        std::vector<std::uint8_t> raw_buf;
        int chunks_received = 0;
        bool completed = false;

        while (!completed) {
            LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
            event_envelope evt{};
            LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));

            if (evt.event_type == runtime_event_type::content_delta) {
                chunks_received++;
                // Send protocol WINDOW_UPDATE grant over TCP socket to replenish server window!
                control_envelope win_ctrl{id_fast, runtime_control_type::window_update, "Ack chunk", 100};
                LINEP_TEST_CHECK(client_conn->send_control(win_ctrl));
            } else if (evt.event_type == runtime_event_type::completed) {
                completed = true;
            }
        }

        worker.join();
        server_running = false;
        client_conn->close();
        srv_conn->close();
        srv_control_reader.join();
        server.close();

        LINEP_TEST_CHECK(chunks_received == 20);
        LINEP_TEST_CHECK(srv_session.is_stream_terminal(id_fast));
        active_stream_state fast_st{};
        LINEP_TEST_CHECK(srv_session.get_stream_state(id_fast, fast_st));
        LINEP_TEST_CHECK(fast_st.total_produced_bytes == 2000);
        LINEP_TEST_CHECK(fast_st.unacked_buffered_bytes == 0); // Window fully drained in real-time
    }

    // --- Scenario B: Real TCP Slow / Stalled Consumer on Socket (Backpressure Overload Protection) ---
    {
        envelope_server server;
        LINEP_TEST_CHECK(server.listen(port_slow));

        std::unique_ptr<envelope_connection> srv_conn;
        std::thread accept_th([&]() {
            srv_conn = server.accept_connection();
        });

        auto client_conn = envelope_connection::connect("127.0.0.1", port_slow);
        LINEP_TEST_CHECK(client_conn != nullptr);
        accept_th.join();

        session_descriptor desc{};
        desc.limits.max_buffered_bytes_per_stream = 500; // 500-byte ceiling
        session_manager srv_session(desc);
        runtime_error err{};

        stream_identity id_slow{402, 4002, 0};
        request_envelope req_slow{id_slow, runtime_profile::chat, "llama-3.1-8b", "Slow Consumer Prompt"};
        LINEP_TEST_CHECK(srv_session.submit_request(req_slow, err));

        // Chunk 1: 300 bytes -> Accepted (300 <= 500)
        event_envelope d1{id_slow, 1, runtime_event_type::content_delta, std::string(300, 'A')};
        LINEP_TEST_CHECK(srv_session.dispatch_event(d1, err));
        LINEP_TEST_CHECK(srv_conn->send_event(d1));

        // Chunk 2: 300 bytes without WINDOW_UPDATE from stalled consumer -> (300+300 = 600 > 500) -> EXPLICIT BACKPRESSURE 507!
        event_envelope d2{id_slow, 2, runtime_event_type::content_delta, std::string(300, 'B')};
        bool d2_ok = srv_session.dispatch_event(d2, err);
        LINEP_TEST_CHECK(!d2_ok);
        LINEP_TEST_CHECK(err.category == error_category::resource_exhausted);
        LINEP_TEST_CHECK(err.code == 507);

        // Fail-closed termination of the stalled stream
        event_envelope overload_term{id_slow, 3, runtime_event_type::failed, "", terminal_outcome::failed};
        overload_term.error = err;
        LINEP_TEST_CHECK(srv_session.dispatch_event(overload_term, err));
        LINEP_TEST_CHECK(srv_conn->send_event(overload_term));

        LINEP_TEST_CHECK(srv_session.is_stream_terminal(id_slow));
        active_stream_state slow_st{};
        LINEP_TEST_CHECK(srv_session.get_stream_state(id_slow, slow_st));
        LINEP_TEST_CHECK(slow_st.lifecycle.outcome == terminal_outcome::failed);
        LINEP_TEST_CHECK(slow_st.unacked_buffered_bytes == 0); // Freed capacity

        client_conn->close();
        srv_conn->close();
        server.close();
    }

    std::cout << "  -> Real TCP Transport: Protocol WINDOW_UPDATE Flow Control PASSED" << std::endl;
}

void test_tcp_multi_stream_backpressure_isolation() {
    std::cout << "[Test 5] Real TCP Transport: Multi-Stream Backpressure Isolation (Slow Stream A does NOT block Stream B)..." << std::endl;
    constexpr std::uint16_t port = 19996;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> srv_conn;
    std::thread accept_th([&]() {
        srv_conn = server.accept_connection();
    });

    auto client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    accept_th.join();

    session_descriptor desc{};
    desc.limits.max_buffered_bytes_per_stream = 500; // 500-byte window limit per stream
    session_manager srv_session(desc);
    runtime_error err{};

    stream_identity id_a{501, 5001, 0}; // Slow Stream A
    stream_identity id_b{502, 5002, 0}; // Fast Stream B

    request_envelope req_a{id_a, runtime_profile::chat, "llama-3.1-8b", "Slow Stream A Prompt"};
    request_envelope req_b{id_b, runtime_profile::chat, "llama-3.1-8b", "Fast Stream B Prompt"};

    LINEP_TEST_CHECK(client_conn->send_request(req_a));
    LINEP_TEST_CHECK(client_conn->send_request(req_b));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_a{}, srv_b{};
    LINEP_TEST_CHECK(srv_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_a));
    LINEP_TEST_CHECK(srv_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_b));

    LINEP_TEST_CHECK(srv_session.submit_request(srv_a, err));
    LINEP_TEST_CHECK(srv_session.submit_request(srv_b, err));

    std::atomic<bool> server_running{true};
    std::thread srv_control_reader([&]() {
        std::vector<std::uint8_t> ctrl_buf;
        while (server_running) {
            if (srv_conn->receive_envelope_raw(ctrl_buf)) {
                control_envelope ctrl{};
                if (decode_control(ctrl_buf.data(), ctrl_buf.size(), ctrl)) {
                    srv_session.process_control(ctrl, err);
                }
            } else {
                break;
            }
        }
    });

    // Worker A: tries to push 2x 300-byte chunks without receiving WINDOW_UPDATE -> hits 507
    std::thread worker_a([&]() {
        event_envelope a1{id_a, 1, runtime_event_type::content_delta, std::string(300, 'A')};
        srv_session.dispatch_event(a1, err);
        srv_conn->send_event(a1);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        event_envelope a2{id_a, 2, runtime_event_type::content_delta, std::string(300, 'A')};
        if (!srv_session.dispatch_event(a2, err)) {
            // Overload backpressure triggered on Stream A!
            event_envelope term_a{id_a, 3, runtime_event_type::failed, "", terminal_outcome::failed};
            term_a.error = err;
            srv_session.dispatch_event(term_a, err);
            srv_conn->send_event(term_a);
        }
    });

    // Worker B: streams 15 chunks of 100 bytes (1,500 bytes) with active client WINDOW_UPDATE
    std::thread worker_b([&]() {
        event_seq_t seq = 1;
        for (int i = 0; i < 15; ++i) {
            event_envelope chunk_b{id_b, seq++, runtime_event_type::content_delta, "B-data-chunk-"};
            while (!srv_session.dispatch_event(chunk_b, err)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            srv_conn->send_event(chunk_b);
            std::this_thread::sleep_for(std::chrono::milliseconds(8));
        }
        event_envelope term_b{id_b, seq++, runtime_event_type::completed, "", terminal_outcome::completed};
        srv_session.dispatch_event(term_b, err);
        srv_conn->send_event(term_b);
    });

    // Client receives interleaved events from shared TCP socket:
    // - For Stream A: never sends WINDOW_UPDATE (stalls).
    // - For Stream B: continuously sends WINDOW_UPDATE credits over TCP!
    bool a_failed = false, b_completed = false;
    int b_chunks = 0;

    while (!a_failed || !b_completed) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));

        if (evt.stream == id_a) {
            if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::failed);
                LINEP_TEST_CHECK(evt.error.code == 507);
                a_failed = true;
            }
        } else if (evt.stream == id_b) {
            if (evt.event_type == runtime_event_type::content_delta) {
                b_chunks++;
                // Replenish Stream B window over the shared TCP trunk!
                control_envelope win_b{id_b, runtime_control_type::window_update, "Ack B", static_cast<std::uint32_t>(evt.payload.size())};
                LINEP_TEST_CHECK(client_conn->send_control(win_b));
            } else if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::completed);
                b_completed = true;
            }
        }
    }

    worker_a.join();
    worker_b.join();
    server_running = false;
    client_conn->close();
    srv_conn->close();
    srv_control_reader.join();
    server.close();

    LINEP_TEST_CHECK(a_failed);
    LINEP_TEST_CHECK(b_completed);
    LINEP_TEST_CHECK(b_chunks == 15);

    active_stream_state st_a{}, st_b{};
    LINEP_TEST_CHECK(srv_session.get_stream_state(id_a, st_a));
    LINEP_TEST_CHECK(srv_session.get_stream_state(id_b, st_b));
    LINEP_TEST_CHECK(st_a.lifecycle.outcome == terminal_outcome::failed);
    LINEP_TEST_CHECK(st_b.lifecycle.outcome == terminal_outcome::completed);

    std::cout << "  -> Multi-Stream Backpressure Isolation PASSED (Stream B unaffected by Stream A backpressure)" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Lifecycle, Cancel & Transport Backpressure Test Suite ===" << std::endl;
    test_tcp_end_to_end_socket_cancellation();
    test_tcp_multi_stream_selective_cancellation();
    test_atomic_cancel_vs_completion_race();
    test_real_transport_backpressure_slow_consumer();
    test_tcp_multi_stream_backpressure_isolation();
    std::cout << "ALL 5 V0.2 PHASE C LIFECYCLE & BACKPRESSURE TESTS PASSED 100%!" << std::endl;
    return 0;
}
