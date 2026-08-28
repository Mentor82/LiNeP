#include <cstdlib>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/session.hpp"
#include "linep/v0_2/transport.hpp"
#include "socket.hpp"

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST CHECK FAILED: " #cond " at " __FILE__ ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

using namespace linep::v0_2;

void test_tcp_concurrent_stream_multiplexing() {
    std::cout << "[Test 1] Real TCP Socket: Concurrent Logical Stream Multiplexing & Interleaving..." << std::endl;
    constexpr std::uint16_t port = 19981;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    // Client connects via TCP
    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    LINEP_TEST_CHECK(client_conn->is_connected());

    server_accept_thread.join();
    LINEP_TEST_CHECK(server_conn != nullptr);
    LINEP_TEST_CHECK(server_conn->is_connected());

    stream_identity id_a{101, 1001, 0};
    stream_identity id_b{102, 1002, 0};

    // Client submits two requests over the single persistent TCP connection
    request_envelope req_a{id_a, runtime_profile::chat, "llama-3.1-8b", "Prompt A"};
    request_envelope req_b{id_b, runtime_profile::generate, "llama-3.1-8b", "Prompt B"};

    LINEP_TEST_CHECK(client_conn->send_request(req_a));
    LINEP_TEST_CHECK(client_conn->send_request(req_b));

    // Server reads both requests
    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_req_a{}, srv_req_b{};

    LINEP_TEST_CHECK(server_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_req_a));
    LINEP_TEST_CHECK(srv_req_a.stream == id_a);

    LINEP_TEST_CHECK(server_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_req_b));
    LINEP_TEST_CHECK(srv_req_b.stream == id_b);

    session_manager server_session;
    runtime_error err{};
    LINEP_TEST_CHECK(server_session.submit_request(srv_req_a, err));
    LINEP_TEST_CHECK(server_session.submit_request(srv_req_b, err));

    // Server launches two concurrent worker threads generating interleaved deltas into the shared TCP socket
    std::thread worker_a([&]() {
        std::vector<std::string> tokens = {"The ", "quick ", "brown ", "fox "};
        event_seq_t seq = 1;
        for (const auto& tok : tokens) {
            event_envelope evt{id_a, seq++, runtime_event_type::content_delta, tok};
            server_session.dispatch_event(evt, err);
            server_conn->send_event(evt);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        event_envelope term{id_a, seq++, runtime_event_type::completed, "", terminal_outcome::completed};
        server_session.dispatch_event(term, err);
        server_conn->send_event(term);
    });

    std::thread worker_b([&]() {
        std::vector<std::string> tokens = {"Neural ", "networks ", "compute ", "vectors "};
        event_seq_t seq = 1;
        for (const auto& tok : tokens) {
            event_envelope evt{id_b, seq++, runtime_event_type::content_delta, tok};
            server_session.dispatch_event(evt, err);
            server_conn->send_event(evt);
            std::this_thread::sleep_for(std::chrono::milliseconds(12));
        }
        event_envelope term{id_b, seq++, runtime_event_type::completed, "", terminal_outcome::completed};
        server_session.dispatch_event(term, err);
        server_conn->send_event(term);
    });

    // Client receives all events from the single TCP socket and feeds client session manager
    session_manager client_session;
    LINEP_TEST_CHECK(client_session.submit_request(req_a, err));
    LINEP_TEST_CHECK(client_session.submit_request(req_b, err));

    std::string text_a, text_b;
    bool term_a = false, term_b = false;

    while (!term_a || !term_b) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));
        LINEP_TEST_CHECK(client_session.dispatch_event(evt, err));

        if (evt.stream == id_a) {
            if (evt.event_type == runtime_event_type::content_delta) {
                text_a += evt.payload;
            } else if (evt.event_type == runtime_event_type::completed) {
                term_a = true;
            }
        } else if (evt.stream == id_b) {
            if (evt.event_type == runtime_event_type::content_delta) {
                text_b += evt.payload;
            } else if (evt.event_type == runtime_event_type::completed) {
                term_b = true;
            }
        }
    }

    worker_a.join();
    worker_b.join();

    LINEP_TEST_CHECK(text_a == "The quick brown fox ");
    LINEP_TEST_CHECK(text_b == "Neural networks compute vectors ");
    LINEP_TEST_CHECK(client_session.is_stream_terminal(id_a));
    LINEP_TEST_CHECK(client_session.is_stream_terminal(id_b));

    client_conn->close();
    server_conn->close();
    server.close();

    std::cout << "  -> Real TCP Multiplexing & Interleaved Event Delivery PASSED" << std::endl;
}

void test_tcp_stream_isolation_on_failure() {
    std::cout << "[Test 2] Real TCP Socket: Stream Isolation upon Remote Failure..." << std::endl;
    constexpr std::uint16_t port = 19982;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    server_accept_thread.join();

    stream_identity id_fail{201, 2001, 0};
    stream_identity id_ok{202, 2002, 0};

    request_envelope req_fail{id_fail, runtime_profile::chat, "llama-3.1-8b", "Fail Prompt"};
    request_envelope req_ok{id_ok, runtime_profile::chat, "llama-3.1-8b", "Ok Prompt"};

    LINEP_TEST_CHECK(client_conn->send_request(req_fail));
    LINEP_TEST_CHECK(client_conn->send_request(req_ok));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_fail{}, srv_ok{};
    LINEP_TEST_CHECK(server_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_fail));
    LINEP_TEST_CHECK(server_conn->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_ok));

    session_manager server_session;
    runtime_error err{};
    LINEP_TEST_CHECK(server_session.submit_request(srv_fail, err));
    LINEP_TEST_CHECK(server_session.submit_request(srv_ok, err));

    // Stream Fail worker: emits error event immediately
    std::thread worker_fail([&]() {
        event_envelope err_evt{id_fail, 1, runtime_event_type::failed, "", terminal_outcome::failed};
        err_evt.error.category = error_category::model_error;
        err_evt.error.code = 500;
        err_evt.error.message = "Backend Inference Error";
        server_session.dispatch_event(err_evt, err);
        server_conn->send_event(err_evt);
    });

    // Stream OK worker: streams tokens and completes normally
    std::thread worker_ok([&]() {
        event_envelope delta{id_ok, 1, runtime_event_type::content_delta, "Successful output"};
        server_session.dispatch_event(delta, err);
        server_conn->send_event(delta);

        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        event_envelope term{id_ok, 2, runtime_event_type::completed, "", terminal_outcome::completed};
        server_session.dispatch_event(term, err);
        server_conn->send_event(term);
    });

    session_manager client_session;
    LINEP_TEST_CHECK(client_session.submit_request(req_fail, err));
    LINEP_TEST_CHECK(client_session.submit_request(req_ok, err));

    bool term_fail = false, term_ok = false;
    std::string ok_text;

    while (!term_fail || !term_ok) {
        LINEP_TEST_CHECK(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), evt));
        LINEP_TEST_CHECK(client_session.dispatch_event(evt, err));

        if (evt.stream == id_fail) {
            if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::failed);
                term_fail = true;
            }
        } else if (evt.stream == id_ok) {
            if (evt.event_type == runtime_event_type::content_delta) {
                ok_text += evt.payload;
            } else if (evt.is_terminal()) {
                LINEP_TEST_CHECK(evt.outcome == terminal_outcome::completed);
                term_ok = true;
            }
        }
    }

    worker_fail.join();
    worker_ok.join();

    LINEP_TEST_CHECK(ok_text == "Successful output");
    LINEP_TEST_CHECK(client_session.is_stream_terminal(id_fail));
    LINEP_TEST_CHECK(client_session.is_stream_terminal(id_ok));

    active_stream_state st_fail{}, st_ok{};
    LINEP_TEST_CHECK(client_session.get_stream_state(id_fail, st_fail));
    LINEP_TEST_CHECK(st_fail.lifecycle.outcome == terminal_outcome::failed);
    LINEP_TEST_CHECK(client_session.get_stream_state(id_ok, st_ok));
    LINEP_TEST_CHECK(st_ok.lifecycle.outcome == terminal_outcome::completed);

    client_conn->close();
    server_conn->close();
    server.close();

    std::cout << "  -> Real TCP Stream Isolation PASSED" << std::endl;
}

void test_tcp_clean_connection_teardown() {
    std::cout << "[Test 3] Real TCP Socket: Clean Connection Teardown & EOF Detection..." << std::endl;
    constexpr std::uint16_t port = 19983;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    server_accept_thread.join();

    // Client closes connection gracefully
    client_conn->close();
    LINEP_TEST_CHECK(!client_conn->is_connected());

    // Server reads EOF and cleanly closes
    std::vector<std::uint8_t> raw_buf;
    bool recv_ok = server_conn->receive_envelope_raw(raw_buf);
    LINEP_TEST_CHECK(!recv_ok); // EOF detected

    server_conn->close();
    LINEP_TEST_CHECK(!server_conn->is_connected());
    server.close();

    std::cout << "  -> Real TCP Clean Connection Teardown PASSED" << std::endl;
}

void test_tcp_malformed_and_truncated_payload_length() {
    std::cout << "[Test 4] Real TCP Socket: Malformed & Truncated Payload Length Rejection..." << std::endl;
    constexpr std::uint16_t port = 19984;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    // Client sends header claiming payload_len = 5000, but only sends 10 bytes then abruptly closes
    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    LINEP_TEST_CHECK(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header fake_hdr{};
    fake_hdr.magic = LINEP_V02_MAGIC;
    fake_hdr.version_major = LINEP_V02_VERSION_MAJOR;
    fake_hdr.version_minor = LINEP_V02_VERSION_MINOR;
    fake_hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::request);
    fake_hdr.request_id = 999;
    fake_hdr.execution_id = 888;
    fake_hdr.payload_len = 5000; // Claims 5000 bytes

    std::vector<std::uint8_t> malformed_buf;
    encode_header(fake_hdr, malformed_buf);
    malformed_buf.resize(LINEP_V02_HEADER_SIZE + 10, 0xAA);

    linep::pal::tcp_send_all(raw_s, malformed_buf.data(), static_cast<int>(malformed_buf.size()));
    linep::pal::socket_close(raw_s); // Abrupt close!

    // Server must reject fail-closed without hanging
    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    LINEP_TEST_CHECK(!srv_recv); // Failed closed!
    LINEP_TEST_CHECK(!server_conn->is_connected());

    server_conn->close();
    server.close();

    std::cout << "  -> Malformed/Truncated Payload Length Fail-Closed PASSED" << std::endl;
}

void test_tcp_oversized_payload_dos_protection() {
    std::cout << "[Test 5] Real TCP Socket: Oversized Payload Length DoS Protection (> 16 MB)..." << std::endl;
    constexpr std::uint16_t port = 19985;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    LINEP_TEST_CHECK(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header dos_hdr{};
    dos_hdr.magic = LINEP_V02_MAGIC;
    dos_hdr.version_major = LINEP_V02_VERSION_MAJOR;
    dos_hdr.version_minor = LINEP_V02_VERSION_MINOR;
    dos_hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::request);
    dos_hdr.request_id = 999;
    dos_hdr.execution_id = 888;
    dos_hdr.payload_len = 100 * 1024 * 1024; // 100 MB claim!

    std::vector<std::uint8_t> hdr_buf;
    encode_header(dos_hdr, hdr_buf);

    linep::pal::tcp_send_all(raw_s, hdr_buf.data(), static_cast<int>(hdr_buf.size()));

    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    LINEP_TEST_CHECK(!srv_recv); // Rejected oversized payload!
    LINEP_TEST_CHECK(!server_conn->is_connected());

    linep::pal::socket_close(raw_s);
    server_conn->close();
    server.close();

    std::cout << "  -> Oversized Payload DoS Protection PASSED" << std::endl;
}

void test_tcp_corrupted_magic_midstream() {
    std::cout << "[Test 6] Real TCP Socket: Corrupted Magic Header Mid-Stream Rejection..." << std::endl;
    constexpr std::uint16_t port = 19986;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    LINEP_TEST_CHECK(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header corrupt_hdr{};
    corrupt_hdr.magic = 0xDEADBEEF; // Invalid magic!
    corrupt_hdr.version_major = 0;
    corrupt_hdr.version_minor = 2;
    corrupt_hdr.envelope_type = 1;
    corrupt_hdr.payload_len = 10;

    std::vector<std::uint8_t> hdr_buf;
    encode_header(corrupt_hdr, hdr_buf);

    linep::pal::tcp_send_all(raw_s, hdr_buf.data(), static_cast<int>(hdr_buf.size()));

    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    LINEP_TEST_CHECK(!srv_recv); // Dropped corrupt magic!
    LINEP_TEST_CHECK(!server_conn->is_connected());

    linep::pal::socket_close(raw_s);
    server_conn->close();
    server.close();

    std::cout << "  -> Corrupted Magic Header Mid-Stream Rejection PASSED" << std::endl;
}

void test_tcp_abrupt_disconnect_and_stream_cleanup() {
    std::cout << "[Test 7] Real TCP Socket: Abrupt Disconnect & Active Stream Cleanup..." << std::endl;
    constexpr std::uint16_t port = 19987;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn != nullptr);
    server_accept_thread.join();

    session_manager server_session;
    runtime_error err{};

    stream_identity id_1{701, 7001, 0};
    stream_identity id_2{702, 7002, 0};

    request_envelope r1{id_1, runtime_profile::chat, "llama-3.1-8b", "Prompt 1"};
    request_envelope r2{id_2, runtime_profile::chat, "llama-3.1-8b", "Prompt 2"};

    LINEP_TEST_CHECK(server_session.submit_request(r1, err));
    LINEP_TEST_CHECK(server_session.submit_request(r2, err));
    LINEP_TEST_CHECK(server_session.get_active_stream_count() == 2);

    // Client abruptly terminates connection mid-stream
    client_conn->close();

    // Server reads EOF and invokes fail-closed termination of all active streams on that session
    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    LINEP_TEST_CHECK(!srv_recv);

    runtime_error disc_err{error_category::transient, 10054, "Client socket abruptly disconnected", "TCP Connection Reset"};
    std::size_t terminated = server_session.terminate_all_active_streams(terminal_outcome::failed, disc_err);
    LINEP_TEST_CHECK(terminated == 2);
    LINEP_TEST_CHECK(server_session.get_active_stream_count() == 0);

    active_stream_state s1{}, s2{};
    LINEP_TEST_CHECK(server_session.get_stream_state(id_1, s1));
    LINEP_TEST_CHECK(server_session.get_stream_state(id_2, s2));
    LINEP_TEST_CHECK(s1.lifecycle.outcome == terminal_outcome::failed);
    LINEP_TEST_CHECK(s2.lifecycle.outcome == terminal_outcome::failed);

    server_conn->close();
    server.close();

    std::cout << "  -> Abrupt Disconnect & Active Stream Cleanup PASSED" << std::endl;
}

void test_tcp_reconnect_clean_session_isolation() {
    std::cout << "[Test 8] Real TCP Socket: Reconnect & Clean Session Isolation..." << std::endl;
    constexpr std::uint16_t port = 19988;

    envelope_server server;
    LINEP_TEST_CHECK(server.listen(port));

    // Phase 1: First Connection (Session 1)
    std::unique_ptr<envelope_connection> srv_conn1;
    std::thread accept_th1([&]() {
        srv_conn1 = server.accept_connection();
    });

    auto client_conn1 = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn1 != nullptr);
    accept_th1.join();

    session_manager srv_session1;
    runtime_error err{};

    stream_identity id_old1{801, 8001, 0};
    request_envelope r_old{id_old1, runtime_profile::chat, "llama-3.1-8b", "Old Prompt"};
    LINEP_TEST_CHECK(client_conn1->send_request(r_old));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_r_old{};
    LINEP_TEST_CHECK(srv_conn1->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_r_old));
    LINEP_TEST_CHECK(srv_session1.submit_request(srv_r_old, err));

    // Abrupt disconnect on connection 1
    client_conn1->close();
    LINEP_TEST_CHECK(!srv_conn1->receive_envelope_raw(raw_buf)); // EOF
    srv_session1.terminate_all_active_streams(terminal_outcome::failed, {error_category::transient, 10054, "Abrupt disconnect"});
    srv_conn1->close();

    // Verify Session 1 has no active streams left
    LINEP_TEST_CHECK(srv_session1.get_active_stream_count() == 0);
    active_stream_state old_state{};
    LINEP_TEST_CHECK(srv_session1.get_stream_state(id_old1, old_state));
    LINEP_TEST_CHECK(old_state.lifecycle.outcome == terminal_outcome::failed);

    // Phase 2: Reconnection on Fresh Socket (Session 2)
    std::unique_ptr<envelope_connection> srv_conn2;
    std::thread accept_th2([&]() {
        srv_conn2 = server.accept_connection();
    });

    auto client_conn2 = envelope_connection::connect("127.0.0.1", port);
    LINEP_TEST_CHECK(client_conn2 != nullptr);
    accept_th2.join();

    session_manager srv_session2;
    stream_identity id_new1{802, 8002, 0};
    request_envelope r_new{id_new1, runtime_profile::chat, "llama-3.1-8b", "New Generation Prompt"};
    LINEP_TEST_CHECK(client_conn2->send_request(r_new));

    request_envelope srv_r_new{};
    LINEP_TEST_CHECK(srv_conn2->receive_envelope_raw(raw_buf));
    LINEP_TEST_CHECK(decode_request(raw_buf.data(), raw_buf.size(), srv_r_new));
    LINEP_TEST_CHECK(srv_session2.submit_request(srv_r_new, err));

    // Emit event on Session 2
    event_envelope new_term{id_new1, 1, runtime_event_type::completed, "Fresh completed output", terminal_outcome::completed};
    LINEP_TEST_CHECK(srv_session2.dispatch_event(new_term, err));
    LINEP_TEST_CHECK(srv_conn2->send_event(new_term));

    // Client receives on connection 2
    LINEP_TEST_CHECK(client_conn2->receive_envelope_raw(raw_buf));
    event_envelope client_evt{};
    LINEP_TEST_CHECK(decode_event(raw_buf.data(), raw_buf.size(), client_evt));
    LINEP_TEST_CHECK(client_evt.stream == id_new1);
    LINEP_TEST_CHECK(client_evt.payload == "Fresh completed output");
    LINEP_TEST_CHECK(client_evt.outcome == terminal_outcome::completed);

    // Assert absolute state isolation: Session 2 does NOT have old stream
    LINEP_TEST_CHECK(!srv_session2.has_stream(id_old1));
    LINEP_TEST_CHECK(srv_session2.has_stream(id_new1));

    client_conn2->close();
    srv_conn2->close();
    server.close();

    std::cout << "  -> Reconnect & Clean Session Isolation PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Real TCP Socket Multiplexing & Fail-Closed Robustness Test Suite ===" << std::endl;
    test_tcp_concurrent_stream_multiplexing();
    test_tcp_stream_isolation_on_failure();
    test_tcp_clean_connection_teardown();
    test_tcp_malformed_and_truncated_payload_length();
    test_tcp_oversized_payload_dos_protection();
    test_tcp_corrupted_magic_midstream();
    test_tcp_abrupt_disconnect_and_stream_cleanup();
    test_tcp_reconnect_clean_session_isolation();
    std::cout << "ALL 8 V0.2 TCP SOCKET MULTIPLEXING & FAIL-CLOSED TESTS PASSED 100%!" << std::endl;
    return 0;
}
