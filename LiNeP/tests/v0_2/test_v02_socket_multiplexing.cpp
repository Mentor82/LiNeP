#include <cassert>
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

using namespace linep::v0_2;

void test_tcp_concurrent_stream_multiplexing() {
    std::cout << "[Test 1] Real TCP Socket: Concurrent Logical Stream Multiplexing & Interleaving..." << std::endl;
    constexpr std::uint16_t port = 19971;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    assert(client_conn != nullptr);
    assert(client_conn->is_connected());

    server_accept_thread.join();
    assert(server_conn != nullptr);
    assert(server_conn->is_connected());

    stream_identity id_a{101, 1001, 0};
    stream_identity id_b{102, 1002, 0};

    // Client submits two requests over the single persistent TCP connection
    request_envelope req_a{id_a, runtime_profile::chat, "llama-3.1-8b", "Prompt A"};
    request_envelope req_b{id_b, runtime_profile::generate, "llama-3.1-8b", "Prompt B"};

    assert(client_conn->send_request(req_a));
    assert(client_conn->send_request(req_b));

    // Server reads both requests
    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_req_a{}, srv_req_b{};

    assert(server_conn->receive_envelope_raw(raw_buf));
    assert(decode_request(raw_buf.data(), raw_buf.size(), srv_req_a));
    assert(srv_req_a.stream == id_a);

    assert(server_conn->receive_envelope_raw(raw_buf));
    assert(decode_request(raw_buf.data(), raw_buf.size(), srv_req_b));
    assert(srv_req_b.stream == id_b);

    session_manager server_session;
    runtime_error err{};
    assert(server_session.submit_request(srv_req_a, err));
    assert(server_session.submit_request(srv_req_b, err));

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
    assert(client_session.submit_request(req_a, err));
    assert(client_session.submit_request(req_b, err));

    std::string text_a, text_b;
    bool term_a = false, term_b = false;

    while (!term_a || !term_b) {
        assert(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        assert(decode_event(raw_buf.data(), raw_buf.size(), evt));
        assert(client_session.dispatch_event(evt, err));

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

    assert(text_a == "The quick brown fox ");
    assert(text_b == "Neural networks compute vectors ");
    assert(client_session.is_stream_terminal(id_a));
    assert(client_session.is_stream_terminal(id_b));

    client_conn->close();
    server_conn->close();
    server.close();

    std::cout << "  -> Real TCP Multiplexing & Interleaved Event Delivery PASSED" << std::endl;
}

void test_tcp_stream_isolation_on_failure() {
    std::cout << "[Test 2] Real TCP Socket: Stream Isolation upon Remote Failure..." << std::endl;
    constexpr std::uint16_t port = 19972;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    assert(client_conn != nullptr);
    server_accept_thread.join();

    stream_identity id_fail{201, 2001, 0};
    stream_identity id_ok{202, 2002, 0};

    request_envelope req_fail{id_fail, runtime_profile::chat, "llama-3.1-8b", "Fail Prompt"};
    request_envelope req_ok{id_ok, runtime_profile::chat, "llama-3.1-8b", "Ok Prompt"};

    assert(client_conn->send_request(req_fail));
    assert(client_conn->send_request(req_ok));

    std::vector<std::uint8_t> raw_buf;
    request_envelope srv_fail{}, srv_ok{};
    assert(server_conn->receive_envelope_raw(raw_buf));
    assert(decode_request(raw_buf.data(), raw_buf.size(), srv_fail));
    assert(server_conn->receive_envelope_raw(raw_buf));
    assert(decode_request(raw_buf.data(), raw_buf.size(), srv_ok));

    session_manager server_session;
    runtime_error err{};
    assert(server_session.submit_request(srv_fail, err));
    assert(server_session.submit_request(srv_ok, err));

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
    assert(client_session.submit_request(req_fail, err));
    assert(client_session.submit_request(req_ok, err));

    bool term_fail = false, term_ok = false;
    std::string ok_text;

    while (!term_fail || !term_ok) {
        assert(client_conn->receive_envelope_raw(raw_buf));
        event_envelope evt{};
        assert(decode_event(raw_buf.data(), raw_buf.size(), evt));
        assert(client_session.dispatch_event(evt, err));

        if (evt.stream == id_fail) {
            if (evt.is_terminal()) {
                assert(evt.outcome == terminal_outcome::failed);
                term_fail = true;
            }
        } else if (evt.stream == id_ok) {
            if (evt.event_type == runtime_event_type::content_delta) {
                ok_text += evt.payload;
            } else if (evt.is_terminal()) {
                assert(evt.outcome == terminal_outcome::completed);
                term_ok = true;
            }
        }
    }

    worker_fail.join();
    worker_ok.join();

    assert(ok_text == "Successful output");
    assert(client_session.is_stream_terminal(id_fail));
    assert(client_session.is_stream_terminal(id_ok));

    active_stream_state st_fail{}, st_ok{};
    assert(client_session.get_stream_state(id_fail, st_fail));
    assert(st_fail.lifecycle.outcome == terminal_outcome::failed);
    assert(client_session.get_stream_state(id_ok, st_ok));
    assert(st_ok.lifecycle.outcome == terminal_outcome::completed);

    client_conn->close();
    server_conn->close();
    server.close();

    std::cout << "  -> Real TCP Stream Isolation PASSED" << std::endl;
}

void test_tcp_clean_connection_teardown() {
    std::cout << "[Test 3] Real TCP Socket: Clean Connection Teardown & EOF Detection..." << std::endl;
    constexpr std::uint16_t port = 19973;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    assert(client_conn != nullptr);
    server_accept_thread.join();

    // Client closes connection gracefully
    client_conn->close();
    assert(!client_conn->is_connected());

    // Server reads EOF and cleanly closes
    std::vector<std::uint8_t> raw_buf;
    bool recv_ok = server_conn->receive_envelope_raw(raw_buf);
    assert(!recv_ok); // EOF detected

    server_conn->close();
    assert(!server_conn->is_connected());
    server.close();

    std::cout << "  -> Real TCP Clean Connection Teardown PASSED" << std::endl;
}

void test_tcp_malformed_and_truncated_payload_length() {
    std::cout << "[Test 4] Real TCP Socket: Malformed & Truncated Payload Length Rejection..." << std::endl;
    constexpr std::uint16_t port = 19974;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    // Client sends header claiming payload_len = 5000, but only sends 10 bytes then abruptly closes
    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    assert(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header fake_hdr{};
    fake_hdr.magic = LINEP_V02_MAGIC;
    fake_hdr.version_major = LINEP_V02_VERSION_MAJOR;
    fake_hdr.version_minor = LINEP_V02_VERSION_MINOR;
    fake_hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::request);
    fake_hdr.request_id = 999;
    fake_hdr.execution_id = 888;
    fake_hdr.payload_len = 5000; // Claims 5000 bytes

    std::vector<std::uint8_t> malformed_buf(sizeof(fake_hdr) + 10, 0xAA);
    std::memcpy(malformed_buf.data(), &fake_hdr, sizeof(fake_hdr));

    linep::pal::tcp_send_all(raw_s, malformed_buf.data(), static_cast<int>(malformed_buf.size()));
    linep::pal::socket_close(raw_s); // Abrupt close!

    // Server must reject fail-closed without hanging
    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    assert(!srv_recv); // Failed closed!
    assert(!server_conn->is_connected());

    server_conn->close();
    server.close();

    std::cout << "  -> Malformed/Truncated Payload Length Fail-Closed PASSED" << std::endl;
}

void test_tcp_oversized_payload_dos_protection() {
    std::cout << "[Test 5] Real TCP Socket: Oversized Payload Length DoS Protection (> 16 MB)..." << std::endl;
    constexpr std::uint16_t port = 19975;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    assert(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header dos_hdr{};
    dos_hdr.magic = LINEP_V02_MAGIC;
    dos_hdr.version_major = LINEP_V02_VERSION_MAJOR;
    dos_hdr.version_minor = LINEP_V02_VERSION_MINOR;
    dos_hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::request);
    dos_hdr.request_id = 999;
    dos_hdr.execution_id = 888;
    dos_hdr.payload_len = 100 * 1024 * 1024; // 100 MB claim!

    linep::pal::tcp_send_all(raw_s, reinterpret_cast<const uint8_t*>(&dos_hdr), sizeof(dos_hdr));

    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    assert(!srv_recv); // Rejected oversized payload!
    assert(!server_conn->is_connected());

    linep::pal::socket_close(raw_s);
    server_conn->close();
    server.close();

    std::cout << "  -> Oversized Payload DoS Protection PASSED" << std::endl;
}

void test_tcp_corrupted_magic_midstream() {
    std::cout << "[Test 6] Real TCP Socket: Corrupted Magic Header Mid-Stream Rejection..." << std::endl;
    constexpr std::uint16_t port = 19976;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    linep::pal::net_init();
    linep::pal::Socket raw_s = linep::pal::tcp_connect("127.0.0.1", port);
    assert(raw_s.valid());
    server_accept_thread.join();

    wire_envelope_header corrupt_hdr{};
    corrupt_hdr.magic = 0xDEADBEEF; // Invalid magic!
    corrupt_hdr.version_major = 0;
    corrupt_hdr.version_minor = 2;
    corrupt_hdr.envelope_type = 1;
    corrupt_hdr.payload_len = 10;

    linep::pal::tcp_send_all(raw_s, reinterpret_cast<const uint8_t*>(&corrupt_hdr), sizeof(corrupt_hdr));

    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    assert(!srv_recv); // Dropped corrupt magic!
    assert(!server_conn->is_connected());

    linep::pal::socket_close(raw_s);
    server_conn->close();
    server.close();

    std::cout << "  -> Corrupted Magic Header Mid-Stream Rejection PASSED" << std::endl;
}

void test_tcp_abrupt_disconnect_and_stream_cleanup() {
    std::cout << "[Test 7] Real TCP Socket: Abrupt Disconnect & Active Stream Cleanup..." << std::endl;
    constexpr std::uint16_t port = 19977;

    envelope_server server;
    assert(server.listen(port));

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    std::unique_ptr<envelope_connection> client_conn = envelope_connection::connect("127.0.0.1", port);
    assert(client_conn != nullptr);
    server_accept_thread.join();

    session_manager server_session;
    runtime_error err{};

    stream_identity id_1{701, 7001, 0};
    stream_identity id_2{702, 7002, 0};

    request_envelope r1{id_1, runtime_profile::chat, "llama-3.1-8b", "Prompt 1"};
    request_envelope r2{id_2, runtime_profile::chat, "llama-3.1-8b", "Prompt 2"};

    assert(server_session.submit_request(r1, err));
    assert(server_session.submit_request(r2, err));
    assert(server_session.get_active_stream_count() == 2);

    // Client abruptly terminates connection mid-stream
    client_conn->close();

    // Server reads EOF and invokes fail-closed termination of all active streams on that session
    std::vector<std::uint8_t> srv_buf;
    bool srv_recv = server_conn->receive_envelope_raw(srv_buf);
    assert(!srv_recv);

    runtime_error disc_err{error_category::transient, 10054, "Client socket abruptly disconnected", "TCP Connection Reset"};
    std::size_t terminated = server_session.terminate_all_active_streams(terminal_outcome::failed, disc_err);
    assert(terminated == 2);
    assert(server_session.get_active_stream_count() == 0);

    active_stream_state s1{}, s2{};
    assert(server_session.get_stream_state(id_1, s1));
    assert(server_session.get_stream_state(id_2, s2));
    assert(s1.lifecycle.outcome == terminal_outcome::failed);
    assert(s2.lifecycle.outcome == terminal_outcome::failed);

    server_conn->close();
    server.close();

    std::cout << "  -> Abrupt Disconnect & Active Stream Cleanup PASSED" << std::endl;
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
    std::cout << "ALL 7 V0.2 TCP SOCKET MULTIPLEXING & FAIL-CLOSED TESTS PASSED 100%!" << std::endl;
    return 0;
}
