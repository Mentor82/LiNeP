#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/session.hpp"
#include "linep/v0_2/transport.hpp"

using namespace linep::v0_2;

void test_tcp_concurrent_stream_multiplexing() {
    std::cout << "[Test 1] Real TCP Socket: Concurrent Logical Stream Multiplexing & Interleaving..." << std::endl;
    constexpr std::uint16_t port = 19961;

    envelope_server server;
    bool listen_ok = server.listen(port);
    assert(listen_ok);

    std::unique_ptr<envelope_connection> server_conn;
    std::thread server_accept_thread([&]() {
        server_conn = server.accept_connection();
    });

    // Client connects via TCP
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
    constexpr std::uint16_t port = 19962;

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
    constexpr std::uint16_t port = 19963;

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

int main() {
    std::cout << "=== LiNeP V0.2 Real TCP Socket Multiplexing Test Suite ===" << std::endl;
    test_tcp_concurrent_stream_multiplexing();
    test_tcp_stream_isolation_on_failure();
    test_tcp_clean_connection_teardown();
    std::cout << "ALL V0.2 TCP SOCKET MULTIPLEXING TESTS PASSED 100%!" << std::endl;
    return 0;
}
