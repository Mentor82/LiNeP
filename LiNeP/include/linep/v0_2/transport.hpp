#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/session.hpp"

namespace linep::v0_2 {

class envelope_connection {
public:
    envelope_connection();
    explicit envelope_connection(std::uintptr_t raw_socket);
    ~envelope_connection();

    envelope_connection(envelope_connection&& other) noexcept;
    envelope_connection& operator=(envelope_connection&& other) noexcept;

    envelope_connection(const envelope_connection&) = delete;
    envelope_connection& operator=(const envelope_connection&) = delete;

    // Connect to a remote host:port over TCP
    static std::unique_ptr<envelope_connection> connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_ms = 5000);

    // Thread-safe envelope transmission over the persistent connection
    bool send_request(const request_envelope& req);
    bool send_event(const event_envelope& evt);
    bool send_control(const control_envelope& ctrl);
    bool send_capabilities(const capabilities_envelope& caps);

    // Receive the next binary envelope from the TCP stream (blocking)
    bool receive_envelope_raw(std::vector<std::uint8_t>& out_buffer);

    // Connection state & lifecycle
    bool is_connected() const noexcept;
    void close() noexcept;

private:
    bool send_bytes_locked(const std::uint8_t* data, std::size_t len);
    bool recv_all_bytes(std::uint8_t* buf, std::size_t len);

    std::uintptr_t sock_{~static_cast<std::uintptr_t>(0u)};
    mutable std::mutex send_mutex_;
};

class envelope_server {
public:
    envelope_server();
    ~envelope_server();

    envelope_server(const envelope_server&) = delete;
    envelope_server& operator=(const envelope_server&) = delete;

    // Bind and listen on port
    bool listen(std::uint16_t port, int backlog = 16);

    // Accept an incoming client connection (blocking)
    std::unique_ptr<envelope_connection> accept_connection();

    // Stop listening and close socket
    void close() noexcept;

    std::uint16_t get_bound_port() const noexcept { return port_; }

private:
    std::uintptr_t listen_sock_{~static_cast<std::uintptr_t>(0u)};
    std::uint16_t port_{0};
};

} // namespace linep::v0_2
