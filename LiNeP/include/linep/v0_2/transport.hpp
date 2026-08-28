#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
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
    friend class stream_send_scheduler;

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

// ── stream_send_scheduler ───────────────────────────────────────────────────
// Fair Round-Robin Trunk Send Multiplexer with Per-Stream Bounded Queues
class stream_send_scheduler {
public:
    explicit stream_send_scheduler(std::size_t max_queued_per_stream = 16)
        : max_queued_per_stream_(max_queued_per_stream) {}

    // Enqueue envelopes with per-stream queue bounds. Returns false if stream's queue is full.
    bool enqueue_event(const event_envelope& evt);
    bool enqueue_request(const request_envelope& req);
    bool enqueue_control(const control_envelope& ctrl);

    // Pull next envelope in fair round-robin order across active stream queues
    bool pull_next_scheduled(stream_identity& out_stream, std::vector<std::uint8_t>& out_frame);

    // Flush and transmit all queued frames over the given connection in fair round-robin order
    std::size_t flush_scheduled(envelope_connection& conn);

    // Drop/clear queues for a specific stream (e.g. upon terminal state or cancel)
    void drop_stream(const stream_identity& stream);

    std::size_t get_stream_queued_count(const stream_identity& stream) const;
    std::size_t get_total_queued_count() const;

private:
    bool enqueue_raw(const stream_identity& stream, std::vector<std::uint8_t> frame);

    std::size_t max_queued_per_stream_{16};
    mutable std::mutex mutex_;
    std::vector<stream_identity> active_order_;
    std::unordered_map<stream_identity, std::deque<std::vector<std::uint8_t>>, stream_identity_hash> stream_queues_;
    std::size_t rr_cursor_{0};
};

} // namespace linep::v0_2
