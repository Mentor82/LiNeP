#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/transport.hpp"
#include "linep/v0_2/udp_transport.hpp"

namespace linep::v0_2 {

// ── lease_client ────────────────────────────────────────────────────────────
// Client (node role) side of the dual-plane handshake:
//
//   NODE_HELLO --> INVITE(lease) --> LEASE_ACK --> SESSION_BIND on the trunk
//
// - NODE_HELLO is retransmitted until an INVITE arrives (UDP loss); issuers
//   answer a same-epoch HELLO of an INVITED identity with the same lease.
// - LEASE_ACK has no reply on the wire. After the ACK the client probes with a
//   same-epoch HELLO: an INVITE back means the ACK was lost and is re-sent,
//   silence means the lease is active.
// - renew() starts a new incarnation (higher control epoch) with a new lease.
//   Use it after a 401 stale_binding, then bind() again on the same connection.
// - Leases expire without control traffic; start_keepalive() sends HEARTBEATs.
struct lease_client_config {
    std::string control_host{"127.0.0.1"}; // IPv4 address of the lease issuer's UDP control port
    std::uint16_t control_port{0};
    node_endpoint_identity identity{};     // node_id/runtime_id == 0 -> random identity
    std::uint64_t control_epoch{0};        // 0 -> derived from the wall clock
    std::uint16_t trunk_port{0};           // advertised TCP trunk port (tcp_port), must be > 0
    std::uint32_t retransmit_ms{200};      // wait for an INVITE before re-sending NODE_HELLO
    std::uint32_t max_attempts{10};        // NODE_HELLO / LEASE_ACK attempts per acquire()
    std::uint32_t confirm_ms{100};         // LEASE_ACK delivery probe window (0 = no probe)
};

class lease_client {
public:
    explicit lease_client(lease_client_config config);
    ~lease_client();

    lease_client(const lease_client&) = delete;
    lease_client& operator=(const lease_client&) = delete;

    // Full handshake: request_invite() + ack_lease()
    bool acquire(std::string* out_error = nullptr);

    // NODE_HELLO -> INVITE only; the lease is offered but not yet active
    bool request_invite(std::string* out_error = nullptr);

    // LEASE_ACK for the offered lease, with delivery probe
    bool ack_lease(std::string* out_error = nullptr);

    // New incarnation (control_epoch + 1) and a fresh lease
    bool renew(std::string* out_error = nullptr);

    // SESSION_BIND with the current lease on a trunk connection
    bool bind(envelope_connection& conn) const;

    // HEARTBEAT keeps the lease alive on issuers with an idle timeout
    bool send_heartbeat();
    void start_keepalive(std::uint32_t interval_ms = 30000);
    void stop_keepalive();

    bool has_lease() const;      // a lease is offered or active
    bool is_active() const;      // LEASE_ACK sent and confirmed
    session_bind_envelope current_bind() const;
    node_endpoint_identity identity() const;
    std::uint64_t control_epoch() const;

private:
    bool ensure_open_locked(std::string* out_error);
    udp_control_datagram make_datagram_locked(control_message_type type);
    bool send_locked(const udp_control_datagram& dgram);
    bool wait_invite_locked(std::uint32_t window_ms, udp_control_datagram& out_invite);
    bool request_invite_locked(std::string* out_error);
    bool ack_lease_locked(std::string* out_error);

    lease_client_config config_;
    mutable std::mutex mutex_;
    udp_endpoint_channel channel_;
    std::uint64_t next_seq_{1};
    std::uint64_t lease_token_{0};
    bool active_{false};

    std::thread keepalive_thread_;
    std::mutex keepalive_mutex_;
    std::condition_variable keepalive_cv_;
    bool keepalive_stop_{false};
};

// Connect to a trunk and bind it with the client's current lease
std::unique_ptr<envelope_connection> connect_bound(const std::string& host, std::uint16_t port, const lease_client& lease,
                                                   std::uint32_t timeout_ms = 5000);

// A stream-level 401 whose message starts with "stale_binding": re-bind (renew + bind) and retry
bool is_stale_binding_event(const event_envelope& evt) noexcept;

// ── lease_issuer ────────────────────────────────────────────────────────────
// Scheduler side of the UDP control plane: owns a control_plane_router, answers
// NODE_HELLO with an INVITE (the same lease again while INVITED) and ingests
// LEASE_ACK / HEARTBEAT / STATUS / PONG. Hand router() to a trunk server via
// mock_runtime_server::set_control_plane_router().
class lease_issuer {
public:
    lease_issuer() = default;
    ~lease_issuer();

    lease_issuer(const lease_issuer&) = delete;
    lease_issuer& operator=(const lease_issuer&) = delete;

    // Bind the UDP control port (0 for an ephemeral port) and start serving
    bool start(std::uint16_t udp_port);
    void stop();

    bool is_running() const noexcept { return running_; }
    std::uint16_t get_bound_port() const noexcept { return channel_.get_bound_port(); }
    const control_plane_router& router() const noexcept { return router_; }
    control_plane_router& router() noexcept { return router_; }

private:
    void serve_loop();
    std::uint64_t next_lease_token();

    control_plane_router router_;
    udp_endpoint_channel channel_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::uint64_t lease_counter_{0};
};

} // namespace linep::v0_2
