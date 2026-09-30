#include "linep/v0_2/lease.hpp"

#include <chrono>
#include <random>

namespace linep::v0_2 {

namespace {

constexpr std::uint32_t RECV_POLL_MS = 20;

std::uint64_t random_nonzero_u64() {
    std::random_device rd;
    std::uint64_t v = 0;
    while (v == 0) {
        v = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
    }
    return v;
}

std::uint64_t wall_clock_epoch() {
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return us > 0 ? static_cast<std::uint64_t>(us) : 1;
}

void set_error(std::string* out_error, const std::string& msg) {
    if (out_error) {
        *out_error = msg;
    }
}

} // anonymous namespace

// ── lease_client ────────────────────────────────────────────────────────────

lease_client::lease_client(lease_client_config config)
    : config_(std::move(config)) {
    if (config_.identity.node_id == 0) {
        config_.identity.node_id = random_nonzero_u64();
    }
    if (config_.identity.runtime_id == 0) {
        config_.identity.runtime_id = random_nonzero_u64();
    }
    if (config_.control_epoch == 0) {
        config_.control_epoch = wall_clock_epoch();
    }
    if (config_.max_attempts == 0) {
        config_.max_attempts = 1;
    }
}

lease_client::~lease_client() {
    stop_keepalive();
    channel_.close();
}

bool lease_client::ensure_open_locked(std::string* out_error) {
    if (config_.control_port == 0 || config_.control_host.empty()) {
        set_error(out_error, "lease client: no control endpoint configured");
        return false;
    }
    if (config_.trunk_port == 0) {
        set_error(out_error, "lease client: trunk_port must be > 0 (LEASE_ACK requires a ready trunk)");
        return false;
    }
    if (!channel_.is_open() && !channel_.open_and_bind(0, RECV_POLL_MS)) {
        set_error(out_error, "lease client: failed to open UDP control socket");
        return false;
    }
    return true;
}

udp_control_datagram lease_client::make_datagram_locked(control_message_type type) {
    udp_control_datagram d{};
    d.message_type = static_cast<std::uint8_t>(type);
    d.node_id = config_.identity.node_id;
    d.runtime_id = config_.identity.runtime_id;
    d.endpoint_id = config_.identity.endpoint_id;
    d.control_seq = next_seq_++;
    d.control_epoch = config_.control_epoch;
    d.availability = static_cast<std::uint8_t>(node_availability::available);
    d.health = static_cast<std::uint8_t>(node_health::healthy);
    d.tcp_port = config_.trunk_port;
    d.set_trunk_ready(true);
    return d;
}

bool lease_client::send_locked(const udp_control_datagram& dgram) {
    return channel_.send_datagram(config_.control_host.c_str(), config_.control_port, dgram);
}

bool lease_client::wait_invite_locked(std::uint32_t window_ms, udp_control_datagram& out_invite) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(window_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        udp_control_datagram d{};
        if (!channel_.recv_datagram(d)) {
            continue;
        }
        if (d.message_type == static_cast<std::uint8_t>(control_message_type::invite) &&
            d.node_id == config_.identity.node_id &&
            d.runtime_id == config_.identity.runtime_id &&
            d.endpoint_id == config_.identity.endpoint_id &&
            d.control_epoch == config_.control_epoch &&
            d.lease_token != 0) {
            out_invite = d;
            return true;
        }
    }
    return false;
}

bool lease_client::request_invite_locked(std::string* out_error) {
    if (!ensure_open_locked(out_error)) {
        return false;
    }
    lease_token_ = 0;
    active_ = false;
    for (std::uint32_t attempt = 0; attempt < config_.max_attempts; ++attempt) {
        if (!send_locked(make_datagram_locked(control_message_type::node_hello))) {
            set_error(out_error, "lease client: failed to send NODE_HELLO");
            return false;
        }
        udp_control_datagram invite{};
        if (wait_invite_locked(config_.retransmit_ms, invite)) {
            lease_token_ = invite.lease_token;
            return true;
        }
    }
    set_error(out_error, "lease client: no INVITE from " + config_.control_host + ":" +
                         std::to_string(config_.control_port) + " after " +
                         std::to_string(config_.max_attempts) + " NODE_HELLO attempts");
    return false;
}

bool lease_client::ack_lease_locked(std::string* out_error) {
    if (lease_token_ == 0) {
        set_error(out_error, "lease client: no lease offered (request_invite first)");
        return false;
    }
    for (std::uint32_t attempt = 0; attempt < config_.max_attempts; ++attempt) {
        udp_control_datagram ack = make_datagram_locked(control_message_type::lease_ack);
        ack.lease_token = lease_token_;
        if (!send_locked(ack)) {
            set_error(out_error, "lease client: failed to send LEASE_ACK");
            return false;
        }
        if (config_.confirm_ms == 0) {
            active_ = true;
            return true;
        }
        // Delivery probe: an issuer re-sends the INVITE only while the identity is still INVITED
        if (!send_locked(make_datagram_locked(control_message_type::node_hello))) {
            set_error(out_error, "lease client: failed to send NODE_HELLO probe");
            return false;
        }
        udp_control_datagram invite{};
        if (!wait_invite_locked(config_.confirm_ms, invite)) {
            active_ = true;
            return true;
        }
        if (invite.lease_token != lease_token_) {
            set_error(out_error, "lease client: issuer changed the lease of an INVITED identity");
            lease_token_ = 0;
            return false;
        }
    }
    set_error(out_error, "lease client: LEASE_ACK not confirmed after " +
                         std::to_string(config_.max_attempts) + " attempts");
    return false;
}

bool lease_client::acquire(std::string* out_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    return request_invite_locked(out_error) && ack_lease_locked(out_error);
}

bool lease_client::request_invite(std::string* out_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    return request_invite_locked(out_error);
}

bool lease_client::ack_lease(std::string* out_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    return ack_lease_locked(out_error);
}

bool lease_client::renew(std::string* out_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::uint64_t now = wall_clock_epoch();
    config_.control_epoch = now > config_.control_epoch ? now : config_.control_epoch + 1;
    return request_invite_locked(out_error) && ack_lease_locked(out_error);
}

void lease_client::set_sl1(bool enable, std::uint16_t key_id, std::vector<std::uint8_t> key) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enable_sl1 = enable;
    config_.sl1_key_id = key_id;
    config_.sl1_key = std::move(key);
}

bool lease_client::send_bind(envelope_connection& conn) const {
    session_bind_envelope b = current_bind();
    if (!b.is_valid()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.enable_sl1) {
        if (config_.sl1_key.size() < 32) {
            return false; // Minimum key size >= 32 bytes (256 bits)
        }
        b.sl1_requested = true;
        b.key_id = config_.sl1_key_id;
        conn.set_sl1_auth(b, message_direction::initiator_to_responder, config_.sl1_key_id, config_.sl1_key);
        return conn.send_session_bind(b);
    } else {
        return conn.send_session_bind(b);
    }
}

bool lease_client::bind(envelope_connection& conn) const {
    session_bind_envelope b = current_bind();
    if (!b.is_valid()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.enable_sl1) {
        if (config_.sl1_key.size() < 32) {
            return false; // Minimum key size >= 32 bytes (256 bits)
        }
        b.sl1_requested = true;
        b.key_id = config_.sl1_key_id;
        conn.set_sl1_auth(b, message_direction::initiator_to_responder, config_.sl1_key_id, config_.sl1_key);
        if (!conn.send_session_bind(b)) {
            return false;
        }

        // Wait for server's signed confirmation frame
        std::vector<std::uint8_t> confirm_raw;
        if (!conn.receive_envelope_raw(confirm_raw)) {
            return false;
        }

        wire_envelope_header hdr{};
        if (!decode_header(confirm_raw.data(), confirm_raw.size(), hdr)) {
            return false;
        }

        if (hdr.envelope_type == static_cast<std::uint8_t>(runtime_envelope_type::session_bind)) {
            session_bind_envelope confirm_bind{};
            if (!decode_session_bind(confirm_raw.data(), confirm_raw.size(), confirm_bind)) {
                return false;
            }
            if (!confirm_bind.sl1_requested) {
                return false;
            }
            wire_auth_extension ext{};
            std::string err;
            if (!verify_envelope_buffer(confirm_raw.data(), confirm_raw.size(), b,
                                        message_direction::responder_to_initiator,
                                        config_.sl1_key.data(), config_.sl1_key.size(),
                                        ext, &err)) {
                return false;
            }
            if (ext.auth_seq != 1) {
                return false;
            }
            return true;
        } else {
            return false; // Received error event or unexpected frame
        }
    } else {
        return conn.send_session_bind(b);
    }
}

bool lease_client::send_heartbeat() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || !channel_.is_open()) {
        return false;
    }
    return send_locked(make_datagram_locked(control_message_type::heartbeat));
}

void lease_client::start_keepalive(std::uint32_t interval_ms) {
    stop_keepalive();
    {
        std::lock_guard<std::mutex> lock(keepalive_mutex_);
        keepalive_stop_ = false;
    }
    keepalive_thread_ = std::thread([this, interval_ms]() {
        std::unique_lock<std::mutex> lock(keepalive_mutex_);
        while (!keepalive_cv_.wait_for(lock, std::chrono::milliseconds(interval_ms), [this] { return keepalive_stop_; })) {
            lock.unlock();
            send_heartbeat();
            lock.lock();
        }
    });
}

void lease_client::stop_keepalive() {
    {
        std::lock_guard<std::mutex> lock(keepalive_mutex_);
        keepalive_stop_ = true;
    }
    keepalive_cv_.notify_all();
    if (keepalive_thread_.joinable()) {
        keepalive_thread_.join();
    }
}

bool lease_client::has_lease() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lease_token_ != 0;
}

bool lease_client::is_active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_;
}

session_bind_envelope lease_client::current_bind() const {
    std::lock_guard<std::mutex> lock(mutex_);
    session_bind_envelope b{};
    b.identity = config_.identity;
    b.control_epoch = config_.control_epoch;
    b.lease_token = lease_token_;
    return b;
}

node_endpoint_identity lease_client::identity() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.identity;
}

std::uint64_t lease_client::control_epoch() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.control_epoch;
}

std::unique_ptr<envelope_connection> connect_bound(const std::string& host, std::uint16_t port, const lease_client& lease,
                                                   std::uint32_t timeout_ms) {
    auto conn = envelope_connection::connect(host, port, timeout_ms);
    if (!conn) {
        return nullptr;
    }
    if (!lease.bind(*conn)) {
        conn->close();
        return nullptr;
    }
    return conn;
}

bool is_stale_binding_event(const event_envelope& evt) noexcept {
    return !evt.stream.is_connection_level() &&
           evt.event_type == runtime_event_type::failed &&
           evt.error.code == 401 &&
           evt.error.message.rfind("stale_binding", 0) == 0;
}

// ── lease_issuer ────────────────────────────────────────────────────────────

lease_issuer::~lease_issuer() {
    stop();
}

bool lease_issuer::start(std::uint16_t udp_port) {
    stop();
    if (!channel_.open_and_bind(udp_port, 100)) {
        return false;
    }
    if (lease_counter_ == 0) {
        // Random base: leases of a restarted issuer never repeat earlier ones
        lease_counter_ = random_nonzero_u64() >> 1;
    }
    running_ = true;
    thread_ = std::thread(&lease_issuer::serve_loop, this);
    return true;
}

void lease_issuer::stop() {
    if (running_.exchange(false)) {
        if (thread_.joinable()) {
            thread_.join();
        }
        channel_.close();
    }
}

std::uint64_t lease_issuer::next_lease_token() {
    if (++lease_counter_ == 0) {
        ++lease_counter_;
    }
    return lease_counter_;
}

void lease_issuer::serve_loop() {
    while (running_) {
        udp_control_datagram dgram{};
        std::string src_ip;
        std::uint16_t src_port = 0;
        if (!channel_.recv_datagram(dgram, &src_ip, &src_port)) {
            continue;
        }
        auto now_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        router_.ingest_datagram(dgram, now_us);

        if (dgram.message_type != static_cast<std::uint8_t>(control_message_type::node_hello)) {
            continue;
        }
        node_endpoint_identity id{dgram.node_id, dgram.runtime_id, dgram.endpoint_id};
        udp_control_datagram inv{};
        // SEEN -> fresh lease; still INVITED (INVITE or LEASE_ACK lost) -> same lease again
        if (router_.issue_invite(id, next_lease_token(), inv) || router_.reissue_invite(id, dgram.control_epoch, inv)) {
            channel_.send_datagram(src_ip.c_str(), src_port, inv);
        }
    }
}

} // namespace linep::v0_2
