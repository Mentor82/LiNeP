#include "linep/v0_2/transport.hpp"
#include "socket.hpp"
#include <cstring>

namespace linep::v0_2 {

envelope_connection::envelope_connection() {
    pal::net_init();
}

envelope_connection::envelope_connection(std::uintptr_t raw_socket) {
    pal::net_init();
    sock_ = raw_socket;
}

envelope_connection::~envelope_connection() {
    close();
}

envelope_connection::envelope_connection(envelope_connection&& other) noexcept {
    sock_ = other.sock_;
    other.sock_ = ~static_cast<std::uintptr_t>(0u);
}

envelope_connection& envelope_connection::operator=(envelope_connection&& other) noexcept {
    if (this != &other) {
        close();
        sock_ = other.sock_;
        other.sock_ = ~static_cast<std::uintptr_t>(0u);
    }
    return *this;
}

std::unique_ptr<envelope_connection> envelope_connection::connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_ms) {
    pal::net_init();
    pal::Socket s = pal::tcp_connect(host.c_str(), port, timeout_ms);
    if (!s.valid()) {
        return nullptr;
    }
    auto conn = std::make_unique<envelope_connection>();
    conn->sock_ = static_cast<std::uintptr_t>(s.fd);
    return conn;
}

bool envelope_connection::is_connected() const noexcept {
    return sock_ != ~static_cast<std::uintptr_t>(0u);
}

void envelope_connection::close() noexcept {
    if (is_connected()) {
        pal::Socket s{static_cast<pal::RawSocket>(sock_)};
        pal::socket_close(s);
        sock_ = ~static_cast<std::uintptr_t>(0u);
    }
}

bool envelope_connection::send_bytes_locked(const std::uint8_t* data, std::size_t len) {
    if (!is_connected() || !data || len == 0) {
        return false;
    }
    pal::Socket s{static_cast<pal::RawSocket>(sock_)};
    int sent = pal::tcp_send_all(s, data, static_cast<int>(len));
    return sent == static_cast<int>(len);
}

bool envelope_connection::recv_all_bytes(std::uint8_t* buf, std::size_t len) {
    if (!is_connected() || !buf || len == 0) {
        return false;
    }
    pal::Socket s{static_cast<pal::RawSocket>(sock_)};
    int recvd = pal::tcp_recv_all(s, buf, static_cast<int>(len));
    return recvd == static_cast<int>(len);
}

bool envelope_connection::send_request(const request_envelope& req) {
    std::vector<std::uint8_t> buf;
    if (!encode_request(req, buf)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(send_mutex_);
    return send_bytes_locked(buf.data(), buf.size());
}

bool envelope_connection::send_event(const event_envelope& evt) {
    std::vector<std::uint8_t> buf;
    if (!encode_event(evt, buf)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(send_mutex_);
    return send_bytes_locked(buf.data(), buf.size());
}

bool envelope_connection::send_control(const control_envelope& ctrl) {
    std::vector<std::uint8_t> buf;
    if (!encode_control(ctrl, buf)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(send_mutex_);
    return send_bytes_locked(buf.data(), buf.size());
}

bool envelope_connection::send_capabilities(const capabilities_envelope& caps) {
    std::vector<std::uint8_t> buf;
    if (!encode_capabilities(caps, buf)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(send_mutex_);
    return send_bytes_locked(buf.data(), buf.size());
}

bool envelope_connection::receive_envelope_raw(std::vector<std::uint8_t>& out_buffer) {
    out_buffer.clear();
    std::uint8_t hdr_bytes[LINEP_V02_HEADER_SIZE];
    if (!recv_all_bytes(hdr_bytes, LINEP_V02_HEADER_SIZE)) {
        close();
        return false; // Connection closed or error
    }

    wire_envelope_header hdr{};
    if (!decode_header(hdr_bytes, LINEP_V02_HEADER_SIZE, hdr)) {
        close(); // Fail closed on malformed header
        return false;
    }

    if (hdr.magic != LINEP_V02_MAGIC || hdr.version_major != LINEP_V02_VERSION_MAJOR) {
        close(); // Fail closed on corrupted magic / protocol version
        return false;
    }

    if (hdr.payload_len > LINEP_V02_MAX_PAYLOAD_BYTES) {
        close(); // Fail closed on oversized payload claim (DoS protection)
        return false;
    }

    out_buffer.resize(LINEP_V02_HEADER_SIZE + hdr.payload_len);
    std::memcpy(out_buffer.data(), hdr_bytes, LINEP_V02_HEADER_SIZE);

    if (hdr.payload_len > 0) {
        if (!recv_all_bytes(out_buffer.data() + LINEP_V02_HEADER_SIZE, hdr.payload_len)) {
            close(); // Fail closed on truncated payload
            return false;
        }
    }
    return true;
}

// ── envelope_server ──────────────────────────────────────────────────────────

envelope_server::envelope_server() {
    pal::net_init();
}

envelope_server::~envelope_server() {
    close();
}

bool envelope_server::listen(std::uint16_t port, int backlog) {
    close();
    pal::Socket s = pal::tcp_listen(port, backlog);
    if (!s.valid()) {
        return false;
    }
    listen_sock_ = static_cast<std::uintptr_t>(s.fd);
    port_ = port;
    return true;
}

std::unique_ptr<envelope_connection> envelope_server::accept_connection() {
    if (listen_sock_ == ~static_cast<std::uintptr_t>(0u)) {
        return nullptr;
    }
    pal::Socket s{static_cast<pal::RawSocket>(listen_sock_)};
    pal::Socket client = pal::tcp_accept(s);
    if (!client.valid()) {
        return nullptr;
    }
    return std::make_unique<envelope_connection>(static_cast<std::uintptr_t>(client.fd));
}

void envelope_server::close() noexcept {
    if (listen_sock_ != ~static_cast<std::uintptr_t>(0u)) {
        pal::Socket s{static_cast<pal::RawSocket>(listen_sock_)};
        pal::socket_close(s);
        listen_sock_ = ~static_cast<std::uintptr_t>(0u);
    }
}

// ── stream_send_scheduler Implementation ────────────────────────────────────

bool stream_send_scheduler::enqueue_raw(const stream_identity& stream, std::vector<std::uint8_t> frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& q = stream_queues_[stream];
    if (q.size() >= max_queued_per_stream_) {
        return false; // Per-stream send queue backpressure
    }
    if (q.empty()) {
        active_order_.push_back(stream);
    }
    q.push_back(std::move(frame));
    return true;
}

bool stream_send_scheduler::enqueue_event(const event_envelope& evt) {
    std::vector<std::uint8_t> buf;
    if (!encode_event(evt, buf)) {
        return false;
    }
    return enqueue_raw(evt.stream, std::move(buf));
}

bool stream_send_scheduler::enqueue_request(const request_envelope& req) {
    std::vector<std::uint8_t> buf;
    if (!encode_request(req, buf)) {
        return false;
    }
    return enqueue_raw(req.stream, std::move(buf));
}

bool stream_send_scheduler::enqueue_control(const control_envelope& ctrl) {
    std::vector<std::uint8_t> buf;
    if (!encode_control(ctrl, buf)) {
        return false;
    }
    return enqueue_raw(ctrl.stream, std::move(buf));
}

bool stream_send_scheduler::pull_next_scheduled(stream_identity& out_stream, std::vector<std::uint8_t>& out_frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_order_.empty()) {
        return false;
    }

    if (rr_cursor_ >= active_order_.size()) {
        rr_cursor_ = 0;
    }

    std::size_t attempts = 0;
    while (attempts < active_order_.size()) {
        const auto& stream = active_order_[rr_cursor_];
        auto it = stream_queues_.find(stream);
        if (it != stream_queues_.end() && !it->second.empty()) {
            out_stream = stream;
            out_frame = std::move(it->second.front());
            it->second.pop_front();

            if (it->second.empty()) {
                stream_queues_.erase(it);
                active_order_.erase(active_order_.begin() + rr_cursor_);
                if (rr_cursor_ >= active_order_.size()) {
                    rr_cursor_ = 0;
                }
            } else {
                rr_cursor_ = (rr_cursor_ + 1) % active_order_.size();
            }
            return true;
        } else {
            // Clean empty entry
            if (it != stream_queues_.end()) {
                stream_queues_.erase(it);
            }
            active_order_.erase(active_order_.begin() + rr_cursor_);
            if (active_order_.empty()) {
                rr_cursor_ = 0;
                return false;
            }
            if (rr_cursor_ >= active_order_.size()) {
                rr_cursor_ = 0;
            }
        }
        attempts++;
    }

    return false;
}

std::size_t stream_send_scheduler::flush_scheduled(envelope_connection& conn) {
    std::size_t flushed = 0;
    stream_identity stream{};
    std::vector<std::uint8_t> frame;
    std::lock_guard<std::mutex> lock(conn.send_mutex_);
    while (pull_next_scheduled(stream, frame)) {
        if (!conn.send_bytes_locked(frame.data(), frame.size())) {
            break;
        }
        flushed++;
    }
    return flushed;
}

void stream_send_scheduler::drop_stream(const stream_identity& stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    stream_queues_.erase(stream);
    for (auto it = active_order_.begin(); it != active_order_.end();) {
        if (*it == stream) {
            it = active_order_.erase(it);
        } else {
            ++it;
        }
    }
    if (rr_cursor_ >= active_order_.size()) {
        rr_cursor_ = 0;
    }
}

std::size_t stream_send_scheduler::get_stream_queued_count(const stream_identity& stream) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stream_queues_.find(stream);
    if (it == stream_queues_.end()) {
        return 0;
    }
    return it->second.size();
}

std::size_t stream_send_scheduler::get_total_queued_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t total = 0;
    for (const auto& pair : stream_queues_) {
        total += pair.second.size();
    }
    return total;
}

} // namespace linep::v0_2
