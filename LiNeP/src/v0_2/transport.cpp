#include "linep/v0_2/transport.hpp"
#include "socket.hpp"
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

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
    if (sent != static_cast<int>(len)) {
        // Partial send or socket error corrupts the TCP framing!
        // Fail closed immediately to prevent writing corrupted bytes on this stream.
        close();
        return false;
    }
    return true;
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

bool envelope_connection::send_frame_raw(const std::uint8_t* data, std::size_t len) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    return send_bytes_locked(data, len);
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

    sockaddr_in sin{};
#ifdef _WIN32
    int sin_len = sizeof(sin);
    if (::getsockname(static_cast<SOCKET>(s.fd), reinterpret_cast<sockaddr*>(&sin), &sin_len) == 0) {
        port_ = ntohs(sin.sin_port);
    } else {
        port_ = port;
    }
#else
    socklen_t sin_len = sizeof(sin);
    if (::getsockname(s.fd, reinterpret_cast<sockaddr*>(&sin), &sin_len) == 0) {
        port_ = ntohs(sin.sin_port);
    } else {
        port_ = port;
    }
#endif

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
    std::size_t frame_bytes = frame.size();

    // Check dual limits: frames per stream, bytes per stream, total connection bytes
    if (q.frames.size() >= limits_.max_frames_per_stream) {
        return false;
    }
    if ((q.total_bytes + frame_bytes) > limits_.max_bytes_per_stream) {
        return false;
    }
    if ((total_connection_bytes_ + frame_bytes) > limits_.max_total_connection_bytes) {
        return false;
    }

    if (q.frames.empty()) {
        active_order_.push_back(stream);
    }
    q.total_bytes += frame_bytes;
    total_connection_bytes_ += frame_bytes;
    q.frames.push_back(std::move(frame));
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

bool stream_send_scheduler::peek_next_scheduled(stream_identity& out_stream, std::vector<std::uint8_t>& out_frame) {
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
        if (it != stream_queues_.end() && !it->second.frames.empty()) {
            out_stream = stream;
            out_frame = it->second.frames.front();
            return true;
        } else {
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

void stream_send_scheduler::commit_next_scheduled() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_order_.empty()) {
        return;
    }
    if (rr_cursor_ >= active_order_.size()) {
        rr_cursor_ = 0;
    }
    const auto& stream = active_order_[rr_cursor_];
    auto it = stream_queues_.find(stream);
    if (it != stream_queues_.end() && !it->second.frames.empty()) {
        std::size_t bytes = it->second.frames.front().size();
        it->second.frames.pop_front();
        it->second.total_bytes = (it->second.total_bytes >= bytes) ? (it->second.total_bytes - bytes) : 0;
        total_connection_bytes_ = (total_connection_bytes_ >= bytes) ? (total_connection_bytes_ - bytes) : 0;

        if (it->second.frames.empty()) {
            stream_queues_.erase(it);
            active_order_.erase(active_order_.begin() + rr_cursor_);
            if (rr_cursor_ >= active_order_.size()) {
                rr_cursor_ = 0;
            }
        } else {
            rr_cursor_ = (rr_cursor_ + 1) % active_order_.size();
        }
    }
}

bool stream_send_scheduler::pull_next_scheduled(stream_identity& out_stream, std::vector<std::uint8_t>& out_frame) {
    if (!peek_next_scheduled(out_stream, out_frame)) {
        return false;
    }
    commit_next_scheduled();
    return true;
}

std::size_t stream_send_scheduler::flush_scheduled(envelope_connection& conn) {
    // Guarantees single-writer execution across concurrent flush callers
    std::lock_guard<std::mutex> flush_lock(flush_mutex_);

    std::size_t flushed = 0;
    stream_identity stream{};
    std::vector<std::uint8_t> frame;

    // Transmit one frame at a time with per-frame lock granularity:
    // Frame is ONLY committed and removed upon verified successful transmission (zero frame loss on failure).
    while (peek_next_scheduled(stream, frame)) {
        bool ok = false;
        {
            std::lock_guard<std::mutex> lock(conn.send_mutex_);
            ok = conn.send_bytes_locked(frame.data(), frame.size());
        }
        if (!ok) {
            // Send failed: frame remains uncommitted in queue to prevent silent delta loss!
            break;
        }
        commit_next_scheduled();
        flushed++;
    }
    return flushed;
}

void stream_send_scheduler::drop_stream(const stream_identity& stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stream_queues_.find(stream);
    if (it != stream_queues_.end()) {
        total_connection_bytes_ = (total_connection_bytes_ >= it->second.total_bytes) ?
            (total_connection_bytes_ - it->second.total_bytes) : 0;
        stream_queues_.erase(it);
    }
    for (auto oit = active_order_.begin(); oit != active_order_.end();) {
        if (*oit == stream) {
            oit = active_order_.erase(oit);
        } else {
            ++oit;
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
    return it->second.frames.size();
}

std::size_t stream_send_scheduler::get_stream_queued_bytes(const stream_identity& stream) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stream_queues_.find(stream);
    if (it == stream_queues_.end()) {
        return 0;
    }
    return it->second.total_bytes;
}

std::size_t stream_send_scheduler::get_total_queued_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t total = 0;
    for (const auto& pair : stream_queues_) {
        total += pair.second.frames.size();
    }
    return total;
}

std::size_t stream_send_scheduler::get_total_queued_bytes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_connection_bytes_;
}

} // namespace linep::v0_2
