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

} // namespace linep::v0_2
