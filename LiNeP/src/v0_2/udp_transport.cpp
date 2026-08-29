#include "linep/v0_2/udp_transport.hpp"
#include "socket.hpp"

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

udp_endpoint_channel::udp_endpoint_channel() {
    pal::net_init();
}

udp_endpoint_channel::~udp_endpoint_channel() {
    close();
}

bool udp_endpoint_channel::open_and_bind(std::uint16_t port, std::uint32_t timeout_ms) {
    close();
    pal::Socket s = pal::udp_open();
    if (!s.valid()) {
        return false;
    }
    if (!pal::udp_bind(s, port)) {
        pal::socket_close(s);
        return false;
    }
    pal::udp_set_recv_timeout(s, timeout_ms);
    sock_ = static_cast<std::uintptr_t>(s.fd);

    sockaddr_in sin{};
#ifdef _WIN32
    int sin_len = sizeof(sin);
    if (::getsockname(static_cast<SOCKET>(s.fd), reinterpret_cast<sockaddr*>(&sin), &sin_len) == 0) {
        bound_port_ = ntohs(sin.sin_port);
    } else {
        bound_port_ = port;
    }
#else
    socklen_t sin_len = sizeof(sin);
    if (::getsockname(s.fd, reinterpret_cast<sockaddr*>(&sin), &sin_len) == 0) {
        bound_port_ = ntohs(sin.sin_port);
    } else {
        bound_port_ = port;
    }
#endif

    return true;
}

bool udp_endpoint_channel::send_datagram(const char* host, std::uint16_t port, const udp_control_datagram& dgram) {
    if (!is_open() || !host || port == 0) {
        return false;
    }
    std::vector<std::uint8_t> buf;
    encode_control_datagram(dgram, buf);

    std::lock_guard<std::mutex> lock(send_mutex_);
    pal::Socket s{static_cast<pal::RawSocket>(sock_)};
    int sent = pal::udp_sendto(s, host, port, buf.data(), static_cast<int>(buf.size()));
    return sent == static_cast<int>(buf.size());
}

bool udp_endpoint_channel::recv_datagram(udp_control_datagram& out_dgram, std::string* out_src_ip, std::uint16_t* out_src_port) {
    if (!is_open()) {
        return false;
    }
    std::uint8_t buf[LINEP_V02_UDP_DATAGRAM_SIZE * 2];
    char ip_buf[64] = {0};
    std::uint16_t src_port = 0;

    pal::Socket s{static_cast<pal::RawSocket>(sock_)};
    int recvd = pal::udp_recvfrom(s, buf, sizeof(buf), ip_buf, sizeof(ip_buf), &src_port);
    if (recvd < static_cast<int>(LINEP_V02_UDP_DATAGRAM_SIZE)) {
        return false;
    }

    if (out_src_ip) {
        *out_src_ip = ip_buf;
    }
    if (out_src_port) {
        *out_src_port = src_port;
    }

    return decode_control_datagram(buf, static_cast<std::size_t>(recvd), out_dgram);
}

void udp_endpoint_channel::close() noexcept {
    if (sock_ != ~static_cast<std::uintptr_t>(0u)) {
        pal::Socket s{static_cast<pal::RawSocket>(sock_)};
        pal::socket_close(s);
        sock_ = ~static_cast<std::uintptr_t>(0u);
        bound_port_ = 0;
    }
}

bool udp_endpoint_channel::is_open() const noexcept {
    return sock_ != ~static_cast<std::uintptr_t>(0u);
}

} // namespace linep::v0_2
