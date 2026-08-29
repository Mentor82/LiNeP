#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "linep/v0_2/control_plane.hpp"

namespace linep::v0_2 {

class udp_endpoint_channel {
public:
    udp_endpoint_channel();
    ~udp_endpoint_channel();

    udp_endpoint_channel(const udp_endpoint_channel&) = delete;
    udp_endpoint_channel& operator=(const udp_endpoint_channel&) = delete;

    // Open UDP socket and bind to local port (0 for ephemeral OS port)
    bool open_and_bind(std::uint16_t port = 0, std::uint32_t timeout_ms = 100);

    // Send a control datagram to remote host:port
    bool send_datagram(const char* host, std::uint16_t port, const udp_control_datagram& dgram);

    // Receive the next control datagram (blocking up to timeout_ms)
    bool recv_datagram(udp_control_datagram& out_dgram, std::string* out_src_ip = nullptr, std::uint16_t* out_src_port = nullptr);

    void close() noexcept;
    bool is_open() const noexcept;
    std::uint16_t get_bound_port() const noexcept { return bound_port_; }

private:
    std::uintptr_t sock_{~static_cast<std::uintptr_t>(0u)};
    std::uint16_t bound_port_{0};
    mutable std::mutex send_mutex_;
};

} // namespace linep::v0_2
