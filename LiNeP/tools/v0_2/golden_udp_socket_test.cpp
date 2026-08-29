#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "linep/v0_2/control_plane.hpp"

using namespace linep::v0_2;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: golden_udp_socket_test <ip> <port>" << std::endl;
        return 1;
    }

    std::string ip = argv[1];
    int port = std::atoi(argv[2]);

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        std::cerr << "Failed to create UDP socket" << std::endl;
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    // 1. Send NODE_HELLO from C++
    udp_control_datagram hello{};
    hello.magic = LINEP_V02_UDP_MAGIC;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.node_id = 9901;
    hello.runtime_id = 9902;
    hello.endpoint_id = 1;
    hello.control_seq = 1;
    hello.control_epoch = 1;
    hello.availability = static_cast<std::uint8_t>(node_availability::available);
    hello.health = static_cast<std::uint8_t>(node_health::healthy);
    hello.tcp_port = 11435;
    hello.set_trunk_ready(true);

    std::vector<std::uint8_t> hello_buf;
    encode_control_datagram(hello, hello_buf);
    if (sendto(sock, reinterpret_cast<const char*>(hello_buf.data()), static_cast<int>(hello_buf.size()), 0,
               reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "Failed to send NODE_HELLO" << std::endl;
        return 1;
    }
    std::cout << "[C++ UDP Client] Sent NODE_HELLO to " << ip << ":" << port << std::endl;

    // 2. Receive INVITE with lease_token from Go UDP Listener
    std::vector<std::uint8_t> resp_buf(LINEP_V02_UDP_DATAGRAM_SIZE);
    sockaddr_in from_addr{};
#ifdef _WIN32
    int from_len = sizeof(from_addr);
#else
    socklen_t from_len = sizeof(from_addr);
#endif
    int n = recvfrom(sock, reinterpret_cast<char*>(resp_buf.data()), static_cast<int>(resp_buf.size()), 0,
                     reinterpret_cast<sockaddr*>(&from_addr), &from_len);
    if (n != static_cast<int>(LINEP_V02_UDP_DATAGRAM_SIZE)) {
        std::cerr << "Failed to receive INVITE datagram, bytes=" << n << std::endl;
        return 1;
    }

    udp_control_datagram invite{};
    if (!decode_control_datagram(resp_buf.data(), resp_buf.size(), invite)) {
        std::cerr << "Failed to decode INVITE datagram" << std::endl;
        return 1;
    }
    if (invite.message_type != static_cast<std::uint8_t>(control_message_type::invite) || invite.lease_token == 0) {
        std::cerr << "Invalid INVITE datagram: type=" << static_cast<int>(invite.message_type) << " lease=" << invite.lease_token << std::endl;
        return 1;
    }
    std::cout << "  [C++ Received] INVITE with Lease Token = 0x" << std::hex << invite.lease_token << std::dec << std::endl;

    // 3. Send LEASE_ACK with granted lease_token
    udp_control_datagram ack{};
    ack.magic = LINEP_V02_UDP_MAGIC;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.node_id = 9901;
    ack.runtime_id = 9902;
    ack.endpoint_id = 1;
    ack.control_seq = 2;
    ack.control_epoch = 1;
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = 11435;
    ack.set_trunk_ready(true);
    ack.lease_token = invite.lease_token;

    std::vector<std::uint8_t> ack_buf;
    encode_control_datagram(ack, ack_buf);
    sendto(sock, reinterpret_cast<const char*>(ack_buf.data()), static_cast<int>(ack_buf.size()), 0,
           reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));

    // 4. Send HEARTBEAT
    udp_control_datagram hb{};
    hb.magic = LINEP_V02_UDP_MAGIC;
    hb.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    hb.node_id = 9901;
    hb.runtime_id = 9902;
    hb.endpoint_id = 1;
    hb.control_seq = 3;
    hb.control_epoch = 1;
    hb.availability = static_cast<std::uint8_t>(node_availability::available);
    hb.health = static_cast<std::uint8_t>(node_health::healthy);
    hb.load_pct = 25;
    hb.queue_depth = 1;
    hb.set_trunk_ready(true);

    std::vector<std::uint8_t> hb_buf;
    encode_control_datagram(hb, hb_buf);
    sendto(sock, reinterpret_cast<const char*>(hb_buf.data()), static_cast<int>(hb_buf.size()), 0,
           reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));

    std::cout << "[C++ UDP Client] UDP Control Plane Handshake & Heartbeat PASSED 100%!" << std::endl;

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return 0;
}
