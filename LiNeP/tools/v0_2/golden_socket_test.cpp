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

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"

using namespace linep::v0_2;

static bool send_all(int sock, const std::vector<std::uint8_t>& buf) {
    std::size_t total = 0;
    while (total < buf.size()) {
        int n = send(sock, reinterpret_cast<const char*>(buf.data() + total), static_cast<int>(buf.size() - total), 0);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

static bool recv_envelope(int sock, std::vector<std::uint8_t>& out_buf) {
    out_buf.resize(LINEP_V02_HEADER_SIZE);
    std::size_t read_bytes = 0;
    while (read_bytes < LINEP_V02_HEADER_SIZE) {
        int n = recv(sock, reinterpret_cast<char*>(out_buf.data() + read_bytes), static_cast<int>(LINEP_V02_HEADER_SIZE - read_bytes), 0);
        if (n <= 0) return false;
        read_bytes += n;
    }

    wire_envelope_header hdr{};
    if (!decode_header(out_buf.data(), out_buf.size(), hdr)) return false;

    if (hdr.payload_len > 0) {
        std::size_t offset = out_buf.size();
        out_buf.resize(LINEP_V02_HEADER_SIZE + hdr.payload_len);
        std::size_t payload_read = 0;
        while (payload_read < hdr.payload_len) {
            int n = recv(sock, reinterpret_cast<char*>(out_buf.data() + offset + payload_read), static_cast<int>(hdr.payload_len - payload_read), 0);
            if (n <= 0) return false;
            payload_read += n;
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: golden_socket_test <ip> <port>" << std::endl;
        return 1;
    }

    std::string ip = argv[1];
    int port = std::atoi(argv[2]);

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Failed to connect to " << ip << ":" << port << std::endl;
        return 1;
    }

    std::cout << "[C++ Socket Client] Connected to Go LiNeP Server at " << ip << ":" << port << std::endl;

    // 1. Send Request Envelope from C++ Core
    request_envelope req{};
    req.stream.request_id = 9901;
    req.stream.execution_id = 9902;
    req.stream.output_id = 0;
    req.profile = runtime_profile::chat;
    req.model_id = "llama3:8b";
    req.payload = "Hello from C++ Socket Client!";
    req.max_tokens = 256;
    req.temperature = 0.7f;
    req.stream_requested = true;

    std::vector<std::uint8_t> req_buf;
    if (!encode_request(req, req_buf) || !send_all(sock, req_buf)) {
        std::cerr << "Failed to send request envelope from C++" << std::endl;
        return 1;
    }

    // 2. Read streamed events and decode with C++ Core
    bool got_accepted = false;
    bool got_started = false;
    bool got_delta = false;
    bool got_completed = false;

    while (true) {
        std::vector<std::uint8_t> frame_buf;
        if (!recv_envelope(sock, frame_buf)) {
            std::cerr << "Socket read failed or disconnected" << std::endl;
            break;
        }

        runtime_envelope_type env_type = peek_envelope_type(frame_buf.data(), frame_buf.size());
        if (env_type != runtime_envelope_type::event) {
            std::cerr << "Unexpected envelope type: " << static_cast<int>(env_type) << std::endl;
            return 1;
        }

        event_envelope evt{};
        if (!decode_event(frame_buf.data(), frame_buf.size(), evt)) {
            std::cerr << "C++ FAILED to decode event from Go server!" << std::endl;
            return 1;
        }

        std::cout << "  [C++ Received Event] Seq=" << evt.event_seq << " Type=" << static_cast<int>(evt.event_type) << " Payload=" << evt.payload << std::endl;

        if (evt.event_type == runtime_event_type::accepted) got_accepted = true;
        if (evt.event_type == runtime_event_type::started) got_started = true;
        if (evt.event_type == runtime_event_type::content_delta) got_delta = true;
        if (evt.event_type == runtime_event_type::completed) {
            got_completed = true;
            if (evt.outcome != terminal_outcome::completed) {
                std::cerr << "Unexpected outcome: " << static_cast<int>(evt.outcome) << std::endl;
                return 1;
            }
            break;
        }
    }

    if (!got_accepted || !got_started || !got_delta || !got_completed) {
        std::cerr << "Missing required event in stream!" << std::endl;
        return 1;
    }

    std::cout << "[C++ Socket Client] Real Socket Streaming C++ Client <-> Go Server PASSED 100%!" << std::endl;

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return 0;
}
