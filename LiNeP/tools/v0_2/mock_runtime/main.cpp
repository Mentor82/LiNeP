#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/udp_transport.hpp"

using namespace linep::v0_2;

static std::atomic<bool> g_shutdown{false};

static void signal_handler(int) {
    g_shutdown = true;
}

static void print_usage(const char* prog) {
    std::cout << "LiNeP V0.2 Deterministic Mock Runtime Server\n"
              << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --port <port>                 TCP listen port (default: 11435, 0 for ephemeral)\n"
              << "  --udp-port <port>             UDP control plane listen port (default: 0 = disabled)\n"
              << "  --model <id>                  Model ID to advertise (default: linep-mock-v02)\n"
              << "  --delay-per-event <ms>        Delay between stream events (default: 2 ms)\n"
              << "  --tokens <N>                  Default tokens to generate per stream (default: 10)\n"
              << "  --delta-mode                  Emit content deltas (default: true)\n"
              << "  --snapshot-mode               Emit cumulative content snapshots\n"
              << "  --multi-output <N>            Emit N candidate output streams concurrently\n"
              << "  --fail-after <N>              Force backend failure after N events (-1 = disabled)\n"
              << "  --duplicate-event             Inject duplicate event transmissions\n"
              << "  --disconnect-before-terminal  Abruptly drop TCP connection before terminal event\n"
              << "  --ignore-cancel               Ignore client cancellation requests\n"
              << "  --cancel-after-accept         Instantly emit cancelled event after accept\n"
              << "  --slow-reader                 Throttle socket reading speed\n"
              << "  --batch-embed <N>             Return N embedding output vectors per embed request\n"
              << "  --space-id <id>               Embedding space ID (default: nomic-embed-v1.5)\n"
              << "  --dimensions <N>              Embedding vector dimensions (default: 768)\n"
              << "  --help, -h                    Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    mock_runtime_config cfg{};
    std::uint16_t tcp_port = 11435;
    std::uint16_t udp_port = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--port" && i + 1 < argc) {
            tcp_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--udp-port" && i + 1 < argc) {
            udp_port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--model" && i + 1 < argc) {
            cfg.model_id = argv[++i];
        } else if (arg == "--delay-per-event" && i + 1 < argc) {
            cfg.delay_per_event_ms = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--tokens" && i + 1 < argc) {
            cfg.default_tokens = std::stoul(argv[++i]);
        } else if (arg == "--delta-mode") {
            cfg.delta_mode = true;
            cfg.snapshot_mode = false;
        } else if (arg == "--snapshot-mode") {
            cfg.snapshot_mode = true;
            cfg.delta_mode = false;
        } else if (arg == "--multi-output" && i + 1 < argc) {
            cfg.multi_output_count = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--fail-after" && i + 1 < argc) {
            cfg.fail_after_n = std::stoi(argv[++i]);
        } else if (arg == "--duplicate-event") {
            cfg.duplicate_event = true;
        } else if (arg == "--disconnect-before-terminal") {
            cfg.disconnect_before_terminal = true;
        } else if (arg == "--ignore-cancel") {
            cfg.ignore_cancel = true;
        } else if (arg == "--cancel-after-accept") {
            cfg.cancel_after_accept = true;
        } else if (arg == "--slow-reader") {
            cfg.slow_reader = true;
        } else if (arg == "--batch-embed" && i + 1 < argc) {
            cfg.batch_embed_count = std::stoul(argv[++i]);
        } else if (arg == "--space-id" && i + 1 < argc) {
            cfg.embedding_space_id = argv[++i];
        } else if (arg == "--dimensions" && i + 1 < argc) {
            cfg.embedding_dimensions = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    mock_runtime_server server(cfg);
    if (!server.start(tcp_port)) {
        std::cerr << "Failed to start mock runtime TCP server on port " << tcp_port << "\n";
        return 1;
    }

    std::uint16_t bound_tcp = server.get_bound_port();
    std::cout << "[LiNeP Mock Runtime] TCP Data Plane listening on 0.0.0.0:" << bound_tcp << "\n";
    std::cout << "  Model: " << cfg.model_id << " | Tokens: " << cfg.default_tokens << " | Delay: " << cfg.delay_per_event_ms << "ms\n";

    std::unique_ptr<udp_endpoint_channel> udp_channel;
    std::thread udp_thread;
    std::atomic<bool> udp_running{false};

    if (udp_port > 0) {
        udp_channel = std::make_unique<udp_endpoint_channel>();
        if (udp_channel->open_and_bind(udp_port, 200)) {
            std::uint16_t bound_udp = udp_channel->get_bound_port();
            std::cout << "[LiNeP Mock Runtime] UDP Control Plane listening on 0.0.0.0:" << bound_udp << "\n";
            udp_running = true;

            udp_thread = std::thread([&, bound_tcp]() {
                control_plane_router router;
                std::uint64_t lease_counter = 0x100020003000ULL;

                while (udp_running && !g_shutdown) {
                    udp_control_datagram dgram{};
                    std::string src_ip;
                    std::uint16_t src_port = 0;
                    if (udp_channel->recv_datagram(dgram, &src_ip, &src_port)) {
                        auto now_us = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count());

                        router.ingest_datagram(dgram, now_us);

                        if (dgram.message_type == static_cast<std::uint8_t>(control_message_type::node_hello)) {
                            // Automatically issue INVITE to the node
                            node_endpoint_identity id{dgram.node_id, dgram.runtime_id, dgram.endpoint_id};
                            udp_control_datagram inv{};
                            std::uint64_t assigned_token = ++lease_counter;
                            if (router.issue_invite(id, assigned_token, inv)) {
                                udp_channel->send_datagram(src_ip.c_str(), src_port, inv);
                            }
                        }
                    }
                }
            });
        } else {
            std::cerr << "Warning: Failed to bind UDP control plane on port " << udp_port << "\n";
        }
    }

    std::cout << "[LiNeP Mock Runtime] Ready. Press Ctrl+C to terminate.\n";

    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n[LiNeP Mock Runtime] Shutting down...\n";
    udp_running = false;
    if (udp_thread.joinable()) {
        udp_thread.join();
    }
    if (udp_channel) {
        udp_channel->close();
    }
    server.stop();
    std::cout << "[LiNeP Mock Runtime] Stopped.\n";
    return 0;
}
