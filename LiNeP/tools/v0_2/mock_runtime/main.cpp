#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/lease.hpp"

using namespace linep::v0_2;

static std::atomic<bool> g_shutdown{false};

static void signal_handler(int) {
    g_shutdown = true;
}

static bool parse_hex_key(const std::string& hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = hex_val(high);
        int l = hex_val(low);
        if (h < 0 || l < 0) return false;
        out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return true;
}

static void print_usage(const char* prog) {
    std::cout << "LiNeP V0.2 Deterministic Mock Runtime Server\n"
              << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --port <port>                 TCP listen port (default: 11435, 0 for ephemeral)\n"
              << "  --udp-port <port>             UDP control plane (lease issuer) port (default: 0 = disabled)\n"
              << "  --require-lease               Reject REQUESTs without a current SESSION_BIND (needs --udp-port)\n"
              << "  --require-sl1                 Require SL1 authenticated session binding on all trunks\n"
              << "  --sl1-key <hex>               Hex-encoded SL1 shared secret key (>= 32 bytes / 64 hex digits)\n"
              << "  --sl1-key-id <id>             SL1 key ID (default: 1)\n"
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
        } else if (arg == "--require-lease") {
            cfg.require_lease = true;
        } else if (arg == "--require-sl1") {
            cfg.require_sl1 = true;
        } else if (arg == "--sl1-key" && i + 1 < argc) {
            std::string hex = argv[++i];
            if (!parse_hex_key(hex, cfg.sl1_key) || cfg.sl1_key.size() < 32) {
                std::cerr << "Error: --sl1-key must be a valid hex string of at least 32 bytes (64 hex characters)\n";
                return 1;
            }
        } else if (arg == "--sl1-key-id" && i + 1 < argc) {
            cfg.sl1_key_id = static_cast<std::uint16_t>(std::stoul(argv[++i]));
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

    if (cfg.require_sl1 && cfg.sl1_key.empty()) {
        std::cerr << "Error: --require-sl1 requires --sl1-key <hex> (at least 32 bytes)\n";
        return 1;
    }
    if (!cfg.sl1_key.empty() && cfg.sl1_key_id == 0) {
        cfg.sl1_key_id = 1;
    }

    if (cfg.require_lease && udp_port == 0) {
        std::cerr << "--require-lease needs --udp-port: clients obtain leases on the UDP control plane\n";
        return 1;
    }

    // UDP control plane first: its router validates every SESSION_BIND on the trunk
    lease_issuer issuer;
    if (udp_port > 0 && !issuer.start(udp_port)) {
        std::cerr << "Failed to bind UDP control plane on port " << udp_port << "\n";
        return 1;
    }

    mock_runtime_server server(cfg);
    if (issuer.is_running()) {
        server.set_control_plane_router(&issuer.router());
    }
    if (!server.start(tcp_port)) {
        std::cerr << "Failed to start mock runtime TCP server on port " << tcp_port << "\n";
        return 1;
    }

    std::uint16_t bound_tcp = server.get_bound_port();
    std::cout << "[LiNeP Mock Runtime] TCP Data Plane listening on 0.0.0.0:" << bound_tcp << "\n";
    std::cout << "  Model: " << cfg.model_id << " | Tokens: " << cfg.default_tokens << " | Delay: " << cfg.delay_per_event_ms << "ms\n";
    if (cfg.require_sl1) {
        std::cout << "  SL1 Authentication: REQUIRED (key_id=" << cfg.sl1_key_id << ", " << cfg.sl1_key.size() << " bytes)\n";
    } else if (!cfg.sl1_key.empty()) {
        std::cout << "  SL1 Authentication: OPTIONAL (key_id=" << cfg.sl1_key_id << ", " << cfg.sl1_key.size() << " bytes)\n";
    }
    if (issuer.is_running()) {
        std::cout << "[LiNeP Mock Runtime] UDP Control Plane (lease issuer) listening on 0.0.0.0:" << issuer.get_bound_port() << "\n";
        std::cout << "  SESSION_BIND: " << (cfg.require_lease ? "required before REQUEST" : "optional (binds are validated)") << "\n";
    }

    std::cout << "[LiNeP Mock Runtime] Ready. Press Ctrl+C to terminate.\n";

    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n[LiNeP Mock Runtime] Shutting down...\n";
    server.stop();
    issuer.stop();
    std::cout << "[LiNeP Mock Runtime] Stopped.\n";
    return 0;
}
