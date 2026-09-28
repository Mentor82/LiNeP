#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "linep/v0_2/conformance.hpp"

using namespace linep::v0_2;

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
    std::cout << "LiNeP V0.2 Conformance Test Runner\n"
              << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --endpoint <host:port>    Target LiNeP endpoint (default: 127.0.0.1:11435)\n"
              << "  --control <host:port>     UDP control plane (lease issuer) of the endpoint; every suite\n"
              << "                            binds with SESSION_BIND and 'all' adds the dual-plane suites\n"
              << "  --sl1-key <hex>           Hex-encoded SL1 shared secret key (>= 32 bytes / 64 hex digits)\n"
              << "  --sl1-key-id <id>         SL1 key ID (default: 1)\n"
              << "  --profile <name>          Profile to verify: generate, chat, embed, dual_plane, sl1, all (default: all)\n"
              << "                            dual_plane needs --control and an endpoint that requires leases\n"
              << "                            sl1 needs --sl1-key\n"
              << "  --json                    Output report in JSON format\n"
              << "  --output-report <file>    Write report to specified file path\n"
              << "  --help, -h                Show this help message\n";
}

static bool parse_endpoint(const std::string& ep, std::string& out_host, std::uint16_t& out_port) {
    auto pos = ep.find(':');
    if (pos == std::string::npos) {
        out_host = ep;
        out_port = 11435;
        return true;
    }
    out_host = ep.substr(0, pos);
    try {
        int p = std::stoi(ep.substr(pos + 1));
        if (p <= 0 || p > 65535) return false;
        out_port = static_cast<std::uint16_t>(p);
        return true;
    } catch (...) {
        return false;
    }
}

static std::string format_json_report(const conformance_report& rep) {
    std::string s;
    s += "{\n";
    s += "  \"target_endpoint\": \"" + rep.target_endpoint + "\",\n";
    s += "  \"total_tests\": " + std::to_string(rep.total_tests) + ",\n";
    s += "  \"passed_tests\": " + std::to_string(rep.passed_tests) + ",\n";
    s += "  \"failed_tests\": " + std::to_string(rep.failed_tests) + ",\n";
    s += "  \"all_passed\": " + std::string(rep.is_all_passed() ? "true" : "false") + ",\n";
    s += "  \"tests\": [\n";
    for (std::size_t i = 0; i < rep.results.size(); ++i) {
        const auto& r = rep.results[i];
        s += "    {\n";
        s += "      \"name\": \"" + r.test_name + "\",\n";
        s += "      \"passed\": " + std::string(r.passed ? "true" : "false") + ",\n";
        s += "      \"duration_ms\": " + std::to_string(r.duration_ms) + ",\n";
        s += "      \"details\": \"" + r.details + "\"\n";
        s += "    }" + std::string(i + 1 < rep.results.size() ? "," : "") + "\n";
    }
    s += "  ],\n";
    s += "  \"profiles\": [\n";
    for (std::size_t i = 0; i < rep.profiles.size(); ++i) {
        const auto& p = rep.profiles[i];
        s += "    {\n";
        s += "      \"profile_name\": \"" + p.profile_name + "\",\n";
        s += "      \"conformant\": " + std::string(p.conformant ? "true" : "false") + "\n";
        s += "    }" + std::string(i + 1 < rep.profiles.size() ? "," : "") + "\n";
    }
    s += "  ]\n";
    s += "}\n";
    return s;
}

static std::string format_text_report(const conformance_report& rep) {
    std::string s;
    s += "============================================================\n";
    s += "LiNeP V0.2 Conformance Test Report\n";
    s += "Target Endpoint: " + rep.target_endpoint + "\n";
    s += "============================================================\n\n";

    s += "SUITE RESULTS:\n";
    for (const auto& r : rep.results) {
        s += "[" + std::string(r.passed ? "PASS" : "FAIL") + "] " + r.test_name;
        if (r.test_name.size() < 30) {
            s += std::string(30 - r.test_name.size(), ' ');
        }
        s += " (" + std::to_string(r.duration_ms) + " ms) -> " + r.details + "\n";
    }

    s += "\n------------------------------------------------------------\n";
    s += "PROFILE CONFORMANCE SUMMARY:\n";
    s += "------------------------------------------------------------\n";
    for (const auto& p : rep.profiles) {
        s += p.profile_name;
        if (p.profile_name.size() < 24) {
            s += std::string(24 - p.profile_name.size(), ' ');
        }
        s += " ...... " + std::string(p.conformant ? "CONFORMANT" : "NON-CONFORMANT") + "\n";
    }
    s += "------------------------------------------------------------\n";
    s += "Total: " + std::to_string(rep.total_tests) + " | Passed: " +
         std::to_string(rep.passed_tests) + " | Failed: " + std::to_string(rep.failed_tests) + "\n";
    return s;
}

int main(int argc, char* argv[]) {
    std::string endpoint = "127.0.0.1:11435";
    std::string profile_str = "all";
    bool json_output = false;
    std::string report_file;
    std::string control;
    std::vector<std::uint8_t> sl1_key;
    std::uint16_t sl1_key_id = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--endpoint" && i + 1 < argc) {
            endpoint = argv[++i];
        } else if (arg == "--control" && i + 1 < argc) {
            control = argv[++i];
        } else if (arg == "--sl1-key" && i + 1 < argc) {
            std::string hex = argv[++i];
            if (!parse_hex_key(hex, sl1_key) || sl1_key.size() < 32) {
                std::cerr << "Error: --sl1-key must be a valid hex string of at least 32 bytes (64 hex characters)\n";
                return 1;
            }
        } else if (arg == "--sl1-key-id" && i + 1 < argc) {
            sl1_key_id = static_cast<std::uint16_t>(std::stoul(argv[++i]));
        } else if (arg == "--profile" && i + 1 < argc) {
            profile_str = argv[++i];
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg == "--output-report" && i + 1 < argc) {
            report_file = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::string host;
    std::uint16_t port = 11435;
    if (!parse_endpoint(endpoint, host, port)) {
        std::cerr << "Invalid endpoint format: " << endpoint << " (expected host:port)\n";
        return 1;
    }

    conformance_runner runner(host, port);
    if (!control.empty()) {
        std::string control_host;
        std::uint16_t control_port = 0;
        if (!parse_endpoint(control, control_host, control_port) || control.find(':') == std::string::npos) {
            std::cerr << "Invalid control endpoint format: " << control << " (expected host:port)\n";
            return 1;
        }
        runner.set_control_endpoint(control_host, control_port);
    }
    if (!sl1_key.empty()) {
        runner.set_sl1_credentials(sl1_key_id, sl1_key);
    }
    conformance_report rep{};

    if (profile_str == "all") {
        rep = runner.run_all();
    } else if (profile_str == "generate") {
        rep = runner.run_profile(runtime_profile::generate);
    } else if (profile_str == "chat") {
        rep = runner.run_profile(runtime_profile::chat);
    } else if (profile_str == "embed") {
        rep = runner.run_profile(runtime_profile::embed);
    } else if (profile_str == "dual_plane") {
        if (!runner.has_control_endpoint()) {
            std::cerr << "--profile dual_plane needs --control <host:port>\n";
            return 1;
        }
        rep = runner.run_dual_plane();
    } else if (profile_str == "sl1") {
        if (!runner.has_sl1()) {
            std::cerr << "--profile sl1 needs --sl1-key <hex>\n";
            return 1;
        }
        rep = runner.run_sl1();
    } else {
        std::cerr << "Unknown profile: " << profile_str << " (expected: generate, chat, embed, dual_plane, sl1, all)\n";
        return 1;
    }

    std::string formatted = json_output ? format_json_report(rep) : format_text_report(rep);
    std::cout << formatted;

    if (!report_file.empty()) {
        std::ofstream ofs(report_file);
        if (ofs.is_open()) {
            ofs << formatted;
        } else {
            std::cerr << "Warning: Failed to write report to " << report_file << "\n";
        }
    }

    bool success = rep.is_all_passed();
    for (const auto& p : rep.profiles) {
        if (!p.conformant) {
            success = false;
            break;
        }
    }

    return success ? 0 : 1;
}
