#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/conformance.hpp"

using namespace linep::v0_2;

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

namespace fs = std::filesystem;

static bool write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    return ofs.good();
}

static bool read_file(const std::string& path, std::vector<std::uint8_t>& out_data) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) return false;
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    out_data.resize(size);
    ifs.read(reinterpret_cast<char*>(out_data.data()), size);
    return ifs.good();
}

// ── Test 1: Golden Frames Generation & Verification ──────────────────────────
void test_golden_frames_roundtrip() {
    std::cout << "[Golden Test 1] Testing Canonical Golden Frames Generation & Decode..." << std::endl;

    fs::path temp_dir = fs::temp_directory_path() / "linep_v02_golden_test";
    fs::create_directories(temp_dir);

    // 1. Request
    request_envelope req{};
    req.stream.request_id = 1001;
    req.stream.execution_id = 2001;
    req.stream.output_id = 0;
    req.profile = runtime_profile::chat;
    req.model_id = "meta-llama/Llama-3.1-8B-Instruct";
    req.payload = R"({"messages":[{"role":"user","content":"Hello LiNeP V0.2 from C++!"}]})";
    req.max_tokens = 512;
    req.temperature = 0.8f;
    req.stream_requested = true;

    std::vector<std::uint8_t> req_buf;
    LINEP_TEST_CHECK(encode_request(req, req_buf));
    LINEP_TEST_CHECK(write_file((temp_dir / "request_chat_cpp.bin").string(), req_buf));

    std::vector<std::uint8_t> read_buf;
    LINEP_TEST_CHECK(read_file((temp_dir / "request_chat_cpp.bin").string(), read_buf));
    request_envelope decoded_req{};
    LINEP_TEST_CHECK(decode_request(read_buf.data(), read_buf.size(), decoded_req));
    LINEP_TEST_CHECK(decoded_req.stream == req.stream);
    LINEP_TEST_CHECK(decoded_req.model_id == req.model_id);
    LINEP_TEST_CHECK(decoded_req.max_tokens == 512);

    // 2. UDP Control Datagram (Hello)
    udp_control_datagram udp_hello{};
    udp_hello.magic = LINEP_V02_UDP_MAGIC;
    udp_hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    udp_hello.node_id = 1001;
    udp_hello.runtime_id = 2001;
    udp_hello.endpoint_id = 1;
    udp_hello.control_seq = 1;
    udp_hello.control_epoch = 1;
    udp_hello.availability = static_cast<std::uint8_t>(node_availability::available);
    udp_hello.health = static_cast<std::uint8_t>(node_health::healthy);
    udp_hello.tcp_port = 11435;
    udp_hello.set_trunk_ready(true);

    std::vector<std::uint8_t> udp_hello_buf;
    encode_control_datagram(udp_hello, udp_hello_buf);
    LINEP_TEST_CHECK(udp_hello_buf.size() == 80);
    LINEP_TEST_CHECK(write_file((temp_dir / "udp_hello_cpp.bin").string(), udp_hello_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "udp_hello_cpp.bin").string(), read_buf));
    udp_control_datagram decoded_hello{};
    LINEP_TEST_CHECK(decode_control_datagram(read_buf.data(), read_buf.size(), decoded_hello));
    LINEP_TEST_CHECK(decoded_hello.node_id == 1001);
    LINEP_TEST_CHECK(decoded_hello.tcp_port == 11435);
    LINEP_TEST_CHECK(decoded_hello.is_trunk_ready());

    // 3. UDP Control Datagram (Lease Ack with Token)
    udp_control_datagram udp_ack{};
    udp_ack.magic = LINEP_V02_UDP_MAGIC;
    udp_ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    udp_ack.node_id = 1001;
    udp_ack.runtime_id = 2001;
    udp_ack.endpoint_id = 1;
    udp_ack.control_seq = 3;
    udp_ack.control_epoch = 1;
    udp_ack.availability = static_cast<std::uint8_t>(node_availability::available);
    udp_ack.health = static_cast<std::uint8_t>(node_health::healthy);
    udp_ack.tcp_port = 11435;
    udp_ack.set_trunk_ready(true);
    udp_ack.lease_token = 0xAABBCCDDEEFF0011ULL;

    std::vector<std::uint8_t> udp_ack_buf;
    encode_control_datagram(udp_ack, udp_ack_buf);
    LINEP_TEST_CHECK(udp_ack_buf.size() == 80);
    LINEP_TEST_CHECK(write_file((temp_dir / "udp_lease_ack_cpp.bin").string(), udp_ack_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "udp_lease_ack_cpp.bin").string(), read_buf));
    udp_control_datagram decoded_ack{};
    LINEP_TEST_CHECK(decode_control_datagram(read_buf.data(), read_buf.size(), decoded_ack));
    LINEP_TEST_CHECK(decoded_ack.lease_token == 0xAABBCCDDEEFF0011ULL);

    fs::remove_all(temp_dir);
    std::cout << "  -> Golden Frames Generation & Verification PASSED" << std::endl;
}

// ── Test 2: Conformance Runner against Dynamic Mock Runtime ──────────────────
void test_conformance_runner_execution() {
    std::cout << "[Golden Test 2] Testing Conformance Runner against Mock Runtime..." << std::endl;

    mock_runtime_config cfg{};
    cfg.model_id = "linep-conformance-model-v02";
    mock_runtime_server server(cfg);
    LINEP_TEST_CHECK(server.start(0));

    std::uint16_t port = server.get_bound_port();
    LINEP_TEST_CHECK(port > 0);

    conformance_runner runner("127.0.0.1", port);
    conformance_report rep = runner.run_all();

    LINEP_TEST_CHECK(rep.total_tests == 9);
    LINEP_TEST_CHECK(rep.passed_tests == 9);
    LINEP_TEST_CHECK(rep.failed_tests == 0);
    LINEP_TEST_CHECK(rep.is_all_passed());

    // Verify all 3 profiles marked conformant
    LINEP_TEST_CHECK(rep.profiles.size() == 3);
    for (const auto& p : rep.profiles) {
        LINEP_TEST_CHECK(p.conformant);
    }

    server.stop();
    std::cout << "  -> Conformance Runner Execution PASSED (9/9 Suites, All Profiles Conformant)" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Golden Interop & Conformance Integration Suite ===" << std::endl;
    test_golden_frames_roundtrip();
    test_conformance_runner_execution();
    std::cout << "ALL GOLDEN INTEROP INTEGRATION TESTS PASSED 100%!" << std::endl;
    return 0;
}
