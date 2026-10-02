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
#include "linep/v0_2/vision.hpp"

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

    // 1b. Request with Generation Options
    request_envelope req_opts{};
    req_opts.stream.request_id = 5001;
    req_opts.stream.execution_id = 6001;
    req_opts.stream.output_id = 0;
    req_opts.profile = runtime_profile::chat;
    req_opts.model_id = "meta-llama/Llama-3.1-8B-Instruct";
    req_opts.payload = R"({"prompt":"Explain quantum computing"})";
    req_opts.max_tokens = 1024;
    req_opts.temperature = 0.7f;
    req_opts.stream_requested = true;
    req_opts.has_options = true;
    req_opts.options.top_p = 0.95f;
    req_opts.options.top_k = 50;
    req_opts.options.repeat_penalty = 1.15f;
    req_opts.options.repeat_last_n = 128;
    req_opts.options.seed = 42ULL;
    req_opts.options.presence_penalty = 0.1f;
    req_opts.options.frequency_penalty = 0.2f;
    req_opts.options.stop_sequences = {"<|eot_id|>", "USER:"};
    req_opts.options.extra_options = {{"min_p", "0.05"}, {"mirostat", "2"}};

    std::vector<std::uint8_t> req_opts_buf;
    LINEP_TEST_CHECK(encode_request(req_opts, req_opts_buf));
    LINEP_TEST_CHECK(write_file((temp_dir / "request_chat_with_options_cpp.bin").string(), req_opts_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "request_chat_with_options_cpp.bin").string(), read_buf));
    request_envelope decoded_req_opts{};
    LINEP_TEST_CHECK(decode_request(read_buf.data(), read_buf.size(), decoded_req_opts));
    LINEP_TEST_CHECK(decoded_req_opts.has_options);
    LINEP_TEST_CHECK(decoded_req_opts.options.top_p == 0.95f);
    LINEP_TEST_CHECK(decoded_req_opts.options.seed == 42ULL);
    LINEP_TEST_CHECK(decoded_req_opts.options.stop_sequences.size() == 2);
    LINEP_TEST_CHECK(decoded_req_opts.options.extra_options.size() == 2);
    LINEP_TEST_CHECK(decoded_req_opts.options.extra_options[0].first == "min_p");
    LINEP_TEST_CHECK(decoded_req_opts.options.extra_options[1].first == "mirostat");

    // 1c. Event Vision Detect Result (Issue #32)
    event_envelope evt_vis{};
    evt_vis.stream.request_id = 7001;
    evt_vis.stream.execution_id = 8001;
    evt_vis.stream.output_id = 0;
    evt_vis.event_seq = 1;
    evt_vis.event_type = runtime_event_type::vision_result;
    evt_vis.timestamp_us = 1700000000123600ULL;
    evt_vis.vision.task = vision_task::detect;
    evt_vis.vision.model_id = "yolov8n-detect";
    evt_vis.vision.model_revision = "v1.0.0";
    evt_vis.vision.detect.label_set_id = "coco80:v1";
    evt_vis.vision.detect.original_width = 1920;
    evt_vis.vision.detect.original_height = 1080;
    vision_detection d1{};
    d1.class_id = 0;
    d1.label = "person";
    d1.score = 0.92f;
    d1.box = vision_box_2d{0.1f, 0.2f, 0.5f, 0.8f};
    vision_detection d2{};
    d2.class_id = 16;
    d2.label = "dog";
    d2.score = 0.85f;
    d2.box = vision_box_2d{0.6f, 0.3f, 0.85f, 0.75f};
    evt_vis.vision.detect.detections = {d1, d2};

    std::vector<std::uint8_t> vis_buf;
    LINEP_TEST_CHECK(encode_event(evt_vis, vis_buf));
    LINEP_TEST_CHECK(write_file((temp_dir / "event_vision_detect_cpp.bin").string(), vis_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "event_vision_detect_cpp.bin").string(), read_buf));
    event_envelope decoded_vis{};
    LINEP_TEST_CHECK(decode_event(read_buf.data(), read_buf.size(), decoded_vis));
    LINEP_TEST_CHECK(decoded_vis.event_type == runtime_event_type::vision_result);
    LINEP_TEST_CHECK(decoded_vis.vision.task == vision_task::detect);
    LINEP_TEST_CHECK(decoded_vis.vision.model_id == "yolov8n-detect");
    LINEP_TEST_CHECK(decoded_vis.vision.model_revision == "v1.0.0");
    LINEP_TEST_CHECK(decoded_vis.vision.detect.label_set_id == "coco80:v1");
    LINEP_TEST_CHECK(decoded_vis.vision.detect.original_width == 1920);
    LINEP_TEST_CHECK(decoded_vis.vision.detect.original_height == 1080);
    LINEP_TEST_CHECK(decoded_vis.vision.detect.detections.size() == 2);
    LINEP_TEST_CHECK(decoded_vis.vision.detect.detections[0].class_id == 0);
    LINEP_TEST_CHECK(decoded_vis.vision.detect.detections[0].label == "person");
    LINEP_TEST_CHECK(decoded_vis.vision.detect.detections[1].class_id == 16);
    LINEP_TEST_CHECK(decoded_vis.vision.detect.detections[1].label == "dog");

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

    // 4. TCP Data Plane Session Bind Frame (Issue #15)
    session_bind_envelope bind_env{};
    bind_env.identity.node_id = 1001;
    bind_env.identity.runtime_id = 2001;
    bind_env.identity.endpoint_id = 1;
    bind_env.control_epoch = 1;
    bind_env.lease_token = 0xAABBCCDDEEFF0011ULL;

    std::vector<std::uint8_t> bind_buf;
    LINEP_TEST_CHECK(encode_session_bind(bind_env, bind_buf));
    LINEP_TEST_CHECK(bind_buf.size() == 68); // 32 byte header + 36 byte canonical payload
    LINEP_TEST_CHECK(write_file((temp_dir / "session_bind_cpp.bin").string(), bind_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "session_bind_cpp.bin").string(), read_buf));
    session_bind_envelope decoded_bind{};
    LINEP_TEST_CHECK(decode_session_bind(read_buf.data(), read_buf.size(), decoded_bind));
    LINEP_TEST_CHECK(decoded_bind.identity == bind_env.identity);
    LINEP_TEST_CHECK(decoded_bind.control_epoch == 1);
    LINEP_TEST_CHECK(decoded_bind.lease_token == 0xAABBCCDDEEFF0011ULL);

    // 5. SL1 Mutual Handshake & MAC Reference Frames
    const std::vector<std::uint8_t> sl1_primary_key(32, 0x33);
    const std::vector<std::uint8_t> sl1_rotated_key(32, 0x77);

    session_bind_envelope sl1_bind = bind_env;
    sl1_bind.sl1_requested = true;
    sl1_bind.key_id = 1;
    session_bind_envelope base_bind = sl1_bind;
    base_bind.sl1_requested = false;

    // 5a. SL1 Signed Bind (Client -> Server, auth_seq = 1)
    std::vector<std::uint8_t> sl1_bind_buf;
    LINEP_TEST_CHECK(encode_session_bind(base_bind, sl1_bind_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(sl1_bind_buf, sl1_bind, message_direction::initiator_to_responder,
                                          1, 1, sl1_primary_key.data(), sl1_primary_key.size()));
    LINEP_TEST_CHECK(sl1_bind_buf.size() == 92); // 32 header + 24 auth + 36 payload
    LINEP_TEST_CHECK(write_file((temp_dir / "session_bind_sl1_cpp.bin").string(), sl1_bind_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "session_bind_sl1_cpp.bin").string(), read_buf));
    session_bind_envelope decoded_sl1_bind{};
    LINEP_TEST_CHECK(decode_session_bind(read_buf.data(), read_buf.size(), decoded_sl1_bind));
    LINEP_TEST_CHECK(decoded_sl1_bind.sl1_requested);
    LINEP_TEST_CHECK(decoded_sl1_bind.key_id == 1);
    wire_auth_extension sl1_ext{};
    std::string err;
    LINEP_TEST_CHECK(verify_envelope_buffer(read_buf.data(), read_buf.size(), sl1_bind,
                                            message_direction::initiator_to_responder,
                                            sl1_primary_key.data(), sl1_primary_key.size(),
                                            sl1_ext, &err));
    LINEP_TEST_CHECK(sl1_ext.auth_seq == 1);

    // 5b. SL1 Signed Confirmation (Server -> Client, auth_seq = 1)
    std::vector<std::uint8_t> sl1_conf_buf;
    LINEP_TEST_CHECK(encode_session_bind(base_bind, sl1_conf_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(sl1_conf_buf, sl1_bind, message_direction::responder_to_initiator,
                                          1, 1, sl1_primary_key.data(), sl1_primary_key.size()));
    LINEP_TEST_CHECK(sl1_conf_buf.size() == 92);
    LINEP_TEST_CHECK(write_file((temp_dir / "session_bind_sl1_confirm_cpp.bin").string(), sl1_conf_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "session_bind_sl1_confirm_cpp.bin").string(), read_buf));
    LINEP_TEST_CHECK(verify_envelope_buffer(read_buf.data(), read_buf.size(), sl1_bind,
                                            message_direction::responder_to_initiator,
                                            sl1_primary_key.data(), sl1_primary_key.size(),
                                            sl1_ext, &err));
    LINEP_TEST_CHECK(sl1_ext.auth_seq == 1);

    // 5c. SL1 Signed Request (Client -> Server, auth_seq = 2, key_id = 1)
    std::vector<std::uint8_t> sl1_req_buf;
    LINEP_TEST_CHECK(encode_request(req, sl1_req_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(sl1_req_buf, sl1_bind, message_direction::initiator_to_responder,
                                          2, 1, sl1_primary_key.data(), sl1_primary_key.size()));
    LINEP_TEST_CHECK(write_file((temp_dir / "request_chat_sl1_cpp.bin").string(), sl1_req_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "request_chat_sl1_cpp.bin").string(), read_buf));
    request_envelope decoded_sl1_req{};
    LINEP_TEST_CHECK(decode_request(read_buf.data(), read_buf.size(), decoded_sl1_req));
    LINEP_TEST_CHECK(verify_envelope_buffer(read_buf.data(), read_buf.size(), sl1_bind,
                                            message_direction::initiator_to_responder,
                                            sl1_primary_key.data(), sl1_primary_key.size(),
                                            sl1_ext, &err));
    LINEP_TEST_CHECK(sl1_ext.auth_seq == 2);
    LINEP_TEST_CHECK(sl1_ext.key_id == 1);

    // 5d. SL1 Signed Request with Rotated Key (Client -> Server, auth_seq = 3, key_id = 2)
    std::vector<std::uint8_t> sl1_rot_buf;
    LINEP_TEST_CHECK(encode_request(req, sl1_rot_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(sl1_rot_buf, sl1_bind, message_direction::initiator_to_responder,
                                          3, 2, sl1_rotated_key.data(), sl1_rotated_key.size()));
    LINEP_TEST_CHECK(write_file((temp_dir / "request_chat_sl1_rotated_key_cpp.bin").string(), sl1_rot_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "request_chat_sl1_rotated_key_cpp.bin").string(), read_buf));
    LINEP_TEST_CHECK(verify_envelope_buffer(read_buf.data(), read_buf.size(), sl1_bind,
                                            message_direction::initiator_to_responder,
                                            sl1_rotated_key.data(), sl1_rotated_key.size(),
                                            sl1_ext, &err));
    LINEP_TEST_CHECK(sl1_ext.auth_seq == 3);
    LINEP_TEST_CHECK(sl1_ext.key_id == 2);

    // 5e. SL1 Signed Content Delta (Server -> Client, auth_seq = 2, key_id = 1)
    event_envelope evt_delta{};
    evt_delta.stream.request_id = 1001;
    evt_delta.stream.execution_id = 2001;
    evt_delta.stream.output_id = 1;
    evt_delta.event_seq = 42;
    evt_delta.event_type = runtime_event_type::content_delta;
    evt_delta.payload = "Neural";
    evt_delta.timestamp_us = 1700000000123456ULL;

    std::vector<std::uint8_t> sl1_delta_buf;
    LINEP_TEST_CHECK(encode_event(evt_delta, sl1_delta_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(sl1_delta_buf, sl1_bind, message_direction::responder_to_initiator,
                                          2, 1, sl1_primary_key.data(), sl1_primary_key.size()));
    LINEP_TEST_CHECK(write_file((temp_dir / "event_delta_sl1_cpp.bin").string(), sl1_delta_buf));

    LINEP_TEST_CHECK(read_file((temp_dir / "event_delta_sl1_cpp.bin").string(), read_buf));
    event_envelope decoded_sl1_delta{};
    LINEP_TEST_CHECK(decode_event(read_buf.data(), read_buf.size(), decoded_sl1_delta));
    LINEP_TEST_CHECK(verify_envelope_buffer(read_buf.data(), read_buf.size(), sl1_bind,
                                            message_direction::responder_to_initiator,
                                            sl1_primary_key.data(), sl1_primary_key.size(),
                                            sl1_ext, &err));
    LINEP_TEST_CHECK(sl1_ext.auth_seq == 2);
    LINEP_TEST_CHECK(sl1_ext.key_id == 1);

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
