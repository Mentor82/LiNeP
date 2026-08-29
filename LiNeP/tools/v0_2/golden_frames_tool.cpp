#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/embedding.hpp"
#include "linep/v0_2/lifecycle.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/control_plane.hpp"

using namespace linep::v0_2;

static bool write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open for writing: " << path << std::endl;
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    return ofs.good();
}

static bool read_file(const std::string& path, std::vector<std::uint8_t>& out_data) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        std::cerr << "Failed to open for reading: " << path << std::endl;
        return false;
    }
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    out_data.resize(size);
    ifs.read(reinterpret_cast<char*>(out_data.data()), size);
    return ifs.good();
}

int do_generate(const std::string& dir) {
    std::cout << "[C++ Golden Tool] Generating C++ Reference Frames to " << dir << std::endl;

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
    if (!encode_request(req, req_buf) || !write_file(dir + "/request_chat_cpp.bin", req_buf)) {
        return 1;
    }

    // 2. Event Content Delta
    event_envelope evt_delta{};
    evt_delta.stream.request_id = 1001;
    evt_delta.stream.execution_id = 2001;
    evt_delta.stream.output_id = 1;
    evt_delta.event_seq = 42;
    evt_delta.event_type = runtime_event_type::content_delta;
    evt_delta.payload = "Neural";
    evt_delta.timestamp_us = 1700000000123456ULL;

    std::vector<std::uint8_t> delta_buf;
    if (!encode_event(evt_delta, delta_buf) || !write_file(dir + "/event_content_delta_cpp.bin", delta_buf)) {
        return 1;
    }

    // 3. Event Reasoning Delta
    event_envelope evt_reason{};
    evt_reason.stream.request_id = 1001;
    evt_reason.stream.execution_id = 2001;
    evt_reason.stream.output_id = 1;
    evt_reason.event_seq = 43;
    evt_reason.event_type = runtime_event_type::reasoning_delta;
    evt_reason.payload = "Analyzing user intent deeply...";
    evt_reason.timestamp_us = 1700000000123460ULL;

    std::vector<std::uint8_t> reason_buf;
    if (!encode_event(evt_reason, reason_buf) || !write_file(dir + "/event_reasoning_delta_cpp.bin", reason_buf)) {
        return 1;
    }

    // 4. Event Embedding Result
    event_envelope evt_embed{};
    evt_embed.stream.request_id = 3001;
    evt_embed.stream.execution_id = 4001;
    evt_embed.stream.output_id = 0;
    evt_embed.event_seq = 1;
    evt_embed.event_type = runtime_event_type::embedding_result;
    evt_embed.embedding.space.embedding_space_id = "nomic-embed-text-v1.5";
    evt_embed.embedding.space.model_id = "nomic-ai/nomic-embed-text-v1.5";
    evt_embed.embedding.space.model_revision = "v1.5";
    evt_embed.embedding.space.dimensions = 4;
    evt_embed.embedding.space.normalization = embedding_normalization::l2;
    evt_embed.embedding.space.distance_metric = embedding_distance_metric::cosine;
    evt_embed.embedding.vector = {0.1f, -0.25f, 0.77f, 0.05f};
    evt_embed.timestamp_us = 1700000000123500ULL;

    std::vector<std::uint8_t> embed_buf;
    if (!encode_event(evt_embed, embed_buf) || !write_file(dir + "/event_embedding_cpp.bin", embed_buf)) {
        return 1;
    }

    // 5. Event Completed
    event_envelope evt_comp{};
    evt_comp.stream.request_id = 1001;
    evt_comp.stream.execution_id = 2001;
    evt_comp.stream.output_id = 1;
    evt_comp.event_seq = 44;
    evt_comp.event_type = runtime_event_type::completed;
    evt_comp.outcome = terminal_outcome::completed;
    evt_comp.timestamp_us = 1700000000200000ULL;

    std::vector<std::uint8_t> comp_buf;
    if (!encode_event(evt_comp, comp_buf) || !write_file(dir + "/event_completed_cpp.bin", comp_buf)) {
        return 1;
    }

    // 6. Event Error
    event_envelope evt_err{};
    evt_err.stream.request_id = 1001;
    evt_err.stream.execution_id = 2001;
    evt_err.stream.output_id = 1;
    evt_err.event_seq = 45;
    evt_err.event_type = runtime_event_type::error;
    evt_err.outcome = terminal_outcome::failed;
    evt_err.error.category = error_category::resource_exhausted;
    evt_err.error.code = 503;
    evt_err.error.message = "CUDA out of memory";
    evt_err.error.backend_diagnostic = "vLLM KV cache full, 0 blocks free";
    evt_err.timestamp_us = 1700000000300000ULL;

    std::vector<std::uint8_t> err_buf;
    if (!encode_event(evt_err, err_buf) || !write_file(dir + "/event_error_cpp.bin", err_buf)) {
        return 1;
    }

    // 7. Control Cancel
    control_envelope ctrl_cancel{};
    ctrl_cancel.stream.request_id = 1001;
    ctrl_cancel.stream.execution_id = 2001;
    ctrl_cancel.stream.output_id = 1;
    ctrl_cancel.control_type = runtime_control_type::cancel;
    ctrl_cancel.reason = "User requested cancellation via UI";

    std::vector<std::uint8_t> cancel_buf;
    if (!encode_control(ctrl_cancel, cancel_buf) || !write_file(dir + "/control_cancel_cpp.bin", cancel_buf)) {
        return 1;
    }

    // 8. Control Window Update
    control_envelope ctrl_win{};
    ctrl_win.stream.request_id = 1001;
    ctrl_win.stream.execution_id = 2001;
    ctrl_win.stream.output_id = 1;
    ctrl_win.control_type = runtime_control_type::window_update;
    ctrl_win.ack_offset_bytes = 8192;

    std::vector<std::uint8_t> win_buf;
    if (!encode_control(ctrl_win, win_buf) || !write_file(dir + "/control_window_update_cpp.bin", win_buf)) {
        return 1;
    }

    // 9. Capabilities
    capabilities_envelope caps{};
    caps.descriptor.supported_profiles = {runtime_profile::generate, runtime_profile::chat, runtime_profile::embed};
    caps.descriptor.max_context_tokens = 8192;
    caps.descriptor.max_output_tokens = 4096;
    caps.descriptor.supports_streaming = true;
    caps.descriptor.supports_cancellation = true;
    caps.descriptor.supports_tool_calling = true;
    caps.descriptor.supports_reasoning_deltas = true;
    caps.descriptor.supported_models = {"llama3:8b", "qwen2.5:7b"};
    caps.descriptor.supported_embedding_spaces = {
        {"nomic-embed-text-v1.5", "nomic-ai/nomic-embed-text-v1.5", "v1.5", 768, embedding_normalization::l2, embedding_distance_metric::cosine}
    };

    std::vector<std::uint8_t> caps_buf;
    if (!encode_capabilities(caps, caps_buf) || !write_file(dir + "/capabilities_cpp.bin", caps_buf)) {
        return 1;
    }

    // 10. UDP Control Plane: Node Hello
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
    write_file(dir + "/udp_hello_cpp.bin", udp_hello_buf);

    // 11. UDP Control Plane: Invite
    udp_control_datagram udp_invite{};
    udp_invite.magic = LINEP_V02_UDP_MAGIC;
    udp_invite.message_type = static_cast<std::uint8_t>(control_message_type::invite);
    udp_invite.node_id = 1001;
    udp_invite.runtime_id = 2001;
    udp_invite.endpoint_id = 1;
    udp_invite.control_seq = 2;
    udp_invite.control_epoch = 1;
    udp_invite.lease_token = 0xAABBCCDDEEFF0011ULL;
    std::vector<std::uint8_t> udp_invite_buf;
    encode_control_datagram(udp_invite, udp_invite_buf);
    write_file(dir + "/udp_invite_cpp.bin", udp_invite_buf);

    // 12. UDP Control Plane: Lease Ack
    udp_control_datagram udp_lease_ack{};
    udp_lease_ack.magic = LINEP_V02_UDP_MAGIC;
    udp_lease_ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    udp_lease_ack.node_id = 1001;
    udp_lease_ack.runtime_id = 2001;
    udp_lease_ack.endpoint_id = 1;
    udp_lease_ack.control_seq = 3;
    udp_lease_ack.control_epoch = 1;
    udp_lease_ack.availability = static_cast<std::uint8_t>(node_availability::available);
    udp_lease_ack.health = static_cast<std::uint8_t>(node_health::healthy);
    udp_lease_ack.tcp_port = 11435;
    udp_lease_ack.set_trunk_ready(true);
    udp_lease_ack.lease_token = 0xAABBCCDDEEFF0011ULL;
    std::vector<std::uint8_t> udp_ack_buf;
    encode_control_datagram(udp_lease_ack, udp_ack_buf);
    write_file(dir + "/udp_lease_ack_cpp.bin", udp_ack_buf);

    // 13. UDP Control Plane: Heartbeat
    udp_control_datagram udp_hb{};
    udp_hb.magic = LINEP_V02_UDP_MAGIC;
    udp_hb.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    udp_hb.node_id = 1001;
    udp_hb.runtime_id = 2001;
    udp_hb.endpoint_id = 1;
    udp_hb.control_seq = 4;
    udp_hb.control_epoch = 1;
    udp_hb.availability = static_cast<std::uint8_t>(node_availability::available);
    udp_hb.health = static_cast<std::uint8_t>(node_health::healthy);
    udp_hb.load_pct = 45;
    udp_hb.queue_depth = 3;
    udp_hb.set_trunk_ready(true);
    std::vector<std::uint8_t> udp_hb_buf;
    encode_control_datagram(udp_hb, udp_hb_buf);
    write_file(dir + "/udp_heartbeat_cpp.bin", udp_hb_buf);

    std::cout << "[C++ Golden Tool] Successfully generated all Reference Frames." << std::endl;
    return 0;
}

int do_verify(const std::string& dir) {
    std::cout << "[C++ Golden Tool] Verifying Go-Generated Frames from " << dir << std::endl;
    std::vector<std::uint8_t> buf;

    // 1. Verify Go Request Frame
    if (!read_file(dir + "/request_chat_go.bin", buf)) return 1;
    request_envelope req{};
    if (!decode_request(buf.data(), buf.size(), req)) {
        std::cerr << "C++ FAILED to decode Go request frame!" << std::endl;
        return 1;
    }
    if (req.stream.request_id != 5001 || req.stream.execution_id != 6001 || req.stream.output_id != 0 ||
        req.profile != runtime_profile::chat || req.model_id != "llama3.1:8b" || req.max_tokens != 1024) {
        std::cerr << "C++ request validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> request_chat_go.bin: PASS" << std::endl;

    // 2. Verify Go Content Delta
    if (!read_file(dir + "/event_content_delta_go.bin", buf)) return 1;
    event_envelope evt_delta{};
    if (!decode_event(buf.data(), buf.size(), evt_delta)) {
        std::cerr << "C++ FAILED to decode Go content delta event!" << std::endl;
        return 1;
    }
    if (evt_delta.stream.request_id != 5001 || evt_delta.stream.output_id != 2 || evt_delta.event_seq != 10 ||
        evt_delta.event_type != runtime_event_type::content_delta || evt_delta.payload != "Hello from Go!") {
        std::cerr << "C++ content delta validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_content_delta_go.bin: PASS" << std::endl;

    // 3. Verify Go Reasoning Delta
    if (!read_file(dir + "/event_reasoning_delta_go.bin", buf)) return 1;
    event_envelope evt_reason{};
    if (!decode_event(buf.data(), buf.size(), evt_reason)) {
        std::cerr << "C++ FAILED to decode Go reasoning delta event!" << std::endl;
        return 1;
    }
    if (evt_reason.event_type != runtime_event_type::reasoning_delta || evt_reason.payload != "Thinking deeply in Go...") {
        std::cerr << "C++ reasoning delta validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_reasoning_delta_go.bin: PASS" << std::endl;

    // 4. Verify Go Embedding Result
    if (!read_file(dir + "/event_embedding_go.bin", buf)) return 1;
    event_envelope evt_embed{};
    if (!decode_event(buf.data(), buf.size(), evt_embed)) {
        std::cerr << "C++ FAILED to decode Go embedding event!" << std::endl;
        return 1;
    }
    if (evt_embed.embedding.space.embedding_space_id != "nomic-embed-text-v1.5" ||
        evt_embed.embedding.space.dimensions != 4 ||
        evt_embed.embedding.space.normalization != embedding_normalization::l2 ||
        evt_embed.embedding.space.distance_metric != embedding_distance_metric::cosine ||
        evt_embed.embedding.vector.size() != 4 ||
        evt_embed.embedding.vector[0] != 0.1f) {
        std::cerr << "C++ embedding validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_embedding_go.bin: PASS" << std::endl;

    // 5. Verify Go Completed
    if (!read_file(dir + "/event_completed_go.bin", buf)) return 1;
    event_envelope evt_comp{};
    if (!decode_event(buf.data(), buf.size(), evt_comp)) {
        std::cerr << "C++ FAILED to decode Go completed event!" << std::endl;
        return 1;
    }
    if (evt_comp.event_type != runtime_event_type::completed || evt_comp.outcome != terminal_outcome::completed) {
        std::cerr << "C++ completed event validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_completed_go.bin: PASS" << std::endl;

    // 6. Verify Go Error
    if (!read_file(dir + "/event_error_go.bin", buf)) return 1;
    event_envelope evt_err{};
    if (!decode_event(buf.data(), buf.size(), evt_err)) {
        std::cerr << "C++ FAILED to decode Go error event!" << std::endl;
        return 1;
    }
    if (evt_err.error.category != error_category::resource_exhausted || evt_err.error.code != 503 ||
        evt_err.error.message != "CUDA out of memory" || evt_err.error.backend_diagnostic != "vLLM KV cache full, 0 blocks free") {
        std::cerr << "C++ error validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_error_go.bin: PASS" << std::endl;

    // 7. Verify Go Cancel Control
    if (!read_file(dir + "/control_cancel_go.bin", buf)) return 1;
    control_envelope ctrl_cancel{};
    if (!decode_control(buf.data(), buf.size(), ctrl_cancel)) {
        std::cerr << "C++ FAILED to decode Go cancel control!" << std::endl;
        return 1;
    }
    if (ctrl_cancel.control_type != runtime_control_type::cancel || ctrl_cancel.reason != "User canceled via Go UI") {
        std::cerr << "C++ cancel validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> control_cancel_go.bin: PASS" << std::endl;

    // 8. Verify Go Window Update Control
    if (!read_file(dir + "/control_window_update_go.bin", buf)) return 1;
    control_envelope ctrl_win{};
    if (!decode_control(buf.data(), buf.size(), ctrl_win)) {
        std::cerr << "C++ FAILED to decode Go window update control!" << std::endl;
        return 1;
    }
    if (ctrl_win.control_type != runtime_control_type::window_update || ctrl_win.ack_offset_bytes != 16384) {
        std::cerr << "C++ window update validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> control_window_update_go.bin: PASS" << std::endl;

    // 9. Verify Go Capabilities
    if (!read_file(dir + "/capabilities_go.bin", buf)) return 1;
    capabilities_envelope caps{};
    if (!decode_capabilities(buf.data(), buf.size(), caps)) {
        std::cerr << "C++ FAILED to decode Go capabilities!" << std::endl;
        return 1;
    }
    if (caps.descriptor.max_context_tokens != 8192 || caps.descriptor.supported_models.size() != 2 ||
        caps.descriptor.supported_embedding_spaces.size() != 1 ||
        caps.descriptor.supported_embedding_spaces[0].distance_metric != embedding_distance_metric::cosine) {
        std::cerr << "C++ capabilities validation mismatch on Go frame!" << std::endl;
        return 1;
    }
    std::cout << "  -> capabilities_go.bin: PASS" << std::endl;

    // 10. Verify Go UDP Hello Datagram
    if (!read_file(dir + "/udp_hello_go.bin", buf)) return 1;
    udp_control_datagram udp_hello{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_hello)) {
        std::cerr << "C++ FAILED to decode Go UDP Hello datagram!" << std::endl;
        return 1;
    }
    if (udp_hello.message_type != static_cast<std::uint8_t>(control_message_type::node_hello) ||
        udp_hello.node_id != 8001 || udp_hello.runtime_id != 9001 || udp_hello.tcp_port != 11435) {
        std::cerr << "C++ UDP Hello validation mismatch on Go datagram!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_hello_go.bin: PASS" << std::endl;

    // 11. Verify Go UDP LeaseAck Datagram
    if (!read_file(dir + "/udp_lease_ack_go.bin", buf)) return 1;
    udp_control_datagram udp_ack{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_ack)) {
        std::cerr << "C++ FAILED to decode Go UDP LeaseAck datagram!" << std::endl;
        return 1;
    }
    if (udp_ack.message_type != static_cast<std::uint8_t>(control_message_type::lease_ack) ||
        udp_ack.lease_token != 0x9988776655443322ULL) {
        std::cerr << "C++ UDP LeaseAck validation mismatch on Go datagram!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_lease_ack_go.bin: PASS" << std::endl;

    // 12. Verify Go UDP Heartbeat Datagram
    if (!read_file(dir + "/udp_heartbeat_go.bin", buf)) return 1;
    udp_control_datagram udp_hb{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_hb)) {
        std::cerr << "C++ FAILED to decode Go UDP Heartbeat datagram!" << std::endl;
        return 1;
    }
    if (udp_hb.message_type != static_cast<std::uint8_t>(control_message_type::heartbeat) ||
        udp_hb.load_pct != 60 || udp_hb.queue_depth != 4) {
        std::cerr << "C++ UDP Heartbeat validation mismatch on Go datagram!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_heartbeat_go.bin: PASS" << std::endl;

    std::cout << "[C++ Golden Tool] ALL GO-GENERATED FRAMES (TCP & UDP) DECODED AND VERIFIED BY C++ CORE 100%!" << std::endl;
    return 0;
}

int do_verify_cpp(const std::string& dir) {
    std::cout << "[C++ Golden Tool] Verifying C++ Reference Frames from " << dir << std::endl;
    std::vector<std::uint8_t> buf;

    // 1. Request
    if (!read_file(dir + "/request_chat_cpp.bin", buf)) return 1;
    request_envelope req{};
    if (!decode_request(buf.data(), buf.size(), req) || req.stream.request_id != 1001 || req.max_tokens != 512) {
        std::cerr << "C++ verification failed on request_chat_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> request_chat_cpp.bin: PASS" << std::endl;

    // 2. Content Delta
    if (!read_file(dir + "/event_content_delta_cpp.bin", buf)) return 1;
    event_envelope evt_delta{};
    if (!decode_event(buf.data(), buf.size(), evt_delta) || evt_delta.event_seq != 42 || evt_delta.payload != "Neural") {
        std::cerr << "C++ verification failed on event_content_delta_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_content_delta_cpp.bin: PASS" << std::endl;

    // 3. Reasoning Delta
    if (!read_file(dir + "/event_reasoning_delta_cpp.bin", buf)) return 1;
    event_envelope evt_reason{};
    if (!decode_event(buf.data(), buf.size(), evt_reason) || evt_reason.event_type != runtime_event_type::reasoning_delta) {
        std::cerr << "C++ verification failed on event_reasoning_delta_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_reasoning_delta_cpp.bin: PASS" << std::endl;

    // 4. Embedding
    if (!read_file(dir + "/event_embedding_cpp.bin", buf)) return 1;
    event_envelope evt_embed{};
    if (!decode_event(buf.data(), buf.size(), evt_embed) || evt_embed.embedding.space.dimensions != 4) {
        std::cerr << "C++ verification failed on event_embedding_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_embedding_cpp.bin: PASS" << std::endl;

    // 5. Completed
    if (!read_file(dir + "/event_completed_cpp.bin", buf)) return 1;
    event_envelope evt_comp{};
    if (!decode_event(buf.data(), buf.size(), evt_comp) || evt_comp.outcome != terminal_outcome::completed) {
        std::cerr << "C++ verification failed on event_completed_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_completed_cpp.bin: PASS" << std::endl;

    // 6. Error
    if (!read_file(dir + "/event_error_cpp.bin", buf)) return 1;
    event_envelope evt_err{};
    if (!decode_event(buf.data(), buf.size(), evt_err) || evt_err.error.code != 503) {
        std::cerr << "C++ verification failed on event_error_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> event_error_cpp.bin: PASS" << std::endl;

    // 7. Control Cancel
    if (!read_file(dir + "/control_cancel_cpp.bin", buf)) return 1;
    control_envelope ctrl_cancel{};
    if (!decode_control(buf.data(), buf.size(), ctrl_cancel) || ctrl_cancel.control_type != runtime_control_type::cancel) {
        std::cerr << "C++ verification failed on control_cancel_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> control_cancel_cpp.bin: PASS" << std::endl;

    // 8. Control Window Update
    if (!read_file(dir + "/control_window_update_cpp.bin", buf)) return 1;
    control_envelope ctrl_win{};
    if (!decode_control(buf.data(), buf.size(), ctrl_win) || ctrl_win.ack_offset_bytes != 8192) {
        std::cerr << "C++ verification failed on control_window_update_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> control_window_update_cpp.bin: PASS" << std::endl;

    // 9. Capabilities
    if (!read_file(dir + "/capabilities_cpp.bin", buf)) return 1;
    capabilities_envelope caps{};
    if (!decode_capabilities(buf.data(), buf.size(), caps) || caps.descriptor.max_context_tokens != 8192) {
        std::cerr << "C++ verification failed on capabilities_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> capabilities_cpp.bin: PASS" << std::endl;

    // 10. UDP Hello
    if (!read_file(dir + "/udp_hello_cpp.bin", buf)) return 1;
    udp_control_datagram udp_hello{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_hello) || udp_hello.node_id != 1001 || udp_hello.tcp_port != 11435) {
        std::cerr << "C++ verification failed on udp_hello_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_hello_cpp.bin: PASS" << std::endl;

    // 11. UDP Invite
    if (!read_file(dir + "/udp_invite_cpp.bin", buf)) return 1;
    udp_control_datagram udp_inv{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_inv) || udp_inv.lease_token != 0xAABBCCDDEEFF0011ULL) {
        std::cerr << "C++ verification failed on udp_invite_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_invite_cpp.bin: PASS" << std::endl;

    // 12. UDP Lease Ack
    if (!read_file(dir + "/udp_lease_ack_cpp.bin", buf)) return 1;
    udp_control_datagram udp_ack{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_ack) || udp_ack.lease_token != 0xAABBCCDDEEFF0011ULL) {
        std::cerr << "C++ verification failed on udp_lease_ack_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_lease_ack_cpp.bin: PASS" << std::endl;

    // 13. UDP Heartbeat
    if (!read_file(dir + "/udp_heartbeat_cpp.bin", buf)) return 1;
    udp_control_datagram udp_hb{};
    if (!decode_control_datagram(buf.data(), buf.size(), udp_hb) || udp_hb.load_pct != 45) {
        std::cerr << "C++ verification failed on udp_heartbeat_cpp.bin!" << std::endl;
        return 1;
    }
    std::cout << "  -> udp_heartbeat_cpp.bin: PASS" << std::endl;

    std::cout << "[C++ Golden Tool] ALL 13 C++ REFERENCE FRAMES VERIFIED 100%!" << std::endl;
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: golden_frames_tool <generate|verify|verify-cpp> <directory>" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string dir = argv[2];

    if (mode == "generate") {
        return do_generate(dir);
    } else if (mode == "verify") {
        return do_verify(dir);
    } else if (mode == "verify-cpp") {
        return do_verify_cpp(dir);
    } else {
        std::cerr << "Unknown mode: " << mode << std::endl;
        return 1;
    }
}
