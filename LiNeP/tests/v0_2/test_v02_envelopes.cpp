#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/embedding.hpp"
#include "linep/v0_2/lifecycle.hpp"
#include "linep/v0_2/envelopes.hpp"

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST CHECK FAILED: " #cond " at " __FILE__ ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

using namespace linep::v0_2;

void test_request_envelope() {
    std::cout << "[Test 1] Request Envelope Roundtrip & Validation..." << std::endl;
    request_envelope req{};
    req.stream.request_id = 1001;
    req.stream.execution_id = 2001;
    req.stream.output_id = 0;
    req.profile = runtime_profile::chat;
    req.model_id = "meta-llama/Llama-3.1-8B-Instruct";
    req.payload = R"({"messages":[{"role":"user","content":"Hello LiNeP V0.2!"}]})";
    req.max_tokens = 512;
    req.temperature = 0.8f;
    req.stream_requested = true;

    LINEP_TEST_CHECK(req.is_valid());

    std::vector<std::uint8_t> buffer;
    bool enc_ok = encode_request(req, buffer);
    LINEP_TEST_CHECK(enc_ok);
    LINEP_TEST_CHECK(buffer.size() >= LINEP_V02_HEADER_SIZE);

    LINEP_TEST_CHECK(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::request);

    request_envelope decoded{};
    bool dec_ok = decode_request(buffer.data(), buffer.size(), decoded);
    LINEP_TEST_CHECK(dec_ok);
    LINEP_TEST_CHECK(decoded.stream.request_id == 1001);
    LINEP_TEST_CHECK(decoded.stream.execution_id == 2001);
    LINEP_TEST_CHECK(decoded.stream.output_id == 0);
    LINEP_TEST_CHECK(decoded.profile == runtime_profile::chat);
    LINEP_TEST_CHECK(decoded.model_id == "meta-llama/Llama-3.1-8B-Instruct");
    LINEP_TEST_CHECK(decoded.payload == req.payload);
    LINEP_TEST_CHECK(decoded.max_tokens == 512);
    LINEP_TEST_CHECK(decoded.stream_requested == true);

    // Test invalid request: request_id == 0 -> Invalid!
    request_envelope invalid_req = req;
    invalid_req.stream.request_id = 0;
    LINEP_TEST_CHECK(!invalid_req.is_valid());
    std::vector<std::uint8_t> bad_buf;
    LINEP_TEST_CHECK(!encode_request(invalid_req, bad_buf));

    // Test trailing garbage rejection (strict canonical framing)
    std::vector<std::uint8_t> garbage_buf = buffer;
    garbage_buf.push_back(0xFF);
    // Note: header payload_len doesn't match total or reader has remaining bytes
    wire_envelope_header hdr{};
    decode_header(garbage_buf.data(), garbage_buf.size(), hdr);
    hdr.payload_len += 1;
    garbage_buf.clear();
    encode_header(hdr, garbage_buf);
    garbage_buf.insert(garbage_buf.end(), buffer.begin() + LINEP_V02_HEADER_SIZE, buffer.end());
    garbage_buf.push_back(0xFF);
    request_envelope garbage_req{};
    LINEP_TEST_CHECK(!decode_request(garbage_buf.data(), garbage_buf.size(), garbage_req));

    std::cout << "  -> Request Envelope Tests PASSED" << std::endl;
}

void test_event_envelope() {
    std::cout << "[Test 2] Event Envelope Roundtrip & Delta/Reasoning/Terminal Invariants..." << std::endl;
    event_envelope evt{};
    evt.stream.request_id = 1001;
    evt.stream.execution_id = 2001;
    evt.stream.output_id = 1;
    evt.event_seq = 42;
    evt.event_type = runtime_event_type::content_delta;
    evt.payload = "Neural";
    evt.timestamp_us = 1700000000123456ULL;

    LINEP_TEST_CHECK(evt.is_valid());
    LINEP_TEST_CHECK(!evt.is_terminal());

    // Invariant: event_seq == 0 is INVALID!
    event_envelope zero_seq_evt = evt;
    zero_seq_evt.event_seq = 0;
    LINEP_TEST_CHECK(!zero_seq_evt.is_valid());
    std::vector<std::uint8_t> bad_seq_buf;
    LINEP_TEST_CHECK(!encode_event(zero_seq_evt, bad_seq_buf));

    std::vector<std::uint8_t> buffer;
    LINEP_TEST_CHECK(encode_event(evt, buffer));
    LINEP_TEST_CHECK(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::event);

    event_envelope dec_evt{};
    LINEP_TEST_CHECK(decode_event(buffer.data(), buffer.size(), dec_evt));
    LINEP_TEST_CHECK(dec_evt.stream.request_id == 1001);
    LINEP_TEST_CHECK(dec_evt.stream.execution_id == 2001);
    LINEP_TEST_CHECK(dec_evt.stream.output_id == 1);
    LINEP_TEST_CHECK(dec_evt.event_seq == 42);
    LINEP_TEST_CHECK(dec_evt.event_type == runtime_event_type::content_delta);
    LINEP_TEST_CHECK(dec_evt.payload == "Neural");
    LINEP_TEST_CHECK(dec_evt.timestamp_us == 1700000000123456ULL);

    // Test terminal event (completed)
    event_envelope term_evt{};
    term_evt.stream = evt.stream;
    term_evt.event_seq = 43;
    term_evt.event_type = runtime_event_type::completed;
    term_evt.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(term_evt.is_valid());
    LINEP_TEST_CHECK(term_evt.is_terminal());

    buffer.clear();
    LINEP_TEST_CHECK(encode_event(term_evt, buffer));
    event_envelope dec_term{};
    LINEP_TEST_CHECK(decode_event(buffer.data(), buffer.size(), dec_term));
    LINEP_TEST_CHECK(dec_term.is_terminal());
    LINEP_TEST_CHECK(dec_term.outcome == terminal_outcome::completed);

    // Test error event with preserved backend diagnostic
    event_envelope err_evt{};
    err_evt.stream = evt.stream;
    err_evt.event_seq = 44;
    err_evt.event_type = runtime_event_type::error;
    err_evt.outcome = terminal_outcome::failed;
    err_evt.error.category = error_category::resource_exhausted;
    err_evt.error.code = 503;
    err_evt.error.message = "CUDA out of memory";
    err_evt.error.backend_diagnostic = "vLLM KV cache full, 0 blocks free";

    buffer.clear();
    LINEP_TEST_CHECK(encode_event(err_evt, buffer));
    event_envelope dec_err{};
    LINEP_TEST_CHECK(decode_event(buffer.data(), buffer.size(), dec_err));
    LINEP_TEST_CHECK(dec_err.error.category == error_category::resource_exhausted);
    LINEP_TEST_CHECK(dec_err.error.code = 503);
    LINEP_TEST_CHECK(dec_err.error.message == "CUDA out of memory");
    LINEP_TEST_CHECK(dec_err.error.backend_diagnostic == "vLLM KV cache full, 0 blocks free");

    std::cout << "  -> Event Envelope Tests PASSED" << std::endl;
}

void test_embedding_envelope_and_vector_spaces() {
    std::cout << "[Test 3] Embedding Envelope & Vector Space Validation..." << std::endl;
    embedding_space_descriptor space_a{
        "nomic-embed-text-v1.5",
        "nomic-ai/nomic-embed-text-v1.5",
        "v1.5",
        768,
        embedding_normalization::l2,
        embedding_distance_metric::cosine
    };

    embedding_space_descriptor space_b{
        "bge-base-en-v1.5",
        "BAAI/bge-base-en-v1.5",
        "v1.5",
        768, // Same dimension, DIFFERENT embedding space!
        embedding_normalization::l2,
        embedding_distance_metric::cosine
    };

    // Equal dimension is NEVER sufficient proof of compatible space!
    LINEP_TEST_CHECK(!compatible_embedding_space(space_a, space_b));

    embedding_space_descriptor space_a_clone = space_a;
    LINEP_TEST_CHECK(compatible_embedding_space(space_a, space_a_clone));

    event_envelope embed_evt{};
    embed_evt.stream.request_id = 3001;
    embed_evt.stream.execution_id = 4001;
    embed_evt.stream.output_id = 0;
    embed_evt.event_seq = 1;
    embed_evt.event_type = runtime_event_type::embedding_result;
    embed_evt.embedding.space = space_a;
    embed_evt.embedding.vector.assign(768, 0.042f);

    LINEP_TEST_CHECK(embed_evt.is_valid());

    std::vector<std::uint8_t> buffer;
    LINEP_TEST_CHECK(encode_event(embed_evt, buffer));

    event_envelope dec_embed{};
    LINEP_TEST_CHECK(decode_event(buffer.data(), buffer.size(), dec_embed));
    LINEP_TEST_CHECK(dec_embed.event_type == runtime_event_type::embedding_result);
    LINEP_TEST_CHECK(dec_embed.embedding.space.embedding_space_id == "nomic-embed-text-v1.5");
    LINEP_TEST_CHECK(dec_embed.embedding.space.dimensions == 768);
    LINEP_TEST_CHECK(dec_embed.embedding.vector.size() == 768);
    LINEP_TEST_CHECK(dec_embed.embedding.vector[0] == 0.042f);

    // Test Embedding Decoder Allocation DoS Protection:
    // Manipulated frame claiming 0xFFFFFFFF dimensions / vec_count with small remaining payload
    std::vector<std::uint8_t> dos_embed_buf = buffer;
    // Overwrite dimensions and vec_count in serialized payload
    // Search for 768 (0x0300 in little-endian 32-bit = 0x00, 0x03, 0x00, 0x00) and replace with 0xFFFFFFFF
    for (std::size_t i = LINEP_V02_HEADER_SIZE; i + 4 <= dos_embed_buf.size(); ++i) {
        if (dos_embed_buf[i] == 0x00 && dos_embed_buf[i+1] == 0x03 && dos_embed_buf[i+2] == 0x00 && dos_embed_buf[i+3] == 0x00) {
            dos_embed_buf[i] = 0xFF;
            dos_embed_buf[i+1] = 0xFF;
            dos_embed_buf[i+2] = 0xFF;
            dos_embed_buf[i+3] = 0xFF;
            break;
        }
    }
    event_envelope dos_dec{};
    LINEP_TEST_CHECK(!decode_event(dos_embed_buf.data(), dos_embed_buf.size(), dos_dec));

    std::cout << "  -> Embedding Envelope Tests PASSED" << std::endl;
}

void test_control_envelope() {
    std::cout << "[Test 4] Control Envelope (Cancel targeted by Execution ID & Window Update Flow Control)..." << std::endl;
    // 1. Cancel Control
    control_envelope ctrl{};
    ctrl.stream.request_id = 1001;
    ctrl.stream.execution_id = 2001; // Target cancellation to specific execution attempt
    ctrl.control_type = runtime_control_type::cancel;
    ctrl.reason = "User requested cancellation via UI";

    LINEP_TEST_CHECK(ctrl.is_valid());

    std::vector<std::uint8_t> buffer;
    LINEP_TEST_CHECK(encode_control(ctrl, buffer));
    LINEP_TEST_CHECK(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::control);

    control_envelope dec_ctrl{};
    LINEP_TEST_CHECK(decode_control(buffer.data(), buffer.size(), dec_ctrl));
    LINEP_TEST_CHECK(dec_ctrl.stream.request_id == 1001);
    LINEP_TEST_CHECK(dec_ctrl.stream.execution_id == 2001);
    LINEP_TEST_CHECK(dec_ctrl.control_type == runtime_control_type::cancel);
    LINEP_TEST_CHECK(dec_ctrl.reason == "User requested cancellation via UI");

    // 2. Window Update Control
    control_envelope win_ctrl{};
    win_ctrl.stream.request_id = 1001;
    win_ctrl.stream.execution_id = 2001;
    win_ctrl.stream.output_id = 0;
    win_ctrl.control_type = runtime_control_type::window_update;
    win_ctrl.window_credit_bytes = 4096;

    LINEP_TEST_CHECK(win_ctrl.is_valid());
    buffer.clear();
    LINEP_TEST_CHECK(encode_control(win_ctrl, buffer));

    control_envelope dec_win{};
    LINEP_TEST_CHECK(decode_control(buffer.data(), buffer.size(), dec_win));
    LINEP_TEST_CHECK(dec_win.control_type == runtime_control_type::window_update);
    LINEP_TEST_CHECK(dec_win.window_credit_bytes == 4096);

    std::cout << "  -> Control Envelope Tests PASSED" << std::endl;
}

void test_capabilities_envelope() {
    std::cout << "[Test 5] Capabilities Envelope..." << std::endl;
    capabilities_envelope caps{};
    caps.descriptor.supported_profiles = {runtime_profile::generate, runtime_profile::chat, runtime_profile::embed};
    caps.descriptor.max_context_tokens = 131072;
    caps.descriptor.max_output_tokens = 4096;
    caps.descriptor.supports_streaming = true;
    caps.descriptor.supports_cancellation = true;
    caps.descriptor.supports_tool_calling = true;
    caps.descriptor.supports_reasoning_deltas = true;
    caps.descriptor.supported_models = {"llama-3.1-8b", "mistral-7b-instruct"};

    embedding_space_descriptor sp{"nomic-embed-v1.5", "nomic-ai", "1.5", 768, embedding_normalization::l2, embedding_distance_metric::cosine};
    caps.descriptor.supported_embedding_spaces.push_back(sp);

    std::vector<std::uint8_t> buffer;
    LINEP_TEST_CHECK(encode_capabilities(caps, buffer));
    LINEP_TEST_CHECK(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::capabilities);

    capabilities_envelope dec_caps{};
    LINEP_TEST_CHECK(decode_capabilities(buffer.data(), buffer.size(), dec_caps));
    LINEP_TEST_CHECK(dec_caps.descriptor.supports_profile(runtime_profile::chat));
    LINEP_TEST_CHECK(dec_caps.descriptor.supports_profile(runtime_profile::embed));
    LINEP_TEST_CHECK(dec_caps.descriptor.max_context_tokens == 131072);
    LINEP_TEST_CHECK(dec_caps.descriptor.supports_tool_calling == true);
    LINEP_TEST_CHECK(dec_caps.descriptor.supported_models.size() == 2);
    LINEP_TEST_CHECK(dec_caps.descriptor.supported_embedding_spaces.size() == 1);
    LINEP_TEST_CHECK(dec_caps.descriptor.supported_embedding_spaces[0].dimensions == 768);

    std::cout << "  -> Capabilities Envelope Tests PASSED" << std::endl;
}

void test_lifecycle_state_machine() {
    std::cout << "[Test 6] Lifecycle State Machine Invariants..." << std::endl;
    lifecycle_status lc{};
    LINEP_TEST_CHECK(lc.state == lifecycle_state::received);
    LINEP_TEST_CHECK(!lc.has_terminal_outcome);

    // Normal happy path: received -> accepted -> started -> terminal(completed)
    LINEP_TEST_CHECK(lc.transition_to(lifecycle_state::accepted));
    LINEP_TEST_CHECK(lc.transition_to(lifecycle_state::started));
    LINEP_TEST_CHECK(lc.transition_to(lifecycle_state::terminal, terminal_outcome::completed));
    LINEP_TEST_CHECK(lc.has_terminal_outcome);
    LINEP_TEST_CHECK(lc.outcome == terminal_outcome::completed);

    // Terminal state is immutable: no further transitions allowed!
    LINEP_TEST_CHECK(!lc.can_transition_to(lifecycle_state::started));
    LINEP_TEST_CHECK(!lc.transition_to(lifecycle_state::started));

    // Cancel requested path:
    lifecycle_status lc_cancel{};
    LINEP_TEST_CHECK(lc_cancel.transition_to(lifecycle_state::accepted));
    LINEP_TEST_CHECK(lc_cancel.transition_to(lifecycle_state::started));
    LINEP_TEST_CHECK(lc_cancel.transition_to(lifecycle_state::cancel_requested));
    
    // Invariant: cancel_requested is NON-terminal!
    LINEP_TEST_CHECK(lc_cancel.state == lifecycle_state::cancel_requested);
    LINEP_TEST_CHECK(!lc_cancel.has_terminal_outcome);

    // cancel_requested transitions to terminal outcome
    LINEP_TEST_CHECK(lc_cancel.transition_to(lifecycle_state::terminal, terminal_outcome::cancelled));
    LINEP_TEST_CHECK(lc_cancel.has_terminal_outcome);
    LINEP_TEST_CHECK(lc_cancel.outcome == terminal_outcome::cancelled);

    std::cout << "  -> Lifecycle Invariants Tests PASSED" << std::endl;
}

void test_tampered_and_corrupt_envelopes() {
    std::cout << "[Test 7] Fail-Closed Tampered & Malformed Envelope Protection..." << std::endl;
    // 1. Truncated buffer (< 32 bytes)
    std::vector<std::uint8_t> short_buf = {0x50, 0x4E, 0x4C, 0x32};
    request_envelope req_dec{};
    LINEP_TEST_CHECK(!decode_request(short_buf.data(), short_buf.size(), req_dec));
    LINEP_TEST_CHECK(peek_envelope_type(short_buf.data(), short_buf.size()) == runtime_envelope_type::unknown);

    // 2. Corrupted magic bytes
    request_envelope req{};
    req.stream.request_id = 10;
    req.stream.execution_id = 20;
    req.model_id = "test-model";
    req.payload = "hi";
    std::vector<std::uint8_t> valid_buf;
    LINEP_TEST_CHECK(encode_request(req, valid_buf));

    valid_buf[0] = 0x00; // Corrupt magic
    LINEP_TEST_CHECK(!decode_request(valid_buf.data(), valid_buf.size(), req_dec));
    LINEP_TEST_CHECK(peek_envelope_type(valid_buf.data(), valid_buf.size()) == runtime_envelope_type::unknown);

    std::cout << "  -> Tampered/Corrupt Buffer Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Envelope & Contract Test Suite ===" << std::endl;
    test_request_envelope();
    test_event_envelope();
    test_embedding_envelope_and_vector_spaces();
    test_control_envelope();
    test_capabilities_envelope();
    test_lifecycle_state_machine();
    test_tampered_and_corrupt_envelopes();
    std::cout << "ALL V0.2 PHASE A ENVELOPE AND CONTRACT TESTS PASSED 100%!" << std::endl;
    return 0;
}
