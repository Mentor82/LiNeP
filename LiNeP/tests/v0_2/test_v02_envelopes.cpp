#include <cassert>
#include <iostream>
#include <vector>
#include <string>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/embedding.hpp"
#include "linep/v0_2/lifecycle.hpp"
#include "linep/v0_2/envelopes.hpp"

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

    assert(req.is_valid());

    std::vector<std::uint8_t> buffer;
    bool enc_ok = encode_request(req, buffer);
    assert(enc_ok);
    assert(buffer.size() >= sizeof(wire_envelope_header));

    assert(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::request);

    request_envelope decoded{};
    bool dec_ok = decode_request(buffer.data(), buffer.size(), decoded);
    assert(dec_ok);
    assert(decoded.stream.request_id == 1001);
    assert(decoded.stream.execution_id == 2001);
    assert(decoded.stream.output_id == 0);
    assert(decoded.profile == runtime_profile::chat);
    assert(decoded.model_id == "meta-llama/Llama-3.1-8B-Instruct");
    assert(decoded.payload == req.payload);
    assert(decoded.max_tokens == 512);
    assert(decoded.stream_requested == true);

    // Test invalid request: request_id == 0 -> Invalid!
    request_envelope invalid_req = req;
    invalid_req.stream.request_id = 0;
    assert(!invalid_req.is_valid());
    std::vector<std::uint8_t> bad_buf;
    assert(!encode_request(invalid_req, bad_buf));

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

    assert(evt.is_valid());
    assert(!evt.is_terminal());

    std::vector<std::uint8_t> buffer;
    assert(encode_event(evt, buffer));
    assert(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::event);

    event_envelope dec_evt{};
    assert(decode_event(buffer.data(), buffer.size(), dec_evt));
    assert(dec_evt.stream.request_id == 1001);
    assert(dec_evt.stream.execution_id == 2001);
    assert(dec_evt.stream.output_id == 1);
    assert(dec_evt.event_seq == 42);
    assert(dec_evt.event_type == runtime_event_type::content_delta);
    assert(dec_evt.payload == "Neural");
    assert(dec_evt.timestamp_us == 1700000000123456ULL);

    // Test terminal event (completed)
    event_envelope term_evt{};
    term_evt.stream = evt.stream;
    term_evt.event_seq = 43;
    term_evt.event_type = runtime_event_type::completed;
    term_evt.outcome = terminal_outcome::completed;
    assert(term_evt.is_valid());
    assert(term_evt.is_terminal());

    buffer.clear();
    assert(encode_event(term_evt, buffer));
    event_envelope dec_term{};
    assert(decode_event(buffer.data(), buffer.size(), dec_term));
    assert(dec_term.is_terminal());
    assert(dec_term.outcome == terminal_outcome::completed);

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
    assert(encode_event(err_evt, buffer));
    event_envelope dec_err{};
    assert(decode_event(buffer.data(), buffer.size(), dec_err));
    assert(dec_err.error.category == error_category::resource_exhausted);
    assert(dec_err.error.code == 503);
    assert(dec_err.error.message == "CUDA out of memory");
    assert(dec_err.error.backend_diagnostic == "vLLM KV cache full, 0 blocks free");

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
    assert(!compatible_embedding_space(space_a, space_b));

    embedding_space_descriptor space_a_clone = space_a;
    assert(compatible_embedding_space(space_a, space_a_clone));

    event_envelope embed_evt{};
    embed_evt.stream.request_id = 3001;
    embed_evt.stream.execution_id = 4001;
    embed_evt.stream.output_id = 0;
    embed_evt.event_seq = 1;
    embed_evt.event_type = runtime_event_type::embedding_result;
    embed_evt.embedding.space = space_a;
    embed_evt.embedding.vector.assign(768, 0.042f);

    assert(embed_evt.is_valid());

    std::vector<std::uint8_t> buffer;
    assert(encode_event(embed_evt, buffer));

    event_envelope dec_embed{};
    assert(decode_event(buffer.data(), buffer.size(), dec_embed));
    assert(dec_embed.event_type == runtime_event_type::embedding_result);
    assert(dec_embed.embedding.space.embedding_space_id == "nomic-embed-text-v1.5");
    assert(dec_embed.embedding.space.dimensions == 768);
    assert(dec_embed.embedding.vector.size() == 768);
    assert(dec_embed.embedding.vector[0] == 0.042f);

    std::cout << "  -> Embedding Envelope Tests PASSED" << std::endl;
}

void test_control_envelope() {
    std::cout << "[Test 4] Control Envelope (Cancel targeted by Execution ID)..." << std::endl;
    control_envelope ctrl{};
    ctrl.stream.request_id = 1001;
    ctrl.stream.execution_id = 2001; // Target cancellation to specific execution attempt
    ctrl.control_type = runtime_control_type::cancel;
    ctrl.reason = "User requested cancellation via UI";

    assert(ctrl.is_valid());

    std::vector<std::uint8_t> buffer;
    assert(encode_control(ctrl, buffer));
    assert(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::control);

    control_envelope dec_ctrl{};
    assert(decode_control(buffer.data(), buffer.size(), dec_ctrl));
    assert(dec_ctrl.stream.request_id == 1001);
    assert(dec_ctrl.stream.execution_id == 2001);
    assert(dec_ctrl.control_type == runtime_control_type::cancel);
    assert(dec_ctrl.reason == "User requested cancellation via UI");

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
    assert(encode_capabilities(caps, buffer));
    assert(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::capabilities);

    capabilities_envelope dec_caps{};
    assert(decode_capabilities(buffer.data(), buffer.size(), dec_caps));
    assert(dec_caps.descriptor.supports_profile(runtime_profile::chat));
    assert(dec_caps.descriptor.supports_profile(runtime_profile::embed));
    assert(dec_caps.descriptor.max_context_tokens == 131072);
    assert(dec_caps.descriptor.supports_tool_calling == true);
    assert(dec_caps.descriptor.supported_models.size() == 2);
    assert(dec_caps.descriptor.supported_embedding_spaces.size() == 1);
    assert(dec_caps.descriptor.supported_embedding_spaces[0].dimensions == 768);

    std::cout << "  -> Capabilities Envelope Tests PASSED" << std::endl;
}

void test_lifecycle_state_machine() {
    std::cout << "[Test 6] Lifecycle State Machine Invariants..." << std::endl;
    lifecycle_status lc{};
    assert(lc.state == lifecycle_state::received);
    assert(!lc.has_terminal_outcome);

    // Normal happy path: received -> accepted -> started -> terminal(completed)
    assert(lc.transition_to(lifecycle_state::accepted));
    assert(lc.transition_to(lifecycle_state::started));
    assert(lc.transition_to(lifecycle_state::terminal, terminal_outcome::completed));
    assert(lc.has_terminal_outcome);
    assert(lc.outcome == terminal_outcome::completed);

    // Terminal state is immutable: no further transitions allowed!
    assert(!lc.can_transition_to(lifecycle_state::started));
    assert(!lc.transition_to(lifecycle_state::started));

    // Cancel requested path:
    lifecycle_status lc_cancel{};
    assert(lc_cancel.transition_to(lifecycle_state::accepted));
    assert(lc_cancel.transition_to(lifecycle_state::started));
    assert(lc_cancel.transition_to(lifecycle_state::cancel_requested));
    
    // Invariant: cancel_requested is NON-terminal!
    assert(lc_cancel.state == lifecycle_state::cancel_requested);
    assert(!lc_cancel.has_terminal_outcome);

    // cancel_requested transitions to terminal outcome
    assert(lc_cancel.transition_to(lifecycle_state::terminal, terminal_outcome::cancelled));
    assert(lc_cancel.has_terminal_outcome);
    assert(lc_cancel.outcome == terminal_outcome::cancelled);

    std::cout << "  -> Lifecycle Invariants Tests PASSED" << std::endl;
}

void test_tampered_and_corrupt_envelopes() {
    std::cout << "[Test 7] Fail-Closed Tampered & Malformed Envelope Protection..." << std::endl;
    // 1. Truncated buffer (< 32 bytes)
    std::vector<std::uint8_t> short_buf = {0x50, 0x4E, 0x4C, 0x32};
    request_envelope req_dec{};
    assert(!decode_request(short_buf.data(), short_buf.size(), req_dec));
    assert(peek_envelope_type(short_buf.data(), short_buf.size()) == runtime_envelope_type::unknown);

    // 2. Corrupted magic bytes
    request_envelope req{};
    req.stream.request_id = 10;
    req.stream.execution_id = 20;
    req.model_id = "test-model";
    req.payload = "hi";
    std::vector<std::uint8_t> valid_buf;
    assert(encode_request(req, valid_buf));

    valid_buf[0] = 0x00; // Corrupt magic
    assert(!decode_request(valid_buf.data(), valid_buf.size(), req_dec));
    assert(peek_envelope_type(valid_buf.data(), valid_buf.size()) == runtime_envelope_type::unknown);

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
