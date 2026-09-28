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

    // 2. Window Update Control (Idempotent Monotonic ack_offset_bytes)
    control_envelope win_ctrl{};
    win_ctrl.stream.request_id = 1001;
    win_ctrl.stream.execution_id = 2001;
    win_ctrl.stream.output_id = 0;
    win_ctrl.control_type = runtime_control_type::window_update;
    win_ctrl.ack_offset_bytes = 4096;

    LINEP_TEST_CHECK(win_ctrl.is_valid());
    buffer.clear();
    LINEP_TEST_CHECK(encode_control(win_ctrl, buffer));

    control_envelope dec_win{};
    LINEP_TEST_CHECK(decode_control(buffer.data(), buffer.size(), dec_win));
    LINEP_TEST_CHECK(dec_win.control_type == runtime_control_type::window_update);
    LINEP_TEST_CHECK(dec_win.ack_offset_bytes == 4096);

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

void test_request_envelope_with_generation_options() {
    std::cout << "[Test 8] Request Envelope with Generation Options (Runtime Parity & Canonical Sorting)..." << std::endl;
    request_envelope req{};
    req.stream.request_id = 5001;
    req.stream.execution_id = 6001;
    req.stream.output_id = 0;
    req.profile = runtime_profile::chat;
    req.model_id = "meta-llama/Llama-3.1-8B-Instruct";
    req.payload = R"({"prompt":"Explain quantum computing"})";
    req.max_tokens = 1024;
    req.temperature = 0.7f;
    req.stream_requested = true;
    req.has_options = true;
    req.options.top_p = 0.95f;
    req.options.top_k = 50;
    req.options.repeat_penalty = 1.15f;
    req.options.repeat_last_n = 128;
    req.options.seed = 42ULL;
    req.options.presence_penalty = 0.1f;
    req.options.frequency_penalty = 0.2f;
    req.options.stop_sequences = {"<|eot_id|>", "USER:", "\n\nHuman:"};
    // Deliberately unsorted in struct to test automatic canonical sorting during encode
    req.options.extra_options = {
        {"typical_p", "0.9"},
        {"mirostat", "2"},
        {"min_p", "0.05"}
    };

    LINEP_TEST_CHECK(req.is_valid());

    std::vector<std::uint8_t> buf;
    bool enc_ok = encode_request(req, buf);
    LINEP_TEST_CHECK(enc_ok);

    request_envelope dec{};
    bool dec_ok = decode_request(buf.data(), buf.size(), dec);
    LINEP_TEST_CHECK(dec_ok);
    LINEP_TEST_CHECK(dec.has_options == true);
    LINEP_TEST_CHECK(dec.options.top_p == 0.95f);
    LINEP_TEST_CHECK(dec.options.top_k == 50);
    LINEP_TEST_CHECK(dec.options.repeat_penalty == 1.15f);
    LINEP_TEST_CHECK(dec.options.repeat_last_n == 128);
    LINEP_TEST_CHECK(dec.options.seed == 42ULL);
    LINEP_TEST_CHECK(dec.options.presence_penalty == 0.1f);
    LINEP_TEST_CHECK(dec.options.frequency_penalty == 0.2f);
    LINEP_TEST_CHECK(dec.options.stop_sequences.size() == 3);
    LINEP_TEST_CHECK(dec.options.stop_sequences[0] == "<|eot_id|>");
    LINEP_TEST_CHECK(dec.options.stop_sequences[1] == "USER:");
    LINEP_TEST_CHECK(dec.options.stop_sequences[2] == "\n\nHuman:");
    LINEP_TEST_CHECK(dec.options.extra_options.size() == 3);
    // Verified canonical lexicographical sorting: "min_p", "mirostat", "typical_p"
    LINEP_TEST_CHECK(dec.options.extra_options[0].first == "min_p");
    LINEP_TEST_CHECK(dec.options.extra_options[0].second == "0.05");
    LINEP_TEST_CHECK(dec.options.extra_options[1].first == "mirostat");
    LINEP_TEST_CHECK(dec.options.extra_options[1].second == "2");
    LINEP_TEST_CHECK(dec.options.extra_options[2].first == "typical_p");
    LINEP_TEST_CHECK(dec.options.extra_options[2].second == "0.9");

    // Test duplicate key rejection in encode
    request_envelope dup_req = req;
    dup_req.options.extra_options = {{"mirostat", "1"}, {"mirostat", "2"}};
    std::vector<std::uint8_t> dup_buf;
    LINEP_TEST_CHECK(!encode_request(dup_req, dup_buf)); // Must reject duplicate keys!

    std::cout << "  -> Request with Generation Options Tests PASSED" << std::endl;
}

void test_session_bind_envelope() {
    std::cout << "[Test 9] Session Bind Envelope & Connection-level Events (Issue #15)..." << std::endl;

    session_bind_envelope bind{};
    bind.identity.node_id = 0x1122334455667788ULL;
    bind.identity.runtime_id = 0x8877665544332211ULL;
    bind.identity.endpoint_id = 42;
    bind.control_epoch = 7;
    bind.lease_token = 0xAABBCCDDEEFF0011ULL;

    LINEP_TEST_CHECK(bind.is_valid());

    std::vector<std::uint8_t> buffer;
    LINEP_TEST_CHECK(encode_session_bind(bind, buffer));
    LINEP_TEST_CHECK(buffer.size() == (LINEP_V02_HEADER_SIZE + LINEP_V02_SESSION_BIND_PAYLOAD_SIZE)); // Exactly 32 + 36 = 68 bytes
    LINEP_TEST_CHECK(peek_envelope_type(buffer.data(), buffer.size()) == runtime_envelope_type::session_bind);

    session_bind_envelope dec_bind{};
    LINEP_TEST_CHECK(decode_session_bind(buffer.data(), buffer.size(), dec_bind));
    LINEP_TEST_CHECK(dec_bind.identity == bind.identity);
    LINEP_TEST_CHECK(dec_bind.control_epoch == 7);
    LINEP_TEST_CHECK(dec_bind.lease_token == 0xAABBCCDDEEFF0011ULL);

    // Fail-closed checks:
    // 1. Zero lease token
    session_bind_envelope zero_token = bind;
    zero_token.lease_token = 0;
    LINEP_TEST_CHECK(!zero_token.is_valid());
    std::vector<std::uint8_t> bad_buf;
    LINEP_TEST_CHECK(!encode_session_bind(zero_token, bad_buf));

    // 2. Tampered header checks:
    // a) Non-zero request_id (must be rejected)
    std::vector<std::uint8_t> tampered_req = buffer;
    tampered_req[8] = 0x01; // set request_id != 0
    session_bind_envelope bad_dec{};
    LINEP_TEST_CHECK(!decode_session_bind(tampered_req.data(), tampered_req.size(), bad_dec));

    // b) Non-zero execution_id (must be rejected)
    std::vector<std::uint8_t> tampered_exec = buffer;
    tampered_exec[16] = 0x01; // set execution_id != 0
    LINEP_TEST_CHECK(!decode_session_bind(tampered_exec.data(), tampered_exec.size(), bad_dec));

    // c) Non-zero output_id (must be rejected)
    std::vector<std::uint8_t> tampered_out = buffer;
    tampered_out[24] = 0x01; // set output_id != 0
    LINEP_TEST_CHECK(!decode_session_bind(tampered_out.data(), tampered_out.size(), bad_dec));

    // d) Non-zero flags (must be rejected)
    std::vector<std::uint8_t> tampered_flags = buffer;
    tampered_flags[6] = 0x01; // set flags != 0
    LINEP_TEST_CHECK(!decode_session_bind(tampered_flags.data(), tampered_flags.size(), bad_dec));

    // e) Wrong payload length in header (e.g. 35 or 37 bytes instead of 36)
    std::vector<std::uint8_t> tampered_len = buffer;
    tampered_len[28] = 37;
    LINEP_TEST_CHECK(!decode_session_bind(tampered_len.data(), tampered_len.size(), bad_dec));

    // f) Trailing garbage bytes in buffer (must reject trailing bytes, exact wire size 68 required)
    std::vector<std::uint8_t> trailing_buf = buffer;
    trailing_buf.push_back(0xFF);
    LINEP_TEST_CHECK(!decode_session_bind(trailing_buf.data(), trailing_buf.size(), bad_dec));

    // 3. Connection-level terminal EVENT (request_id=0, execution_id=0, output_id=0)
    event_envelope conn_evt{};
    conn_evt.stream = stream_identity{0, 0, 0};
    conn_evt.event_seq = 1;
    conn_evt.event_type = runtime_event_type::failed;
    conn_evt.outcome = terminal_outcome::failed;
    conn_evt.error.category = error_category::unauthorized;
    conn_evt.error.code = 401;
    conn_evt.error.message = "lease_invalid";

    LINEP_TEST_CHECK(conn_evt.stream.is_connection_level());
    LINEP_TEST_CHECK(conn_evt.is_valid());

    std::vector<std::uint8_t> conn_evt_buf;
    LINEP_TEST_CHECK(encode_event(conn_evt, conn_evt_buf));
    event_envelope dec_conn_evt{};
    LINEP_TEST_CHECK(decode_event(conn_evt_buf.data(), conn_evt_buf.size(), dec_conn_evt));
    LINEP_TEST_CHECK(dec_conn_evt.stream.is_connection_level());
    LINEP_TEST_CHECK(dec_conn_evt.error.category == error_category::unauthorized);
    LINEP_TEST_CHECK(dec_conn_evt.error.code == 401);
    LINEP_TEST_CHECK(dec_conn_evt.error.message == "lease_invalid");

    std::cout << "  -> Session Bind Envelope Tests PASSED" << std::endl;
}

void test_sl1_authentication_and_envelopes() {
    std::cout << "[Test 10] SL1 Authentication, Framing, Replay & Tampering Invariants..." << std::endl;

    // 1. SESSION_BIND SL1 announcement
    session_bind_envelope bind{};
    bind.identity.node_id = 1001;
    bind.identity.runtime_id = 2001;
    bind.identity.endpoint_id = 1;
    bind.control_epoch = 42;
    bind.lease_token = 0xAABBCCDDEEFF0011ULL;
    bind.sl1_requested = true;
    bind.key_id = 1;

    const std::vector<std::uint8_t> secret_key_1 = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    // Client encodes unauthenticated bind buffer first, then signs with auth_seq = 1
    session_bind_envelope raw_bind = bind;
    raw_bind.sl1_requested = false; // base encoding
    std::vector<std::uint8_t> bind_buf;
    LINEP_TEST_CHECK(encode_session_bind(raw_bind, bind_buf));
    LINEP_TEST_CHECK(bind_buf.size() == LINEP_V02_HEADER_SIZE + LINEP_V02_SESSION_BIND_PAYLOAD_SIZE);

    // Sign the SESSION_BIND (Client -> Server: auth_seq = 1, direction = initiator_to_responder)
    LINEP_TEST_CHECK(sign_envelope_buffer(
        bind_buf,
        bind,
        message_direction::initiator_to_responder,
        1 /* auth_seq */,
        1 /* key_id */,
        secret_key_1.data(),
        secret_key_1.size()
    ));
    LINEP_TEST_CHECK(bind_buf.size() == LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE + LINEP_V02_SESSION_BIND_PAYLOAD_SIZE);
    
    wire_envelope_header bind_hdr{};
    LINEP_TEST_CHECK(decode_header(bind_buf.data(), bind_buf.size(), bind_hdr));
    LINEP_TEST_CHECK((bind_hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0);

    session_bind_envelope dec_bind{};
    LINEP_TEST_CHECK(decode_session_bind(bind_buf.data(), bind_buf.size(), dec_bind));
    LINEP_TEST_CHECK(dec_bind.sl1_requested == true);
    LINEP_TEST_CHECK(dec_bind.auth_ext.auth_seq == 1);
    LINEP_TEST_CHECK(dec_bind.auth_ext.key_id == 1);

    // Server verifies Client's signed SESSION_BIND
    wire_auth_extension srv_ext{};
    std::string srv_err;
    LINEP_TEST_CHECK(verify_envelope_buffer(
        bind_buf.data(), bind_buf.size(), bind,
        message_direction::initiator_to_responder,
        secret_key_1.data(), secret_key_1.size(),
        srv_ext, &srv_err
    ));
    LINEP_TEST_CHECK(srv_ext.auth_seq == 1);

    // Server confirms with signed frame (Server -> Client: auth_seq = 1, direction = responder_to_initiator)
    std::vector<std::uint8_t> confirm_buf;
    LINEP_TEST_CHECK(encode_session_bind(raw_bind, confirm_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(
        confirm_buf,
        bind,
        message_direction::responder_to_initiator,
        1 /* auth_seq */,
        1 /* key_id */,
        secret_key_1.data(),
        secret_key_1.size()
    ));

    // Client verifies Server's signed confirmation
    wire_auth_extension cli_ext{};
    std::string cli_err;
    LINEP_TEST_CHECK(verify_envelope_buffer(
        confirm_buf.data(), confirm_buf.size(), bind,
        message_direction::responder_to_initiator,
        secret_key_1.data(), secret_key_1.size(),
        cli_ext, &cli_err
    ));
    LINEP_TEST_CHECK(cli_ext.auth_seq == 1);

    // Reject unknown bind flags (e.g. 0x02)
    std::vector<std::uint8_t> bad_bind_flags = bind_buf;
    bad_bind_flags[7] = 0x02; // unknown flag
    session_bind_envelope bad_bind{};
    LINEP_TEST_CHECK(!decode_session_bind(bad_bind_flags.data(), bad_bind_flags.size(), bad_bind));

    // Reject unauthenticated buffer claiming FLAG_AUTHENTICATED without extension (68 bytes)
    std::vector<std::uint8_t> truncated_auth_bind;
    LINEP_TEST_CHECK(encode_session_bind(raw_bind, truncated_auth_bind));
    truncated_auth_bind[7] = LINEP_V02_FLAG_AUTHENTICATED; // 0x01 flag on 68-byte buffer
    session_bind_envelope trunc_dec{};
    LINEP_TEST_CHECK(!decode_session_bind(truncated_auth_bind.data(), truncated_auth_bind.size(), trunc_dec));

    request_envelope req{};
    req.stream.request_id = 500;
    req.stream.execution_id = 600;
    req.stream.output_id = 0;
    req.profile = runtime_profile::chat;
    req.model_id = "test-model";
    req.payload = "Hello SL1 authenticated world!";
    req.max_tokens = 256;
    req.temperature = 0.5f;

    std::vector<std::uint8_t> raw_req_buf;
    LINEP_TEST_CHECK(encode_request(req, raw_req_buf));
    std::size_t unauth_size = raw_req_buf.size();

    // Sign the request
    bool sign_ok = sign_envelope_buffer(
        raw_req_buf,
        bind,
        message_direction::initiator_to_responder,
        1 /* auth_seq */,
        1 /* key_id */,
        secret_key_1.data(),
        secret_key_1.size()
    );
    LINEP_TEST_CHECK(sign_ok);
    LINEP_TEST_CHECK(raw_req_buf.size() == unauth_size + LINEP_V02_AUTH_EXTENSION_SIZE);

    // Verify envelope header has FLAG_AUTHENTICATED
    wire_envelope_header req_hdr{};
    LINEP_TEST_CHECK(decode_header(raw_req_buf.data(), raw_req_buf.size(), req_hdr));
    LINEP_TEST_CHECK((req_hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0);

    // Verify envelope buffer
    wire_auth_extension ext{};
    std::string err;
    bool verify_ok = verify_envelope_buffer(
        raw_req_buf.data(),
        raw_req_buf.size(),
        bind,
        message_direction::initiator_to_responder,
        secret_key_1.data(),
        secret_key_1.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(verify_ok);
    LINEP_TEST_CHECK(ext.auth_seq == 1);
    LINEP_TEST_CHECK(ext.key_id == 1);
    LINEP_TEST_CHECK(ext.reserved == 0);

    // Decode request directly from authenticated buffer
    request_envelope dec_req{};
    LINEP_TEST_CHECK(decode_request(raw_req_buf.data(), raw_req_buf.size(), dec_req));
    LINEP_TEST_CHECK(dec_req.stream.request_id == 500);
    LINEP_TEST_CHECK(dec_req.stream.execution_id == 600);
    LINEP_TEST_CHECK(dec_req.model_id == "test-model");
    LINEP_TEST_CHECK(dec_req.payload == "Hello SL1 authenticated world!");

    // 3. Negative / Tampering Tests
    // a) Wrong direction (reflection attack prevention)
    bool refl_ok = verify_envelope_buffer(
        raw_req_buf.data(),
        raw_req_buf.size(),
        bind,
        message_direction::responder_to_initiator, // wrong direction!
        secret_key_1.data(),
        secret_key_1.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(!refl_ok);

    // b) Wrong binding (cross-session / cross-node replay prevention)
    session_bind_envelope other_bind = bind;
    other_bind.lease_token = 0x99999999ULL;
    bool other_ok = verify_envelope_buffer(
        raw_req_buf.data(),
        raw_req_buf.size(),
        other_bind,
        message_direction::initiator_to_responder,
        secret_key_1.data(),
        secret_key_1.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(!other_ok);

    // c) Tampered payload
    std::vector<std::uint8_t> tampered_payload = raw_req_buf;
    tampered_payload.back() ^= 0xFF;
    bool tamp_pay_ok = verify_envelope_buffer(
        tampered_payload.data(),
        tampered_payload.size(),
        bind,
        message_direction::initiator_to_responder,
        secret_key_1.data(),
        secret_key_1.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(!tamp_pay_ok);

    // d) Tampered auth_seq
    std::vector<std::uint8_t> tampered_seq = raw_req_buf;
    tampered_seq[LINEP_V02_HEADER_SIZE] = 0x02; // Change auth_seq
    bool tamp_seq_ok = verify_envelope_buffer(
        tampered_seq.data(),
        tampered_seq.size(),
        bind,
        message_direction::initiator_to_responder,
        secret_key_1.data(),
        secret_key_1.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(!tamp_seq_ok);

    // e) Wrong secret key
    const std::vector<std::uint8_t> wrong_key(32, 0xEE);
    bool wrong_key_ok = verify_envelope_buffer(
        raw_req_buf.data(),
        raw_req_buf.size(),
        bind,
        message_direction::initiator_to_responder,
        wrong_key.data(),
        wrong_key.size(),
        ext,
        &err
    );
    LINEP_TEST_CHECK(!wrong_key_ok);

    // 4. Authenticated EVENT roundtrip (Server -> Client)
    event_envelope evt{};
    evt.stream = stream_identity{500, 600, 0};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::content_delta;
    evt.payload = "Authenticated delta token";
    evt.timestamp_us = 1234567890ULL;

    std::vector<std::uint8_t> raw_evt_buf;
    LINEP_TEST_CHECK(encode_event(evt, raw_evt_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(
        raw_evt_buf,
        bind,
        message_direction::responder_to_initiator,
        1, // auth_seq
        1, // key_id
        secret_key_1.data(),
        secret_key_1.size()
    ));

    event_envelope dec_evt{};
    LINEP_TEST_CHECK(decode_event(raw_evt_buf.data(), raw_evt_buf.size(), dec_evt));
    LINEP_TEST_CHECK(dec_evt.stream.request_id == 500);
    LINEP_TEST_CHECK(dec_evt.payload == "Authenticated delta token");

    // 5. Key Rotation Support
    const std::vector<std::uint8_t> secret_key_2(32, 0x77);
    event_envelope evt2{};
    evt2.stream = stream_identity{500, 600, 0};
    evt2.event_seq = 2;
    evt2.event_type = runtime_event_type::completed;
    evt2.outcome = terminal_outcome::completed;

    std::vector<std::uint8_t> raw_evt2_buf;
    LINEP_TEST_CHECK(encode_event(evt2, raw_evt2_buf));
    LINEP_TEST_CHECK(sign_envelope_buffer(
        raw_evt2_buf,
        bind,
        message_direction::responder_to_initiator,
        2, // auth_seq
        2, // key_id: rotated!
        secret_key_2.data(),
        secret_key_2.size()
    ));

    // Verifying with key 1 must fail
    LINEP_TEST_CHECK(!verify_envelope_buffer(
        raw_evt2_buf.data(), raw_evt2_buf.size(),
        bind, message_direction::responder_to_initiator,
        secret_key_1.data(), secret_key_1.size(),
        ext, &err
    ));

    // Verifying with key 2 must succeed
    LINEP_TEST_CHECK(verify_envelope_buffer(
        raw_evt2_buf.data(), raw_evt2_buf.size(),
        bind, message_direction::responder_to_initiator,
        secret_key_2.data(), secret_key_2.size(),
        ext, &err
    ));
    LINEP_TEST_CHECK(ext.key_id == 2);
    LINEP_TEST_CHECK(ext.auth_seq == 2);

    std::cout << "  -> SL1 Authentication & Envelopes Tests PASSED" << std::endl;
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
    test_request_envelope_with_generation_options();
    test_session_bind_envelope();
    test_sl1_authentication_and_envelopes();
    std::cout << "ALL V0.2 PHASE A ENVELOPE AND CONTRACT TESTS PASSED 100%!" << std::endl;
    return 0;
}
