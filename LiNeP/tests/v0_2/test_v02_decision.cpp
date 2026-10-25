#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/decision.hpp"
#include "linep/v0_2/registration.hpp"

using namespace linep::v0_2;

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

static std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        auto b = static_cast<std::uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

static std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    for (std::uint8_t b : bytes) {
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ── Test 1: Wire IDs & Basic Structural Invariants ──────────────────────────
void test_wire_ids_and_invariants() {
    std::cout << "[Test 1] Testing DECISION Wire IDs & Invariants..." << std::endl;

    // Normative Profile 5 & Event 14 allocation
    LINEP_TEST_CHECK(static_cast<std::uint8_t>(runtime_profile::decision) == 5);
    LINEP_TEST_CHECK(static_cast<std::uint8_t>(runtime_event_type::decision_result) == 14);

    // Request with Profile 5
    request_envelope req{};
    req.stream = stream_identity{10, 20, 1};
    req.profile = runtime_profile::decision;
    req.model_id = "clef-decision:test";
    req.payload = R"({"questions":{"q1":{"type":"choice"}}})";
    LINEP_TEST_CHECK(req.is_valid());

    // Event DECISION_RESULT is non-terminal DATA event
    event_envelope evt{};
    evt.stream = stream_identity{10, 20, 1};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::decision_result;
    evt.payload = R"({"answers":{"q1":{"choice":"A"}}})";
    evt.timestamp_us = 1729876800000000ULL;

    LINEP_TEST_CHECK(evt.is_valid());
    LINEP_TEST_CHECK(!evt.is_terminal()); // Must NOT be terminal!

    // Invariant: DECISION_RESULT cannot be terminal
    evt.outcome = terminal_outcome::completed;
    // In our validator, outcome is allowed to be set or unknown, but is_terminal() must be false
    LINEP_TEST_CHECK(!evt.is_terminal());

    // Invariant: empty payload in DECISION_RESULT must fail
    event_envelope empty_payload_evt = evt;
    empty_payload_evt.payload = "";
    LINEP_TEST_CHECK(!empty_payload_evt.is_valid());

    std::cout << "  -> Passed Test 1" << std::endl;
}

// ── Test 2: Positional Capabilities Encoding & Decoding (Pfad A) ─────────────
void test_positional_capabilities_pfad_a() {
    std::cout << "[Test 2] Testing Positional Capabilities (Pfad A) Roundtrips..." << std::endl;

    // Case 2a: Both Vision and Decision models present
    {
        capabilities_envelope caps{};
        caps.descriptor.supported_profiles = {runtime_profile::chat, runtime_profile::vision, runtime_profile::decision};
        caps.descriptor.supported_models = {"vision-model", "decision-model"};

        vision_model_descriptor vm{};
        vm.model_id = "vision-model";
        vm.model_revision = "v1";
        vm.label_set_id = "coco80:v1";
        vm.task = vision_task::detect;
        vm.max_detections = 50;
        caps.descriptor.supported_vision_models.push_back(vm);

        decision_model_descriptor dm{};
        dm.model_id = "decision-model";
        dm.model_revision = "v1.2";
        dm.decision_type = "choice,score,noul";
        caps.descriptor.supported_decision_models.push_back(dm);

        std::vector<std::uint8_t> buf;
        LINEP_TEST_CHECK(encode_capabilities(caps, buf));

        capabilities_envelope decoded{};
        LINEP_TEST_CHECK(decode_capabilities(buf.data(), buf.size(), decoded));
        LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models.size() == 1);
        LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models[0] == vm);
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models.size() == 1);
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models[0] == dm);
        LINEP_TEST_CHECK(decoded.descriptor.supports_decision_model("decision-model"));
        LINEP_TEST_CHECK(!decoded.descriptor.supports_decision_model("unknown-model"));
    }

    // Case 2b: Decision models present, Vision models EMPTY (Positional Offset: v_count = 0)
    {
        capabilities_envelope caps{};
        caps.descriptor.supported_profiles = {runtime_profile::generate, runtime_profile::decision};
        caps.descriptor.supported_models = {"decision-model"};

        decision_model_descriptor dm{};
        dm.model_id = "decision-model";
        dm.model_revision = "v2.0";
        dm.decision_type = "choice";
        caps.descriptor.supported_decision_models.push_back(dm);

        std::vector<std::uint8_t> buf;
        LINEP_TEST_CHECK(encode_capabilities(caps, buf));

        capabilities_envelope decoded{};
        LINEP_TEST_CHECK(decode_capabilities(buf.data(), buf.size(), decoded));
        LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models.empty());
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models.size() == 1);
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models[0] == dm);
    }

    // Case 2c: Vision models present, Decision models EMPTY
    {
        capabilities_envelope caps{};
        caps.descriptor.supported_profiles = {runtime_profile::vision};
        caps.descriptor.supported_models = {"vision-model"};

        vision_model_descriptor vm{};
        vm.model_id = "vision-model";
        vm.model_revision = "v1";
        vm.label_set_id = "coco80:v1";
        vm.task = vision_task::detect;
        vm.max_detections = 20;
        caps.descriptor.supported_vision_models.push_back(vm);

        std::vector<std::uint8_t> buf;
        LINEP_TEST_CHECK(encode_capabilities(caps, buf));

        capabilities_envelope decoded{};
        LINEP_TEST_CHECK(decode_capabilities(buf.data(), buf.size(), decoded));
        LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models.size() == 1);
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models.empty());
    }

    // Case 2d: Neither Vision nor Decision models present (Baseline V0.2)
    {
        capabilities_envelope caps{};
        caps.descriptor.supported_profiles = {runtime_profile::generate, runtime_profile::chat};
        caps.descriptor.supported_models = {"llama-3"};

        std::vector<std::uint8_t> buf;
        LINEP_TEST_CHECK(encode_capabilities(caps, buf));

        capabilities_envelope decoded{};
        LINEP_TEST_CHECK(decode_capabilities(buf.data(), buf.size(), decoded));
        LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models.empty());
        LINEP_TEST_CHECK(decoded.descriptor.supported_decision_models.empty());
    }

    std::cout << "  -> Passed Test 2" << std::endl;
}

// ── Test 3: OldPeer-Matrix & Fail-Closed Invariants ─────────────────────────
void test_oldpeer_fail_closed_invariants() {
    std::cout << "[Test 3] Testing OldPeer-Matrix & Fail-Closed Invariants..." << std::endl;

    // Create a capabilities frame with decision models
    capabilities_envelope caps{};
    caps.descriptor.supported_profiles = {runtime_profile::decision};
    caps.descriptor.supported_models = {"clef-decision:test"};
    decision_model_descriptor dm{"clef-decision:test", "1.0", "choice"};
    caps.descriptor.supported_decision_models.push_back(dm);

    std::vector<std::uint8_t> valid_buf;
    LINEP_TEST_CHECK(encode_capabilities(caps, valid_buf));

    // Trailing garbage check: append 1 byte to valid capabilities payload
    std::vector<std::uint8_t> garbage_buf = valid_buf;
    garbage_buf.push_back(0xFF);
    std::uint32_t new_len = static_cast<std::uint32_t>(valid_buf.size() - 32 + 1);
    garbage_buf[28] = static_cast<std::uint8_t>(new_len & 0xFF);
    garbage_buf[29] = static_cast<std::uint8_t>((new_len >> 8) & 0xFF);
    garbage_buf[30] = static_cast<std::uint8_t>((new_len >> 16) & 0xFF);
    garbage_buf[31] = static_cast<std::uint8_t>((new_len >> 24) & 0xFF);

    capabilities_envelope rejected_caps{};
    LINEP_TEST_CHECK(!decode_capabilities(garbage_buf.data(), garbage_buf.size(), rejected_caps));

    // Corrupted decision model count: claim 50000 models with truncated buffer
    std::vector<std::uint8_t> corrupt_buf = valid_buf;
    std::size_t d_count_offset = valid_buf.size() - 33 - 2;
    corrupt_buf[d_count_offset] = 0xFF;
    corrupt_buf[d_count_offset + 1] = 0xFF;
    LINEP_TEST_CHECK(!decode_capabilities(corrupt_buf.data(), corrupt_buf.size(), rejected_caps));

    std::cout << "  -> Passed Test 3" << std::endl;
}

// ── Test 4: Runtime Registration (Envelope 6) with PROFILE_DECISION ───────────
void test_runtime_registration_decision() {
    std::cout << "[Test 4] Testing Runtime Registration with PROFILE_DECISION (5)..." << std::endl;

    runtime_registration_envelope reg{};
    reg.operation = registration_operation::register_runtime;
    reg.concurrent_slots = 4;
    reg.capabilities.descriptor.supported_profiles = {runtime_profile::decision};
    reg.capabilities.descriptor.supported_models = {"clef-decision:test"};

    decision_model_descriptor dm{"clef-decision:test", "1.0", "choice"};
    reg.capabilities.descriptor.supported_decision_models.push_back(dm);

    std::vector<std::uint8_t> reg_buf;
    LINEP_TEST_CHECK(encode_runtime_registration(reg, reg_buf));

    runtime_registration_envelope decoded_reg{};
    LINEP_TEST_CHECK(decode_runtime_registration(reg_buf.data(), reg_buf.size(), decoded_reg));
    LINEP_TEST_CHECK(decoded_reg.concurrent_slots == 4);
    LINEP_TEST_CHECK(decoded_reg.capabilities.descriptor.supported_profiles.size() == 1);
    LINEP_TEST_CHECK(decoded_reg.capabilities.descriptor.supported_profiles[0] == runtime_profile::decision);
    LINEP_TEST_CHECK(decoded_reg.capabilities.descriptor.supported_decision_models.size() == 1);
    LINEP_TEST_CHECK(decoded_reg.capabilities.descriptor.supported_decision_models[0] == dm);

    // Negative case 4a: Profile 5 present, but supported_decision_models is empty -> must fail!
    runtime_registration_envelope reg_no_models = reg;
    reg_no_models.capabilities.descriptor.supported_decision_models.clear();
    std::vector<std::uint8_t> fail_buf;
    LINEP_TEST_CHECK(!encode_runtime_registration(reg_no_models, fail_buf));

    // Negative case 4b: Decision models present, but Profile 5 missing -> must fail!
    runtime_registration_envelope reg_no_profile = reg;
    reg_no_profile.capabilities.descriptor.supported_profiles = {runtime_profile::chat};
    LINEP_TEST_CHECK(!encode_runtime_registration(reg_no_profile, fail_buf));

    // Negative case 4c: Unallocated Profile 6 -> must fail closed (v < 1 || v > 5)!
    runtime_registration_envelope reg_prof_6 = reg;
    reg_prof_6.capabilities.descriptor.supported_profiles = {static_cast<runtime_profile>(6)};
    LINEP_TEST_CHECK(!encode_runtime_registration(reg_prof_6, fail_buf));

    std::cout << "  -> Passed Test 4" << std::endl;
}

// ── Test 5: Golden Vector 1 (Standard Choice Question, Plain, 307 Bytes) ─────
void test_golden_vector_1_request() {
    std::cout << "[Test 5] Testing Golden Vector 1 (Plain Request, 307 Bytes)..." << std::endl;

    const std::string golden_hex =
        "324C4E5000020100010000000000000001000000000000000100000013010000051200636C65662D6465636973696F6E3A74657374F100"
        "00007B226D6F64656C223A22636C65662D6465636973696F6E3A74657374222C227374617465223A7B2273657373696F6E5F6964223A22"
        "746573742D63312D303031227D2C227175657374696F6E73223A7B227131223A7B2274797065223A2263686F696365222C22696E737472"
        "756374696F6E73223A2257656C636865732050726F746F6B6F6C6C2062696574657420737472696B7465204661696C2D436C6F73656420"
        "476172616E7469656E3F222C226372697465726961223A7B22485454502F312E31223A6E756C6C2C224C694E65502056302E32223A6E75"
        "6C6C2C22576562536F636B6574223A6E756C6C7D7D7D7D000000000000000000";

    std::vector<std::uint8_t> golden_bytes = hex_to_bytes(golden_hex);
    LINEP_TEST_CHECK(golden_bytes.size() == 307);

    request_envelope req{};
    LINEP_TEST_CHECK(decode_request(golden_bytes.data(), golden_bytes.size(), req));

    // Verify header and stream
    LINEP_TEST_CHECK(req.stream.request_id == 1);
    LINEP_TEST_CHECK(req.stream.execution_id == 1);
    LINEP_TEST_CHECK(req.stream.output_id == 1);

    // Verify profile and model
    LINEP_TEST_CHECK(req.profile == runtime_profile::decision);
    LINEP_TEST_CHECK(req.model_id == "clef-decision:test");

    // Verify exact RAW-JSON payload (241 bytes)
    const std::string expected_json =
        R"({"model":"clef-decision:test","state":{"session_id":"test-c1-001"},"questions":{"q1":{"type":"choice","instructions":"Welches Protokoll bietet strikte Fail-Closed Garantien?","criteria":{"HTTP/1.1":null,"LiNeP V0.2":null,"WebSocket":null}}}})";
    LINEP_TEST_CHECK(req.payload.size() == 241);
    LINEP_TEST_CHECK(req.payload == expected_json);

    // Verify options and limits
    LINEP_TEST_CHECK(req.max_tokens == 0);
    LINEP_TEST_CHECK(req.temperature == 0.0f);
    LINEP_TEST_CHECK(!req.stream_requested);
    LINEP_TEST_CHECK(!req.has_options);

    // Re-encode and verify byte-for-byte identity with Golden Vector 1
    std::vector<std::uint8_t> encoded_bytes;
    LINEP_TEST_CHECK(encode_request(req, encoded_bytes));
    LINEP_TEST_CHECK(encoded_bytes.size() == 307);
    LINEP_TEST_CHECK(encoded_bytes == golden_bytes);

    std::cout << "  -> Passed Test 5 (Golden Vector 1: 307 bytes exact match)" << std::endl;
}

// ── Test 6: Golden Vector 2 (Noul Probability Event, SL1, 211 Bytes) ──────────
void test_golden_vector_2_event() {
    std::cout << "[Test 6] Testing Golden Vector 2 (SL1 Event DECISION_RESULT, 211 Bytes)..." << std::endl;

    const std::string golden_hex =
        "324C4E500002020101000000000000000100000000000000010000009B0000000100000000010000152FE0ECB29AEA0114A2E4D3A52B60"
        "1F01000000000000000E000000000000000000007C0000007B226D6F64656C223A22636C65662D6465636973696F6E3A74657374222C22"
        "616E7377657273223A7B227132223A7B2274797065223A226E6F756C222C226E6F756C223A302E393939357D7D2C227573616765223A7B"
        "22696E7075745F746F6B656E73223A33382C226F75747075745F746F6B656E73223A31357D7D00502B5450250600";

    std::vector<std::uint8_t> golden_bytes = hex_to_bytes(golden_hex);
    LINEP_TEST_CHECK(golden_bytes.size() == 211);

    // Decode event
    event_envelope evt{};
    LINEP_TEST_CHECK(decode_event(golden_bytes.data(), golden_bytes.size(), evt));

    // Verify stream identity
    LINEP_TEST_CHECK(evt.stream.request_id == 1);
    LINEP_TEST_CHECK(evt.stream.execution_id == 1);
    LINEP_TEST_CHECK(evt.stream.output_id == 1);

    // Verify event metadata
    LINEP_TEST_CHECK(evt.event_seq == 1);
    LINEP_TEST_CHECK(evt.event_type == runtime_event_type::decision_result);
    LINEP_TEST_CHECK(evt.outcome == terminal_outcome::unknown);
    LINEP_TEST_CHECK(evt.error.category == error_category::none);
    LINEP_TEST_CHECK(evt.error.code == 0);
    LINEP_TEST_CHECK(evt.error.message.empty());
    LINEP_TEST_CHECK(evt.error.backend_diagnostic.empty());

    // Verify exact RAW-JSON payload (124 bytes)
    const std::string expected_json =
        R"({"model":"clef-decision:test","answers":{"q2":{"type":"noul","noul":0.9995}},"usage":{"input_tokens":38,"output_tokens":15}})";
    LINEP_TEST_CHECK(evt.payload.size() == 124);
    LINEP_TEST_CHECK(evt.payload == expected_json);
    LINEP_TEST_CHECK(evt.timestamp_us == 1729876800000000ULL);

    // Verify SL1 MAC over canonical 80-byte prefix
    const std::vector<std::uint8_t> test_psk(32, 0x42);
    session_bind_envelope binding{};
    binding.identity.node_id = 1;
    binding.identity.runtime_id = 2;
    binding.identity.endpoint_id = 3;
    binding.control_epoch = 4;
    binding.lease_token = 5;
    binding.sl1_requested = true;
    binding.key_id = 0x0100;

    wire_auth_extension out_auth{};
    std::string err;
    LINEP_TEST_CHECK(verify_envelope_buffer(golden_bytes.data(), golden_bytes.size(),
                                            binding, message_direction::responder_to_initiator,
                                            test_psk.data(), test_psk.size(),
                                            out_auth, &err));

    LINEP_TEST_CHECK(out_auth.auth_seq == 1);
    LINEP_TEST_CHECK(out_auth.key_id == 0x0100);

    // Re-encode, sign, and verify byte-for-byte identity with Golden Vector 2
    std::vector<std::uint8_t> encoded_bytes;
    LINEP_TEST_CHECK(encode_event(evt, encoded_bytes));
    LINEP_TEST_CHECK(sign_envelope_buffer(encoded_bytes, binding,
                                          message_direction::responder_to_initiator,
                                          1, 0x0100, test_psk.data(), test_psk.size()));
    LINEP_TEST_CHECK(encoded_bytes.size() == 211);
    LINEP_TEST_CHECK(encoded_bytes == golden_bytes);

    std::cout << "  -> Passed Test 6 (Golden Vector 2: 211 bytes exact match with SL1)" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 DECISION Extension & Golden Vectors Unit Suite ===" << std::endl;
    test_wire_ids_and_invariants();
    test_positional_capabilities_pfad_a();
    test_oldpeer_fail_closed_invariants();
    test_runtime_registration_decision();
    test_golden_vector_1_request();
    test_golden_vector_2_event();
    std::cout << "ALL DECISION UNIT TESTS & GOLDEN VECTORS PASSED 100%!" << std::endl;
    return 0;
}
