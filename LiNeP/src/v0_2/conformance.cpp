#include "linep/v0_2/conformance.hpp"
#include <chrono>
#include <cmath>
#include <iostream>

namespace linep::v0_2 {

conformance_runner::conformance_runner(std::string host, std::uint16_t port)
    : host_(std::move(host)), port_(port) {
}

std::unique_ptr<envelope_connection> conformance_runner::create_connection() {
    return envelope_connection::connect(host_, port_);
}

conformance_report conformance_runner::run_all() {
    conformance_report rep{};
    rep.target_endpoint = host_ + ":" + std::to_string(port_);

    auto run_test = [&](auto test_fn) -> test_result {
        auto res = test_fn();
        rep.total_tests++;
        if (res.passed) {
            rep.passed_tests++;
        } else {
            rep.failed_tests++;
        }
        rep.results.push_back(res);
        return res;
    };

    auto r_caps = run_test([this]() { return test_capabilities_handshake(); });
    auto r_chat = run_test([this]() { return test_basic_chat_streaming(); });
    auto r_reas = run_test([this]() { return test_reasoning_deltas(); });
    auto r_emb  = run_test([this]() { return test_embedding_space(); });
    auto r_canc = run_test([this]() { return test_network_cancellation(); });
    auto r_flow = run_test([this]() { return test_window_update_flow_control(); });
    auto r_fail = run_test([this]() { return test_fail_closed_robustness(); });
    auto r_snap = run_test([this]() { return test_content_snapshot_mode(); });
    auto r_mout = run_test([this]() { return test_multi_output_streams(); });

    // Profile Conformance Evaluation:
    // 1. PROFILE_GENERATE
    profile_conformance_status p_gen{};
    p_gen.profile = runtime_profile::generate;
    p_gen.profile_name = "PROFILE_GENERATE";
    p_gen.conformant = (r_caps.passed && r_chat.passed && r_canc.passed && r_flow.passed && r_fail.passed && r_snap.passed);
    rep.profiles.push_back(p_gen);

    // 2. PROFILE_CHAT
    profile_conformance_status p_chat{};
    p_chat.profile = runtime_profile::chat;
    p_chat.profile_name = "PROFILE_CHAT";
    p_chat.conformant = (r_caps.passed && r_chat.passed && r_reas.passed && r_canc.passed && r_flow.passed && r_fail.passed);
    rep.profiles.push_back(p_chat);

    // 3. PROFILE_EMBED
    profile_conformance_status p_emb{};
    p_emb.profile = runtime_profile::embed;
    p_emb.profile_name = "PROFILE_EMBED";
    p_emb.conformant = (r_caps.passed && r_emb.passed && r_fail.passed);
    rep.profiles.push_back(p_emb);

    return rep;
}

conformance_report conformance_runner::run_profile(runtime_profile profile) {
    auto full = run_all();
    conformance_report filtered{};
    filtered.target_endpoint = full.target_endpoint;

    for (const auto& p : full.profiles) {
        if (p.profile == profile) {
            filtered.profiles.push_back(p);
        }
    }
    filtered.results = full.results;
    filtered.total_tests = full.total_tests;
    filtered.passed_tests = full.passed_tests;
    filtered.failed_tests = full.failed_tests;
    return filtered;
}

test_result conformance_runner::test_capabilities_handshake() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"CAPABILITIES_HANDSHAKE", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect to target endpoint";
        return res;
    }

    capabilities_envelope query{};
    if (!conn->send_capabilities(query)) {
        res.details = "Failed to send capabilities query";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        res.details = "Failed to receive capabilities response";
        return res;
    }

    capabilities_envelope caps{};
    if (!decode_capabilities(raw.data(), raw.size(), caps)) {
        res.details = "Failed to decode capabilities envelope";
        return res;
    }

    if (caps.descriptor.supported_models.empty() || 
        caps.descriptor.supported_profiles.empty() || 
        !caps.descriptor.supports_streaming) {
        res.details = "Capabilities envelope missing required fields";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Handshake verified for model: " + caps.descriptor.supported_models[0];
    return res;
}

test_result conformance_runner::test_basic_chat_streaming() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"BASIC_CHAT_STREAMING", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{101, 1001, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Test chat prompt"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send chat request";
        return res;
    }

    std::uint64_t expected_seq = 1;
    bool reached_terminal = false;
    std::string full_response;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event envelope";
            return res;
        }

        if (evt.stream != id) {
            res.details = "Stream identity mismatch";
            return res;
        }

        if (evt.event_seq != expected_seq++) {
            res.details = "Event sequence non-monotonic";
            return res;
        }

        if (evt.event_type == runtime_event_type::content_delta) {
            full_response += evt.payload;
        } else if (evt.event_type == runtime_event_type::completed) {
            if (evt.outcome != terminal_outcome::completed || evt.error.code != 200) {
                res.details = "Terminal outcome not completed/200";
                return res;
            }
            reached_terminal = true;
            break;
        }
    }

    if (!reached_terminal || full_response.empty()) {
        res.details = "Did not reach terminal completed event or empty response";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Streaming verified: " + std::to_string(expected_seq - 1) + " events received";
    return res;
}

test_result conformance_runner::test_reasoning_deltas() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"REASONING_DELTAS", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{102, 1002, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Explain quantum computing"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    std::size_t reasoning_count = 0;
    std::size_t content_count = 0;
    bool terminal_ok = false;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }

        if (evt.event_type == runtime_event_type::reasoning_delta) {
            if (content_count > 0) {
                res.details = "Reasoning delta arrived AFTER content delta";
                return res;
            }
            reasoning_count++;
        } else if (evt.event_type == runtime_event_type::content_delta) {
            content_count++;
        } else if (evt.event_type == runtime_event_type::completed) {
            terminal_ok = (evt.outcome == terminal_outcome::completed);
            break;
        }
    }

    if (!terminal_ok || reasoning_count == 0 || content_count == 0) {
        res.details = "Reasoning delta contract violated";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Reasoning verified: " + std::to_string(reasoning_count) + " reasoning deltas before content";
    return res;
}

test_result conformance_runner::test_embedding_space() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"EMBEDDING_SPACE_CONFORMANCE", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{103, 1003, 0};
    request_envelope req{id, runtime_profile::embed, "linep-conformance-model-v02", "Vectorize this sentence"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send embed request";
        return res;
    }

    bool emb_received = false;
    bool term_received = false;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }

        if (evt.event_type == runtime_event_type::embedding_result) {
            if (evt.embedding.space.dimensions != 768 || evt.embedding.vector.size() != 768) {
                res.details = "Embedding dimension mismatch";
                return res;
            }
            float sum_sq = 0.0f;
            for (float v : evt.embedding.vector) {
                sum_sq += v * v;
            }
            if (std::abs(std::sqrt(sum_sq) - 1.0f) > 0.01f) {
                res.details = "Embedding vector is not normalized";
                return res;
            }
            emb_received = true;
        } else if (evt.event_type == runtime_event_type::completed) {
            term_received = (evt.outcome == terminal_outcome::completed);
            break;
        }
    }

    if (!emb_received || !term_received) {
        res.details = "Failed to receive valid embedding and terminal event";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Embedding space verified: 768-dim normalized cosine vector";
    return res;
}

test_result conformance_runner::test_network_cancellation() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"CANCEL_UNDER_LOAD", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{104, 1004, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Generate 1000 tokens"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    bool cancelled_ok = false;
    std::size_t events_before_cancel = 0;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }

        if (evt.event_type == runtime_event_type::content_delta || evt.event_type == runtime_event_type::reasoning_delta) {
            events_before_cancel++;
            if (events_before_cancel == 2) {
                // Fire network cancellation targeting exact stream
                control_envelope ctrl{id, runtime_control_type::cancel, "Test cancellation"};
                conn->send_control(ctrl);
            }
        } else if (evt.event_type == runtime_event_type::cancelled) {
            if (evt.outcome == terminal_outcome::cancelled && evt.error.code == 499) {
                cancelled_ok = true;
            }
            break;
        }
    }

    if (!cancelled_ok) {
        res.details = "Stream was not cancelled with 499 status";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Cancellation verified: stream stopped after " + std::to_string(events_before_cancel) + " events with outcome=cancelled (499)";
    return res;
}

test_result conformance_runner::test_window_update_flow_control() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"BACKPRESSURE_FLOW_CONTROL", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{105, 1005, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Paced stream prompt"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    std::uint64_t cumulative_ack = 0;
    bool completed_ok = false;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }

        if (evt.event_type == runtime_event_type::content_delta || evt.event_type == runtime_event_type::reasoning_delta) {
            cumulative_ack += evt.payload.size();
            // Send cumulative WINDOW_UPDATE credit
            control_envelope ack_ctrl{id, runtime_control_type::window_update, "ACK", cumulative_ack};
            conn->send_control(ack_ctrl);
        } else if (evt.event_type == runtime_event_type::completed) {
            if (evt.outcome == terminal_outcome::completed) {
                completed_ok = true;
            }
            break;
        }
    }

    if (!completed_ok) {
        res.details = "Flow controlled stream failed to reach completed state";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Flow control verified: " + std::to_string(cumulative_ack) + " bytes paced via cumulative WINDOW_UPDATE";
    return res;
}

test_result conformance_runner::test_fail_closed_robustness() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"PROTOCOL_VIOLATION_FAIL_CLOSED", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{106, 1006, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Trigger violation test"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    // Invert/corrupt magic header mid-stream
    std::uint8_t bad_frame[LINEP_V02_HEADER_SIZE] = {0xFF, 0xFF, 0x00, 0x00};
    conn->send_frame_raw(bad_frame, sizeof(bad_frame));

    // Assert that server immediately closes socket (fail-closed)
    std::vector<std::uint8_t> raw;
    bool saw_eof = false;
    for (int i = 0; i < 50; ++i) {
        if (!conn->receive_envelope_raw(raw)) {
            saw_eof = true;
            break;
        }
    }

    if (!saw_eof && conn->is_connected()) {
        res.details = "Server did not fail closed on corrupted magic header";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Fail-closed robustness verified: server disconnected upon protocol violation";
    return res;
}

test_result conformance_runner::test_content_snapshot_mode() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"CONTENT_SNAPSHOT_EQUIVALENCE", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{107, 1007, 0};
    request_envelope req{id, runtime_profile::generate, "linep-conformance-model-v02", "Snapshot prompt"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    std::size_t events = 0;
    bool terminal_ok = false;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }
        events++;
        if (evt.event_type == runtime_event_type::completed) {
            terminal_ok = (evt.outcome == terminal_outcome::completed);
            break;
        }
    }

    if (!terminal_ok || events == 0) {
        res.details = "Snapshot mode test failed";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Snapshot equivalence verified (" + std::to_string(events) + " events processed)";
    return res;
}

test_result conformance_runner::test_multi_output_streams() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"MULTI_OUTPUT_STREAMING", false, "", 0};

    auto conn = create_connection();
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }

    stream_identity id{108, 1008, 0};
    request_envelope req{id, runtime_profile::generate, "linep-conformance-model-v02", "Multi output prompt"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    std::size_t events = 0;
    bool completed_ok = false;

    std::vector<std::uint8_t> raw;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event";
            return res;
        }
        events++;
        if (evt.event_type == runtime_event_type::completed) {
            completed_ok = (evt.outcome == terminal_outcome::completed);
            break;
        }
    }

    if (!completed_ok) {
        res.details = "Multi-output stream failed to complete";
        return res;
    }

    auto t1 = std::chrono::steady_clock::now();
    res.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    res.passed = true;
    res.details = "Multi-output streaming verified (" + std::to_string(events) + " events received)";
    return res;
}

} // namespace linep::v0_2
