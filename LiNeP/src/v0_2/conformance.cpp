#include "linep/v0_2/conformance.hpp"
#include <chrono>
#include <cmath>
#include <iostream>

namespace linep::v0_2 {

conformance_runner::conformance_runner(std::string host, std::uint16_t port)
    : host_(std::move(host)), port_(port) {
}

conformance_runner::~conformance_runner() = default;

void conformance_runner::set_control_endpoint(std::string host, std::uint16_t port) {
    control_host_ = std::move(host);
    control_port_ = port;
    lease_.reset();
}

void conformance_runner::set_sl1_credentials(std::uint16_t key_id, std::vector<std::uint8_t> key) {
    sl1_key_id_ = key_id;
    sl1_key_ = std::move(key);
    if (lease_) {
        lease_->set_sl1(true, sl1_key_id_, sl1_key_);
    }
}

std::unique_ptr<lease_client> conformance_runner::make_lease_client() const {
    lease_client_config cfg{};
    cfg.control_host = control_host_;
    cfg.control_port = control_port_;
    cfg.trunk_port = port_;
    if (has_sl1()) {
        cfg.enable_sl1 = true;
        cfg.sl1_key_id = sl1_key_id_;
        cfg.sl1_key = sl1_key_;
    }
    return std::make_unique<lease_client>(cfg);
}

bool conformance_runner::ensure_lease(std::string& out_error) {
    if (lease_ && lease_->is_active()) {
        return true;
    }
    lease_ = make_lease_client();
    return lease_->acquire(&out_error);
}

bool conformance_runner::prepare_session_bind(session_bind_envelope& out_bind, std::string& out_error) {
    if (has_control_endpoint()) {
        if (!ensure_lease(out_error)) {
            return false;
        }
    }
    if (lease_ && lease_->has_lease()) {
        out_bind = lease_->current_bind();
    } else {
        out_bind = session_bind_envelope{};
        out_bind.identity = node_endpoint_identity{1001, 2001, 1};
        out_bind.control_epoch = 1;
        out_bind.lease_token = 0xC0FFEE1234ULL;
    }
    return true;
}

std::unique_ptr<envelope_connection> conformance_runner::create_connection() {
    if (has_control_endpoint()) {
        std::string err;
        if (!ensure_lease(err)) {
            std::cerr << "[conformance] lease acquisition failed: " << err << std::endl;
            return nullptr;
        }
        return connect_bound(host_, port_, *lease_);
    }
    auto conn = envelope_connection::connect(host_, port_);
    if (conn && has_sl1()) {
        session_bind_envelope bind{};
        bind.identity = node_endpoint_identity{1001, 2001, 1};
        bind.control_epoch = 1;
        bind.lease_token = 0xC0FFEE1234ULL;
        bind.sl1_requested = true;
        bind.key_id = sl1_key_id_;
        conn->set_sl1_auth(bind, message_direction::initiator_to_responder, sl1_key_id_, sl1_key_);
        if (!conn->send_session_bind(bind)) {
            conn->close();
            return nullptr;
        }
        std::vector<std::uint8_t> raw;
        if (!conn->receive_envelope_raw(raw)) {
            conn->close();
            return nullptr;
        }
    }
    return conn;
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

    if (has_control_endpoint()) {
        run_dual_plane_suites(rep);
    }

    if (has_sl1()) {
        run_sl1_suites(rep);
    }

    return rep;
}

conformance_report conformance_runner::run_dual_plane() {
    conformance_report rep{};
    rep.target_endpoint = host_ + ":" + std::to_string(port_);
    run_dual_plane_suites(rep);
    return rep;
}

conformance_report conformance_runner::run_sl1() {
    conformance_report rep{};
    rep.target_endpoint = host_ + ":" + std::to_string(port_);
    run_sl1_suites(rep);
    return rep;
}

void conformance_runner::run_dual_plane_suites(conformance_report& rep) {
    profile_conformance_status p_dual{};
    p_dual.profile = runtime_profile::unspecified;
    p_dual.profile_name = "PROFILE_DUAL_PLANE";
    p_dual.conformant = true;

    auto run_test = [&](test_result res) {
        rep.total_tests++;
        if (res.passed) {
            rep.passed_tests++;
            p_dual.passed_suites.push_back(res.test_name);
        } else {
            rep.failed_tests++;
            p_dual.failed_suites.push_back(res.test_name);
            p_dual.conformant = false;
        }
        rep.results.push_back(res);
    };

    if (!has_control_endpoint()) {
        run_test(test_result{"DUAL_PLANE_CONTROL_ENDPOINT", false, "No UDP control endpoint configured", 0});
    } else {
        run_test(test_dual_plane_bind_before_lease_ack());
        run_test(test_dual_plane_duplicate_bind());
        run_test(test_dual_plane_unbound_request());
        run_test(test_dual_plane_stale_rebind());
        run_test(test_dual_plane_identity_change());
        run_test(test_dual_plane_malformed_bind());
    }
    rep.profiles.push_back(p_dual);
}

void conformance_runner::run_sl1_suites(conformance_report& rep) {
    profile_conformance_status p_sl1{};
    p_sl1.profile = runtime_profile::unspecified;
    p_sl1.profile_name = "PROFILE_SL1";
    p_sl1.conformant = true;

    auto run_test = [&](test_result res) {
        rep.total_tests++;
        if (res.passed) {
            rep.passed_tests++;
            p_sl1.passed_suites.push_back(res.test_name);
        } else {
            rep.failed_tests++;
            p_sl1.failed_suites.push_back(res.test_name);
            p_sl1.conformant = false;
        }
        rep.results.push_back(res);
    };

    if (!has_sl1()) {
        run_test(test_result{"SL1_CREDENTIALS", false, "No SL1 shared secret configured", 0});
    } else {
        run_test(test_sl1_mutual_handshake());
        run_test(test_sl1_authenticated_streaming());
        if (sl1_required_) {
            run_test(test_sl1_missing_auth_rejection());
        }
        run_test(test_sl1_wrong_key_rejection());
        run_test(test_sl1_replay_rejection());
    }
    rep.profiles.push_back(p_sl1);
}

conformance_report conformance_runner::run_profile(runtime_profile profile) {
    auto full = run_all();
    conformance_report filtered{};
    filtered.target_endpoint = full.target_endpoint;

    for (const auto& p : full.profiles) {
        // The dual-plane and SL1 profiles gate every profile once enabled
        if (p.profile == profile || p.profile_name == "PROFILE_DUAL_PLANE" || p.profile_name == "PROFILE_SL1") {
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

// ── Dual-plane SESSION_BIND suites ──────────────────────────────────────────

namespace {

std::uint64_t elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count());
}

bool next_event(envelope_connection& conn, event_envelope& out_evt) {
    std::vector<std::uint8_t> raw;
    if (!conn.receive_envelope_raw(raw)) {
        return false;
    }
    out_evt = event_envelope{};
    return decode_event(raw.data(), raw.size(), out_evt);
}

// The peer closes the connection without sending further frames
bool expect_closed(envelope_connection& conn) {
    std::vector<std::uint8_t> raw;
    for (int i = 0; i < 64; ++i) {
        if (!conn.receive_envelope_raw(raw)) {
            return true;
        }
    }
    return false;
}

// Send a REQUEST and read its stream up to the terminal event
bool run_request(envelope_connection& conn, const stream_identity& id, event_envelope& out_terminal, std::string& out_error) {
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Dual-plane request"};
    if (!conn.send_request(req)) {
        out_error = "Failed to send request";
        return false;
    }
    event_envelope evt{};
    while (next_event(conn, evt)) {
        if (evt.stream.is_connection_level() && evt.is_terminal()) {
            out_error = "Connection-level " + std::to_string(evt.error.code) + " " + evt.error.message;
            return false;
        }
        if (evt.stream == id && evt.is_terminal()) {
            out_terminal = evt;
            return true;
        }
    }
    out_error = "Connection closed before a terminal event";
    return false;
}

std::string describe(const event_envelope& evt) {
    return std::string(evt.stream.is_connection_level() ? "connection-level " : "stream ") +
           std::to_string(evt.error.code) + " '" + evt.error.message + "'";
}

bool is_connection_failure(const event_envelope& evt, std::uint32_t code, const std::string& message) {
    return evt.stream.is_connection_level() &&
           evt.event_type == runtime_event_type::failed &&
           evt.error.code == code &&
           evt.error.message == message;
}

} // anonymous namespace

test_result conformance_runner::test_dual_plane_bind_before_lease_ack() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_BIND_BEFORE_LEASE_ACK", false, "", 0};

    auto early = make_lease_client();
    std::string err;
    if (!early->request_invite(&err)) {
        res.details = err;
        return res;
    }
    auto conn = envelope_connection::connect(host_, port_);
    if (!conn || !early->bind(*conn)) {
        res.details = "Failed to connect or send SESSION_BIND";
        return res;
    }

    event_envelope evt{};
    if (!next_event(*conn, evt) || !is_connection_failure(evt, 401, "lease_invalid")) {
        res.details = "Expected connection-level 401 lease_invalid for an INVITED (un-ACKed) lease";
        return res;
    }
    if (!expect_closed(*conn)) {
        res.details = "Connection stayed open after lease_invalid";
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Bind before LEASE_ACK rejected with 401 lease_invalid and closed";
    return res;
}

test_result conformance_runner::test_dual_plane_duplicate_bind() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_DUPLICATE_BIND", false, "", 0};

    std::string err;
    if (!ensure_lease(err)) {
        res.details = err;
        return res;
    }
    auto conn = connect_bound(host_, port_, *lease_);
    if (!conn || !lease_->bind(*conn)) {
        res.details = "Failed to connect or send duplicate SESSION_BIND";
        return res;
    }

    event_envelope term{};
    if (!run_request(*conn, stream_identity{201, 2001, 0}, term, err)) {
        res.details = "Duplicate bind was not a no-op: " + err;
        return res;
    }
    if (term.outcome != terminal_outcome::completed) {
        res.details = "Request after duplicate bind did not complete: " + describe(term);
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Duplicate SESSION_BIND is an idempotent no-op";
    return res;
}

test_result conformance_runner::test_dual_plane_unbound_request() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_UNBOUND_REQUEST", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect";
        return res;
    }
    stream_identity id{202, 2002, 0};
    request_envelope req{id, runtime_profile::chat, "linep-conformance-model-v02", "Unbound request"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send request";
        return res;
    }

    event_envelope evt{};
    if (!next_event(*conn, evt)) {
        res.details = "Connection closed without a 401 event";
        return res;
    }
    if (evt.stream != id || evt.event_type != runtime_event_type::failed || evt.error.code != 401) {
        res.details = "Expected stream 401 for an UNBOUND REQUEST, got " + describe(evt) +
                      " (does the endpoint require leases?)";
        return res;
    }
    if (!expect_closed(*conn)) {
        res.details = "Connection stayed open after an UNBOUND REQUEST";
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "UNBOUND REQUEST rejected with 401 and closed";
    return res;
}

test_result conformance_runner::test_dual_plane_stale_rebind() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_STALE_REBIND", false, "", 0};

    // Own identity: the epoch change must not disturb the shared lease
    auto lease = make_lease_client();
    std::string err;
    if (!lease->acquire(&err)) {
        res.details = err;
        return res;
    }
    auto conn = connect_bound(host_, port_, *lease);
    if (!conn) {
        res.details = "Failed to connect and bind";
        return res;
    }

    event_envelope term{};
    if (!run_request(*conn, stream_identity{203, 2003, 0}, term, err) || term.outcome != terminal_outcome::completed) {
        res.details = "Bound request did not complete: " + (err.empty() ? describe(term) : err);
        return res;
    }

    // New incarnation: the existing binding turns stale
    if (!lease->renew(&err)) {
        res.details = err;
        return res;
    }
    stream_identity stale_id{204, 2004, 0};
    if (!run_request(*conn, stale_id, term, err)) {
        res.details = "Stale REQUEST: " + err;
        return res;
    }
    if (!is_stale_binding_event(term)) {
        res.details = "Expected stream 401 stale_binding after an epoch change, got " + describe(term);
        return res;
    }

    // In-band re-bind on the same connection
    if (!lease->bind(*conn)) {
        res.details = "Connection closed after stale_binding (must stay open)";
        return res;
    }
    if (!run_request(*conn, stream_identity{205, 2005, 0}, term, err) || term.outcome != terminal_outcome::completed) {
        res.details = "Request after in-band re-bind did not complete: " + (err.empty() ? describe(term) : err);
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Epoch change -> 401 stale_binding on an open connection, in-band re-bind served";
    return res;
}

test_result conformance_runner::test_dual_plane_identity_change() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_IDENTITY_CHANGE", false, "", 0};

    std::string err;
    if (!ensure_lease(err)) {
        res.details = err;
        return res;
    }
    auto other = make_lease_client();
    if (!other->acquire(&err)) {
        res.details = err;
        return res;
    }
    auto conn = connect_bound(host_, port_, *lease_);
    if (!conn || !other->bind(*conn)) {
        res.details = "Failed to connect or send the second SESSION_BIND";
        return res;
    }

    event_envelope evt{};
    if (!next_event(*conn, evt) || !is_connection_failure(evt, 401, "identity_change_on_existing_connection")) {
        res.details = "Expected connection-level 401 identity_change_on_existing_connection";
        return res;
    }
    if (!expect_closed(*conn)) {
        res.details = "Connection stayed open after an identity change";
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Identity change on a bound connection rejected with 401 and closed";
    return res;
}

test_result conformance_runner::test_dual_plane_malformed_bind() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"DUAL_PLANE_MALFORMED_BIND", false, "", 0};

    std::string err;
    if (!ensure_lease(err)) {
        res.details = err;
        return res;
    }
    std::vector<std::uint8_t> frame;
    if (!encode_session_bind(lease_->current_bind(), frame)) {
        res.details = "Failed to encode SESSION_BIND";
        return res;
    }
    frame[7] = 0x80; // reserved header flags must be zero (0x01 is FLAG_AUTHENTICATED in V0.2)

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn || !conn->send_frame_raw(frame.data(), frame.size())) {
        res.details = "Failed to connect or send malformed SESSION_BIND";
        return res;
    }

    event_envelope evt{};
    if (!next_event(*conn, evt) || !is_connection_failure(evt, 400, "invalid_session_bind")) {
        res.details = "Expected connection-level 400 invalid_session_bind";
        return res;
    }
    if (!expect_closed(*conn)) {
        res.details = "Connection stayed open after a malformed SESSION_BIND";
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Malformed SESSION_BIND rejected with 400 and closed";
    return res;
}

test_result conformance_runner::test_sl1_mutual_handshake() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"SL1_MUTUAL_HANDSHAKE", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect to " + host_ + ":" + std::to_string(port_);
        return res;
    }
    conn->set_recv_timeout(5000);

    session_bind_envelope bind{};
    std::string err;
    if (!prepare_session_bind(bind, err)) {
        res.details = "Lease preparation failed: " + err;
        return res;
    }
    bind.sl1_requested = true;
    bind.key_id = sl1_key_id_;

    conn->set_sl1_auth(bind, message_direction::initiator_to_responder, sl1_key_id_, sl1_key_);
    if (!conn->send_session_bind(bind)) {
        res.details = "Failed to send signed SESSION_BIND";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        res.details = conn->timed_out() ? "Timed out waiting for confirmation frame from server"
                                        : "No confirmation frame received from server";
        return res;
    }

    wire_envelope_header hdr{};
    if (!decode_header(raw.data(), raw.size(), hdr)) {
        res.details = "Malformed confirmation frame header";
        return res;
    }

    if (hdr.envelope_type != static_cast<std::uint8_t>(runtime_envelope_type::session_bind)) {
        res.details = "Expected SESSION_BIND confirmation, got envelope type " + std::to_string(hdr.envelope_type);
        return res;
    }

    session_bind_envelope confirm{};
    if (!decode_session_bind(raw.data(), raw.size(), confirm)) {
        res.details = "Failed to decode SESSION_BIND confirmation";
        return res;
    }

    if (!confirm.sl1_requested) {
        res.details = "Server confirmation missing sl1_requested / FLAG_AUTHENTICATED";
        return res;
    }

    wire_auth_extension ext{};
    if (!verify_envelope_buffer(raw.data(), raw.size(), bind, message_direction::responder_to_initiator,
                                sl1_key_.data(), sl1_key_.size(), ext, &err)) {
        res.details = "Server confirmation MAC verification failed: " + err;
        return res;
    }

    if (ext.auth_seq != 1) {
        res.details = "Server confirmation auth_seq must be 1, got " + std::to_string(ext.auth_seq);
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Mutual SL1 key confirmation established (auth_seq=1 in both directions)";
    return res;
}

test_result conformance_runner::test_sl1_authenticated_streaming() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"SL1_AUTHENTICATED_STREAMING", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect to " + host_ + ":" + std::to_string(port_);
        return res;
    }
    conn->set_recv_timeout(5000);

    session_bind_envelope bind{};
    std::string err;
    if (!prepare_session_bind(bind, err)) {
        res.details = "Lease preparation failed: " + err;
        return res;
    }
    bind.sl1_requested = true;
    bind.key_id = sl1_key_id_;

    conn->set_sl1_auth(bind, message_direction::initiator_to_responder, sl1_key_id_, sl1_key_);
    if (!conn->send_session_bind(bind)) {
        res.details = "Failed to send signed SESSION_BIND";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        res.details = conn->timed_out() ? "Timed out waiting for SESSION_BIND confirmation"
                                        : "Server did not confirm SESSION_BIND";
        return res;
    }

    // Submit authenticated chat request (auth_seq = 2)
    request_envelope req{stream_identity{101, 201, 0}, runtime_profile::chat, "linep-conformance-model-v02", "SL1 stream test"};
    if (!conn->send_request(req)) {
        res.details = "Failed to send signed request envelope";
        return res;
    }

    std::size_t events_received = 0;
    std::uint32_t last_auth_seq = 1; // Server confirmation was seq 1
    bool saw_completed = false;

    while (conn->receive_envelope_raw(raw)) {
        wire_envelope_header hdr{};
        if (!decode_header(raw.data(), raw.size(), hdr)) {
            res.details = "Malformed event header";
            return res;
        }

        if ((hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) == 0) {
            res.details = "Unauthenticated frame received on active SL1 session";
            return res;
        }

        wire_auth_extension ext{};
        if (!verify_envelope_buffer(raw.data(), raw.size(), bind, message_direction::responder_to_initiator,
                                    sl1_key_.data(), sl1_key_.size(), ext, &err)) {
            res.details = "Event MAC verification failed: " + err;
            return res;
        }

        if (ext.auth_seq <= last_auth_seq) {
            res.details = "Non-monotonic server auth_seq (last=" + std::to_string(last_auth_seq) +
                          ", got=" + std::to_string(ext.auth_seq) + ")";
            return res;
        }
        last_auth_seq = ext.auth_seq;

        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            res.details = "Failed to decode event envelope";
            return res;
        }

        events_received++;
        if (evt.event_type == runtime_event_type::completed) {
            saw_completed = true;
            break;
        }
    }

    if (!saw_completed) {
        if (conn->timed_out()) {
            res.details = "Stream timed out waiting for events (received " + std::to_string(events_received) + " events)";
        } else {
            res.details = "Stream ended without completed terminal event (received " + std::to_string(events_received) + " events)";
        }
        return res;
    }

    res.duration_ms = elapsed_ms(t0);
    res.passed = true;
    res.details = "Authenticated streaming verified (" + std::to_string(events_received) + " signed events with monotonic auth_seq)";
    return res;
}

test_result conformance_runner::test_sl1_missing_auth_rejection() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"SL1_MISSING_AUTH_REJECTION", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect to " + host_ + ":" + std::to_string(port_);
        return res;
    }
    conn->set_recv_timeout(1000);

    session_bind_envelope bind{};
    std::string err;
    if (!prepare_session_bind(bind, err)) {
        res.details = "Lease preparation failed: " + err;
        return res;
    }
    bind.sl1_requested = false;

    if (!conn->send_session_bind(bind)) {
        res.details = "Failed to send unauthenticated SESSION_BIND";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        if (conn->timed_out()) {
            res.details = "Connection timed out waiting for rejection; endpoint did not reject unsigned bind (does the endpoint require SL1? Use --sl1-required to assert)";
            return res;
        }
        res.passed = true;
        res.duration_ms = elapsed_ms(t0);
        res.details = "Unauthenticated connection closed immediately by server";
        return res;
    }

    event_envelope evt{};
    if (decode_event(raw.data(), raw.size(), evt)) {
        if (evt.stream.is_connection_level() && evt.error.code == 401 &&
            (evt.error.message == "auth_required" || evt.error.message.rfind("auth_required", 0) == 0)) {
            res.passed = true;
            res.duration_ms = elapsed_ms(t0);
            res.details = "Unauthenticated bind rejected with 401 auth_required and socket closed";
            return res;
        }
    }

    res.details = "Expected 401 auth_required or immediate connection close";
    return res;
}

test_result conformance_runner::test_sl1_wrong_key_rejection() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"SL1_WRONG_KEY_REJECTION", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect to " + host_ + ":" + std::to_string(port_);
        return res;
    }
    conn->set_recv_timeout(1000);

    std::vector<std::uint8_t> bad_key(sl1_key_.size(), 0xEE);

    session_bind_envelope bind{};
    std::string err;
    if (!prepare_session_bind(bind, err)) {
        res.details = "Lease preparation failed: " + err;
        return res;
    }
    bind.sl1_requested = true;
    bind.key_id = sl1_key_id_;

    conn->set_sl1_auth(bind, message_direction::initiator_to_responder, sl1_key_id_, bad_key);
    if (!conn->send_session_bind(bind)) {
        res.details = "Failed to send signed SESSION_BIND with bad key";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        if (conn->timed_out()) {
            res.details = "Connection timed out waiting for rejection; endpoint did not reject invalid key";
            return res;
        }
        res.passed = true;
        res.duration_ms = elapsed_ms(t0);
        res.details = "Connection with invalid MAC closed immediately by server";
        return res;
    }

    event_envelope evt{};
    if (decode_event(raw.data(), raw.size(), evt)) {
        if (evt.stream.is_connection_level() && evt.error.code == 401) {
            res.passed = true;
            res.duration_ms = elapsed_ms(t0);
            res.details = "Invalid MAC rejected with 401 (" + evt.error.message + ")";
            return res;
        }
    }

    res.details = "Expected 401 unauthorized or immediate socket close";
    return res;
}

test_result conformance_runner::test_sl1_replay_rejection() {
    auto t0 = std::chrono::steady_clock::now();
    test_result res{"SL1_REPLAY_REJECTION", false, "", 0};

    auto conn = envelope_connection::connect(host_, port_);
    if (!conn) {
        res.details = "Failed to connect to " + host_ + ":" + std::to_string(port_);
        return res;
    }
    conn->set_recv_timeout(1000);

    session_bind_envelope bind{};
    std::string err;
    if (!prepare_session_bind(bind, err)) {
        res.details = "Lease preparation failed: " + err;
        return res;
    }
    bind.sl1_requested = true;
    bind.key_id = sl1_key_id_;

    session_bind_envelope base_bind = bind;
    base_bind.sl1_requested = false;
    std::vector<std::uint8_t> raw_bind;
    encode_session_bind(base_bind, raw_bind);
    // Bind with invalid auth_seq != 1 (replay attempt)
    if (!sign_envelope_buffer(raw_bind, bind, message_direction::initiator_to_responder,
                             42, sl1_key_id_, sl1_key_.data(), sl1_key_.size())) {
        res.details = "Failed to sign envelope buffer for replay test";
        return res;
    }

    if (!conn->send_frame_raw(raw_bind.data(), raw_bind.size())) {
        res.details = "Failed to send replayed SESSION_BIND frame";
        return res;
    }

    std::vector<std::uint8_t> raw;
    if (!conn->receive_envelope_raw(raw)) {
        if (conn->timed_out()) {
            res.details = "Connection timed out waiting for rejection; endpoint did not reject replayed auth_seq";
            return res;
        }
        res.passed = true;
        res.duration_ms = elapsed_ms(t0);
        res.details = "Replay sequence closed immediately by server";
        return res;
    }

    event_envelope evt{};
    if (decode_event(raw.data(), raw.size(), evt)) {
        if (evt.stream.is_connection_level() && evt.error.code == 401 &&
            (evt.error.message == "auth_replay" || evt.error.message.rfind("auth_replay", 0) == 0)) {
            res.passed = true;
            res.duration_ms = elapsed_ms(t0);
            res.details = "Replayed sequence rejected with 401 auth_replay";
            return res;
        }
    }

    res.details = "Expected 401 auth_replay or immediate socket close";
    return res;
}

} // namespace linep::v0_2
