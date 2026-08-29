#include "linep/v0_2/mock_runtime.hpp"
#include <chrono>
#include <cmath>
#include <iostream>
#include <sstream>

namespace linep::v0_2 {

mock_runtime_server::mock_runtime_server(mock_runtime_config config)
    : config_(std::move(config)) {
}

mock_runtime_server::~mock_runtime_server() {
    stop();
}

bool mock_runtime_server::start(std::uint16_t port) {
    stop();
    if (!server_.listen(port)) {
        return false;
    }
    running_ = true;
    accept_thread_ = std::thread(&mock_runtime_server::accept_loop, this);
    return true;
}

void mock_runtime_server::stop() {
    if (running_.exchange(false)) {
        std::uint16_t p = server_.get_bound_port();
        if (p > 0) {
            // Wake up blocking accept() BEFORE closing listen socket
            auto dummy = envelope_connection::connect("127.0.0.1", p, 50);
        }
        server_.close();
        {
            std::lock_guard<std::mutex> lock(conns_mutex_);
            for (auto& c : active_conns_) {
                if (c) {
                    c->close();
                }
            }
            active_conns_.clear();
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    }
}

void mock_runtime_server::accept_loop() {
    std::vector<std::thread> client_threads;
    while (running_) {
        auto conn_unique = server_.accept_connection();
        if (!conn_unique) {
            break;
        }
        if (!running_) {
            conn_unique->close();
            break;
        }
        std::shared_ptr<envelope_connection> conn = std::move(conn_unique);
        {
            std::lock_guard<std::mutex> lock(conns_mutex_);
            active_conns_.push_back(conn);
        }
        client_threads.emplace_back(&mock_runtime_server::client_loop, this, conn);
    }
    for (auto& t : client_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void mock_runtime_server::client_loop(std::shared_ptr<envelope_connection> conn) {
    session_descriptor desc{};
    desc.limits.max_buffered_bytes_per_stream = config_.max_buffered_bytes_per_stream;
    session_manager session(desc);

    std::vector<std::thread> workers;
    std::vector<std::uint8_t> raw;

    while (running_ && conn->is_connected()) {
        if (config_.slow_reader) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (!conn->receive_envelope_raw(raw)) {
            break;
        }
        if (raw.size() < LINEP_V02_HEADER_SIZE) {
            break;
        }

        wire_envelope_header hdr{};
        if (!decode_header(raw.data(), raw.size(), hdr)) {
            break;
        }

        if (hdr.envelope_type == static_cast<std::uint8_t>(runtime_envelope_type::request)) {
            request_envelope req{};
            if (decode_request(raw.data(), raw.size(), req)) {
                runtime_error err{};
                if (session.submit_request(req, err)) {
                    workers.emplace_back(&mock_runtime_server::execute_stream, this, conn, std::ref(session), req);
                } else {
                    event_envelope fail_evt{req.stream, 1, runtime_event_type::failed, "Request rejected", terminal_outcome::failed};
                    fail_evt.error.code = 400;
                    conn->send_event(fail_evt);
                }
            }
        } else if (hdr.envelope_type == static_cast<std::uint8_t>(runtime_envelope_type::control)) {
            control_envelope ctrl{};
            if (decode_control(raw.data(), raw.size(), ctrl)) {
                runtime_error err{};
                session.process_control(ctrl, err);
            }
        } else if (hdr.envelope_type == static_cast<std::uint8_t>(runtime_envelope_type::capabilities)) {
            capabilities_envelope caps{};
            caps.descriptor.supported_models.push_back(config_.model_id);
            caps.descriptor.supported_profiles.push_back(runtime_profile::generate);
            caps.descriptor.supported_profiles.push_back(runtime_profile::chat);
            caps.descriptor.supported_profiles.push_back(runtime_profile::embed);
            caps.descriptor.supports_streaming = true;
            caps.descriptor.supports_cancellation = true;
            caps.descriptor.supports_reasoning_deltas = config_.enable_reasoning;

            embedding_space_descriptor emb_space{};
            emb_space.embedding_space_id = config_.embedding_space_id;
            emb_space.model_id = config_.model_id;
            emb_space.dimensions = config_.embedding_dimensions;
            emb_space.normalization = embedding_normalization::l2;
            emb_space.distance_metric = embedding_distance_metric::cosine;
            caps.descriptor.supported_embedding_spaces.push_back(emb_space);

            conn->send_capabilities(caps);
        }
    }

    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }
    conn->close();
}

void mock_runtime_server::execute_stream(std::shared_ptr<envelope_connection> conn, session_manager& session, const request_envelope& req) {
    if (config_.cancel_after_accept) {
        runtime_error err{};
        event_envelope cancel_evt{req.stream, 1, runtime_event_type::cancelled, "Cancelled after accept", terminal_outcome::cancelled};
        cancel_evt.error.code = 499;
        session.dispatch_event(cancel_evt, err);
        conn->send_event(cancel_evt);
        return;
    }

    std::uint32_t outputs = (config_.multi_output_count > 0) ? config_.multi_output_count : 1;
    for (std::uint32_t out_idx = 0; out_idx < outputs; ++out_idx) {
        execute_single_output(conn, session, req, out_idx);
    }
}

void mock_runtime_server::execute_single_output(std::shared_ptr<envelope_connection> conn, session_manager& session, const request_envelope& req, output_id_t output_id) {
    stream_identity stream_id = req.stream;
    stream_id.output_id = output_id;

    std::uint64_t seq = 1;
    runtime_error err{};
    int emitted_events = 0;

    auto check_cancel = [&]() -> bool {
        if (!running_ || !conn->is_connected()) {
            return true;
        }
        if (config_.ignore_cancel) {
            return false;
        }
        return session.is_cancel_requested(stream_id);
    };

    if (req.profile == runtime_profile::embed) {
        std::size_t batch_size = (config_.batch_embed_count > 0) ? config_.batch_embed_count : 1;
        for (std::size_t b = 0; b < batch_size; ++b) {
            stream_identity batch_stream = stream_id;
            batch_stream.output_id = static_cast<output_id_t>(b);

            event_envelope emb_evt{batch_stream, seq++, runtime_event_type::embedding_result};
            emb_evt.embedding.space.embedding_space_id = config_.embedding_space_id;
            emb_evt.embedding.space.model_id = config_.model_id;
            emb_evt.embedding.space.dimensions = config_.embedding_dimensions;
            emb_evt.embedding.space.normalization = embedding_normalization::l2;
            emb_evt.embedding.space.distance_metric = embedding_distance_metric::cosine;
            emb_evt.embedding.vector.resize(config_.embedding_dimensions);

            float sum_sq = 0.0f;
            for (std::uint32_t i = 0; i < config_.embedding_dimensions; ++i) {
                float val = std::sin(static_cast<float>(i + 1 + b));
                emb_evt.embedding.vector[i] = val;
                sum_sq += val * val;
            }
            float norm = std::sqrt(sum_sq);
            for (std::uint32_t i = 0; i < config_.embedding_dimensions; ++i) {
                emb_evt.embedding.vector[i] /= norm;
            }

            session.dispatch_event(emb_evt, err);
            conn->send_event(emb_evt);
        }

        event_envelope term_evt{stream_id, seq++, runtime_event_type::completed, "Embedding completed", terminal_outcome::completed};
        term_evt.error.code = 200;
        session.dispatch_event(term_evt, err);
        conn->send_event(term_evt);
        return;
    }

    // Chat / Generate profile:
    if (config_.enable_reasoning) {
        std::vector<std::string> reasoning_chunks = {
            "Thinking through the query...",
            "Validating LiNeP V0.2 contract..."
        };
        for (const auto& chunk : reasoning_chunks) {
            if (check_cancel()) {
                event_envelope cancel_evt{stream_id, seq++, runtime_event_type::cancelled, "Cancelled by client", terminal_outcome::cancelled};
                cancel_evt.error.code = 499;
                session.dispatch_event(cancel_evt, err);
                conn->send_event(cancel_evt);
                return;
            }

            event_envelope r_evt{stream_id, seq++, runtime_event_type::reasoning_delta, chunk};
            session.dispatch_event(r_evt, err);
            conn->send_event(r_evt);
            emitted_events++;

            if (config_.fail_after_n >= 0 && emitted_events >= config_.fail_after_n) {
                event_envelope fail_evt{stream_id, seq++, runtime_event_type::failed, "Forced backend error", terminal_outcome::failed};
                fail_evt.error.code = 500;
                session.dispatch_event(fail_evt, err);
                conn->send_event(fail_evt);
                return;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_per_event_ms));
        }
    }

    // Stream content deltas or snapshots
    std::string accumulated_text;
    for (std::size_t i = 1; i <= config_.default_tokens; ++i) {
        if (check_cancel()) {
            event_envelope cancel_evt{stream_id, seq++, runtime_event_type::cancelled, "Cancelled by client", terminal_outcome::cancelled};
            cancel_evt.error.code = 499;
            session.dispatch_event(cancel_evt, err);
            conn->send_event(cancel_evt);
            return;
        }

        std::string delta = "Token_" + std::to_string(i) + (output_id > 0 ? ("_out" + std::to_string(output_id)) : "") + " ";
        accumulated_text += delta;

        // Flow control / backpressure wait loop
        auto start_wait = std::chrono::steady_clock::now();
        active_stream_state st{};
        while (running_ && conn->is_connected() && session.get_stream_state(stream_id, st) && 
               (st.unacked_buffered_bytes() + delta.size() > session.descriptor().limits.max_buffered_bytes_per_stream)) {
            if (check_cancel()) {
                event_envelope cancel_evt{stream_id, seq++, runtime_event_type::cancelled, "Cancelled by client", terminal_outcome::cancelled};
                cancel_evt.error.code = 499;
                session.dispatch_event(cancel_evt, err);
                conn->send_event(cancel_evt);
                return;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_wait).count();
            if (elapsed > 500) {
                // Client stalled: Fail closed with 507
                event_envelope stall_evt{stream_id, seq++, runtime_event_type::failed, "Client buffer window exhausted (backpressure stall)", terminal_outcome::failed};
                stall_evt.error.code = 507;
                session.dispatch_event(stall_evt, err);
                conn->send_event(stall_evt);
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        runtime_event_type ev_type = config_.snapshot_mode ? runtime_event_type::content_snapshot : runtime_event_type::content_delta;
        std::string payload_to_send = config_.snapshot_mode ? accumulated_text : delta;

        event_envelope c_evt{stream_id, seq++, ev_type, payload_to_send};
        session.dispatch_event(c_evt, err);
        conn->send_event(c_evt);
        emitted_events++;

        if (config_.duplicate_event) {
            conn->send_event(c_evt); // Duplicate injection
        }

        if (config_.fail_after_n >= 0 && emitted_events >= config_.fail_after_n) {
            event_envelope fail_evt{stream_id, seq++, runtime_event_type::failed, "Forced backend error", terminal_outcome::failed};
            fail_evt.error.code = 500;
            session.dispatch_event(fail_evt, err);
            conn->send_event(fail_evt);
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_per_event_ms));
    }

    if (config_.disconnect_before_terminal) {
        conn->close();
        return;
    }

    // Final completed terminal outcome
    event_envelope term_evt{stream_id, seq++, runtime_event_type::completed, "Generation completed successfully", terminal_outcome::completed};
    term_evt.error.code = 200;
    session.dispatch_event(term_evt, err);
    conn->send_event(term_evt);
}

} // namespace linep::v0_2
