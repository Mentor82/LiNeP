#include "linep/v0_2/session.hpp"
#include "linep/v0_2/control_plane.hpp"

namespace linep::v0_2 {

bool session_manager::submit_request(const request_envelope& req, runtime_error& out_err) {
    if (!req.is_valid()) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Invalid request envelope: missing stream identity, model ID, or profile";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (descriptor_.require_lease) {
        if (binding_state_ == session_binding_state::unbound) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "Connection is UNBOUND: valid SESSION_BIND required before REQUEST";
            return false;
        }
        if (binding_state_ == session_binding_state::bound_stale) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "stale_binding: control epoch or lease rotated, re-bind required before new REQUEST";
            return false;
        }
    }

    // Check for collision with existing active stream
    if (active_streams_.find(req.stream) != active_streams_.end()) {
        out_err.category = error_category::bad_request;
        out_err.code = 409;
        out_err.message = "Stream identity already active in session";
        return false;
    }

    // Enforce in-flight (non-terminal) stream limit (Backpressure protection)
    std::size_t inflight_count = 0;
    for (const auto& pair : active_streams_) {
        if (pair.second.lifecycle.state != lifecycle_state::terminal) {
            inflight_count++;
        }
    }
    if (inflight_count >= descriptor_.limits.max_inflight_streams) {
        out_err.category = error_category::resource_exhausted;
        out_err.code = 503;
        out_err.message = "Max in-flight stream limit reached on session (backpressure)";
        return false;
    }

    active_stream_state state{};
    state.stream = req.stream;
    state.profile = req.profile;
    state.model_id = req.model_id;
    state.lifecycle.transition_to(lifecycle_state::accepted);

    active_streams_[req.stream] = std::move(state);
    return true;
}

bool session_manager::dispatch_event(const event_envelope& evt, runtime_error& out_err) {
    if (!evt.is_valid()) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Invalid event envelope: missing stream identity or event type";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = active_streams_.find(evt.stream);
    if (it == active_streams_.end()) {
        out_err.category = error_category::bad_request;
        out_err.code = 404;
        out_err.message = "Stream identity not found in active session";
        return false;
    }

    auto& stream_state = it->second;

    // Check if stream is already terminal (Immutable terminal state rule)
    if (stream_state.lifecycle.state == lifecycle_state::terminal) {
        out_err.category = error_category::bad_request;
        out_err.code = 410;
        out_err.message = "Stream has already reached terminal state; no further events allowed";
        return false;
    }

    // Semantic event sequencing check (event_seq starts at 1, strictly monotonically increasing)
    if (evt.event_seq == 0 || evt.event_seq <= stream_state.last_event_seq) {
        out_err.category = error_category::bad_request;
        out_err.code = 422;
        out_err.message = "Semantic event_seq must be >= 1 and strictly greater than last_event_seq";
        return false;
    }

    // Bounded buffer calculation based on monotonic unacknowledged bytes
    std::size_t event_bytes = evt.payload.size() +
        (evt.event_type == runtime_event_type::embedding_result ? evt.embedding.vector.size() * sizeof(float) : 0);

    if ((stream_state.unacked_buffered_bytes() + event_bytes) > descriptor_.limits.max_buffered_bytes_per_stream) {
        out_err.category = error_category::resource_exhausted;
        out_err.code = 507;
        out_err.message = "Stream buffer limit exceeded (unacked backpressure protection)";
        return false;
    }

    // Update lifecycle state machine
    if (stream_state.lifecycle.state == lifecycle_state::accepted && !evt.is_terminal()) {
        stream_state.lifecycle.transition_to(lifecycle_state::started);
    }

    stream_state.total_produced_bytes += event_bytes;

    if (evt.is_terminal()) {
        terminal_outcome out = evt.outcome;
        if (out == terminal_outcome::unknown) {
            if (evt.event_type == runtime_event_type::completed) out = terminal_outcome::completed;
            else if (evt.event_type == runtime_event_type::cancelled) out = terminal_outcome::cancelled;
            else if (evt.event_type == runtime_event_type::failed) out = terminal_outcome::failed;
            else out = terminal_outcome::completed;
        }
        stream_state.lifecycle.transition_to(lifecycle_state::terminal, out);
        // Terminal outcome acknowledges and frees all in-flight bytes
        stream_state.acknowledged_offset_bytes = stream_state.total_produced_bytes;
    }

    stream_state.last_event_seq = evt.event_seq;
    return true;
}

bool session_manager::acknowledge_stream_offset(const stream_identity& id, std::uint64_t cumulative_ack_offset) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_streams_.find(id);
    if (it == active_streams_.end()) {
        return false;
    }
    // Idempotent: Ignore duplicate or stale ACK offsets
    if (cumulative_ack_offset <= it->second.acknowledged_offset_bytes) {
        return true;
    }
    // Fail closed on invalid future ACK
    if (cumulative_ack_offset > it->second.total_produced_bytes) {
        return false;
    }
    it->second.acknowledged_offset_bytes = cumulative_ack_offset;
    return true;
}

bool session_manager::acknowledge_stream_drain(const stream_identity& id, std::size_t bytes_drained) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_streams_.find(id);
    if (it == active_streams_.end()) {
        return false;
    }
    std::uint64_t target = it->second.acknowledged_offset_bytes + bytes_drained;
    if (target > it->second.total_produced_bytes) {
        return false;
    }
    it->second.acknowledged_offset_bytes = target;
    return true;
}

bool session_manager::cancel_execution(execution_id_t execution_id, const std::string& reason, std::size_t& out_cancelled_count) {
    out_cancelled_count = 0;
    if (execution_id == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& pair : active_streams_) {
        if (pair.first.execution_id == execution_id) {
            if (pair.second.lifecycle.state != lifecycle_state::terminal &&
                pair.second.lifecycle.state != lifecycle_state::cancel_requested) {
                if (pair.second.lifecycle.transition_to(lifecycle_state::cancel_requested)) {
                    out_cancelled_count++;
                }
            }
        }
    }
    return out_cancelled_count > 0;
}

bool session_manager::process_control(const control_envelope& ctrl, runtime_error& out_err) {
    if (!ctrl.is_valid()) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Invalid control envelope";
        return false;
    }

    if (ctrl.control_type == runtime_control_type::cancel) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool found = false;
        bool any_cancelled = false;
        bool already_terminal = false;

        for (auto& pair : active_streams_) {
            bool matches = false;
            // Explicit Scope Targeting:
            // If request_id != 0: Exact Stream Match (request_id, execution_id, output_id exact)
            // If request_id == 0: Execution Scope Match (all streams under execution_id)
            if (ctrl.stream.request_id != 0) {
                matches = (pair.first == ctrl.stream);
            } else {
                matches = (pair.first.execution_id == ctrl.stream.execution_id);
            }

            if (matches) {
                found = true;
                if (pair.second.lifecycle.state == lifecycle_state::terminal) {
                    already_terminal = true;
                } else if (pair.second.lifecycle.state != lifecycle_state::cancel_requested) {
                    if (pair.second.lifecycle.transition_to(lifecycle_state::cancel_requested)) {
                        any_cancelled = true;
                    }
                }
            }
        }

        if (!found) {
            out_err.category = error_category::bad_request;
            out_err.code = 404;
            out_err.message = "Stream identity not found in active session";
            return false;
        }

        if (already_terminal && !any_cancelled) {
            out_err.category = error_category::bad_request;
            out_err.code = 410;
            out_err.message = "Stream has already reached terminal state; cancel ignored";
            return false;
        }

        return any_cancelled;
    }

    if (ctrl.control_type == runtime_control_type::window_update) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool found = false;
        for (auto& pair : active_streams_) {
            bool matches = false;
            if (ctrl.stream.request_id != 0) {
                matches = (pair.first == ctrl.stream);
            } else {
                matches = (pair.first.execution_id == ctrl.stream.execution_id);
            }
            if (matches) {
                found = true;
                // Strict validation: Reject impossible future ACK exceeding total produced bytes
                if (ctrl.ack_offset_bytes > pair.second.total_produced_bytes) {
                    out_err.category = error_category::bad_request;
                    out_err.code = 422;
                    out_err.message = "Future ACK offset exceeds total produced stream bytes (protocol violation)";
                    return false;
                }
                // Replay-safe monotonic credit advancement:
                if (ctrl.ack_offset_bytes > pair.second.acknowledged_offset_bytes) {
                    pair.second.acknowledged_offset_bytes = ctrl.ack_offset_bytes;
                }
            }
        }
        if (!found) {
            out_err.category = error_category::bad_request;
            out_err.code = 404;
            out_err.message = "Stream identity not found in active session";
            return false;
        }
        return true;
    }

    out_err.category = error_category::bad_request;
    out_err.code = 400;
    out_err.message = "Unsupported control type";
    return false;
}

std::size_t session_manager::get_active_stream_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t count = 0;
    for (const auto& pair : active_streams_) {
        if (pair.second.lifecycle.state != lifecycle_state::terminal) {
            count++;
        }
    }
    return count;
}

bool session_manager::has_stream(const stream_identity& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_streams_.find(id) != active_streams_.end();
}

bool session_manager::get_stream_state(const stream_identity& id, active_stream_state& out_state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_streams_.find(id);
    if (it == active_streams_.end()) {
        return false;
    }
    out_state = it->second;
    return true;
}

bool session_manager::is_stream_terminal(const stream_identity& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_streams_.find(id);
    if (it == active_streams_.end()) {
        return false;
    }
    return it->second.lifecycle.state == lifecycle_state::terminal;
}

bool session_manager::is_cancel_requested(const stream_identity& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_streams_.find(id);
    if (it == active_streams_.end()) {
        return false;
    }
    return it->second.lifecycle.state == lifecycle_state::cancel_requested;
}

std::size_t session_manager::terminate_all_active_streams(terminal_outcome outcome, const runtime_error& err) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t terminated = 0;
    for (auto& pair : active_streams_) {
        if (pair.second.lifecycle.state != lifecycle_state::terminal) {
            pair.second.lifecycle.transition_to(lifecycle_state::terminal, outcome);
            pair.second.acknowledged_offset_bytes = pair.second.total_produced_bytes;
            terminated++;
        }
    }
    return terminated;
}

session_binding_state session_manager::binding_state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return binding_state_;
}

session_bind_envelope session_manager::bound_session() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return bound_bind_;
}

void session_manager::mark_binding_stale() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (binding_state_ == session_binding_state::bound_current) {
        binding_state_ = session_binding_state::bound_stale;
    }
}

bool session_manager::process_session_bind(const session_bind_envelope& bind, runtime_error& out_err) {
    return process_session_bind(bind, nullptr, out_err);
}

bool session_manager::process_session_bind(const session_bind_envelope& bind, const control_plane_router* router, runtime_error& out_err) {
    if (!bind.is_valid()) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Invalid session_bind envelope: missing identity or zero lease token";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Identity change on existing connection is forbidden (prevents connection reassignment)
    if (binding_state_ != session_binding_state::unbound && bound_bind_.identity != bind.identity) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "identity_change_on_existing_connection";
        return false;
    }

    if (router != nullptr) {
        if (!router->validate_tcp_session_binding(bind.identity, bind.control_epoch, bind.lease_token)) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "lease_invalid";
            return false;
        }
    }

    // Check if SL1 is required on this trunk
    if (descriptor_.require_sl1 && !bind.sl1_requested) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_required: SL1 authentication required on this trunk";
        return false;
    }

    if (bind.sl1_requested) {
        if (bind.auth_ext.auth_seq != 1) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "auth_replay: bind auth_seq must be 1";
            return false;
        }
        if (descriptor_.sl1_keys.empty()) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "unknown_key: no SL1 key configured";
            return false;
        }
        auto it = descriptor_.sl1_keys.find(bind.auth_ext.key_id);
        if (it == descriptor_.sl1_keys.end()) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "unknown_key: key_id not recognized";
            return false;
        }
        if (descriptor_.previous_key_id != 0) {
            if (bind.auth_ext.key_id != descriptor_.current_key_id &&
                bind.auth_ext.key_id != descriptor_.previous_key_id) {
                out_err.category = error_category::unauthorized;
                out_err.code = 401;
                out_err.message = "unknown_key: key_id outside rotation window";
                return false;
            }
        }
    }

    // Idempotent duplicate bind: same lease token & epoch while already bound
    if (binding_state_ == session_binding_state::bound_current && bound_bind_ == bind) {
        return true;
    }

    bound_bind_ = bind;
    binding_state_ = session_binding_state::bound_current;
    if (bind.sl1_requested) {
        is_sl1_active_ = true;
        next_outbound_auth_seq_ = 1;
        expected_inbound_auth_seq_ = 2; // Sequence 1 was consumed by SESSION_BIND
    } else {
        is_sl1_active_ = false;
    }
    return true;
}

bool session_manager::add_sl1_key(std::uint16_t key_id, std::vector<std::uint8_t> key) {
    if (key.size() < 32) {
        return false; // Minimum key length requirement >= 32 bytes (256 bits)
    }
    std::lock_guard<std::mutex> lock(mutex_);
    descriptor_.sl1_keys[key_id] = std::move(key);
    return true;
}

bool session_manager::get_sl1_key(std::uint16_t key_id, std::vector<std::uint8_t>& out_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = descriptor_.sl1_keys.find(key_id);
    if (it == descriptor_.sl1_keys.end()) {
        return false;
    }
    out_key = it->second;
    return true;
}

bool session_manager::is_sl1_active() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_sl1_active_;
}

bool session_manager::verify_inbound_frame(
    const std::uint8_t* data,
    std::size_t size,
    message_direction direction,
    wire_auth_extension& out_auth_ext,
    runtime_error& out_err)
{
    if (!data || size < LINEP_V02_HEADER_SIZE) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Malformed envelope: truncated header";
        return false;
    }

    wire_envelope_header hdr{};
    if (!decode_header(data, LINEP_V02_HEADER_SIZE, hdr)) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Malformed envelope header";
        return false;
    }

    // SESSION_BIND is connection-level handshake (handled via process_session_bind)
    if (hdr.envelope_type == static_cast<std::uint8_t>(runtime_envelope_type::session_bind)) {
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    const bool has_auth = (hdr.flags & LINEP_V02_FLAG_AUTHENTICATED) != 0;

    if (!is_sl1_active_) {
        if (has_auth) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "auth_unexpected: authenticated envelope received on non-SL1 connection";
            return false;
        }
        return true; // Unauthenticated connection, regular frame
    }

    // SL1 is active on this connection: all frames MUST be authenticated
    if (!has_auth) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_required: unauthenticated envelope received on SL1 connection";
        return false;
    }

    if (size < (LINEP_V02_HEADER_SIZE + LINEP_V02_AUTH_EXTENSION_SIZE)) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_invalid: envelope truncated";
        return false;
    }

    if (!decode_auth_extension(data + LINEP_V02_HEADER_SIZE, LINEP_V02_AUTH_EXTENSION_SIZE, out_auth_ext)) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_invalid: invalid auth extension";
        return false;
    }

    // Replay / sequence check (strictly monotone per direction)
    if (out_auth_ext.auth_seq != expected_inbound_auth_seq_) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_replay: sequence mismatch (expected " +
                          std::to_string(expected_inbound_auth_seq_) + ", got " +
                          std::to_string(out_auth_ext.auth_seq) + ")";
        return false;
    }

    // Key lookup & rotation check (accept current and previous key_id during grace window)
    if (descriptor_.previous_key_id != 0) {
        if (out_auth_ext.key_id != descriptor_.current_key_id &&
            out_auth_ext.key_id != descriptor_.previous_key_id) {
            out_err.category = error_category::unauthorized;
            out_err.code = 401;
            out_err.message = "unknown_key: key_id " + std::to_string(out_auth_ext.key_id) + " outside rotation window";
            return false;
        }
    }
    auto it = descriptor_.sl1_keys.find(out_auth_ext.key_id);
    if (it == descriptor_.sl1_keys.end()) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "unknown_key: key_id " + std::to_string(out_auth_ext.key_id) + " not found";
        return false;
    }

    // MAC verification
    std::string verify_err;
    if (!verify_envelope_buffer(
            data, size, bound_bind_, direction,
            it->second.data(), it->second.size(),
            out_auth_ext, &verify_err)) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_invalid: " + verify_err;
        return false;
    }

    // Sequence accepted (bounded at 2^32-1)
    if (expected_inbound_auth_seq_ < 0xFFFFFFFF) {
        expected_inbound_auth_seq_++;
    }
    return true;
}

bool session_manager::sign_outbound_frame(
    std::vector<std::uint8_t>& in_out_buf,
    message_direction direction,
    runtime_error& out_err)
{
    if (in_out_buf.size() < LINEP_V02_HEADER_SIZE) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Buffer too small for envelope header";
        return false;
    }

    wire_envelope_header hdr{};
    if (!decode_header(in_out_buf.data(), LINEP_V02_HEADER_SIZE, hdr)) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Failed to decode envelope header";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_sl1_active_) {
        return true; // Not an SL1 connection, send frame as-is
    }

    // Sender always uses current_key_id
    std::uint16_t key_id = descriptor_.current_key_id;
    auto it = descriptor_.sl1_keys.find(key_id);
    if (it == descriptor_.sl1_keys.end()) {
        key_id = descriptor_.default_key_id;
        it = descriptor_.sl1_keys.find(key_id);
        if (it == descriptor_.sl1_keys.end()) {
            if (!descriptor_.sl1_keys.empty()) {
                it = descriptor_.sl1_keys.begin();
                key_id = it->first;
            } else {
                out_err.category = error_category::unauthorized;
                out_err.code = 401;
                out_err.message = "unknown_key: no SL1 key configured for signing";
                return false;
            }
        }
    }

    // Overflow protection: 32-bit sequence cannot wrap around
    if (next_outbound_auth_seq_ >= 0xFFFFFFFF) {
        out_err.category = error_category::unauthorized;
        out_err.code = 401;
        out_err.message = "auth_seq_exhausted: 32-bit sequence limit reached, re-bind required";
        return false;
    }

    std::uint32_t seq = next_outbound_auth_seq_;
    if (!sign_envelope_buffer(
            in_out_buf, bound_bind_, direction, seq, key_id,
            it->second.data(), it->second.size())) {
        out_err.category = error_category::internal;
        out_err.code = 500;
        out_err.message = "Failed to sign envelope buffer";
        return false;
    }

    next_outbound_auth_seq_++;
    return true;
}

} // namespace linep::v0_2
