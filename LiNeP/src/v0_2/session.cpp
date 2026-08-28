#include "linep/v0_2/session.hpp"

namespace linep::v0_2 {

bool session_manager::submit_request(const request_envelope& req, runtime_error& out_err) {
    if (!req.is_valid()) {
        out_err.category = error_category::bad_request;
        out_err.code = 400;
        out_err.message = "Invalid request envelope: missing stream identity, model ID, or profile";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

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

    // Semantic event sequencing check (monotonically increasing event_seq)
    if (stream_state.last_event_seq > 0 && evt.event_seq <= stream_state.last_event_seq) {
        out_err.category = error_category::bad_request;
        out_err.code = 422;
        out_err.message = "Semantic event_seq out of order, duplicate, or non-monotonic";
        return false;
    }

    // Bounded buffer calculation
    std::size_t event_bytes = evt.payload.size() +
        (evt.event_type == runtime_event_type::embedding_result ? evt.embedding.vector.size() * sizeof(float) : 0);

    if ((stream_state.buffered_bytes + event_bytes) > descriptor_.limits.max_buffered_bytes_per_stream) {
        out_err.category = error_category::resource_exhausted;
        out_err.code = 507;
        out_err.message = "Stream buffer limit exceeded (overload protection)";
        return false;
    }

    // Update lifecycle state machine
    if (stream_state.lifecycle.state == lifecycle_state::accepted && !evt.is_terminal()) {
        stream_state.lifecycle.transition_to(lifecycle_state::started);
    }

    if (evt.is_terminal()) {
        terminal_outcome out = evt.outcome;
        if (out == terminal_outcome::unknown) {
            if (evt.event_type == runtime_event_type::completed) out = terminal_outcome::completed;
            else if (evt.event_type == runtime_event_type::cancelled) out = terminal_outcome::cancelled;
            else if (evt.event_type == runtime_event_type::failed) out = terminal_outcome::failed;
            else out = terminal_outcome::completed;
        }
        stream_state.lifecycle.transition_to(lifecycle_state::terminal, out);
    }

    stream_state.last_event_seq = evt.event_seq;
    stream_state.buffered_bytes += event_bytes;
    stream_state.emitted_events.push_back(evt);

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

std::size_t session_manager::terminate_all_active_streams(terminal_outcome outcome, const runtime_error& err) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t terminated = 0;
    for (auto& pair : active_streams_) {
        if (pair.second.lifecycle.state != lifecycle_state::terminal) {
            pair.second.lifecycle.transition_to(lifecycle_state::terminal, outcome);
            event_envelope term_evt{pair.first, pair.second.last_event_seq + 1, runtime_event_type::failed, "", outcome};
            term_evt.error = err;
            pair.second.emitted_events.push_back(term_evt);
            terminated++;
        }
    }
    return terminated;
}

} // namespace linep::v0_2
