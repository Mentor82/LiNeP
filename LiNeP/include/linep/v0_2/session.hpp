#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/lifecycle.hpp"

namespace linep::v0_2 {

struct stream_identity_hash {
    std::size_t operator()(const stream_identity& id) const noexcept {
        std::size_t h1 = std::hash<std::uint64_t>{}(id.request_id);
        std::size_t h2 = std::hash<std::uint64_t>{}(id.execution_id);
        std::size_t h3 = std::hash<std::uint32_t>{}(id.output_id);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

struct session_limits {
    std::size_t max_inflight_streams{64};
    std::size_t max_buffered_bytes_per_stream{1U << 20}; // 1 MB
};

struct session_descriptor {
    std::uint64_t session_id{0};
    session_limits limits{};
};

struct active_stream_state {
    stream_identity stream{};
    runtime_profile profile{runtime_profile::unspecified};
    std::string model_id;
    lifecycle_status lifecycle{};
    event_seq_t last_event_seq{0};
    std::uint64_t total_produced_bytes{0};      // Cumulative produced bytes
    std::uint64_t acknowledged_offset_bytes{0}; // Cumulative confirmed consumed/drained bytes (monotonic)

    std::size_t unacked_buffered_bytes() const noexcept {
        if (total_produced_bytes <= acknowledged_offset_bytes) {
            return 0;
        }
        return static_cast<std::size_t>(total_produced_bytes - acknowledged_offset_bytes);
    }
};

class session_manager {
public:
    explicit session_manager(session_descriptor descriptor = {})
        : descriptor_(descriptor) {}

    const session_descriptor& descriptor() const noexcept {
        return descriptor_;
    }

    // Submit a new request to start an active stream
    bool submit_request(const request_envelope& req, runtime_error& out_err);

    // Dispatch an incoming event to an existing active stream
    bool dispatch_event(const event_envelope& evt, runtime_error& out_err);

    // Idempotent / replay-safe cumulative acknowledgment of consumed stream bytes
    bool acknowledge_stream_offset(const stream_identity& id, std::uint64_t cumulative_ack_offset);

    // Delta-based drain acknowledgment (convenience wrapper updating cumulative offset)
    bool acknowledge_stream_drain(const stream_identity& id, std::size_t bytes_drained);

    // Target cancellation by execution identity (cancel_requested -> non-terminal)
    bool cancel_execution(execution_id_t execution_id, const std::string& reason, std::size_t& out_cancelled_count);

    // Process a control envelope (e.g. cancel) from network wire
    bool process_control(const control_envelope& ctrl, runtime_error& out_err);

    // Query active streams
    std::size_t get_active_stream_count() const;
    bool has_stream(const stream_identity& id) const;
    bool get_stream_state(const stream_identity& id, active_stream_state& out_state) const;

    // Check if stream is in terminal state or has cancel requested
    bool is_stream_terminal(const stream_identity& id) const;
    bool is_cancel_requested(const stream_identity& id) const;

    // Fail-closed termination of all in-flight streams on connection disconnect / error
    std::size_t terminate_all_active_streams(terminal_outcome outcome = terminal_outcome::unknown, const runtime_error& err = {});

private:
    session_descriptor descriptor_;
    mutable std::mutex mutex_;
    std::unordered_map<stream_identity, active_stream_state, stream_identity_hash> active_streams_;
};

} // namespace linep::v0_2
