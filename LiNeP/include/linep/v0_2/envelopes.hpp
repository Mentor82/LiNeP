#pragma once

#include <cstdint>
#include "linep/v0_2/runtime_types.hpp"

namespace linep::v0_2 {

enum class runtime_envelope_type : std::uint8_t {
    request = 1,
    event = 2,
    control = 3,
    capabilities = 4,
};

enum class runtime_event_type : std::uint8_t {
    accepted = 1,
    started = 2,
    content_delta = 3,
    content_snapshot = 4,
    reasoning_delta = 5,
    tool_call = 6,
    embedding_result = 7,
    metrics = 8,
    error = 9,
    completed = 10,
    cancelled = 11,
    failed = 12,
    unknown = 13,
};

enum class runtime_control_type : std::uint8_t {
    cancel = 1,
};

// Deliberately only a scaffold. Exact wire layout and encoding belong to Issue #10.
struct runtime_envelope_header {
    runtime_envelope_type type{};
    stream_identity stream{};
    event_seq_t event_seq{};
};

} // namespace linep::v0_2
