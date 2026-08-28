#pragma once

#include <cstddef>
#include <cstdint>

namespace linep::v0_2 {

struct session_limits {
    std::size_t max_inflight_streams{64};
    std::size_t max_buffered_bytes_per_stream{1U << 20};
};

struct session_descriptor {
    std::uint64_t session_id{};
    session_limits limits{};
};

// The first implementation should provide a persistent connection/session that can
// carry multiple independent logical executions without cross-talk.

} // namespace linep::v0_2
