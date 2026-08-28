#pragma once

#include <cstdint>

namespace linep::v0_2 {

using request_id_t = std::uint64_t;
using execution_id_t = std::uint64_t;
using output_id_t = std::uint32_t;
using event_seq_t = std::uint64_t;
using fragment_seq_t = std::uint32_t;

enum class runtime_profile : std::uint8_t {
    generate = 1,
    chat = 2,
    embed = 3,
};

enum class terminal_outcome : std::uint8_t {
    completed = 1,
    cancelled = 2,
    failed = 3,
    unknown = 4,
};

// V0.2 rule: semantic event sequencing and transport fragmentation are distinct.
struct stream_identity {
    request_id_t request_id{};
    execution_id_t execution_id{};
    output_id_t output_id{};
};

} // namespace linep::v0_2
