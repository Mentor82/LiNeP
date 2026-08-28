#pragma once

#include <cstdint>
#include <string>

namespace linep::v0_2 {

using request_id_t = std::uint64_t;
using execution_id_t = std::uint64_t;
using output_id_t = std::uint32_t;
using event_seq_t = std::uint64_t;
using fragment_seq_t = std::uint32_t;

enum class runtime_profile : std::uint8_t {
    unspecified = 0,
    generate = 1,
    chat = 2,
    embed = 3,
};

enum class terminal_outcome : std::uint8_t {
    unknown = 0,
    completed = 1,
    cancelled = 2,
    failed = 3,
};

enum class error_category : std::uint8_t {
    none = 0,
    transient = 1,
    bad_request = 2,
    unauthorized = 3,
    resource_exhausted = 4,
    model_error = 5,
    unsupported = 6,
    internal = 7,
};

struct runtime_error {
    error_category category{error_category::none};
    std::uint32_t code{0};
    std::string message;
    std::string backend_diagnostic;
};

// V0.2 rule: semantic event sequencing and transport fragmentation are distinct.
struct stream_identity {
    request_id_t request_id{};
    execution_id_t execution_id{};
    output_id_t output_id{};

    bool is_valid() const noexcept {
        return request_id != 0 && execution_id != 0;
    }

    bool operator==(const stream_identity& other) const noexcept {
        return request_id == other.request_id &&
               execution_id == other.execution_id &&
               output_id == other.output_id;
    }

    bool operator!=(const stream_identity& other) const noexcept {
        return !(*this == other);
    }
};

} // namespace linep::v0_2
