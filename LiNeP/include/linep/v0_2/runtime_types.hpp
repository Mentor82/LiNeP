#pragma once

#include <cstdint>
#include <functional>
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

    bool is_connection_level() const noexcept {
        return request_id == 0 && execution_id == 0 && output_id == 0;
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

struct node_endpoint_identity {
    std::uint64_t node_id{0};
    std::uint64_t runtime_id{0};
    std::uint32_t endpoint_id{0};

    bool is_valid() const noexcept {
        return node_id != 0 && runtime_id != 0;
    }

    bool operator==(const node_endpoint_identity& other) const noexcept {
        return node_id == other.node_id &&
               runtime_id == other.runtime_id &&
               endpoint_id == other.endpoint_id;
    }
    bool operator!=(const node_endpoint_identity& other) const noexcept {
        return !(*this == other);
    }
};

struct node_endpoint_hash {
    std::size_t operator()(const node_endpoint_identity& id) const noexcept {
        std::size_t h1 = std::hash<std::uint64_t>{}(id.node_id);
        std::size_t h2 = std::hash<std::uint64_t>{}(id.runtime_id);
        std::size_t h3 = std::hash<std::uint32_t>{}(id.endpoint_id);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

} // namespace linep::v0_2
