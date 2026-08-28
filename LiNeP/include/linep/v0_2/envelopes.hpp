#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/embedding.hpp"
#include "linep/v0_2/lifecycle.hpp"

namespace linep::v0_2 {

constexpr std::uint32_t LINEP_V02_MAGIC = 0x504E4C32; // "2LNP" (LiNeP V0.2)
constexpr std::uint8_t LINEP_V02_VERSION_MAJOR = 0;
constexpr std::uint8_t LINEP_V02_VERSION_MINOR = 2;
constexpr std::size_t LINEP_V02_HEADER_SIZE = 32;
constexpr std::size_t LINEP_V02_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB max payload limit

enum class runtime_envelope_type : std::uint8_t {
    unknown = 0,
    request = 1,
    event = 2,
    control = 3,
    capabilities = 4,
};

enum class runtime_event_type : std::uint8_t {
    unknown = 0,
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
};

enum class runtime_control_type : std::uint8_t {
    unknown = 0,
    cancel = 1,
    window_update = 2,
};

#pragma pack(push, 1)
struct wire_envelope_header {
    std::uint32_t magic{LINEP_V02_MAGIC};
    std::uint8_t version_major{LINEP_V02_VERSION_MAJOR};
    std::uint8_t version_minor{LINEP_V02_VERSION_MINOR};
    std::uint8_t envelope_type{0};
    std::uint8_t flags{0};
    std::uint64_t request_id{0};
    std::uint64_t execution_id{0};
    std::uint32_t output_id{0};
    std::uint32_t payload_len{0};
};
#pragma pack(pop)

static_assert(sizeof(wire_envelope_header) == 32, "wire_envelope_header must be exactly 32 bytes");

struct request_envelope {
    stream_identity stream;
    runtime_profile profile{runtime_profile::generate};
    std::string model_id;
    std::string payload; // Prompt text or messages
    std::uint32_t max_tokens{0};
    float temperature{0.7f};
    bool stream_requested{true};

    bool is_valid() const noexcept {
        return stream.is_valid() &&
               profile != runtime_profile::unspecified &&
               !model_id.empty();
    }
};

struct event_envelope {
    stream_identity stream;
    event_seq_t event_seq{0};
    runtime_event_type event_type{runtime_event_type::unknown};
    std::string payload;
    terminal_outcome outcome{terminal_outcome::unknown};
    runtime_error error;
    embedding_result_payload embedding;
    std::uint64_t timestamp_us{0};

    bool is_valid() const noexcept {
        if (!stream.is_valid() || event_type == runtime_event_type::unknown || event_seq == 0) {
            return false;
        }
        if (event_type == runtime_event_type::embedding_result && !embedding.is_valid()) {
            return false;
        }
        return true;
    }

    bool is_terminal() const noexcept {
        return event_type == runtime_event_type::completed ||
               event_type == runtime_event_type::cancelled ||
               event_type == runtime_event_type::failed;
    }
};

struct control_envelope {
    stream_identity stream;
    runtime_control_type control_type{runtime_control_type::cancel};
    std::string reason;
    std::uint32_t window_credit_bytes{0};

    bool is_valid() const noexcept {
        return stream.is_valid() &&
               control_type != runtime_control_type::unknown;
    }
};

struct capabilities_envelope {
    runtime_capabilities_descriptor descriptor;
};

// Canonical little-endian header encoding and decoding functions
void encode_header(const wire_envelope_header& hdr, std::vector<std::uint8_t>& out_buf);
bool decode_header(const std::uint8_t* data, std::size_t size, wire_envelope_header& out_hdr);

// Serialization and deserialization functions
bool encode_request(const request_envelope& req, std::vector<std::uint8_t>& out_buffer);
bool decode_request(const std::uint8_t* data, std::size_t size, request_envelope& out_req);

bool encode_event(const event_envelope& evt, std::vector<std::uint8_t>& out_buffer);
bool decode_event(const std::uint8_t* data, std::size_t size, event_envelope& out_evt);

bool encode_control(const control_envelope& ctrl, std::vector<std::uint8_t>& out_buffer);
bool decode_control(const std::uint8_t* data, std::size_t size, control_envelope& out_ctrl);

bool encode_capabilities(const capabilities_envelope& caps, std::vector<std::uint8_t>& out_buffer);
bool decode_capabilities(const std::uint8_t* data, std::size_t size, capabilities_envelope& out_caps);

runtime_envelope_type peek_envelope_type(const std::uint8_t* data, std::size_t size) noexcept;

} // namespace linep::v0_2
