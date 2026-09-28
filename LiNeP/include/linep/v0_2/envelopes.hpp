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
constexpr std::size_t LINEP_V02_SESSION_BIND_PAYLOAD_SIZE = 36; // 8+8+4+8+8 bytes canonical wire size
constexpr std::size_t LINEP_V02_AUTH_EXTENSION_SIZE = 24; // 4+2+2+16 bytes canonical wire size
constexpr std::uint8_t LINEP_V02_FLAG_AUTHENTICATED = 1u << 0; // 0x01: wire_auth_extension (SL1) precedes payload
constexpr std::uint8_t LINEP_V02_BIND_FLAG_SL1       = 1u << 0; // 0x01: SESSION_BIND announces SL1 on this connection

enum class message_direction : std::uint8_t {
    initiator_to_responder = 1, // Client to server (e.g. REQUEST, CANCEL, client SESSION_BIND)
    responder_to_initiator = 2, // Server to client (e.g. EVENT, CAPABILITIES)
};

#pragma pack(push, 1)
struct wire_auth_extension {
    std::uint32_t auth_seq{0}; // Monotonically increasing sequence per connection & direction (starts at 1)
    std::uint16_t key_id{0};   // Key identifier (enables key rotation)
    std::uint16_t reserved{0}; // Padding/reserved (must be 0)
    std::uint8_t  mac[16]{};   // 16-byte HMAC-SHA-256 MAC tag
};
#pragma pack(pop)

static_assert(sizeof(wire_auth_extension) == 24, "wire_auth_extension must be exactly 24 bytes");

enum class runtime_envelope_type : std::uint8_t {
    unknown = 0,
    request = 1,
    event = 2,
    control = 3,
    capabilities = 4,
    session_bind = 5,
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

struct generation_options {
    float top_p{0.9f};
    std::int32_t top_k{40};
    float repeat_penalty{1.0f};
    std::int32_t repeat_last_n{64};
    std::uint64_t seed{0};
    float presence_penalty{0.0f};
    float frequency_penalty{0.0f};
    std::vector<std::string> stop_sequences;
    std::vector<std::pair<std::string, std::string>> extra_options;

    bool is_default() const noexcept {
        return top_p == 0.9f &&
               top_k == 40 &&
               repeat_penalty == 1.0f &&
               repeat_last_n == 64 &&
               seed == 0 &&
               presence_penalty == 0.0f &&
               frequency_penalty == 0.0f &&
               stop_sequences.empty() &&
               extra_options.empty();
    }
};

struct request_envelope {
    stream_identity stream;
    runtime_profile profile{runtime_profile::generate};
    std::string model_id;
    std::string payload; // Prompt text or messages
    std::uint32_t max_tokens{0};
    float temperature{0.7f};
    bool stream_requested{true};
    bool has_options{false};
    generation_options options;

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
        if (!stream.is_valid() && !stream.is_connection_level()) {
            return false;
        }
        if (event_type == runtime_event_type::unknown) {
            return false;
        }
        if (!stream.is_connection_level() && event_seq == 0) {
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
    std::uint64_t ack_offset_bytes{0}; // Cumulative consumed/drained byte offset (monotonic & idempotent)

    bool is_valid() const noexcept {
        return stream.is_valid() &&
               control_type != runtime_control_type::unknown;
    }
};

struct capabilities_envelope {
    runtime_capabilities_descriptor descriptor;
};

// V0.2 Dual-Plane: binds a TCP data-plane session/trunk to the UDP control-plane identity/lease
// Note: lease_token (64-bit) binds control-plane lease semantics and incarnation state;
// cryptographic authentication and confidentiality are provided separately by LiNeP-SL.
struct session_bind_envelope {
    node_endpoint_identity identity{};
    std::uint64_t control_epoch{0};
    std::uint64_t lease_token{0};
    bool sl1_requested{false};
    std::uint16_t key_id{1}; // Optional default key_id (default 1)
    wire_auth_extension auth_ext{};

    bool is_valid() const noexcept {
        return identity.node_id != 0 &&
               identity.runtime_id != 0 &&
               lease_token != 0;
    }

    bool operator==(const session_bind_envelope& other) const noexcept {
        return identity == other.identity &&
               control_epoch == other.control_epoch &&
               lease_token == other.lease_token &&
               sl1_requested == other.sl1_requested &&
               key_id == other.key_id;
    }

    bool operator!=(const session_bind_envelope& other) const noexcept {
        return !(*this == other);
    }
};

// Canonical little-endian header encoding and decoding functions
void encode_header(const wire_envelope_header& hdr, std::vector<std::uint8_t>& out_buf);
bool decode_header(const std::uint8_t* data, std::size_t size, wire_envelope_header& out_hdr);

// Auth Extension encoding and decoding functions
void encode_auth_extension(const wire_auth_extension& ext, std::vector<std::uint8_t>& out_buf);
bool decode_auth_extension(const std::uint8_t* data, std::size_t size, wire_auth_extension& out_ext);

// SL1 MAC computation & verification
void compute_sl1_mac(
    const std::uint8_t*          secret_key,
    std::size_t                  key_len,
    const wire_envelope_header&  header,
    const wire_auth_extension&   auth_ext,
    const session_bind_envelope& binding,
    message_direction            direction,
    const std::uint8_t*          payload,
    std::uint32_t                payload_len,
    std::uint8_t                 out_mac[16]) noexcept;

bool verify_sl1_mac(
    const std::uint8_t*          secret_key,
    std::size_t                  key_len,
    const wire_envelope_header&  header,
    const wire_auth_extension&   auth_ext,
    const session_bind_envelope& binding,
    message_direction            direction,
    const std::uint8_t*          payload,
    std::uint32_t                payload_len) noexcept;

// Helper to sign an envelope buffer [32B Header][Payload] -> [32B Header with FLAG_AUTHENTICATED][24B AuthExt][Payload]
bool sign_envelope_buffer(
    std::vector<std::uint8_t>&   in_out_envelope_buf,
    const session_bind_envelope& binding,
    message_direction            direction,
    std::uint32_t                auth_seq,
    std::uint16_t                key_id,
    const std::uint8_t*          secret_key,
    std::size_t                  key_len);

// Helper to verify an envelope buffer [32B Header with FLAG_AUTHENTICATED][24B AuthExt][Payload]
bool verify_envelope_buffer(
    const std::uint8_t*          data,
    std::size_t                  size,
    const session_bind_envelope& binding,
    message_direction            direction,
    const std::uint8_t*          secret_key,
    std::size_t                  key_len,
    wire_auth_extension&         out_auth_ext,
    std::string*                 out_error = nullptr);

// Serialization and deserialization functions
bool encode_request(const request_envelope& req, std::vector<std::uint8_t>& out_buffer);
bool decode_request(const std::uint8_t* data, std::size_t size, request_envelope& out_req);

bool encode_event(const event_envelope& evt, std::vector<std::uint8_t>& out_buffer);
bool decode_event(const std::uint8_t* data, std::size_t size, event_envelope& out_evt);

bool encode_control(const control_envelope& ctrl, std::vector<std::uint8_t>& out_buffer);
bool decode_control(const std::uint8_t* data, std::size_t size, control_envelope& out_ctrl);

bool encode_capabilities(const capabilities_envelope& caps, std::vector<std::uint8_t>& out_buffer);
bool decode_capabilities(const std::uint8_t* data, std::size_t size, capabilities_envelope& out_caps);

bool encode_session_bind(const session_bind_envelope& bind, std::vector<std::uint8_t>& out_buffer);
bool decode_session_bind(const std::uint8_t* data, std::size_t size, session_bind_envelope& out_bind);

runtime_envelope_type peek_envelope_type(const std::uint8_t* data, std::size_t size) noexcept;

} // namespace linep::v0_2
