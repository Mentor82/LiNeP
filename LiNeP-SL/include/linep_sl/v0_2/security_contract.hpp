#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <linep/v0_2/control_plane.hpp>
#include <linep/v0_2/runtime_types.hpp>

namespace linep::sl::v0_2 {

constexpr std::uint8_t contract_version_major = 0;
constexpr std::uint8_t contract_version_minor = 2;
constexpr std::size_t max_content_digest_bytes = 64;

enum class security_plane : std::uint8_t {
    unknown = 0,
    control = 1,
    data = 2,
};

enum class message_direction : std::uint8_t {
    unknown = 0,
    initiator_to_responder = 1,
    responder_to_initiator = 2,
};

enum class security_level : std::uint8_t {
    unknown = 0,
    sl0_baseline = 1,
    sl1_authenticated = 2,
    sl2_identity = 3,
    sl3_authorized = 4,
    sl4_governed = 5,
};

enum class security_action : std::uint8_t {
    unknown = 0,
    advertise = 1,
    report_liveness = 2,
    manage_lease = 3,
    execute = 4,
    emit_output = 5,
    cancel = 6,
    invoke_tool = 7,
    read_metrics = 8,
    manage_runtime = 9,
    administer = 10,
};

enum class data_message_class : std::uint8_t {
    unknown = 0,
    request = 1,
    event = 2,
    control = 3,
};

enum class digest_algorithm : std::uint8_t {
    unknown = 0,
    sha256 = 1,
    sha512 = 2,
};

struct security_session_identity {
    std::uint64_t session_id{0};
    std::uint64_t security_epoch{0};
    std::uint32_t key_id{0};
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};

    bool is_valid() const noexcept;
};

struct common_binding {
    security_session_identity session;
    message_direction direction{message_direction::unknown};
    security_level negotiated_level{security_level::unknown};
    security_level required_level{security_level::unknown};
    security_action action{security_action::unknown};
    digest_algorithm digest{digest_algorithm::unknown};
    std::vector<std::uint8_t> content_digest;

    bool is_valid() const noexcept;
};

struct control_plane_binding {
    common_binding common;
    linep::v0_2::node_endpoint_identity endpoint;
    std::uint64_t control_epoch{0};
    std::uint64_t control_seq{0};
    std::uint64_t lease_token{0};
    bool lease_bound{false};

    bool is_valid() const noexcept;
};

struct data_plane_binding {
    common_binding common;
    data_message_class message_class{data_message_class::unknown};
    linep::v0_2::stream_identity stream;
    linep::v0_2::event_seq_t event_seq{0};
    linep::v0_2::fragment_seq_t fragment_seq{0};
    bool has_fragment_seq{false};

    bool is_valid() const noexcept;
};

bool encode_authenticator_input(
    const control_plane_binding& binding,
    std::vector<std::uint8_t>& out);

bool encode_authenticator_input(
    const data_plane_binding& binding,
    std::vector<std::uint8_t>& out);

} // namespace linep::sl::v0_2
