#include <linep_sl/v0_2/security_contract.hpp>

#include <type_traits>

namespace linep::sl::v0_2 {
namespace {

template <typename T>
void append_le(std::vector<std::uint8_t>& out, T value) {
    static_assert(std::is_integral_v<T>, "canonical fields must be integral");
    using unsigned_t = std::make_unsigned_t<T>;
    const auto unsigned_value = static_cast<unsigned_t>(value);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>(unsigned_value >> (i * 8)));
    }
}

void append_prefix(std::vector<std::uint8_t>& out, security_plane plane) {
    out.insert(out.end(), {'L', 'N', 'S', '2'});
    append_le(out, contract_version_major);
    append_le(out, contract_version_minor);
    append_le(out, static_cast<std::uint8_t>(plane));
}

void append_common(std::vector<std::uint8_t>& out, const common_binding& binding) {
    append_le(out, static_cast<std::uint8_t>(binding.direction));
    append_le(out, static_cast<std::uint8_t>(binding.negotiated_level));
    append_le(out, static_cast<std::uint8_t>(binding.required_level));
    append_le(out, static_cast<std::uint8_t>(binding.action));
    append_le(out, static_cast<std::uint8_t>(binding.digest));
    append_le(out, binding.session.session_id);
    append_le(out, binding.session.security_epoch);
    append_le(out, binding.session.key_id);
    append_le(out, binding.session.trust_domain_id);
    append_le(out, binding.session.subject_id);
}

void append_digest(std::vector<std::uint8_t>& out, const std::vector<std::uint8_t>& digest) {
    append_le(out, static_cast<std::uint16_t>(digest.size()));
    out.insert(out.end(), digest.begin(), digest.end());
}

} // namespace

bool security_session_identity::is_valid() const noexcept {
    return session_id != 0 && security_epoch != 0 && key_id != 0 &&
           trust_domain_id != 0 && subject_id != 0;
}

bool common_binding::is_valid() const noexcept {
    return session.is_valid() && direction != message_direction::unknown &&
           negotiated_level != security_level::unknown &&
           required_level != security_level::unknown &&
           static_cast<std::uint8_t>(negotiated_level) >=
               static_cast<std::uint8_t>(required_level) &&
           action != security_action::unknown &&
           digest != digest_algorithm::unknown && !content_digest.empty() &&
           content_digest.size() <= max_content_digest_bytes;
}

bool control_plane_binding::is_valid() const noexcept {
    return common.is_valid() && endpoint.node_id != 0 && endpoint.runtime_id != 0 &&
           endpoint.endpoint_id != 0 && control_epoch != 0 && control_seq != 0 &&
           (!lease_bound || lease_token != 0);
}

bool data_plane_binding::is_valid() const noexcept {
    if (!common.is_valid() || message_class == data_message_class::unknown ||
        !stream.is_valid()) {
        return false;
    }
    if (message_class == data_message_class::event) {
        return event_seq != 0;
    }
    return event_seq == 0;
}

bool encode_authenticator_input(
    const control_plane_binding& binding,
    std::vector<std::uint8_t>& out) {
    if (!binding.is_valid()) {
        out.clear();
        return false;
    }

    out.clear();
    append_prefix(out, security_plane::control);
    append_common(out, binding.common);
    append_le(out, binding.endpoint.node_id);
    append_le(out, binding.endpoint.runtime_id);
    append_le(out, binding.endpoint.endpoint_id);
    append_le(out, binding.control_epoch);
    append_le(out, binding.control_seq);
    append_le(out, binding.lease_token);
    append_le(out, static_cast<std::uint8_t>(binding.lease_bound ? 1 : 0));
    append_digest(out, binding.common.content_digest);
    return true;
}

bool encode_authenticator_input(
    const data_plane_binding& binding,
    std::vector<std::uint8_t>& out) {
    if (!binding.is_valid()) {
        out.clear();
        return false;
    }

    out.clear();
    append_prefix(out, security_plane::data);
    append_common(out, binding.common);
    append_le(out, static_cast<std::uint8_t>(binding.message_class));
    append_le(out, binding.stream.request_id);
    append_le(out, binding.stream.execution_id);
    append_le(out, binding.stream.output_id);
    append_le(out, binding.event_seq);
    append_le(out, binding.fragment_seq);
    append_le(out, static_cast<std::uint8_t>(binding.has_fragment_seq ? 1 : 0));
    append_digest(out, binding.common.content_digest);
    return true;
}

} // namespace linep::sl::v0_2
