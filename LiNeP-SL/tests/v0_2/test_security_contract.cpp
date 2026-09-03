#include <linep_sl/v0_2/security_contract.hpp>

#include <cassert>
#include <cstdint>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

common_binding valid_common(security_action action) {
    common_binding result;
    result.session = {101, 7, 3, 42, 9001};
    result.direction = message_direction::initiator_to_responder;
    result.negotiated_level = security_level::sl3_authorized;
    result.required_level = security_level::sl2_identity;
    result.action = action;
    result.digest = digest_algorithm::sha256;
    result.content_digest.assign(32, 0xA5);
    return result;
}

} // namespace

int main() {
    std::vector<std::uint8_t> encoded;

    control_plane_binding control;
    control.common = valid_common(security_action::manage_lease);
    control.endpoint = {1001, 2001, 1};
    control.control_epoch = 8;
    control.control_seq = 9;
    control.lease_token = 10;
    control.lease_bound = true;

    assert(control.is_valid());
    assert(encode_authenticator_input(control, encoded));
    assert(encoded.size() > control.common.content_digest.size());
    assert(encoded[0] == 'L' && encoded[1] == 'N' && encoded[2] == 'S' && encoded[3] == '2');
    const auto encoded_control = encoded;

    auto no_lease = control;
    no_lease.lease_token = 0;
    assert(!no_lease.is_valid());
    assert(!encode_authenticator_input(no_lease, encoded));
    assert(encoded.empty());

    auto downgrade = control;
    downgrade.common.negotiated_level = security_level::sl1_authenticated;
    downgrade.common.required_level = security_level::sl3_authorized;
    assert(!downgrade.is_valid());

    auto unknown_digest = control;
    unknown_digest.common.digest = digest_algorithm::unknown;
    assert(!unknown_digest.is_valid());

    data_plane_binding request;
    request.common = valid_common(security_action::execute);
    request.message_class = data_message_class::request;
    request.stream = {501, 601, 0};
    assert(request.is_valid());
    assert(encode_authenticator_input(request, encoded));
    const auto encoded_request = encoded;
    assert(encoded_request != encoded_control);

    data_plane_binding event = request;
    event.common.action = security_action::emit_output;
    event.message_class = data_message_class::event;
    event.stream.output_id = 1;
    event.event_seq = 1;
    event.has_fragment_seq = true;
    event.fragment_seq = 0;
    assert(event.is_valid());
    assert(encode_authenticator_input(event, encoded));
    const auto first_fragment = encoded;

    event.fragment_seq = 1;
    assert(encode_authenticator_input(event, encoded));
    assert(encoded != first_fragment);

    event.fragment_seq = 0;
    event.common.direction = message_direction::responder_to_initiator;
    assert(encode_authenticator_input(event, encoded));
    assert(encoded != first_fragment);

    event.event_seq = 0;
    assert(!event.is_valid());

    request.event_seq = 1;
    assert(!request.is_valid());

    request = {};
    assert(!request.is_valid());
    assert(!encode_authenticator_input(request, encoded));
    assert(encoded.empty());

    return 0;
}
