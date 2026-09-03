#include <linep_sl/v0_2/session.hpp>

#include <utility>

namespace linep::sl::v0_2 {

bool authenticated_peer::is_valid_at(std::uint64_t now_us) const noexcept {
    return endpoint.node_id != 0 && endpoint.runtime_id != 0 &&
           endpoint.endpoint_id != 0 && trust_domain_id != 0 && subject_id != 0 &&
           credential_revision != 0 && authenticated_at_us != 0 &&
           authenticated_at_us <= now_us && credential_expires_at_us > now_us &&
           !revoked;
}

bool session_record::is_active_at(std::uint64_t now_us) const noexcept {
    return state == session_state::active && established_at_us <= now_us &&
           now_us < expires_at_us && initiator.is_valid_at(now_us) &&
           responder.is_valid_at(now_us);
}

bool session_registry::establish(
    const negotiation_offer& initiator_offer,
    const negotiation_offer& responder_offer,
    const negotiation_policy& policy,
    const negotiation_result& negotiation,
    const authenticated_peer& initiator,
    const authenticated_peer& responder,
    std::uint64_t session_id,
    std::uint64_t security_epoch,
    std::uint32_t key_id,
    std::uint64_t now_us,
    std::uint64_t expires_at_us) noexcept {
    const auto expected = negotiate(initiator_offer, responder_offer, policy);
    if (!negotiation.accepted() || !expected.accepted() ||
        negotiation.status != expected.status ||
        negotiation.required_level != expected.required_level ||
        negotiation.negotiated_level != expected.negotiated_level ||
        negotiation.suite != expected.suite || session_id == 0 || security_epoch == 0 ||
        key_id == 0 || now_us == 0 || expires_at_us <= now_us ||
        sessions_.find(session_id) != sessions_.end() ||
        !initiator_offer.is_structurally_valid() ||
        !responder_offer.is_structurally_valid() ||
        initiator.endpoint != initiator_offer.endpoint ||
        responder.endpoint != responder_offer.endpoint ||
        !initiator.is_valid_at(now_us) || !responder.is_valid_at(now_us) ||
        initiator.credential_expires_at_us < expires_at_us ||
        responder.credential_expires_at_us < expires_at_us) {
        return false;
    }

    std::vector<std::uint8_t> transcript;
    if (!encode_negotiation_transcript(
            initiator_offer, responder_offer, negotiation, transcript)) {
        return false;
    }

    session_record record;
    record.session_id = session_id;
    record.security_epoch = security_epoch;
    record.key_id = key_id;
    record.negotiated_level = negotiation.negotiated_level;
    record.suite = negotiation.suite;
    record.initiator = initiator;
    record.responder = responder;
    record.initiator_control_epoch = initiator_offer.control_epoch;
    record.initiator_lease_token = initiator_offer.lease_token;
    record.responder_control_epoch = responder_offer.control_epoch;
    record.responder_lease_token = responder_offer.lease_token;
    record.negotiation_transcript = std::move(transcript);
    record.established_at_us = now_us;
    record.key_activated_at_us = now_us;
    record.expires_at_us = expires_at_us;
    record.state = session_state::active;
    return sessions_.emplace(session_id, record).second;
}

bool session_registry::rotate(
    std::uint64_t session_id,
    std::uint64_t new_security_epoch,
    std::uint32_t new_key_id,
    std::uint64_t now_us,
    std::uint64_t new_expires_at_us) noexcept {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return false;
    }
    auto& record = it->second;
    if (!record.is_active_at(now_us) || new_security_epoch <= record.security_epoch ||
        new_key_id == 0 || new_key_id == record.key_id ||
        new_expires_at_us <= now_us ||
        new_expires_at_us > record.initiator.credential_expires_at_us ||
        new_expires_at_us > record.responder.credential_expires_at_us) {
        return false;
    }
    record.security_epoch = new_security_epoch;
    record.key_id = new_key_id;
    record.key_activated_at_us = now_us;
    record.expires_at_us = new_expires_at_us;
    return true;
}

bool session_registry::revoke(std::uint64_t session_id) noexcept {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end() || it->second.state != session_state::active) {
        return false;
    }
    it->second.state = session_state::revoked;
    return true;
}

bool session_registry::close(std::uint64_t session_id) noexcept {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end() || it->second.state == session_state::closed) {
        return false;
    }
    it->second.state = session_state::closed;
    return true;
}

std::size_t session_registry::expire(std::uint64_t now_us) noexcept {
    std::size_t count = 0;
    for (auto& entry : sessions_) {
        auto& record = entry.second;
        if (record.state == session_state::active && !record.is_active_at(now_us)) {
            record.state = session_state::expired;
            ++count;
        }
    }
    return count;
}

bool session_registry::get(std::uint64_t session_id, session_record& out) const noexcept {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool session_registry::make_sender_identity(
    std::uint64_t session_id,
    message_direction direction,
    std::uint64_t now_us,
    security_session_identity& out) const noexcept {
    const auto it = sessions_.find(session_id);
    if (it == sessions_.end() || !it->second.is_active_at(now_us) ||
        (direction != message_direction::initiator_to_responder &&
         direction != message_direction::responder_to_initiator)) {
        out = {};
        return false;
    }
    const auto& record = it->second;
    const auto& sender = direction == message_direction::initiator_to_responder
        ? record.initiator
        : record.responder;
    out = {record.session_id, record.security_epoch, record.key_id,
           sender.trust_domain_id, sender.subject_id};
    return true;
}

} // namespace linep::sl::v0_2
