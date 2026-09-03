#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include <linep_sl/v0_2/negotiation.hpp>

namespace linep::sl::v0_2 {

enum class session_state : std::uint8_t {
    pending = 0,
    active = 1,
    expired = 2,
    revoked = 3,
    closed = 4,
};

struct authenticated_peer {
    linep::v0_2::node_endpoint_identity endpoint;
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};
    std::uint64_t credential_revision{0};
    std::uint64_t authenticated_at_us{0};
    std::uint64_t credential_expires_at_us{0};
    bool revoked{false};

    bool is_valid_at(std::uint64_t now_us) const noexcept;
};

// Implementations verify a transcript-bound proof using their own PKI, key
// store, HSM, or federated identity backend. No provider is mandated here.
class identity_verifier {
public:
    virtual ~identity_verifier() = default;
    virtual bool authenticate(
        const negotiation_offer& offer,
        const std::vector<std::uint8_t>& negotiation_transcript,
        const std::vector<std::uint8_t>& credential_proof,
        std::uint64_t now_us,
        authenticated_peer& out_peer) noexcept = 0;
};

struct session_record {
    std::uint64_t session_id{0};
    std::uint64_t security_epoch{0};
    std::uint32_t key_id{0};
    security_level negotiated_level{security_level::unknown};
    crypto_suite suite{crypto_suite::none};
    authenticated_peer initiator;
    authenticated_peer responder;
    std::uint64_t initiator_control_epoch{0};
    std::uint64_t initiator_lease_token{0};
    std::uint64_t responder_control_epoch{0};
    std::uint64_t responder_lease_token{0};
    std::vector<std::uint8_t> negotiation_transcript;
    std::uint64_t established_at_us{0};
    std::uint64_t key_activated_at_us{0};
    std::uint64_t expires_at_us{0};
    session_state state{session_state::pending};

    bool is_active_at(std::uint64_t now_us) const noexcept;
};

class session_registry {
public:
    bool establish(
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
        std::uint64_t expires_at_us) noexcept;

    bool rotate(
        std::uint64_t session_id,
        std::uint64_t new_security_epoch,
        std::uint32_t new_key_id,
        std::uint64_t now_us,
        std::uint64_t new_expires_at_us) noexcept;

    bool revoke(std::uint64_t session_id) noexcept;
    bool close(std::uint64_t session_id) noexcept;
    std::size_t expire(std::uint64_t now_us) noexcept;

    bool get(std::uint64_t session_id, session_record& out) const noexcept;
    bool make_sender_identity(
        std::uint64_t session_id,
        message_direction direction,
        std::uint64_t now_us,
        security_session_identity& out) const noexcept;

private:
    std::unordered_map<std::uint64_t, session_record> sessions_;
};

} // namespace linep::sl::v0_2
