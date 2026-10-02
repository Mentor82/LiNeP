#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <linep/v0_2/envelopes.hpp>
#include <linep_sl/v0_2/crypto_provider.hpp>
#include <linep_sl/v0_2/negotiation.hpp>
#include <linep_sl/v0_2/plane_authenticator.hpp>
#include <linep_sl/v0_2/session.hpp>

namespace linep::sl::v0_2 {

enum class handshake_msg_type : std::uint8_t {
    unknown = 0,
    client_hello = 1,
    server_hello = 2,
    client_finished = 3,
    server_finished = 4,
};

enum class handshake_state : std::uint8_t {
    uninitialized = 0,
    client_hello_sent = 1,
    client_hello_received = 2,
    server_hello_sent = 3,
    server_hello_received = 4,
    client_finished_sent = 5,
    client_finished_received = 6,
    active = 7,
    failed = 8,
};

struct sl2_client_hello {
    negotiation_offer offer;
    std::vector<std::uint8_t> ephemeral_pubkey; // 32 bytes X25519
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};
    std::vector<std::uint8_t> device_pubkey;    // 32 bytes Ed25519
    std::vector<std::uint8_t> device_signature; // 64 bytes Ed25519 signature
};

struct sl2_server_hello {
    negotiation_offer offer;
    std::vector<std::uint8_t> ephemeral_pubkey; // 32 bytes X25519
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};
    std::vector<std::uint8_t> gateway_pubkey;   // 32 bytes Ed25519
    negotiation_result result;
    std::vector<std::uint8_t> gateway_signature;// 64 bytes Ed25519 signature
};

struct sl2_client_finished {
    std::vector<std::uint8_t> verify_data; // 32 bytes HMAC-SHA-256
};

struct sl2_server_finished {
    std::vector<std::uint8_t> verify_data; // 32 bytes HMAC-SHA-256
};

// Message codecs
bool encode_client_hello(const sl2_client_hello& hello, std::vector<std::uint8_t>& out);
bool decode_client_hello(const std::uint8_t* data, std::size_t size, sl2_client_hello& out);

bool encode_server_hello(const sl2_server_hello& hello, std::vector<std::uint8_t>& out);
bool decode_server_hello(const std::uint8_t* data, std::size_t size, sl2_server_hello& out);

bool encode_client_finished(const sl2_client_finished& fin, std::vector<std::uint8_t>& out);
bool decode_client_finished(const std::uint8_t* data, std::size_t size, sl2_client_finished& out);

bool encode_server_finished(const sl2_server_finished& fin, std::vector<std::uint8_t>& out);
bool decode_server_finished(const std::uint8_t* data, std::size_t size, sl2_server_finished& out);

// Wire Envelope Frame Helpers (Envelope Type 7)
bool wrap_handshake_frame(const std::vector<std::uint8_t>& payload, std::vector<std::uint8_t>& out_frame);
bool unwrap_handshake_frame(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out_payload);

// Key material derived from handshake
struct sl2_session_keys {
    crypto_suite suite{crypto_suite::none};
    std::vector<std::uint8_t> initiator_traffic_key; // 32 bytes
    std::vector<std::uint8_t> responder_traffic_key; // 32 bytes
    std::vector<std::uint8_t> initiator_iv;          // 12 bytes
    std::vector<std::uint8_t> responder_iv;          // 12 bytes
    std::vector<std::uint8_t> initiator_finished_key;// 32 bytes
    std::vector<std::uint8_t> responder_finished_key;// 32 bytes

    void wipe() noexcept;
};

// Handshake Session Manager implementing state machine & RFC 8446 transcript binding
class sl2_handshake_session {
public:
    sl2_handshake_session(
        session_participant_role role,
        identity_verifier& verifier,
        session_registry& registry) noexcept;
    ~sl2_handshake_session();

    // Initiator (Client / Dial-out worker) API:
    bool initiator_start(
        const negotiation_offer& offer,
        std::uint32_t trust_domain_id,
        std::uint64_t subject_id,
        const std::vector<std::uint8_t>& device_privkey,
        const std::vector<std::uint8_t>& device_pubkey,
        std::vector<std::uint8_t>& out_client_hello_frame);

    bool initiator_process_server_hello(
        const std::uint8_t* server_hello_frame,
        std::size_t size,
        std::vector<std::uint8_t>& out_client_finished_frame);

    bool initiator_process_server_finished(
        const std::uint8_t* server_finished_frame,
        std::size_t size,
        session_record& out_session);

    // Responder (Gateway / Router / Server) API:
    bool responder_process_client_hello(
        const std::uint8_t* client_hello_frame,
        std::size_t size,
        const negotiation_policy& policy,
        const negotiation_offer& responder_offer,
        std::uint32_t trust_domain_id,
        std::uint64_t subject_id,
        const std::vector<std::uint8_t>& gateway_privkey,
        const std::vector<std::uint8_t>& gateway_pubkey,
        std::vector<std::uint8_t>& out_server_hello_frame);

    bool responder_process_client_finished(
        const std::uint8_t* client_finished_frame,
        std::size_t size,
        std::vector<std::uint8_t>& out_server_finished_frame,
        session_record& out_session);

    handshake_state state() const noexcept { return state_; }
    const sl2_session_keys& keys() const noexcept { return keys_; }

private:
    void abort() noexcept;
    bool compute_transcript_hash(const std::vector<std::uint8_t>& msg, std::vector<std::uint8_t>& out_h) const noexcept;
    bool derive_keys() noexcept;

    session_participant_role role_{session_participant_role::unknown};
    identity_verifier& verifier_;
    session_registry& registry_;
    handshake_state state_{handshake_state::uninitialized};

    // Long-term credentials
    std::uint32_t trust_domain_id_{0};
    std::uint64_t subject_id_{0};
    std::vector<std::uint8_t> local_privkey_;
    std::vector<std::uint8_t> local_pubkey_;

    // Ephemeral DH keypair
    std::vector<std::uint8_t> ephem_priv_;
    std::vector<std::uint8_t> ephem_pub_;

    // Peer state
    std::vector<std::uint8_t> peer_ephem_pub_;
    authenticated_peer peer_authenticated_{};

    // Stored negotiation offers & result
    negotiation_offer client_offer_{};
    negotiation_offer server_offer_{};
    negotiation_result neg_result_{};

    // Running transcript hashes
    std::vector<std::uint8_t> h0_; // Initial hash
    std::vector<std::uint8_t> h1_; // After ClientHello
    std::vector<std::uint8_t> h2_; // After ServerHello + LNS2NEG
    std::vector<std::uint8_t> h3_; // After ClientFinished
    std::vector<std::uint8_t> h4_; // After ServerFinished

    sl2_session_keys keys_{};
};

} // namespace linep::sl::v0_2
