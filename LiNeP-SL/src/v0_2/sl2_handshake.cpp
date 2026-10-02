#include <linep_sl/v0_2/sl2_handshake.hpp>

#include <algorithm>
#include <cstring>

namespace linep::sl::v0_2 {
namespace {

void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) {
    b.push_back(v);
}

void put_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
}

void put_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
}

bool get_u8(const std::uint8_t* data, std::size_t size, std::size_t& offset, std::uint8_t& out) {
    if (offset + 1 > size) return false;
    out = data[offset++];
    return true;
}

bool get_u16(const std::uint8_t* data, std::size_t size, std::size_t& offset, std::uint16_t& out) {
    if (offset + 2 > size) return false;
    out = static_cast<std::uint16_t>(data[offset]) |
          (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    return true;
}

bool get_u32(const std::uint8_t* data, std::size_t size, std::size_t& offset, std::uint32_t& out) {
    if (offset + 4 > size) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
        out |= static_cast<std::uint32_t>(data[offset + i]) << (i * 8);
    }
    offset += 4;
    return true;
}

bool get_u64(const std::uint8_t* data, std::size_t size, std::size_t& offset, std::uint64_t& out) {
    if (offset + 8 > size) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
    }
    offset += 8;
    return true;
}

bool get_bytes(const std::uint8_t* data, std::size_t size, std::size_t& offset, std::size_t len, std::vector<std::uint8_t>& out) {
    if (offset + len > size) return false;
    out.assign(data + offset, data + offset + len);
    offset += len;
    return true;
}

void encode_offer_fields(std::vector<std::uint8_t>& b, const negotiation_offer& o) {
    put_u8(b, o.version_major);
    put_u8(b, o.version_minor);
    put_u8(b, static_cast<std::uint8_t>(o.minimum_level));
    put_u8(b, static_cast<std::uint8_t>(o.maximum_level));
    put_u64(b, o.endpoint.node_id);
    put_u64(b, o.endpoint.runtime_id);
    put_u32(b, o.endpoint.endpoint_id);
    put_u64(b, o.control_epoch);
    put_u64(b, o.lease_token);
    put_u8(b, static_cast<std::uint8_t>(o.supported_suites.size()));
    for (auto s : o.supported_suites) {
        put_u16(b, static_cast<std::uint16_t>(s));
    }
    b.insert(b.end(), o.nonce.begin(), o.nonce.end());
}

bool decode_offer_fields(const std::uint8_t* data, std::size_t size, std::size_t& offset, negotiation_offer& o) {
    std::uint8_t min_lvl = 0, max_lvl = 0, suite_cnt = 0;
    if (!get_u8(data, size, offset, o.version_major) ||
        !get_u8(data, size, offset, o.version_minor) ||
        !get_u8(data, size, offset, min_lvl) ||
        !get_u8(data, size, offset, max_lvl) ||
        !get_u64(data, size, offset, o.endpoint.node_id) ||
        !get_u64(data, size, offset, o.endpoint.runtime_id) ||
        !get_u32(data, size, offset, o.endpoint.endpoint_id) ||
        !get_u64(data, size, offset, o.control_epoch) ||
        !get_u64(data, size, offset, o.lease_token) ||
        !get_u8(data, size, offset, suite_cnt)) {
        return false;
    }
    o.minimum_level = static_cast<security_level>(min_lvl);
    o.maximum_level = static_cast<security_level>(max_lvl);
    if (suite_cnt == 0 || suite_cnt > max_negotiated_suites) return false;

    o.supported_suites.clear();
    o.supported_suites.reserve(suite_cnt);
    for (std::uint8_t i = 0; i < suite_cnt; ++i) {
        std::uint16_t s = 0;
        if (!get_u16(data, size, offset, s)) return false;
        o.supported_suites.push_back(static_cast<crypto_suite>(s));
    }

    if (offset + negotiation_nonce_bytes > size) return false;
    std::copy(data + offset, data + offset + negotiation_nonce_bytes, o.nonce.begin());
    offset += negotiation_nonce_bytes;
    return o.is_structurally_valid();
}

} // namespace

void sl2_session_keys::wipe() noexcept {
    secure_zero(initiator_traffic_key.data(), initiator_traffic_key.size());
    secure_zero(responder_traffic_key.data(), responder_traffic_key.size());
    secure_zero(initiator_iv.data(), initiator_iv.size());
    secure_zero(responder_iv.data(), responder_iv.size());
    secure_zero(initiator_finished_key.data(), initiator_finished_key.size());
    secure_zero(responder_finished_key.data(), responder_finished_key.size());
    initiator_traffic_key.clear();
    responder_traffic_key.clear();
    initiator_iv.clear();
    responder_iv.clear();
    initiator_finished_key.clear();
    responder_finished_key.clear();
    suite = crypto_suite::none;
}

bool encode_client_hello(const sl2_client_hello& hello, std::vector<std::uint8_t>& out) {
    if (!hello.offer.is_structurally_valid() ||
        hello.ephemeral_pubkey.size() != x25519_key_bytes ||
        hello.device_pubkey.size() != ed25519_pubkey_bytes ||
        hello.device_signature.size() != ed25519_signature_bytes ||
        hello.trust_domain_id == 0 || hello.subject_id == 0) {
        out.clear();
        return false;
    }

    out.clear();
    put_u8(out, static_cast<std::uint8_t>(handshake_msg_type::client_hello));
    encode_offer_fields(out, hello.offer);
    out.insert(out.end(), hello.ephemeral_pubkey.begin(), hello.ephemeral_pubkey.end());
    put_u32(out, hello.trust_domain_id);
    put_u64(out, hello.subject_id);
    out.insert(out.end(), hello.device_pubkey.begin(), hello.device_pubkey.end());
    out.insert(out.end(), hello.device_signature.begin(), hello.device_signature.end());
    return true;
}

bool decode_client_hello(const std::uint8_t* data, std::size_t size, sl2_client_hello& out) {
    if (!data || size < 1 + 54 + x25519_key_bytes + 4 + 8 + ed25519_pubkey_bytes + ed25519_signature_bytes) {
        return false;
    }
    std::size_t offset = 0;
    std::uint8_t type = 0;
    if (!get_u8(data, size, offset, type) ||
        type != static_cast<std::uint8_t>(handshake_msg_type::client_hello)) {
        return false;
    }

    if (!decode_offer_fields(data, size, offset, out.offer) ||
        !get_bytes(data, size, offset, x25519_key_bytes, out.ephemeral_pubkey) ||
        !get_u32(data, size, offset, out.trust_domain_id) ||
        !get_u64(data, size, offset, out.subject_id) ||
        !get_bytes(data, size, offset, ed25519_pubkey_bytes, out.device_pubkey) ||
        !get_bytes(data, size, offset, ed25519_signature_bytes, out.device_signature)) {
        return false;
    }

    return offset == size && out.trust_domain_id != 0 && out.subject_id != 0;
}

bool encode_server_hello(const sl2_server_hello& hello, std::vector<std::uint8_t>& out) {
    if (!hello.offer.is_structurally_valid() ||
        hello.ephemeral_pubkey.size() != x25519_key_bytes ||
        hello.gateway_pubkey.size() != ed25519_pubkey_bytes ||
        hello.gateway_signature.size() != ed25519_signature_bytes ||
        hello.trust_domain_id == 0 || hello.subject_id == 0 ||
        !hello.result.accepted()) {
        out.clear();
        return false;
    }

    out.clear();
    put_u8(out, static_cast<std::uint8_t>(handshake_msg_type::server_hello));
    encode_offer_fields(out, hello.offer);
    out.insert(out.end(), hello.ephemeral_pubkey.begin(), hello.ephemeral_pubkey.end());
    put_u32(out, hello.trust_domain_id);
    put_u64(out, hello.subject_id);
    out.insert(out.end(), hello.gateway_pubkey.begin(), hello.gateway_pubkey.end());

    put_u8(out, static_cast<std::uint8_t>(hello.result.status));
    put_u8(out, static_cast<std::uint8_t>(hello.result.required_level));
    put_u8(out, static_cast<std::uint8_t>(hello.result.negotiated_level));
    put_u16(out, static_cast<std::uint16_t>(hello.result.suite));

    out.insert(out.end(), hello.gateway_signature.begin(), hello.gateway_signature.end());
    return true;
}

bool decode_server_hello(const std::uint8_t* data, std::size_t size, sl2_server_hello& out) {
    if (!data || size < 1 + 54 + x25519_key_bytes + 4 + 8 + ed25519_pubkey_bytes + 5 + ed25519_signature_bytes) {
        return false;
    }
    std::size_t offset = 0;
    std::uint8_t type = 0;
    if (!get_u8(data, size, offset, type) ||
        type != static_cast<std::uint8_t>(handshake_msg_type::server_hello)) {
        return false;
    }

    std::uint8_t st = 0, req_lvl = 0, neg_lvl = 0;
    std::uint16_t su = 0;
    if (!decode_offer_fields(data, size, offset, out.offer) ||
        !get_bytes(data, size, offset, x25519_key_bytes, out.ephemeral_pubkey) ||
        !get_u32(data, size, offset, out.trust_domain_id) ||
        !get_u64(data, size, offset, out.subject_id) ||
        !get_bytes(data, size, offset, ed25519_pubkey_bytes, out.gateway_pubkey) ||
        !get_u8(data, size, offset, st) ||
        !get_u8(data, size, offset, req_lvl) ||
        !get_u8(data, size, offset, neg_lvl) ||
        !get_u16(data, size, offset, su) ||
        !get_bytes(data, size, offset, ed25519_signature_bytes, out.gateway_signature)) {
        return false;
    }

    out.result.status = static_cast<negotiation_status>(st);
    out.result.required_level = static_cast<security_level>(req_lvl);
    out.result.negotiated_level = static_cast<security_level>(neg_lvl);
    out.result.suite = static_cast<crypto_suite>(su);

    return offset == size && out.trust_domain_id != 0 && out.subject_id != 0 && out.result.accepted();
}

bool encode_client_finished(const sl2_client_finished& fin, std::vector<std::uint8_t>& out) {
    if (fin.verify_data.size() != sha256_digest_bytes) {
        out.clear();
        return false;
    }
    out.clear();
    put_u8(out, static_cast<std::uint8_t>(handshake_msg_type::client_finished));
    out.insert(out.end(), fin.verify_data.begin(), fin.verify_data.end());
    return true;
}

bool decode_client_finished(const std::uint8_t* data, std::size_t size, sl2_client_finished& out) {
    if (!data || size != 1 + sha256_digest_bytes || data[0] != static_cast<std::uint8_t>(handshake_msg_type::client_finished)) {
        return false;
    }
    out.verify_data.assign(data + 1, data + 1 + sha256_digest_bytes);
    return true;
}

bool encode_server_finished(const sl2_server_finished& fin, std::vector<std::uint8_t>& out) {
    if (fin.verify_data.size() != sha256_digest_bytes) {
        out.clear();
        return false;
    }
    out.clear();
    put_u8(out, static_cast<std::uint8_t>(handshake_msg_type::server_finished));
    out.insert(out.end(), fin.verify_data.begin(), fin.verify_data.end());
    return true;
}

bool decode_server_finished(const std::uint8_t* data, std::size_t size, sl2_server_finished& out) {
    if (!data || size != 1 + sha256_digest_bytes || data[0] != static_cast<std::uint8_t>(handshake_msg_type::server_finished)) {
        return false;
    }
    out.verify_data.assign(data + 1, data + 1 + sha256_digest_bytes);
    return true;
}

bool wrap_handshake_frame(const std::vector<std::uint8_t>& payload, std::vector<std::uint8_t>& out_frame) {
    if (payload.empty()) {
        out_frame.clear();
        return false;
    }

    linep::v0_2::wire_envelope_header hdr{};
    hdr.magic = linep::v0_2::LINEP_V02_MAGIC;
    hdr.version_major = linep::v0_2::LINEP_V02_VERSION_MAJOR;
    hdr.version_minor = linep::v0_2::LINEP_V02_VERSION_MINOR;
    hdr.envelope_type = static_cast<std::uint8_t>(linep::v0_2::runtime_envelope_type::sl2_handshake);
    hdr.flags = 0;
    hdr.request_id = 0;
    hdr.execution_id = 0;
    hdr.output_id = 0;
    hdr.payload_len = static_cast<std::uint32_t>(payload.size());

    out_frame.clear();
    linep::v0_2::encode_header(hdr, out_frame);
    out_frame.insert(out_frame.end(), payload.begin(), payload.end());
    return true;
}

bool unwrap_handshake_frame(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out_payload) {
    out_payload.clear();
    if (!data || size < linep::v0_2::LINEP_V02_HEADER_SIZE) return false;

    linep::v0_2::wire_envelope_header hdr{};
    if (!linep::v0_2::decode_header(data, linep::v0_2::LINEP_V02_HEADER_SIZE, hdr)) return false;

    if (hdr.magic != linep::v0_2::LINEP_V02_MAGIC ||
        hdr.version_major != linep::v0_2::LINEP_V02_VERSION_MAJOR ||
        hdr.version_minor != linep::v0_2::LINEP_V02_VERSION_MINOR ||
        hdr.envelope_type != static_cast<std::uint8_t>(linep::v0_2::runtime_envelope_type::sl2_handshake) ||
        hdr.flags != 0 || hdr.request_id != 0 || hdr.execution_id != 0 || hdr.output_id != 0) {
        return false;
    }

    if (size != linep::v0_2::LINEP_V02_HEADER_SIZE + hdr.payload_len) {
        return false;
    }

    out_payload.assign(data + linep::v0_2::LINEP_V02_HEADER_SIZE, data + size);
    return true;
}

// ── sl2_handshake_session Implementation ─────────────────────────────────────

sl2_handshake_session::sl2_handshake_session(
    session_participant_role role,
    identity_verifier& verifier,
    session_registry& registry) noexcept
    : role_(role), verifier_(verifier), registry_(registry) {
    // H0 = SHA-256("LNS2-SL2-TRANSCRIPT-V0.2")
    const std::string init_label = "LNS2-SL2-TRANSCRIPT-V0.2";
    compute_sha256_digest(reinterpret_cast<const std::uint8_t*>(init_label.data()), init_label.size(), h0_);
}

sl2_handshake_session::~sl2_handshake_session() {
    abort();
}

void sl2_handshake_session::abort() noexcept {
    state_ = handshake_state::failed;
    secure_zero(ephem_priv_.data(), ephem_priv_.size());
    secure_zero(local_privkey_.data(), local_privkey_.size());
    ephem_priv_.clear();
    local_privkey_.clear();
    keys_.wipe();
}

bool sl2_handshake_session::compute_transcript_hash(
    const std::vector<std::uint8_t>& msg,
    std::vector<std::uint8_t>& out_h) const noexcept {
    std::vector<std::uint8_t> input;
    input.reserve(h0_.size() + msg.size());
    input.insert(input.end(), out_h.begin(), out_h.end());
    input.insert(input.end(), msg.begin(), msg.end());
    return compute_sha256_digest(input.data(), input.size(), out_h);
}

bool sl2_handshake_session::initiator_start(
    const negotiation_offer& offer,
    std::uint32_t trust_domain_id,
    std::uint64_t subject_id,
    const std::vector<std::uint8_t>& device_privkey,
    const std::vector<std::uint8_t>& device_pubkey,
    std::vector<std::uint8_t>& out_client_hello_frame) {
    out_client_hello_frame.clear();
    if (role_ != session_participant_role::initiator || state_ != handshake_state::uninitialized) {
        abort();
        return false;
    }

    if (!offer.is_structurally_valid() || device_privkey.size() != ed25519_privkey_bytes ||
        device_pubkey.size() != ed25519_pubkey_bytes || trust_domain_id == 0 || subject_id == 0) {
        abort();
        return false;
    }

    trust_domain_id_ = trust_domain_id;
    subject_id_ = subject_id;
    local_privkey_ = device_privkey;
    local_pubkey_ = device_pubkey;
    client_offer_ = offer;

    // Generate fresh single-use X25519 keypair (PFS)
    if (!generate_x25519_keypair(ephem_priv_, ephem_pub_)) {
        abort();
        return false;
    }

    // Build ClientHello prefix for transcript and signature:
    // Offer || EphemeralPubKey || TrustDomainID || SubjectID || DevicePubKey
    std::vector<std::uint8_t> prefix;
    put_u8(prefix, static_cast<std::uint8_t>(handshake_msg_type::client_hello));
    encode_offer_fields(prefix, client_offer_);
    prefix.insert(prefix.end(), ephem_pub_.begin(), ephem_pub_.end());
    put_u32(prefix, trust_domain_id_);
    put_u64(prefix, subject_id_);
    prefix.insert(prefix.end(), local_pubkey_.begin(), local_pubkey_.end());

    // H1_prefix = SHA-256(H0 || prefix)
    h1_ = h0_;
    if (!compute_transcript_hash(prefix, h1_)) {
        abort();
        return false;
    }

    // SigInput = "LNS2-SIG-CLIENT-V1" || trust_domain_id || subject_id || H1_prefix
    std::vector<std::uint8_t> sig_input;
    const std::string domain_sep = "LNS2-SIG-CLIENT-V1";
    sig_input.insert(sig_input.end(), domain_sep.begin(), domain_sep.end());
    put_u32(sig_input, trust_domain_id_);
    put_u64(sig_input, subject_id_);
    sig_input.insert(sig_input.end(), h1_.begin(), h1_.end());

    std::vector<std::uint8_t> signature;
    if (!ed25519_sign(local_privkey_, sig_input.data(), sig_input.size(), signature)) {
        abort();
        return false;
    }

    // Full H1 absorbs signature as well
    if (!compute_transcript_hash(signature, h1_)) {
        abort();
        return false;
    }

    sl2_client_hello hello;
    hello.offer = client_offer_;
    hello.ephemeral_pubkey = ephem_pub_;
    hello.trust_domain_id = trust_domain_id_;
    hello.subject_id = subject_id_;
    hello.device_pubkey = local_pubkey_;
    hello.device_signature = std::move(signature);

    std::vector<std::uint8_t> hello_payload;
    if (!encode_client_hello(hello, hello_payload) || !wrap_handshake_frame(hello_payload, out_client_hello_frame)) {
        abort();
        return false;
    }

    state_ = handshake_state::client_hello_sent;
    return true;
}

bool sl2_handshake_session::initiator_process_server_hello(
    const std::uint8_t* server_hello_frame,
    std::size_t size,
    std::vector<std::uint8_t>& out_client_finished_frame) {
    out_client_finished_frame.clear();
    if (role_ != session_participant_role::initiator || state_ != handshake_state::client_hello_sent) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> payload;
    if (!unwrap_handshake_frame(server_hello_frame, size, payload)) {
        abort();
        return false;
    }

    sl2_server_hello s_hello;
    if (!decode_server_hello(payload.data(), payload.size(), s_hello)) {
        abort();
        return false;
    }

    server_offer_ = s_hello.offer;
    neg_result_ = s_hello.result;
    peer_ephem_pub_ = s_hello.ephemeral_pubkey;

    // Verify ServerHello signature
    std::vector<std::uint8_t> s_prefix;
    put_u8(s_prefix, static_cast<std::uint8_t>(handshake_msg_type::server_hello));
    encode_offer_fields(s_prefix, server_offer_);
    s_prefix.insert(s_prefix.end(), peer_ephem_pub_.begin(), peer_ephem_pub_.end());
    put_u32(s_prefix, s_hello.trust_domain_id);
    put_u64(s_prefix, s_hello.subject_id);
    s_prefix.insert(s_prefix.end(), s_hello.gateway_pubkey.begin(), s_hello.gateway_pubkey.end());
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.status));
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.required_level));
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.negotiated_level));
    put_u16(s_prefix, static_cast<std::uint16_t>(neg_result_.suite));

    h2_ = h1_;
    if (!compute_transcript_hash(s_prefix, h2_)) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> sig_input;
    const std::string domain_sep = "LNS2-SIG-SERVER-V1";
    sig_input.insert(sig_input.end(), domain_sep.begin(), domain_sep.end());
    put_u32(sig_input, s_hello.trust_domain_id);
    put_u64(sig_input, s_hello.subject_id);
    sig_input.insert(sig_input.end(), h2_.begin(), h2_.end());

    if (!ed25519_verify(s_hello.gateway_pubkey, sig_input.data(), sig_input.size(),
                        s_hello.gateway_signature.data(), s_hello.gateway_signature.size())) {
        abort();
        return false;
    }

    if (!compute_transcript_hash(s_hello.gateway_signature, h2_)) {
        abort();
        return false;
    }

    // Incorporate Phase B LNS2NEG transcript
    std::vector<std::uint8_t> lns2neg;
    if (!encode_negotiation_transcript(client_offer_, server_offer_, neg_result_, lns2neg)) {
        abort();
        return false;
    }

    if (!compute_transcript_hash(lns2neg, h2_)) {
        abort();
        return false;
    }

    // Authenticate responder identity with identity_verifier
    if (!verifier_.authenticate(server_offer_, lns2neg, s_hello.gateway_pubkey, 1000, peer_authenticated_)) {
        abort();
        return false;
    }

    // Derive symmetric keys
    if (!derive_keys()) {
        abort();
        return false;
    }

    // Create ClientFinished: HMAC-SHA256(initiator_finished_key, h2_)
    auto hmac_auth = create_authenticator(crypto_suite::hmac_sha256_128);
    std::vector<std::uint8_t> verify_data;
    if (!hmac_sha256_authenticator(crypto_suite::none).sign(h2_, keys_.initiator_finished_key, verify_data)) {
        abort();
        return false;
    }

    h3_ = h2_;
    if (!compute_transcript_hash(verify_data, h3_)) {
        abort();
        return false;
    }

    sl2_client_finished fin;
    fin.verify_data = std::move(verify_data);
    std::vector<std::uint8_t> fin_payload;
    if (!encode_client_finished(fin, fin_payload) || !wrap_handshake_frame(fin_payload, out_client_finished_frame)) {
        abort();
        return false;
    }

    state_ = handshake_state::client_finished_sent;
    return true;
}

bool sl2_handshake_session::initiator_process_server_finished(
    const std::uint8_t* server_finished_frame,
    std::size_t size,
    session_record& out_session) {
    if (role_ != session_participant_role::initiator || state_ != handshake_state::client_finished_sent) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> payload;
    if (!unwrap_handshake_frame(server_finished_frame, size, payload)) {
        abort();
        return false;
    }

    sl2_server_finished s_fin;
    if (!decode_server_finished(payload.data(), payload.size(), s_fin)) {
        abort();
        return false;
    }

    // Expected VerifyData = HMAC-SHA256(responder_finished_key, h3_)
    std::vector<std::uint8_t> expected;
    if (!hmac_sha256_authenticator(crypto_suite::none).sign(h3_, keys_.responder_finished_key, expected)) {
        abort();
        return false;
    }

    if (!constant_time_equals(s_fin.verify_data.data(), expected.data(), expected.size())) {
        abort();
        return false;
    }

    h4_ = h3_;
    compute_transcript_hash(s_fin.verify_data, h4_);

    // Register active session in registry
    authenticated_peer local_peer{};
    local_peer.endpoint = client_offer_.endpoint;
    local_peer.trust_domain_id = trust_domain_id_;
    local_peer.subject_id = subject_id_;
    local_peer.credential_revision = 1;
    local_peer.authenticated_at_us = 1000;
    local_peer.credential_expires_at_us = 5000000000ULL;

    negotiation_policy policy{neg_result_.required_level, {neg_result_.suite}};
    const std::uint64_t session_id = client_offer_.endpoint.node_id ^ (server_offer_.endpoint.node_id << 16) ^ 0x5122;

    if (!registry_.establish(client_offer_, server_offer_, policy, neg_result_,
                             local_peer, peer_authenticated_,
                             session_id, 1, 1, 1000, 5000000000ULL)) {
        abort();
        return false;
    }

    if (!registry_.get(session_id, out_session)) {
        abort();
        return false;
    }

    state_ = handshake_state::active;
    return true;
}

// ── Responder Methods ────────────────────────────────────────────────────────

bool sl2_handshake_session::responder_process_client_hello(
    const std::uint8_t* client_hello_frame,
    std::size_t size,
    const negotiation_policy& policy,
    const negotiation_offer& responder_offer,
    std::uint32_t trust_domain_id,
    std::uint64_t subject_id,
    const std::vector<std::uint8_t>& gateway_privkey,
    const std::vector<std::uint8_t>& gateway_pubkey,
    std::vector<std::uint8_t>& out_server_hello_frame) {
    out_server_hello_frame.clear();
    if (role_ != session_participant_role::responder || state_ != handshake_state::uninitialized) {
        abort();
        return false;
    }

    if (!policy.is_valid() || !responder_offer.is_structurally_valid() ||
        gateway_privkey.size() != ed25519_privkey_bytes || gateway_pubkey.size() != ed25519_pubkey_bytes ||
        trust_domain_id == 0 || subject_id == 0) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> payload;
    if (!unwrap_handshake_frame(client_hello_frame, size, payload)) {
        abort();
        return false;
    }

    sl2_client_hello c_hello;
    if (!decode_client_hello(payload.data(), payload.size(), c_hello)) {
        abort();
        return false;
    }

    client_offer_ = c_hello.offer;
    server_offer_ = responder_offer;
    trust_domain_id_ = trust_domain_id;
    subject_id_ = subject_id;
    local_privkey_ = gateway_privkey;
    local_pubkey_ = gateway_pubkey;
    peer_ephem_pub_ = c_hello.ephemeral_pubkey;

    // Negotiate policy and offers
    neg_result_ = negotiate(client_offer_, server_offer_, policy);
    if (!neg_result_.accepted()) {
        abort();
        return false;
    }

    // Verify ClientHello signature
    std::vector<std::uint8_t> c_prefix;
    put_u8(c_prefix, static_cast<std::uint8_t>(handshake_msg_type::client_hello));
    encode_offer_fields(c_prefix, client_offer_);
    c_prefix.insert(c_prefix.end(), peer_ephem_pub_.begin(), peer_ephem_pub_.end());
    put_u32(c_prefix, c_hello.trust_domain_id);
    put_u64(c_prefix, c_hello.subject_id);
    c_prefix.insert(c_prefix.end(), c_hello.device_pubkey.begin(), c_hello.device_pubkey.end());

    h1_ = h0_;
    if (!compute_transcript_hash(c_prefix, h1_)) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> sig_input;
    const std::string domain_sep = "LNS2-SIG-CLIENT-V1";
    sig_input.insert(sig_input.end(), domain_sep.begin(), domain_sep.end());
    put_u32(sig_input, c_hello.trust_domain_id);
    put_u64(sig_input, c_hello.subject_id);
    sig_input.insert(sig_input.end(), h1_.begin(), h1_.end());

    if (!ed25519_verify(c_hello.device_pubkey, sig_input.data(), sig_input.size(),
                        c_hello.device_signature.data(), c_hello.device_signature.size())) {
        abort();
        return false;
    }

    if (!compute_transcript_hash(c_hello.device_signature, h1_)) {
        abort();
        return false;
    }

    // Verify client identity via identity_verifier
    std::vector<std::uint8_t> lns2neg;
    if (!encode_negotiation_transcript(client_offer_, server_offer_, neg_result_, lns2neg)) {
        abort();
        return false;
    }

    if (!verifier_.authenticate(client_offer_, lns2neg, c_hello.device_pubkey, 1000, peer_authenticated_)) {
        abort();
        return false;
    }

    // Generate server ephemeral keypair (PFS)
    if (!generate_x25519_keypair(ephem_priv_, ephem_pub_)) {
        abort();
        return false;
    }

    // Build ServerHello
    std::vector<std::uint8_t> s_prefix;
    put_u8(s_prefix, static_cast<std::uint8_t>(handshake_msg_type::server_hello));
    encode_offer_fields(s_prefix, server_offer_);
    s_prefix.insert(s_prefix.end(), ephem_pub_.begin(), ephem_pub_.end());
    put_u32(s_prefix, trust_domain_id_);
    put_u64(s_prefix, subject_id_);
    s_prefix.insert(s_prefix.end(), local_pubkey_.begin(), local_pubkey_.end());
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.status));
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.required_level));
    put_u8(s_prefix, static_cast<std::uint8_t>(neg_result_.negotiated_level));
    put_u16(s_prefix, static_cast<std::uint16_t>(neg_result_.suite));

    h2_ = h1_;
    if (!compute_transcript_hash(s_prefix, h2_)) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> s_sig_input;
    const std::string s_domain_sep = "LNS2-SIG-SERVER-V1";
    s_sig_input.insert(s_sig_input.end(), s_domain_sep.begin(), s_domain_sep.end());
    put_u32(s_sig_input, trust_domain_id_);
    put_u64(s_sig_input, subject_id_);
    s_sig_input.insert(s_sig_input.end(), h2_.begin(), h2_.end());

    std::vector<std::uint8_t> s_signature;
    if (!ed25519_sign(local_privkey_, s_sig_input.data(), s_sig_input.size(), s_signature)) {
        abort();
        return false;
    }

    if (!compute_transcript_hash(s_signature, h2_)) {
        abort();
        return false;
    }

    // Incorporate LNS2NEG transcript
    if (!compute_transcript_hash(lns2neg, h2_)) {
        abort();
        return false;
    }

    // Derive symmetric keys
    if (!derive_keys()) {
        abort();
        return false;
    }

    sl2_server_hello s_hello;
    s_hello.offer = server_offer_;
    s_hello.ephemeral_pubkey = ephem_pub_;
    s_hello.trust_domain_id = trust_domain_id_;
    s_hello.subject_id = subject_id_;
    s_hello.gateway_pubkey = local_pubkey_;
    s_hello.result = neg_result_;
    s_hello.gateway_signature = std::move(s_signature);

    std::vector<std::uint8_t> s_payload;
    if (!encode_server_hello(s_hello, s_payload) || !wrap_handshake_frame(s_payload, out_server_hello_frame)) {
        abort();
        return false;
    }

    state_ = handshake_state::server_hello_sent;
    return true;
}

bool sl2_handshake_session::responder_process_client_finished(
    const std::uint8_t* client_finished_frame,
    std::size_t size,
    std::vector<std::uint8_t>& out_server_finished_frame,
    session_record& out_session) {
    out_server_finished_frame.clear();
    if (role_ != session_participant_role::responder || state_ != handshake_state::server_hello_sent) {
        abort();
        return false;
    }

    std::vector<std::uint8_t> payload;
    if (!unwrap_handshake_frame(client_finished_frame, size, payload)) {
        abort();
        return false;
    }

    sl2_client_finished c_fin;
    if (!decode_client_finished(payload.data(), payload.size(), c_fin)) {
        abort();
        return false;
    }

    // Expected verify_data = HMAC-SHA256(initiator_finished_key, h2_)
    std::vector<std::uint8_t> expected;
    if (!hmac_sha256_authenticator(crypto_suite::none).sign(h2_, keys_.initiator_finished_key, expected)) {
        abort();
        return false;
    }

    if (!constant_time_equals(c_fin.verify_data.data(), expected.data(), expected.size())) {
        abort();
        return false;
    }

    h3_ = h2_;
    compute_transcript_hash(c_fin.verify_data, h3_);

    // Generate ServerFinished verify_data = HMAC-SHA256(responder_finished_key, h3_)
    std::vector<std::uint8_t> s_verify;
    if (!hmac_sha256_authenticator(crypto_suite::none).sign(h3_, keys_.responder_finished_key, s_verify)) {
        abort();
        return false;
    }

    h4_ = h3_;
    compute_transcript_hash(s_verify, h4_);

    sl2_server_finished s_fin;
    s_fin.verify_data = std::move(s_verify);
    std::vector<std::uint8_t> s_payload;
    if (!encode_server_finished(s_fin, s_payload) || !wrap_handshake_frame(s_payload, out_server_finished_frame)) {
        abort();
        return false;
    }

    // Register active session in registry
    authenticated_peer local_peer{};
    local_peer.endpoint = server_offer_.endpoint;
    local_peer.trust_domain_id = trust_domain_id_;
    local_peer.subject_id = subject_id_;
    local_peer.credential_revision = 1;
    local_peer.authenticated_at_us = 1000;
    local_peer.credential_expires_at_us = 5000000000ULL;

    negotiation_policy policy{neg_result_.required_level, {neg_result_.suite}};
    const std::uint64_t session_id = client_offer_.endpoint.node_id ^ (server_offer_.endpoint.node_id << 16) ^ 0x5122;

    if (!registry_.establish(client_offer_, server_offer_, policy, neg_result_,
                             peer_authenticated_, local_peer,
                             session_id, 1, 1, 1000, 5000000000ULL)) {
        abort();
        return false;
    }

    if (!registry_.get(session_id, out_session)) {
        abort();
        return false;
    }

    state_ = handshake_state::active;
    return true;
}

bool sl2_handshake_session::derive_keys() noexcept {
    // 1. Shared secret via X25519
    std::vector<std::uint8_t> ss;
    if (!diffie_hellman_x25519(ephem_priv_, peer_ephem_pub_, ss)) {
        return false;
    }

    // 2. PRK = HKDF-Extract(salt = h2_, ikm = ss)
    std::vector<std::uint8_t> prk;
    if (!hkdf_extract(h2_, ss, prk)) {
        secure_zero(ss.data(), ss.size());
        return false;
    }
    secure_zero(ss.data(), ss.size());

    // 3. HKDF-Expand keys
    keys_.suite = neg_result_.suite;
    bool ok = hkdf_expand(prk, "lns2.key.init", aead_key_bytes, keys_.initiator_traffic_key) &&
              hkdf_expand(prk, "lns2.key.resp", aead_key_bytes, keys_.responder_traffic_key) &&
              hkdf_expand(prk, "lns2.iv.init", aead_nonce_bytes, keys_.initiator_iv) &&
              hkdf_expand(prk, "lns2.iv.resp", aead_nonce_bytes, keys_.responder_iv) &&
              hkdf_expand(prk, "lns2.fin.init", sha256_digest_bytes, keys_.initiator_finished_key) &&
              hkdf_expand(prk, "lns2.fin.resp", sha256_digest_bytes, keys_.responder_finished_key);

    secure_zero(prk.data(), prk.size());
    if (!ok) {
        keys_.wipe();
    }
    return ok;
}

} // namespace linep::sl::v0_2
