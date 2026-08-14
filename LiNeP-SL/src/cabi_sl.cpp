#include <linep_sl/cabi_sl.h>
#include <linep_sl/sl1.hpp>
#include <linep_sl/sl2.hpp>
#include <linep_sl/sl3.hpp>
#include <linep_sl/sl4.hpp>
#include <cstring>
#include <memory>

extern "C" {

LINEP_SL_API int linep_sl1_compute_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, uint32_t payload_len,
    uint8_t out_mac[16])
{
    if (!secret_key || key_len == 0 || !header_ptr || !out_mac) return 0;
    const auto* hdr = reinterpret_cast<const linep::Header*>(header_ptr);
    linep::sl::compute_sl1_mac(secret_key, key_len, *hdr, session_id, key_id, auth_seq, payload, payload_len, out_mac);
    return 1;
}

LINEP_SL_API int linep_sl1_verify_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, const linep_sl_auth_ext_t* auth_ext,
    const uint8_t* payload, uint32_t payload_len)
{
    if (!secret_key || key_len == 0 || !header_ptr || !auth_ext) return 0;
    const auto* hdr = reinterpret_cast<const linep::Header*>(header_ptr);
    const auto* ext = reinterpret_cast<const linep::sl::HeaderAuthExt*>(auth_ext);
    return linep::sl::verify_sl1_mac(secret_key, key_len, *hdr, *ext, payload, payload_len) ? 1 : 0;
}

LINEP_SL_API int linep_sl2_negotiate_level(
    uint8_t peer_supported,
    uint8_t local_supported,
    uint8_t local_required,
    uint8_t* out_negotiated)
{
    auto res = linep::sl::negotiate_security_level(
        static_cast<linep::sl::SecurityLevel>(peer_supported),
        static_cast<linep::sl::SecurityLevel>(local_supported),
        static_cast<linep::sl::SecurityLevel>(local_required));
    if (out_negotiated) {
        *out_negotiated = static_cast<uint8_t>(res.negotiated_sl);
    }
    return res.success ? 1 : 0;
}

LINEP_SL_API int linep_sl2_validate_peer_identity(
    const linep_sl2_peer_identity_t* peer,
    uint32_t expected_trust_domain)
{
    if (!peer) return 0;
    linep::sl::PeerIdentity p{};
    p.trust_domain_id = peer->trust_domain_id;
    p.node_id = peer->node_id;
    std::memcpy(p.pubkey, peer->pubkey, 32);
    p.revoked = (peer->revoked != 0);
    return linep::sl::validate_peer_identity(p, expected_trust_domain) ? 1 : 0;
}

LINEP_SL_API int linep_sl2_derive_session_key(
    const uint8_t* master_secret, uint32_t master_len,
    uint32_t session_id, uint16_t key_id,
    uint16_t node_id, uint64_t ttl_sec,
    uint64_t current_time_sec,
    linep_sl2_session_key_t* out_key)
{
    if (!master_secret || master_len == 0 || !out_key) return 0;
    linep::sl::SessionKey sk{};
    if (!linep::sl::derive_session_key(master_secret, master_len, session_id, key_id, node_id, ttl_sec, current_time_sec, sk)) {
        return 0;
    }
    out_key->session_id = sk.session_id;
    out_key->key_id = sk.key_id;
    out_key->established_at_sec = sk.established_at_sec;
    out_key->expires_at_sec = sk.expires_at_sec;
    std::memcpy(out_key->secret_key, sk.secret_key, 32);
    return 1;
}

LINEP_SL_API int linep_sl2_verify_session_key_freshness(
    const linep_sl2_session_key_t* key,
    uint64_t current_time_sec)
{
    if (!key) return 0;
    linep::sl::SessionKey sk{};
    sk.session_id = key->session_id;
    sk.key_id = key->key_id;
    sk.established_at_sec = key->established_at_sec;
    sk.expires_at_sec = key->expires_at_sec;
    std::memcpy(sk.secret_key, key->secret_key, 32);
    return linep::sl::verify_session_key_freshness(sk, current_time_sec) ? 1 : 0;
}

LINEP_SL_API int linep_sl3_create_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    uint32_t session_id, uint64_t granted_caps,
    uint64_t expires_at_sec, linep_sl_cap_ext_t* out_token)
{
    if (!secret_key || key_len == 0 || !out_token) return 0;
    out_token->session_id = session_id;
    out_token->granted_caps = granted_caps;
    out_token->expires_at_sec = expires_at_sec;
    linep::sl::compute_cap_token_mac(secret_key, key_len, session_id, granted_caps, expires_at_sec, out_token->cap_mac);
    return 1;
}

LINEP_SL_API int linep_sl3_verify_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    const linep_sl_cap_ext_t* cap_token,
    uint32_t expected_session_id,
    uint64_t current_time_sec,
    uint64_t required_capability)
{
    if (!secret_key || key_len == 0 || !cap_token) return 0;
    const auto* tok = reinterpret_cast<const linep::sl::HeaderCapExt*>(cap_token);
    return linep::sl::verify_cap_token(
        secret_key, key_len, *tok, expected_session_id, current_time_sec,
        static_cast<linep::sl::CapFlags>(required_capability)) ? 1 : 0;
}

LINEP_SL_API int linep_sl4_evaluate_decision(
    uint32_t trust_domain_id,
    uint32_t session_id,
    uint16_t key_id,
    uint16_t remote_node_id,
    uint32_t remote_trust_domain_id,
    uint8_t  remote_revoked,
    uint8_t  negotiated_sl,
    uint64_t requested_cap,
    const char* policy_id,
    uint8_t* out_decision,
    char* out_reason_buf,
    uint32_t reason_buf_len)
{
    auto pol_provider = std::make_shared<linep::sl::MemoryGovernancePolicyProvider>();
    auto id_provider = std::make_shared<linep::sl::MemoryIdentityProvider>(trust_domain_id);
    id_provider->register_peer(remote_node_id, reinterpret_cast<const uint8_t*>("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"));

    auto fed_provider = std::make_shared<linep::sl::MemoryFederationTrustProvider>();
    auto audit_sink = std::make_shared<linep::sl::MemoryAuditSink>();

    linep::sl::SecurityDecisionEngine engine(pol_provider, id_provider, fed_provider, audit_sink);

    linep::sl::DecisionContext ctx{};
    ctx.trust_domain_id = trust_domain_id;
    ctx.session_id = session_id;
    ctx.key_id = key_id;
    ctx.remote_peer.trust_domain_id = remote_trust_domain_id;
    ctx.remote_peer.node_id = remote_node_id;
    std::memcpy(ctx.remote_peer.pubkey, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 32);
    ctx.remote_peer.revoked = (remote_revoked != 0);
    ctx.negotiated_sl = static_cast<linep::sl::SecurityLevel>(negotiated_sl);
    ctx.requested_cap = static_cast<linep::sl::CapFlags>(requested_cap);
    ctx.policy_id = policy_id ? policy_id : "default-policy";
    ctx.timestamp_sec = 1700000000ULL;

    auto res = engine.evaluate(ctx);
    if (out_decision) {
        *out_decision = static_cast<uint8_t>(res.decision);
    }
    if (out_reason_buf && reason_buf_len > 0) {
        std::strncpy(out_reason_buf, res.reason_code.c_str(), reason_buf_len - 1);
        out_reason_buf[reason_buf_len - 1] = '\0';
    }
    return (res.decision == linep::sl::Decision::ALLOW) ? 1 : 0;
}

} // extern "C"
