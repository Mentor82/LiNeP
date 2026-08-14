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

struct linep_sl4_engine {
    std::shared_ptr<linep::sl::MemoryGovernancePolicyProvider> pol_provider;
    std::shared_ptr<linep::sl::MemoryIdentityProvider>          id_provider;
    std::shared_ptr<linep::sl::MemoryFederationTrustProvider>  fed_provider;
    std::shared_ptr<linep::sl::MemoryAuditSink>                 audit_sink;
    std::unique_ptr<linep::sl::SecurityDecisionEngine>          engine;
};

LINEP_SL_API linep_sl4_engine_t* linep_sl4_engine_create(uint32_t local_trust_domain_id) {
    auto e = new linep_sl4_engine();
    e->pol_provider = std::make_shared<linep::sl::MemoryGovernancePolicyProvider>();
    e->id_provider = std::make_shared<linep::sl::MemoryIdentityProvider>(local_trust_domain_id);
    e->fed_provider = std::make_shared<linep::sl::MemoryFederationTrustProvider>();
    e->audit_sink = std::make_shared<linep::sl::MemoryAuditSink>();
    e->engine = std::make_unique<linep::sl::SecurityDecisionEngine>(
        e->pol_provider, e->id_provider, e->fed_provider, e->audit_sink);
    return reinterpret_cast<linep_sl4_engine_t*>(e);
}

LINEP_SL_API void linep_sl4_engine_free(linep_sl4_engine_t* engine) {
    if (engine) {
        delete reinterpret_cast<linep_sl4_engine*>(engine);
    }
}

LINEP_SL_API int linep_sl4_engine_register_peer(
    linep_sl4_engine_t* engine, uint16_t node_id, const uint8_t* pubkey_32bytes)
{
    if (!engine || !pubkey_32bytes) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);
    impl->id_provider->register_peer(node_id, pubkey_32bytes);
    return 1;
}

LINEP_SL_API int linep_sl4_engine_set_policy(
    linep_sl4_engine_t* engine, const char* policy_id, uint32_t revision, uint64_t allowed_caps, uint8_t allow_cross_domain)
{
    if (!engine || !policy_id) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);
    linep::sl::GovernancePolicy pol;
    pol.policy_id = policy_id;
    pol.policy_revision = revision;
    pol.allowed_capabilities = allowed_caps;
    pol.allow_cross_domain = (allow_cross_domain != 0);
    impl->engine->register_policy(pol);
    return 1;
}

LINEP_SL_API int linep_sl4_engine_add_federation(
    linep_sl4_engine_t* engine, uint32_t local_domain, uint32_t remote_domain, uint64_t max_caps, uint32_t revision)
{
    if (!engine) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);
    impl->fed_provider->add_federation(local_domain, remote_domain, max_caps, revision);
    return 1;
}

LINEP_SL_API int linep_sl4_engine_revoke_federation(
    linep_sl4_engine_t* engine, uint32_t local_domain, uint32_t remote_domain)
{
    if (!engine) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);
    impl->fed_provider->revoke_federation(local_domain, remote_domain);
    return 1;
}

LINEP_SL_API int linep_sl4_engine_evaluate(
    linep_sl4_engine_t* engine,
    uint32_t trust_domain_id,
    uint32_t session_id,
    uint16_t key_id,
    uint16_t local_node_id,
    uint16_t remote_node_id,
    uint32_t remote_trust_domain_id,
    const uint8_t* remote_pubkey_32bytes,
    uint8_t  remote_revoked,
    uint8_t  negotiated_sl,
    uint64_t requested_cap,
    uint8_t  msg_type,
    uint32_t correlation_id,
    const char* policy_id,
    uint32_t established_policy_revision,
    uint64_t timestamp_sec,
    uint8_t* out_decision,
    char* out_reason_buf,
    uint32_t reason_buf_len)
{
    if (!engine) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);

    linep::sl::DecisionContext dctx{};
    dctx.trust_domain_id = trust_domain_id;
    dctx.session_id = session_id;
    dctx.key_id = key_id;
    dctx.local_peer.node_id = local_node_id;
    dctx.local_peer.trust_domain_id = trust_domain_id;

    dctx.remote_peer.node_id = remote_node_id;
    dctx.remote_peer.trust_domain_id = remote_trust_domain_id;
    dctx.remote_peer.revoked = (remote_revoked != 0);

    // REAL IDENTITY RESOLUTION: Consume passed pubkey if available, else look up registered identity
    bool pubkey_set = false;
    if (remote_pubkey_32bytes) {
        uint8_t mask = 0;
        for (int i = 0; i < 32; ++i) mask |= remote_pubkey_32bytes[i];
        if (mask != 0) {
            std::memcpy(dctx.remote_peer.pubkey, remote_pubkey_32bytes, 32);
            pubkey_set = true;
        }
    }

    if (!pubkey_set && impl->id_provider) {
        linep::sl::PeerIdentity registered_id{};
        if (impl->id_provider->get_peer_identity(remote_node_id, remote_trust_domain_id, registered_id)) {
            std::memcpy(dctx.remote_peer.pubkey, registered_id.pubkey, 32);
            pubkey_set = true;
        }
    }

    if (!pubkey_set) {
        std::memset(dctx.remote_peer.pubkey, 0, 32); // All zeros -> will fail closed if identity validation is required
    }

    dctx.negotiated_sl = static_cast<linep::sl::SecurityLevel>(negotiated_sl);
    dctx.requested_cap = static_cast<linep::sl::CapFlags>(requested_cap);
    dctx.msg_type = msg_type;
    dctx.correlation_id = correlation_id;
    dctx.policy_id = policy_id ? policy_id : "default-policy";
    dctx.established_policy_revision = established_policy_revision;
    dctx.timestamp_sec = timestamp_sec ? timestamp_sec : 1700000000ULL;

    auto res = impl->engine->evaluate(dctx);
    if (out_decision) {
        *out_decision = static_cast<uint8_t>(res.decision);
    }
    if (out_reason_buf && reason_buf_len > 0) {
        std::strncpy(out_reason_buf, res.reason_code.c_str(), reason_buf_len - 1);
        out_reason_buf[reason_buf_len - 1] = '\0';
    }
    return linep::sl::is_decision_allowed(res) ? 1 : 0;
}

LINEP_SL_API uint32_t linep_sl4_engine_get_audit_count(linep_sl4_engine_t* engine) {
    if (!engine) return 0;
    auto* impl = reinterpret_cast<linep_sl4_engine*>(engine);
    return static_cast<uint32_t>(impl->audit_sink->get_events().size());
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
    auto eng = linep_sl4_engine_create(trust_domain_id);
    int ret = linep_sl4_engine_evaluate(
        eng, trust_domain_id, session_id, key_id, 1, remote_node_id, remote_trust_domain_id,
        nullptr, remote_revoked, negotiated_sl, requested_cap, 0, 0, policy_id, 0, 1700000000ULL,
        out_decision, out_reason_buf, reason_buf_len);
    linep_sl4_engine_free(eng);
    return ret;
}

} // extern "C"
