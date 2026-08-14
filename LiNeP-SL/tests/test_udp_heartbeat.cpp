#include <linep_sl/sl1.hpp>
#include <linep_sl/sl2.hpp>
#include <linep_sl/sl3.hpp>
#include <linep_sl/sl4.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <tuple>

// Replay protection tracker scoped by (session_id, correlation_id, transport_type)
struct DatagramReplayTracker {
    using KeyType = std::tuple<uint32_t, uint32_t, uint8_t>; // (session_id, correlation_id, transport: 0=TCP, 1=UDP)
    std::map<KeyType, uint32_t> last_seq_map;

    bool is_valid_sequence(uint32_t session_id, uint32_t correlation_id, uint8_t transport, uint32_t seq) {
        KeyType k{session_id, correlation_id, transport};
        auto it = last_seq_map.find(k);
        if (it != last_seq_map.end()) {
            if (seq <= it->second) {
                return false; // Stale or duplicate -> REJECT fail-closed!
            }
        }
        last_seq_map[k] = seq;
        return true;
    }
};

int main() {
    std::cout << "[test_udp_heartbeat] Running LiNeP-SL UDP Heartbeat Security Invariants Test Suite..." << std::endl;

    const uint32_t domain_a = 0x4C4E5031; // "LNP1"
    const uint32_t domain_b = 0x4C4E5032; // "LNP2"
    const uint8_t master_secret[32] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    const uint8_t pubkey_node10[32] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                                       0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                                       0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                                       0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};

    const uint32_t session_id = 0x5001;
    const uint16_t key_id = 1;
    const uint16_t node_id = 10;
    const uint64_t now_sec = 1700000000ULL;

    // 1. Setup SL2 Session & Identities
    linep::sl::SessionKey sk{};
    bool sk_ok = linep::sl::derive_session_key(master_secret, sizeof(master_secret), session_id, key_id, node_id, 3600, now_sec, sk);
    assert(sk_ok);

    auto pol_provider = std::make_shared<linep::sl::MemoryGovernancePolicyProvider>();
    auto id_provider = std::make_shared<linep::sl::MemoryIdentityProvider>(domain_a);
    id_provider->register_peer(node_id, pubkey_node10);

    auto fed_provider = std::make_shared<linep::sl::MemoryFederationTrustProvider>();
    auto audit_sink = std::make_shared<linep::sl::MemoryAuditSink>();
    linep::sl::SecurityDecisionEngine engine(pol_provider, id_provider, fed_provider, audit_sink);

    // Register governance policy with CAP_HEARTBEAT_EMIT
    linep::sl::GovernancePolicy hb_pol;
    hb_pol.policy_id = "default-policy";
    hb_pol.policy_revision = 1;
    hb_pol.allowed_capabilities = static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ | linep::sl::CapFlags::CAP_HEARTBEAT_EMIT);
    hb_pol.allow_cross_domain = false;
    engine.register_policy(hb_pol);

    DatagramReplayTracker replay_tracker;

    // Build UDP Heartbeat datagram (Payload + Header + SL1 MAC + SL3 CapToken)
    uint8_t payload[] = "HEARTBEAT_OK_NODE_10";
    uint32_t payload_len = sizeof(payload);

    linep::Header hdr{};
    hdr.magic = linep::MAGIC;
    hdr.version = linep::VERSION;
    hdr.msg_type = 0x05; // HEARTBEAT message type
    hdr.flags = 0x0008; // FLAG_AUTHENTICATED

    linep::sl::HeaderAuthExt auth_ext{};
    auth_ext.session_id = session_id;
    auth_ext.key_id = key_id;
    auth_ext.auth_seq = 100;

    linep::sl::compute_sl1_mac(sk.secret_key, 32, hdr, session_id, key_id, auth_ext.auth_seq, payload, payload_len, auth_ext.mac);

    linep::sl::HeaderCapExt cap_token{};
    cap_token.session_id = session_id;
    cap_token.granted_caps = static_cast<uint64_t>(linep::sl::CapFlags::CAP_HEARTBEAT_EMIT);
    cap_token.expires_at_sec = now_sec + 3600;
    linep::sl::compute_cap_token_mac(sk.secret_key, 32, session_id, cap_token.granted_caps, cap_token.expires_at_sec, cap_token.cap_mac);

    // --- TEST 1: Valid Authenticated UDP Heartbeat -> ACCEPTED ---
    bool mac_valid = linep::sl::verify_sl1_mac(sk.secret_key, 32, hdr, auth_ext, payload, payload_len);
    assert(mac_valid);

    bool cap_valid = linep::sl::verify_cap_token(sk.secret_key, 32, cap_token, session_id, now_sec, linep::sl::CapFlags::CAP_HEARTBEAT_EMIT);
    assert(cap_valid);

    bool seq_valid = replay_tracker.is_valid_sequence(session_id, 0, 1 /*UDP*/, auth_ext.auth_seq);
    assert(seq_valid);

    linep::sl::DecisionContext dctx{};
    dctx.trust_domain_id = domain_a;
    dctx.session_id = session_id;
    dctx.key_id = key_id;
    dctx.local_peer.node_id = 1;
    dctx.local_peer.trust_domain_id = domain_a;
    dctx.remote_peer.node_id = node_id;
    dctx.remote_peer.trust_domain_id = domain_a;
    std::memcpy(dctx.remote_peer.pubkey, pubkey_node10, 32);
    dctx.negotiated_sl = linep::sl::SecurityLevel::SL2_IDENTITY;
    dctx.requested_cap = linep::sl::CapFlags::CAP_HEARTBEAT_EMIT;
    dctx.msg_type = 0x05;
    dctx.policy_id = "default-policy";
    dctx.established_policy_revision = 1;

    auto dec1 = engine.evaluate(dctx);
    assert(linep::sl::is_decision_allowed(dec1));
    assert(dec1.reason_code == "GOVERNANCE_POLICY_ALLOWED");
    std::cout << "  [1] Valid Protected UDP Heartbeat -> ACCEPTED PASSED" << std::endl;

    // --- TEST 2: Tampered UDP Heartbeat MAC -> REJECTED ---
    linep::sl::HeaderAuthExt tampered_auth = auth_ext;
    tampered_auth.mac[0] ^= 0xFF;
    bool mac_tampered = linep::sl::verify_sl1_mac(sk.secret_key, 32, hdr, tampered_auth, payload, payload_len);
    assert(!mac_tampered);
    std::cout << "  [2] Tampered UDP Heartbeat MAC -> REJECTED PASSED" << std::endl;

    // --- TEST 3: Duplicate UDP Heartbeat Replay -> REJECTED ---
    bool dup_seq = replay_tracker.is_valid_sequence(session_id, 0, 1 /*UDP*/, auth_ext.auth_seq);
    assert(!dup_seq); // Duplicate sequence 100 must be rejected!
    std::cout << "  [3] Duplicate UDP Heartbeat Replay -> REJECTED PASSED" << std::endl;

    // --- TEST 4: Replay Protection Isolation (TCP stream vs UDP heartbeat datagram) ---
    // Sequence 100 on TCP (transport=0) should NOT collide with UDP (transport=1)
    bool tcp_seq_valid = replay_tracker.is_valid_sequence(session_id, 0, 0 /*TCP*/, 100);
    assert(tcp_seq_valid);
    std::cout << "  [4] Replay Protection Transport Isolation (TCP vs UDP) -> PASSED" << std::endl;

    // --- TEST 5: UDP Heartbeat Without CAP_HEARTBEAT_EMIT Capability -> REJECTED ---
    bool cap_unauth = linep::sl::verify_cap_token(sk.secret_key, 32, cap_token, session_id, now_sec, linep::sl::CapFlags::CAP_ADMIN);
    assert(!cap_unauth);

    linep::sl::DecisionContext dctx_unauth = dctx;
    dctx_unauth.requested_cap = linep::sl::CapFlags::CAP_ADMIN;
    auto dec5 = engine.evaluate(dctx_unauth);
    assert(!linep::sl::is_decision_allowed(dec5));
    assert(dec5.reason_code == "GOVERNANCE_POLICY_CAPABILITY_DENIED");
    std::cout << "  [5] Unauthorized Capability for UDP Heartbeat -> REJECTED PASSED" << std::endl;

    // --- TEST 6: Cross-Domain UDP Heartbeat Without Federation -> REJECTED ---
    linep::sl::DecisionContext dctx_cross = dctx;
    dctx_cross.remote_peer.trust_domain_id = domain_b;
    auto dec6 = engine.evaluate(dctx_cross);
    assert(!linep::sl::is_decision_allowed(dec6));
    assert(dec6.reason_code == "CROSS_DOMAIN_FEDERATION_DENIED");
    std::cout << "  [6] Cross-Domain UDP Heartbeat without Federation -> REJECTED PASSED" << std::endl;

    std::cout << "[test_udp_heartbeat] ALL UDP HEARTBEAT SECURITY INVARIANT TESTS PASSED 100%!" << std::endl;
    return 0;
}
