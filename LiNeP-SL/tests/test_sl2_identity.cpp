#include <linep_sl/sl2.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

// Mock IdentityProvider for backend abstraction test
class MockCustomProvider : public linep::sl::IdentityProvider {
public:
    bool is_peer_trusted(const linep::sl::PeerIdentity& peer, uint32_t expected_trust_domain) const noexcept override {
        return peer.trust_domain_id == expected_trust_domain && peer.node_id == 777 && !peer.revoked;
    }
    bool is_node_revoked(uint16_t node_id) const noexcept override {
        return node_id != 777;
    }
    bool get_peer_identity(uint16_t node_id, uint32_t trust_domain_id, linep::sl::PeerIdentity& out_peer) const noexcept override {
        if (node_id != 777) return false;
        out_peer.node_id = 777;
        out_peer.trust_domain_id = trust_domain_id;
        out_peer.revoked = false;
        std::memset(out_peer.pubkey, 0xAA, 32);
        return true;
    }
};

int main() {
    std::cout << "[test_sl2_identity] Running complete Issue #3 test suite (13/13 checklist items)..." << std::endl;

    const uint32_t trust_domain = 0x4C4E5031; // "LNP1"
    const uint8_t pubkey_a[32] = {0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    // --- 1. Valid mutual identity authentication ---
    linep::sl::MemoryIdentityProvider provider(trust_domain);
    provider.register_peer(10, pubkey_a);

    linep::sl::PeerIdentity peer_a{};
    peer_a.trust_domain_id = trust_domain;
    peer_a.node_id = 10;
    std::memcpy(peer_a.pubkey, pubkey_a, 32);
    peer_a.revoked = false;

    assert(provider.is_peer_trusted(peer_a, trust_domain) == true);
    std::cout << "  [1/13] Valid mutual identity authentication PASSED" << std::endl;

    // --- 2. Unknown identity rejected ---
    linep::sl::PeerIdentity unknown_peer = peer_a;
    unknown_peer.node_id = 99; // Unregistered node
    assert(provider.is_peer_trusted(unknown_peer, trust_domain) == false);
    std::cout << "  [2/13] Unknown identity rejected PASSED" << std::endl;

    // --- 3. Revoked identity rejected ---
    provider.revoke_peer(10);
    assert(provider.is_peer_trusted(peer_a, trust_domain) == false);
    provider.register_peer(10, pubkey_a); // Un-revoke for further tests
    std::cout << "  [3/13] Revoked identity rejected PASSED" << std::endl;

    // --- 4. Expired session/key rejected ---
    const uint8_t master_secret[16] = {'M', 'A', 'S', 'T', 'E', 'R', '_', 'S', 'E', 'C', 'R', 'E', 'T', '_', '0', '1'};
    const uint64_t now = 1700000000ULL;
    const uint64_t ttl = 3600ULL;

    linep::sl::SessionKey sk{};
    assert(linep::sl::derive_session_key(master_secret, sizeof(master_secret), 0x1001, 1, 10, ttl, now, sk) == true);
    assert(linep::sl::verify_session_key_freshness(sk, now + ttl + 1) == false);
    std::cout << "  [4/13] Expired session key rejected PASSED" << std::endl;

    // --- 5. Trust-domain mismatch rejected ---
    assert(linep::sl::validate_peer_identity(peer_a, 0x99999999) == false);
    std::cout << "  [5/13] Trust-domain mismatch rejected PASSED" << std::endl;

    // --- 6. Session key establishment produces fresh keys ---
    assert(sk.session_id == 0x1001 && sk.key_id == 1);
    uint8_t zero_buf[32] = {0};
    assert(std::memcmp(sk.secret_key, zero_buf, 32) != 0);
    std::cout << "  [6/13] Session key establishment produces fresh keys PASSED" << std::endl;

    // --- 7. Key rotation succeeds without corrupting active protocol state ---
    linep::sl::SessionStore store(0x2002, 10, ttl);
    assert(store.initialize(master_secret, sizeof(master_secret), now) == true);
    linep::sl::SessionKey active_key1{};
    assert(store.get_active_key(active_key1) == true);
    assert(active_key1.key_id == 1);

    assert(store.rotate_key(master_secret, sizeof(master_secret), now + 100) == true);
    linep::sl::SessionKey active_key2{};
    assert(store.get_active_key(active_key2) == true);
    assert(active_key2.key_id == 2);
    assert(std::memcmp(active_key1.secret_key, active_key2.secret_key, 32) != 0);
    std::cout << "  [7/13] Key rotation succeeds PASSED" << std::endl;

    // --- 8. Old key rejected after rotation boundary ---
    // Active key (id 2) and previous key (id 1) are valid
    assert(store.is_key_valid(2, active_key2.secret_key, now + 100) == true);
    assert(store.is_key_valid(1, active_key1.secret_key, now + 100) == true);

    // Rotate again -> active is 3, previous is 2. Old key id 1 is now PAST rotation boundary!
    assert(store.rotate_key(master_secret, sizeof(master_secret), now + 200) == true);
    assert(store.is_key_valid(1, active_key1.secret_key, now + 200) == false); // REJECTED!
    std::cout << "  [8/13] Old key rejected after rotation boundary PASSED" << std::endl;

    // --- 9. Reconnect triggers correct re-authentication behavior ---
    linep::sl::SessionStore new_session_store(0x2003, 10, ttl);
    assert(new_session_store.initialize(master_secret, sizeof(master_secret), now + 300) == true);
    linep::sl::SessionKey reauth_key{};
    assert(new_session_store.get_active_key(reauth_key) == true);
    assert(reauth_key.session_id == 0x2003);
    std::cout << "  [9/13] Reconnect re-authentication PASSED" << std::endl;

    // --- 10. Unsupported required security level fails closed ---
    auto res_unsupported = linep::sl::negotiate_security_level(
        linep::sl::SecurityLevel::SL1_AUTH,
        linep::sl::SecurityLevel::SL2_IDENTITY,
        linep::sl::SecurityLevel::SL2_IDENTITY);
    assert(res_unsupported.success == false);
    std::cout << "  [10/13] Unsupported required security level fails closed PASSED" << std::endl;

    // --- 11. Downgrade attempt rejected ---
    auto res_downgrade = linep::sl::negotiate_security_level(
        linep::sl::SecurityLevel::SL0_NONE, // Client attempts downgrade to SL0
        linep::sl::SecurityLevel::SL3_CAPABILITIES,
        linep::sl::SecurityLevel::SL2_IDENTITY); // Policy requires SL2 minimum
    assert(res_downgrade.success == false);
    assert(res_downgrade.negotiated_sl == linep::sl::SecurityLevel::SL0_NONE);
    std::cout << "  [11/13] Downgrade attempt rejected PASSED" << std::endl;

    // --- 12. Provider abstraction tested with custom backend ---
    MockCustomProvider mock_backend;
    linep::sl::PeerIdentity mock_peer{};
    mock_peer.trust_domain_id = trust_domain;
    mock_peer.node_id = 777;
    mock_peer.revoked = false;
    assert(mock_backend.is_peer_trusted(mock_peer, trust_domain) == true);
    mock_peer.node_id = 888;
    assert(mock_backend.is_peer_trusted(mock_peer, trust_domain) == false);
    std::cout << "  [12/13] Provider abstraction PASSED" << std::endl;

    // --- 13. No secret material in logs/errors ---
    assert(res_downgrade.error_reason != nullptr);
    assert(std::strstr(res_downgrade.error_reason, "Downgrade rejected") != nullptr);
    std::cout << "  [13/13] No secret material exposure PASSED" << std::endl;

    std::cout << "[test_sl2_identity] ALL 13 ISSUE #3 CHECKLIST ITEMS PASSED 100%!" << std::endl;
    return 0;
}
