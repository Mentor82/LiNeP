#include <linep_sl/sl2.hpp>
#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    std::cout << "[test_sl2_identity] Starting LiNeP-SL SL2 Identity & Key Management tests..." << std::endl;

    const uint32_t trust_domain = 0x4C4E5031; // "LNP1"
    linep::sl::PeerIdentity valid_peer{};
    valid_peer.trust_domain_id = trust_domain;
    valid_peer.node_id = 42;
    std::memset(valid_peer.pubkey, 0xAB, 32);
    valid_peer.revoked = false;

    // 1. Valid peer identity check
    bool peer_ok = linep::sl::validate_peer_identity(valid_peer, trust_domain);
    assert(peer_ok == true);
    std::cout << "[test_sl2_identity] Valid peer identity PASSED" << std::endl;

    // 2. Reject revoked peer identity
    linep::sl::PeerIdentity revoked_peer = valid_peer;
    revoked_peer.revoked = true;
    bool revoked_ok = linep::sl::validate_peer_identity(revoked_peer, trust_domain);
    assert(revoked_ok == false);
    std::cout << "[test_sl2_identity] Revoked peer identity rejection PASSED" << std::endl;

    // 3. Reject trust domain mismatch
    bool mismatch_ok = linep::sl::validate_peer_identity(valid_peer, 0x99999999);
    assert(mismatch_ok == false);
    std::cout << "[test_sl2_identity] Trust domain mismatch rejection PASSED" << std::endl;

    // 4. Session key derivation & freshness check
    const uint8_t master_secret[16] = {'M', 'A', 'S', 'T', 'E', 'R', '_', 'S', 'E', 'C', 'R', 'E', 'T', '_', '0', '1'};
    const uint64_t now = 1700000000ULL;
    const uint64_t ttl = 3600ULL;

    linep::sl::SessionKey sk{};
    bool derived_ok = linep::sl::derive_session_key(master_secret, sizeof(master_secret), 0x1001, 1, 42, ttl, now, sk);
    assert(derived_ok == true);
    assert(sk.session_id == 0x1001);
    assert(sk.key_id == 1);
    assert(sk.expires_at_sec == now + ttl);

    bool fresh_ok = linep::sl::verify_session_key_freshness(sk, now + 100);
    assert(fresh_ok == true);
    std::cout << "[test_sl2_identity] Session key derivation & freshness PASSED" << std::endl;

    // 5. Reject expired session key
    bool expired_ok = linep::sl::verify_session_key_freshness(sk, now + ttl + 1);
    assert(expired_ok == false);
    std::cout << "[test_sl2_identity] Expired session key rejection PASSED" << std::endl;

    // 6. Session key rotation
    linep::sl::SessionKey rotated_sk = sk;
    bool rotated_ok = linep::sl::rotate_session_key(master_secret, sizeof(master_secret), rotated_sk, now + 500, ttl);
    assert(rotated_ok == true);
    assert(rotated_sk.key_id == 2);
    assert(std::memcmp(sk.secret_key, rotated_sk.secret_key, 32) != 0); // Secret key MUST be fresh & different!
    std::cout << "[test_sl2_identity] Session key rotation PASSED" << std::endl;

    std::cout << "[test_sl2_identity] ALL SL2 IDENTITY & KEY MANAGEMENT TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
