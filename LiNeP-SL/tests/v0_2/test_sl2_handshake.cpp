#include <linep_sl/v0_2/crypto_provider.hpp>
#include <linep_sl/v0_2/sl2_handshake.hpp>
#include <linep_sl/v0_2/session.hpp>
#include <linep_sl/v0_2/negotiation.hpp>
#include <linep_sl/v0_2/plane_authenticator.hpp>
#include <linep/v0_2/envelopes.hpp>

#include <cassert>
#include <cstring>
#include <iostream>
#include <unordered_set>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

negotiation_offer make_offer(
    std::uint64_t node_id,
    security_level min_lvl,
    security_level max_lvl,
    std::vector<crypto_suite> suites,
    std::uint8_t nonce_val) {
    negotiation_offer o;
    o.minimum_level = min_lvl;
    o.maximum_level = max_lvl;
    o.supported_suites = std::move(suites);
    o.endpoint = {node_id, node_id + 100, 1};
    o.control_epoch = node_id + 10;
    o.lease_token = node_id + 20;
    o.nonce.fill(nonce_val);
    return o;
}

class test_identity_verifier : public identity_verifier {
public:
    bool reject_all{false};
    bool reject_expired{false};
    std::unordered_set<std::uint64_t> revoked_subjects;

    bool authenticate(
        const negotiation_offer& offer,
        const std::vector<std::uint8_t>& /*negotiation_transcript*/,
        const std::vector<std::uint8_t>& /*credential_proof*/,
        std::uint64_t now_us,
        authenticated_peer& out_peer) noexcept override {
        if (reject_all) {
            return false;
        }
        if (reject_expired && now_us > 1000) {
            return false;
        }
        const std::uint64_t sub_id = offer.endpoint.node_id + 1000;
        if (revoked_subjects.count(sub_id) > 0) {
            return false;
        }

        out_peer.endpoint = offer.endpoint;
        out_peer.trust_domain_id = 100;
        out_peer.subject_id = sub_id;
        out_peer.credential_revision = 1;
        out_peer.authenticated_at_us = now_us;
        out_peer.credential_expires_at_us = 5000000000ULL;
        out_peer.revoked = false;
        return true;
    }
};

// Helper: build 12-byte AEAD nonce: BaseIV ^ (0x00_32 || uint64_be(seq))
std::vector<std::uint8_t> make_nonce(const std::vector<std::uint8_t>& base_iv, std::uint64_t seq) {
    assert(base_iv.size() == 12);
    std::vector<std::uint8_t> nonce = base_iv;
    for (std::size_t i = 0; i < 8; ++i) {
        const std::uint8_t b = static_cast<std::uint8_t>((seq >> ((7 - i) * 8)) & 0xFF);
        nonce[4 + i] ^= b;
    }
    return nonce;
}

void test_crypto_primitives_unit() {
    std::cout << "[TEST] test_crypto_primitives_unit..." << std::endl;

    // 1. X25519 DH
    std::vector<std::uint8_t> a_priv, a_pub, b_priv, b_pub;
    assert(generate_x25519_keypair(a_priv, a_pub));
    assert(generate_x25519_keypair(b_priv, b_pub));
    assert(a_priv.size() == x25519_key_bytes && a_pub.size() == x25519_key_bytes);
    assert(b_priv.size() == x25519_key_bytes && b_pub.size() == x25519_key_bytes);

    std::vector<std::uint8_t> ss_ab, ss_ba;
    assert(diffie_hellman_x25519(a_priv, b_pub, ss_ab));
    assert(diffie_hellman_x25519(b_priv, a_pub, ss_ba));
    assert(ss_ab.size() == 32);
    assert(ss_ab == ss_ba);

    // 2. Ed25519 Signatures
    std::vector<std::uint8_t> ed_priv, ed_pub;
    assert(generate_ed25519_keypair(ed_priv, ed_pub));
    assert(ed_priv.size() == ed25519_privkey_bytes);
    assert(ed_pub.size() == ed25519_pubkey_bytes);

    const std::string msg = "Hello LiNeP-SL2 OpenSSL 3.x!";
    std::vector<std::uint8_t> sig;
    assert(ed25519_sign(ed_priv, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(), sig));
    assert(sig.size() == ed25519_signature_bytes);
    assert(ed25519_verify(ed_pub, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(), sig.data(), sig.size()));

    // Corrupted msg verification fails
    const std::string bad_msg = "Hello LiNeP-SL2 OpenSSL 3.y!";
    assert(!ed25519_verify(ed_pub, reinterpret_cast<const std::uint8_t*>(bad_msg.data()), bad_msg.size(), sig.data(), sig.size()));

    // 3. HKDF Extract and Expand
    std::vector<std::uint8_t> salt(32, 0x42);
    std::vector<std::uint8_t> prk;
    assert(hkdf_extract(salt, ss_ab, prk));
    assert(prk.size() == 32);

    std::vector<std::uint8_t> key1, key2;
    assert(hkdf_expand(prk, "lns2.test.1", 32, key1));
    assert(hkdf_expand(prk, "lns2.test.2", 32, key2));
    assert(key1.size() == 32 && key2.size() == 32);
    assert(key1 != key2);

    // 4. AEAD ChaCha20-Poly1305
    {
        const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
        std::vector<std::uint8_t> key(32, 0x11);
        std::vector<std::uint8_t> nonce(12, 0x22);
        std::vector<std::uint8_t> aad = {0x01, 0x02, 0x03};
        std::vector<std::uint8_t> pt = {'V', 'I', 'N', 'O', 'X', '_', 'N', 'P', 'U'};
        std::vector<std::uint8_t> ct, tag;

        assert(aead_encrypt(suite, key, nonce, aad, pt, ct, tag));
        assert(ct.size() == pt.size());
        assert(tag.size() == 16);

        std::vector<std::uint8_t> decrypted;
        assert(aead_decrypt(suite, key, nonce, aad, ct, tag, decrypted));
        assert(decrypted == pt);

        // Corrupted ciphertext
        auto bad_ct = ct;
        bad_ct[0] ^= 0x01;
        assert(!aead_decrypt(suite, key, nonce, aad, bad_ct, tag, decrypted));

        // Corrupted tag
        auto bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert(!aead_decrypt(suite, key, nonce, aad, ct, bad_tag, decrypted));

        // Corrupted AAD
        auto bad_aad = aad;
        bad_aad[0] ^= 0x01;
        assert(!aead_decrypt(suite, key, nonce, bad_aad, ct, tag, decrypted));
    }

    // 5. AEAD AES-256-GCM
    {
        const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm;
        std::vector<std::uint8_t> key(32, 0x33);
        std::vector<std::uint8_t> nonce(12, 0x44);
        std::vector<std::uint8_t> aad = {0x0A, 0x0B};
        std::vector<std::uint8_t> pt = {'A', 'E', 'S', '_', 'G', 'C', 'M', '_', 'T', 'E', 'S', 'T'};
        std::vector<std::uint8_t> ct, tag;

        assert(aead_encrypt(suite, key, nonce, aad, pt, ct, tag));
        assert(ct.size() == pt.size());
        assert(tag.size() == 16);

        std::vector<std::uint8_t> decrypted;
        assert(aead_decrypt(suite, key, nonce, aad, ct, tag, decrypted));
        assert(decrypted == pt);

        // Corrupted tag fails
        auto bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert(!aead_decrypt(suite, key, nonce, aad, ct, bad_tag, decrypted));
    }
}

void test_sl2_handshake_positive_chacha20() {
    std::cout << "[TEST] test_sl2_handshake_positive_chacha20 (SL2-POS-01)..." << std::endl;

    test_identity_verifier verifier;
    session_registry client_registry;
    session_registry server_registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(10, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x11);
    const auto server_offer = make_offer(20, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x22);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, client_registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, server_registry);

    // 1. ClientHello
    std::vector<std::uint8_t> client_hello_frame;
    assert(client_session.initiator_start(client_offer, 100, 1010, c_priv, c_pub, client_hello_frame));
    assert(client_session.state() == handshake_state::client_hello_sent);

    // 2. ServerHello
    std::vector<std::uint8_t> server_hello_frame;
    assert(server_session.responder_process_client_hello(
        client_hello_frame.data(), client_hello_frame.size(),
        server_policy, server_offer, 100, 2020, s_priv, s_pub,
        server_hello_frame));
    assert(server_session.state() == handshake_state::server_hello_sent);

    // 3. ClientFinished
    std::vector<std::uint8_t> client_finished_frame;
    assert(client_session.initiator_process_server_hello(
        server_hello_frame.data(), server_hello_frame.size(),
        client_finished_frame));
    assert(client_session.state() == handshake_state::client_finished_sent);

    // 4. ServerFinished
    std::vector<std::uint8_t> server_finished_frame;
    session_record server_rec;
    assert(server_session.responder_process_client_finished(
        client_finished_frame.data(), client_finished_frame.size(),
        server_finished_frame, server_rec));
    assert(server_session.state() == handshake_state::active);
    assert(server_rec.is_active_at(1000));

    // 5. Client processes ServerFinished
    session_record client_rec;
    assert(client_session.initiator_process_server_finished(
        server_finished_frame.data(), server_finished_frame.size(),
        client_rec));
    assert(client_session.state() == handshake_state::active);
    assert(client_rec.is_active_at(1000));

    // Keys must match across peers
    assert(client_session.keys().initiator_traffic_key == server_session.keys().initiator_traffic_key);
    assert(client_session.keys().responder_traffic_key == server_session.keys().responder_traffic_key);
    assert(client_session.keys().initiator_iv == server_session.keys().initiator_iv);
    assert(client_session.keys().responder_iv == server_session.keys().responder_iv);

    // Bidirectional AEAD communication verification:
    // Initiator -> Responder frame
    {
        const std::vector<std::uint8_t> payload = {'V', 'I', 'N', 'O', 'X', '_', 'I', 'N', 'F', 'E', 'R'};
        const auto nonce = make_nonce(client_session.keys().initiator_iv, 0);
        std::vector<std::uint8_t> ct, tag, pt;
        assert(aead_encrypt(suite, client_session.keys().initiator_traffic_key, nonce, {}, payload, ct, tag));
        assert(aead_decrypt(suite, server_session.keys().initiator_traffic_key, nonce, {}, ct, tag, pt));
        assert(pt == payload);
    }

    // Responder -> Initiator frame
    {
        const std::vector<std::uint8_t> response = {'E', 'M', 'B', 'E', 'D', '_', 'R', 'E', 'S', 'U', 'L', 'T'};
        const auto nonce = make_nonce(server_session.keys().responder_iv, 0);
        std::vector<std::uint8_t> ct, tag, pt;
        assert(aead_encrypt(suite, server_session.keys().responder_traffic_key, nonce, {}, response, ct, tag));
        assert(aead_decrypt(suite, client_session.keys().responder_traffic_key, nonce, {}, ct, tag, pt));
        assert(pt == response);
    }
}

void test_sl2_handshake_positive_aes_gcm() {
    std::cout << "[TEST] test_sl2_handshake_positive_aes_gcm (SL2-POS-02)..." << std::endl;

    test_identity_verifier verifier;
    session_registry client_registry;
    session_registry server_registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_aes256_gcm;
    const auto client_offer = make_offer(11, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x33);
    const auto server_offer = make_offer(21, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x44);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, client_registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, server_registry);

    std::vector<std::uint8_t> c_hello, s_hello, c_fin, s_fin;
    session_record s_rec, c_rec;

    assert(client_session.initiator_start(client_offer, 100, 1011, c_priv, c_pub, c_hello));
    assert(server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2021, s_priv, s_pub, s_hello));
    assert(client_session.initiator_process_server_hello(s_hello.data(), s_hello.size(), c_fin));
    assert(server_session.responder_process_client_finished(c_fin.data(), c_fin.size(), s_fin, s_rec));
    assert(client_session.initiator_process_server_finished(s_fin.data(), s_fin.size(), c_rec));

    assert(client_session.state() == handshake_state::active);
    assert(server_session.state() == handshake_state::active);

    // Bidirectional AES-256-GCM verification
    const std::vector<std::uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
    const auto nonce = make_nonce(client_session.keys().initiator_iv, 0);
    std::vector<std::uint8_t> ct, tag, pt;
    assert(aead_encrypt(suite, client_session.keys().initiator_traffic_key, nonce, {}, test_data, ct, tag));
    assert(aead_decrypt(suite, server_session.keys().initiator_traffic_key, nonce, {}, ct, tag, pt));
    assert(pt == test_data);
}

void test_sl2_rekeying() {
    std::cout << "[TEST] test_sl2_rekeying (SL2-POS-03)..." << std::endl;

    test_identity_verifier verifier;
    session_registry client_registry;
    session_registry server_registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(12, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x55);
    const auto server_offer = make_offer(22, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x66);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, client_registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, server_registry);

    std::vector<std::uint8_t> c_hello, s_hello, c_fin, s_fin;
    session_record s_rec, c_rec;

    assert(client_session.initiator_start(client_offer, 100, 1012, c_priv, c_pub, c_hello));
    assert(server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2022, s_priv, s_pub, s_hello));
    assert(client_session.initiator_process_server_hello(s_hello.data(), s_hello.size(), c_fin));
    assert(server_session.responder_process_client_finished(c_fin.data(), c_fin.size(), s_fin, s_rec));
    assert(client_session.initiator_process_server_finished(s_fin.data(), s_fin.size(), c_rec));

    const std::uint64_t session_id = c_rec.session_id;

    // Rekeying trigger: rotate keys in client_registry
    assert(client_registry.rotate(session_id, 2, 2, 1200, 4000000000ULL));

    security_session_identity identity;
    assert(client_registry.make_sender_identity(session_id, message_direction::initiator_to_responder, 1300, identity));
    assert(identity.security_epoch == 2);
    assert(identity.key_id == 2);
}

void test_sl2_negative_transcript_tamper() {
    std::cout << "[TEST] test_sl2_negative_transcript_tamper (SL2-NEG-01)..." << std::endl;

    test_identity_verifier verifier;
    session_registry registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(13, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x77);
    const auto server_offer = make_offer(23, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x88);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, registry);

    std::vector<std::uint8_t> c_hello, s_hello, c_fin;
    assert(client_session.initiator_start(client_offer, 100, 1013, c_priv, c_pub, c_hello));
    assert(server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2023, s_priv, s_pub, s_hello));

    // Tamper single bit in ServerHello frame payload (after header)
    assert(s_hello.size() > 40);
    s_hello[s_hello.size() - 5] ^= 0x01;

    // Initiator must detect transcript / signature mismatch and abort
    assert(!client_session.initiator_process_server_hello(s_hello.data(), s_hello.size(), c_fin));
    assert(client_session.state() == handshake_state::failed);
}

void test_sl2_negative_untrusted_identity() {
    std::cout << "[TEST] test_sl2_negative_untrusted_identity (SL2-NEG-02)..." << std::endl;

    test_identity_verifier verifier;
    verifier.reject_all = true; // Simulates untrusted domain or rejected certificate
    session_registry registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(14, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x99);
    const auto server_offer = make_offer(24, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0xAA);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, registry);

    std::vector<std::uint8_t> c_hello, s_hello;
    assert(client_session.initiator_start(client_offer, 100, 1014, c_priv, c_pub, c_hello));

    // Server rejects client because verifier rejects identity
    assert(!server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2024, s_priv, s_pub, s_hello));
    assert(server_session.state() == handshake_state::failed);
}

void test_sl2_negative_revocation() {
    std::cout << "[TEST] test_sl2_negative_revocation (SL2-NEG-04)..." << std::endl;

    test_identity_verifier verifier;
    verifier.revoked_subjects.insert(1015); // Worker subject 1015 is revoked
    session_registry registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(15, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0xBB);
    const auto server_offer = make_offer(25, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0xCC);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, registry);

    std::vector<std::uint8_t> c_hello, s_hello;
    assert(client_session.initiator_start(client_offer, 100, 1015, c_priv, c_pub, c_hello));

    // Handshake fails because revoked identity is rejected
    assert(!server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2025, s_priv, s_pub, s_hello));
    assert(server_session.state() == handshake_state::failed);
}

void test_sl2_negative_downgrade() {
    std::cout << "[TEST] test_sl2_negative_downgrade (SL2-NEG-05)..." << std::endl;

    test_identity_verifier verifier;
    session_registry registry;

    // Initiator requires SL2
    const auto client_offer = make_offer(16, security_level::sl2_identity, security_level::sl2_identity,
                                         {crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305}, 0xDD);

    // Responder policy only allows SL1 (downgrade attempt)
    const auto server_offer = make_offer(26, security_level::sl1_authenticated, security_level::sl1_authenticated,
                                         {crypto_suite::hmac_sha256_128}, 0xEE);
    negotiation_policy server_policy{security_level::sl1_authenticated, {crypto_suite::hmac_sha256_128}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, registry);

    std::vector<std::uint8_t> c_hello, s_hello;
    assert(client_session.initiator_start(client_offer, 100, 1016, c_priv, c_pub, c_hello));

    // Negotiation must fail closed
    assert(!server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2026, s_priv, s_pub, s_hello));
    assert(server_session.state() == handshake_state::failed);
}

void test_sl2_negative_forged_client_signature() {
    std::cout << "[TEST] test_sl2_negative_forged_client_signature..." << std::endl;

    test_identity_verifier verifier;
    session_registry registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(17, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x01);
    const auto server_offer = make_offer(27, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x02);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, registry);

    std::vector<std::uint8_t> c_hello, s_hello;
    assert(client_session.initiator_start(client_offer, 100, 1017, c_priv, c_pub, c_hello));

    // Tamper the signature bytes at the end of ClientHello frame
    assert(c_hello.size() > 64);
    c_hello[c_hello.size() - 10] ^= 0xFF;

    assert(!server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2027, s_priv, s_pub, s_hello));
    assert(server_session.state() == handshake_state::failed);
}

void test_sl2_negative_tampered_client_finished() {
    std::cout << "[TEST] test_sl2_negative_tampered_client_finished..." << std::endl;

    test_identity_verifier verifier;
    session_registry client_registry;
    session_registry server_registry;

    const auto suite = crypto_suite::x25519_ed25519_hkdf_sha256_chacha20_poly1305;
    const auto client_offer = make_offer(18, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x03);
    const auto server_offer = make_offer(28, security_level::sl2_identity, security_level::sl2_identity, {suite}, 0x04);
    negotiation_policy server_policy{security_level::sl2_identity, {suite}};

    std::vector<std::uint8_t> c_priv, c_pub, s_priv, s_pub;
    assert(generate_ed25519_keypair(c_priv, c_pub));
    assert(generate_ed25519_keypair(s_priv, s_pub));

    sl2_handshake_session client_session(session_participant_role::initiator, verifier, client_registry);
    sl2_handshake_session server_session(session_participant_role::responder, verifier, server_registry);

    std::vector<std::uint8_t> c_hello, s_hello, c_fin, s_fin;
    session_record s_rec;

    assert(client_session.initiator_start(client_offer, 100, 1018, c_priv, c_pub, c_hello));
    assert(server_session.responder_process_client_hello(c_hello.data(), c_hello.size(), server_policy, server_offer, 100, 2028, s_priv, s_pub, s_hello));
    assert(client_session.initiator_process_server_hello(s_hello.data(), s_hello.size(), c_fin));

    // Tamper the verify_data inside ClientFinished
    assert(c_fin.size() > 5);
    c_fin[c_fin.size() - 2] ^= 0x5A;

    assert(!server_session.responder_process_client_finished(c_fin.data(), c_fin.size(), s_fin, s_rec));
    assert(server_session.state() == handshake_state::failed);
}

void test_sl2_negative_framing() {
    std::cout << "[TEST] test_sl2_negative_framing (SL2-NEG-07)..." << std::endl;

    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> frame;
    assert(wrap_handshake_frame(payload, frame));

    std::vector<std::uint8_t> unwrapped;
    assert(unwrap_handshake_frame(frame.data(), frame.size(), unwrapped));
    assert(unwrapped == payload);

    // 1. Bad magic
    auto bad_magic = frame;
    bad_magic[0] ^= 0xFF;
    assert(!unwrap_handshake_frame(bad_magic.data(), bad_magic.size(), unwrapped));

    // 2. Wrong envelope type (e.g. request envelope type 1)
    auto bad_type = frame;
    bad_type[4] = 1;
    assert(!unwrap_handshake_frame(bad_type.data(), bad_type.size(), unwrapped));

    // 3. Truncated header
    assert(!unwrap_handshake_frame(frame.data(), 10, unwrapped));

    // 4. Truncated payload
    assert(!unwrap_handshake_frame(frame.data(), frame.size() - 1, unwrapped));
}

} // namespace

int main() {
    test_crypto_primitives_unit();
    test_sl2_handshake_positive_chacha20();
    test_sl2_handshake_positive_aes_gcm();
    test_sl2_rekeying();
    test_sl2_negative_transcript_tamper();
    test_sl2_negative_untrusted_identity();
    test_sl2_negative_revocation();
    test_sl2_negative_downgrade();
    test_sl2_negative_forged_client_signature();
    test_sl2_negative_tampered_client_finished();
    test_sl2_negative_framing();

    std::cout << "\nAll LiNeP-SL2 handshake tests PASSED successfully!" << std::endl;
    return 0;
}
