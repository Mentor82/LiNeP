#include <linep_sl/v0_2/group_security.hpp>

#include <cassert>
#include <iostream>
#include <vector>

using namespace linep::sl::v0_2;

namespace {

security_group_member make_coordinator(std::uint64_t node_id = 1) {
    security_group_member m;
    m.endpoint = {node_id, 10, 100};
    m.trust_domain_id = 1;
    m.subject_id = 1000 + node_id;
    m.role = member_role::coordinator;
    m.status = member_status::active;
    m.credential_revision = 1;
    return m;
}

security_group_member make_worker(std::uint64_t node_id, member_role role = member_role::worker_primary) {
    security_group_member m;
    m.endpoint = {node_id, 20, 200};
    m.trust_domain_id = 1;
    m.subject_id = 2000 + node_id;
    m.role = role;
    m.status = member_status::active;
    m.credential_revision = 1;
    return m;
}

std::vector<std::uint8_t> make_initial_secret() {
    return {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01
    };
}

} // namespace

void test_group_creation_and_public_context_hygiene() {
    std::cout << "[Test 1] Group Creation, RFC 9420 Ciphersuites & Public Context Hygiene..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    assert(mgr.create_group(
        9001,
        group_type::ephemeral_task,
        mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        coord,
        initial_secret,
        now_us));

    assert(mgr.get_group_count() == 1);
    assert(mgr.get_active_group_count() == 1);

    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_id == 9001);
    assert(ctx.group_epoch == 1);
    assert(ctx.ciphersuite == mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519);
    assert(ctx.members.size() == 1);
    assert(ctx.members[0].role == member_role::coordinator);
    assert(!ctx.confirmed_transcript_hash.empty());
    assert(!ctx.execution_group_state_hash.empty());

    // Add Primary GPU-A -> Epoch 2
    auto gpu_a = make_worker(10, member_role::worker_primary);
    assert(mgr.add_member(9001, gpu_a, {}, {}, now_us + 1000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 2);
    assert(ctx.members.size() == 2);
    assert(mgr.is_member_active(9001, gpu_a.endpoint));

    // Add Redundant GPU-B -> Epoch 3
    auto gpu_b = make_worker(20, member_role::worker_redundant);
    assert(mgr.add_member(9001, gpu_b, {}, {}, now_us + 2000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 3);
    assert(ctx.members.size() == 3);

    // Add Validator CPU-C -> Epoch 4
    auto cpu_c = make_worker(30, member_role::validator);
    assert(mgr.add_member(9001, cpu_c, {}, {}, now_us + 3000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 4);
    assert(ctx.members.size() == 4);

    std::cout << "  -> Group Creation & Public Context Hygiene Tests PASSED" << std::endl;
}

void test_confidentiality_and_multi_party_messaging() {
    std::cout << "[Test 2] Confidential PrivateMessage & Authenticated PublicMessage Protection..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);
    auto cpu_c = make_worker(30, member_role::validator);

    assert(mgr.create_group(9001, group_type::ephemeral_task, mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, {}, {}, now_us + 100));
    assert(mgr.add_member(9001, cpu_c, {}, {}, now_us + 200));

    // 1. Confidential & Authenticated Task Request from Coordinator
    std::vector<std::uint8_t> secret_request = {'c', 'o', 'n', 'f', 'i', 'd', 'e', 'n', 't', 'i', 'a', 'l', '_', 't', 'a', 's', 'k'};
    protected_group_message prot_req;
    assert(mgr.protect_group_message(
        9001,
        coord.endpoint,
        group_protection_mode::confidential_and_authenticated,
        data_message_class::request,
        secret_request,
        1,
        prot_req));

    // Ensure ciphertext on wire is NOT plaintext
    assert(prot_req.ciphertext_or_payload != secret_request);
    assert(prot_req.ratchet_generation == 1);
    assert(prot_req.message_seq == 1);

    // Primary GPU-A unprotects request
    std::vector<std::uint8_t> dec_request;
    auto status = mgr.unprotect_group_message(prot_req, gpu_a.endpoint, data_message_class::request, dec_request, now_us + 300);
    assert(status == group_verification_status::ok);
    assert(dec_request == secret_request);

    // Replay rejection
    status = mgr.unprotect_group_message(prot_req, gpu_a.endpoint, data_message_class::request, dec_request, now_us + 350);
    assert(status == group_verification_status::replay_rejected);

    // 2. Stream event from GPU-A
    std::vector<std::uint8_t> event_delta = {'t', 'o', 'k', 'e', 'n', '_', '1'};
    protected_group_message prot_evt;
    assert(mgr.protect_group_message(
        9001,
        gpu_a.endpoint,
        group_protection_mode::confidential_and_authenticated,
        data_message_class::event,
        event_delta,
        1,
        prot_evt));

    // Validator CPU-C unprotects GPU-A's event
    std::vector<std::uint8_t> dec_evt;
    status = mgr.unprotect_group_message(prot_evt, cpu_c.endpoint, data_message_class::event, dec_evt, now_us + 400);
    assert(status == group_verification_status::ok);
    assert(dec_evt == event_delta);

    std::cout << "  -> Confidentiality & Messaging Tests PASSED" << std::endl;
}

void test_eviction_forward_secrecy_and_fresh_entropy() {
    std::cout << "[Test 3] Member Eviction with Fresh Commit Entropy & Forward Secrecy..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);
    auto gpu_b = make_worker(20, member_role::worker_redundant);

    assert(mgr.create_group(9001, group_type::ephemeral_task, mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, {}, {}, now_us + 100));
    assert(mgr.add_member(9001, gpu_b, {}, {}, now_us + 200));

    // Epoch 3 active
    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 3);

    // Evict GPU-A by injecting fresh commit entropy
    std::vector<std::uint8_t> fresh_commit_entropy = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    assert(mgr.remove_member(9001, gpu_a.endpoint, fresh_commit_entropy, now_us + 1000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 4);
    assert(!mgr.is_member_active(9001, gpu_a.endpoint));

    // Promote GPU-B to primary worker
    assert(mgr.update_member_role(9001, gpu_b.endpoint, member_role::worker_primary, now_us + 1100));

    // GPU-B protects message in Epoch 4
    std::vector<std::uint8_t> epoch4_payload = {'e', 'p', 'o', 'c', 'h', '_', '4', '_', 't', 'a', 's', 'k'};
    protected_group_message prot_msg4;
    assert(mgr.protect_group_message(
        9001,
        gpu_b.endpoint,
        group_protection_mode::confidential_and_authenticated,
        data_message_class::event,
        epoch4_payload,
        1,
        prot_msg4));

    // Coordinator unprotects GPU-B's message in Epoch 4
    std::vector<std::uint8_t> dec4;
    assert(mgr.unprotect_group_message(prot_msg4, coord.endpoint, data_message_class::event, dec4, now_us + 1200) == group_verification_status::ok);
    assert(dec4 == epoch4_payload);

    // Evicted GPU-A cannot sign messages in Epoch 4
    protected_group_message rogue_msg;
    assert(!mgr.protect_group_message(
        9001,
        gpu_a.endpoint,
        group_protection_mode::confidential_and_authenticated,
        data_message_class::event,
        epoch4_payload,
        1,
        rogue_msg));

    // Forged message claiming sender GPU-A rejected as member_not_active / impersonation
    prot_msg4.sender_endpoint = gpu_a.endpoint;
    assert(mgr.unprotect_group_message(prot_msg4, coord.endpoint, data_message_class::event, dec4, now_us + 1300) == group_verification_status::member_not_active);

    std::cout << "  -> Eviction Forward Secrecy Tests PASSED" << std::endl;
}

void test_post_compromise_security_and_healing() {
    std::cout << "[Test 4] Post-Compromise Security (PCS) & Healing Rekey..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_b = make_worker(20, member_role::worker_primary);

    assert(mgr.create_group(9001, group_type::ephemeral_task, mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_b, {}, {}, now_us + 100));

    // Epoch 2: Assume adversary compromised Epoch 2 state.
    // GPU-B performs a healing rekey with fresh unguessable entropy:
    std::vector<std::uint8_t> fresh_update_entropy = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };

    assert(mgr.rekey_group(9001, gpu_b.endpoint, fresh_update_entropy, now_us + 1000));

    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 3); // Advanced to Epoch 3 with PCS

    // Messages protected in Epoch 3 use new ratchets derived from fresh_update_entropy
    std::vector<std::uint8_t> healed_payload = {'p', 'c', 's', '_', 'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    protected_group_message healed_msg;
    assert(mgr.protect_group_message(
        9001,
        gpu_b.endpoint,
        group_protection_mode::confidential_and_authenticated,
        data_message_class::event,
        healed_payload,
        1,
        healed_msg));

    std::vector<std::uint8_t> dec_healed;
    assert(mgr.unprotect_group_message(healed_msg, coord.endpoint, data_message_class::event, dec_healed, now_us + 1100) == group_verification_status::ok);
    assert(dec_healed == healed_payload);

    std::cout << "  -> Post-Compromise Security Tests PASSED" << std::endl;
}

void test_anti_impersonation_and_sender_authentication() {
    std::cout << "[Test 5] Anti-Impersonation & Per-Sender Signing Key Verification..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);
    auto gpu_b = make_worker(20, member_role::worker_redundant);

    assert(mgr.create_group(9001, group_type::ephemeral_task, mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, {}, {}, now_us + 100));
    assert(mgr.add_member(9001, gpu_b, {}, {}, now_us + 200));

    // GPU-B creates a valid message signed with GPU-B's leaf key
    std::vector<std::uint8_t> payload = {'g', 'p', 'u', '_', 'b', '_', 'm', 's', 'g'};
    protected_group_message msg_b;
    assert(mgr.protect_group_message(
        9001,
        gpu_b.endpoint,
        group_protection_mode::authenticated_only,
        data_message_class::event,
        payload,
        1,
        msg_b));

    // Attacker modifies sender_endpoint to claim the message was produced by GPU-A
    protected_group_message forged_msg = msg_b;
    forged_msg.sender_endpoint = gpu_a.endpoint;

    std::vector<std::uint8_t> dec;
    // Verification MUST fail with signature_invalid because msg_key for GPU-A differs from GPU-B
    auto status = mgr.unprotect_group_message(forged_msg, coord.endpoint, data_message_class::event, dec, now_us + 300);
    assert(status == group_verification_status::signature_invalid);

    std::cout << "  -> Anti-Impersonation Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 RFC 9420 Hardened Group Security Test Suite ===" << std::endl;
    test_group_creation_and_public_context_hygiene();
    test_confidentiality_and_multi_party_messaging();
    test_eviction_forward_secrecy_and_fresh_entropy();
    test_post_compromise_security_and_healing();
    test_anti_impersonation_and_sender_authentication();
    std::cout << "ALL RFC 9420 HARDENED GROUP SECURITY TESTS PASSED 100%!" << std::endl;
    return 0;
}
