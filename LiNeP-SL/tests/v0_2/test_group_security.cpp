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

void test_group_creation_and_membership() {
    std::cout << "[Test 1] Group Creation & Dynamic Membership Epoch Transitions..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    assert(mgr.create_group(9001, group_type::ephemeral_task, crypto_suite::hmac_sha256_128, coord, initial_secret, now_us));
    assert(mgr.get_group_count() == 1);
    assert(mgr.get_active_group_count() == 1);

    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_id == 9001);
    assert(ctx.group_epoch == 1);
    assert(ctx.members.size() == 1);
    assert(ctx.members[0].role == member_role::coordinator);
    assert(mgr.is_member_active(9001, coord.endpoint));

    // Add Primary GPU-A -> Epoch 2
    auto gpu_a = make_worker(10, member_role::worker_primary);
    assert(mgr.add_member(9001, gpu_a, now_us + 1000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 2);
    assert(ctx.members.size() == 2);
    assert(mgr.is_member_active(9001, gpu_a.endpoint));

    // Duplicate add rejected
    assert(!mgr.add_member(9001, gpu_a, now_us + 1500));

    // Add Redundant GPU-B -> Epoch 3
    auto gpu_b = make_worker(20, member_role::worker_redundant);
    assert(mgr.add_member(9001, gpu_b, now_us + 2000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 3);
    assert(ctx.members.size() == 3);

    // Add Validator CPU-C -> Epoch 4
    auto cpu_c = make_worker(30, member_role::validator);
    assert(mgr.add_member(9001, cpu_c, now_us + 3000));
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 4);
    assert(ctx.members.size() == 4);

    std::cout << "  -> Group Creation & Membership Tests PASSED" << std::endl;
}

void test_group_messaging_and_multi_party_flow() {
    std::cout << "[Test 2] Group Messaging & Replay Protection Across Execution Set..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);
    auto gpu_b = make_worker(20, member_role::worker_redundant);
    auto cpu_c = make_worker(30, member_role::validator);

    assert(mgr.create_group(9001, group_type::ephemeral_task, crypto_suite::hmac_sha256_128, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, now_us + 100));
    assert(mgr.add_member(9001, gpu_b, now_us + 200));
    assert(mgr.add_member(9001, cpu_c, now_us + 300));

    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 4);

    // 1. Coordinator signs task request (seq = 1)
    std::vector<std::uint8_t> req_payload = {'t', 'a', 's', 'k', '_', 'r', 'e', 'q', 'u', 'e', 's', 't'};
    std::vector<std::uint8_t> req_tag;
    assert(mgr.sign_group_message(9001, coord.endpoint, data_message_class::request, req_payload, 1, req_tag));

    // Primary GPU-A verifies coordinator's request
    auto status = mgr.verify_group_message(9001, 4, coord.endpoint, data_message_class::request, req_payload, 1, req_tag, now_us + 400);
    assert(status == group_verification_status::ok);

    // 2. Replay attack rejection for coordinator request
    status = mgr.verify_group_message(9001, 4, coord.endpoint, data_message_class::request, req_payload, 1, req_tag, now_us + 450);
    assert(status == group_verification_status::replay_rejected);

    // 3. Primary GPU-A signs intermediate stream delta (seq = 1)
    std::vector<std::uint8_t> delta_payload = {'e', 'v', 'e', 'n', 't', '_', 'd', 'e', 'l', 't', 'a', '_', '1'};
    std::vector<std::uint8_t> delta_tag;
    assert(mgr.sign_group_message(9001, gpu_a.endpoint, data_message_class::event, delta_payload, 1, delta_tag));

    // Validator CPU-C verifies GPU-A's event
    status = mgr.verify_group_message(9001, 4, gpu_a.endpoint, data_message_class::event, delta_payload, 1, delta_tag, now_us + 500);
    assert(status == group_verification_status::ok);

    // 4. Primary GPU-A signs completed result (seq = 2)
    std::vector<std::uint8_t> result_payload = {'e', 'v', 'e', 'n', 't', '_', 'r', 'e', 's', 'u', 'l', 't'};
    std::vector<std::uint8_t> result_tag;
    assert(mgr.sign_group_message(9001, gpu_a.endpoint, data_message_class::event, result_payload, 2, result_tag));

    // Coordinator verifies result
    status = mgr.verify_group_message(9001, 4, gpu_a.endpoint, data_message_class::event, result_payload, 2, result_tag, now_us + 600);
    assert(status == group_verification_status::ok);

    std::cout << "  -> Group Messaging & Replay Protection Tests PASSED" << std::endl;
}

void test_failover_eviction_and_forward_secrecy() {
    std::cout << "[Test 3] Failover, Node Eviction & Cryptographic Forward Secrecy..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);
    auto gpu_b = make_worker(20, member_role::worker_redundant);
    auto cpu_c = make_worker(30, member_role::validator);

    assert(mgr.create_group(9001, group_type::ephemeral_task, crypto_suite::hmac_sha256_128, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, now_us + 100));
    assert(mgr.add_member(9001, gpu_b, now_us + 200));
    assert(mgr.add_member(9001, cpu_c, now_us + 300));

    // Epoch 4 tag from GPU-A
    std::vector<std::uint8_t> epoch4_payload = {'o', 'l', 'd', '_', 'm', 's', 'g'};
    std::vector<std::uint8_t> epoch4_tag;
    assert(mgr.sign_group_message(9001, gpu_a.endpoint, data_message_class::event, epoch4_payload, 10, epoch4_tag));

    // Primary GPU-A is detected faulty -> Cluster OS evicts GPU-A
    assert(mgr.remove_member(9001, gpu_a.endpoint, now_us + 1000));

    group_context ctx;
    assert(mgr.get_group_context(9001, ctx));
    assert(ctx.group_epoch == 5); // Epoch advanced!
    assert(!mgr.is_member_active(9001, gpu_a.endpoint)); // GPU-A no longer active

    // Promote GPU-B to primary worker
    assert(mgr.update_member_role(9001, gpu_b.endpoint, member_role::worker_primary, now_us + 1100));

    // 1. Evicted node GPU-A cannot sign messages in new epoch (signing returns false)
    std::vector<std::uint8_t> new_payload = {'t', 'a', 's', 'k', '_', 'c', 'o', 'n', 't', 'i', 'n', 'u', 'e'};
    std::vector<std::uint8_t> rogue_tag;
    assert(!mgr.sign_group_message(9001, gpu_a.endpoint, data_message_class::event, new_payload, 1, rogue_tag));

    // 2. If an attacker attempts to verify a forged tag under evicted member GPU-A in epoch 5 -> rejected with member_not_active
    std::vector<std::uint8_t> fake_tag(16, 0xAA);
    auto status = mgr.verify_group_message(9001, 5, gpu_a.endpoint, data_message_class::event, new_payload, 1, fake_tag, now_us + 1200);
    assert(status == group_verification_status::member_not_active);

    // 3. Stale epoch replay: Attempting to send epoch 4 message in epoch 5 -> rejected with stale_epoch
    status = mgr.verify_group_message(9001, 4, gpu_a.endpoint, data_message_class::event, epoch4_payload, 10, epoch4_tag, now_us + 1300);
    assert(status == group_verification_status::stale_epoch);

    // 4. Promoted GPU-B signs task continuation in epoch 5
    std::vector<std::uint8_t> epoch5_tag;
    assert(mgr.sign_group_message(9001, gpu_b.endpoint, data_message_class::event, new_payload, 1, epoch5_tag));

    // Validator CPU-C verifies GPU-B in epoch 5 -> ok!
    status = mgr.verify_group_message(9001, 5, gpu_b.endpoint, data_message_class::event, new_payload, 1, epoch5_tag, now_us + 1400);
    assert(status == group_verification_status::ok);

    std::cout << "  -> Failover & Forward Secrecy Tests PASSED" << std::endl;
}

void test_tampering_and_negative_cases() {
    std::cout << "[Test 4] Tampering, Invalid Bindings & Group Closure..." << std::endl;

    group_security_manager mgr;
    std::uint64_t now_us = 1000000ULL;
    auto initial_secret = make_initial_secret();

    auto coord = make_coordinator(1);
    auto gpu_a = make_worker(10, member_role::worker_primary);

    assert(mgr.create_group(9001, group_type::ephemeral_task, crypto_suite::hmac_sha256_128, coord, initial_secret, now_us));
    assert(mgr.add_member(9001, gpu_a, now_us + 100));

    std::vector<std::uint8_t> payload = {'v', 'a', 'l', 'i', 'd', '_', 'd', 'a', 't', 'a'};
    std::vector<std::uint8_t> tag;
    assert(mgr.sign_group_message(9001, gpu_a.endpoint, data_message_class::event, payload, 1, tag));

    // Tampered payload fails
    std::vector<std::uint8_t> bad_payload = payload;
    bad_payload[0] = 'X';
    auto status = mgr.verify_group_message(9001, 2, gpu_a.endpoint, data_message_class::event, bad_payload, 1, tag, now_us + 200);
    assert(status == group_verification_status::signature_invalid);

    // Unknown group ID fails
    status = mgr.verify_group_message(9999, 2, gpu_a.endpoint, data_message_class::event, payload, 1, tag, now_us + 200);
    assert(status == group_verification_status::group_not_found);

    // Non-member endpoint fails
    linep::v0_2::node_endpoint_identity stranger = {99, 99, 99};
    status = mgr.verify_group_message(9001, 2, stranger, data_message_class::event, payload, 1, tag, now_us + 200);
    assert(status == group_verification_status::member_not_found);

    // Close group
    assert(mgr.close_group(9001, now_us + 300));
    assert(mgr.get_active_group_count() == 0);

    // Message verification on closed group fails
    status = mgr.verify_group_message(9001, 2, gpu_a.endpoint, data_message_class::event, payload, 2, tag, now_us + 400);
    assert(status == group_verification_status::group_inactive);

    std::cout << "  -> Tampering & Group Closure Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 MLS Group Security Test Suite ===" << std::endl;
    test_group_creation_and_membership();
    test_group_messaging_and_multi_party_flow();
    test_failover_eviction_and_forward_secrecy();
    test_tampering_and_negative_cases();
    std::cout << "ALL GROUP SECURITY TESTS PASSED 100%!" << std::endl;
    return 0;
}
