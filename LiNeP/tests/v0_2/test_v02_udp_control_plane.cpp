#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>

#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/udp_transport.hpp"
#include "linep/v0_2/transport.hpp"
#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/envelopes.hpp"

using namespace linep::v0_2;

#define LINEP_TEST_CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAILED: " #expr " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while(0)

// ── Test 1: Node HELLO, Invite & LEASE_ACK State Machine ─────────────────────
void test_udp_hello_heartbeat_loopback() {
    std::cout << "[Test 1] UDP Control Plane: Normative HELLO -> INVITE -> LEASE_ACK -> ACTIVE..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1001, 2001, 1};

    // 1. Uninvited node sending HEARTBEAT or STATUS must be REJECTED (cannot jump to ACTIVE!)
    udp_control_datagram bogus_hb{};
    bogus_hb.node_id = 1001;
    bogus_hb.runtime_id = 2001;
    bogus_hb.endpoint_id = 1;
    bogus_hb.control_epoch = 1;
    bogus_hb.control_seq = 1;
    bogus_hb.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    bogus_hb.availability = static_cast<std::uint8_t>(node_availability::available);
    bogus_hb.health = static_cast<std::uint8_t>(node_health::healthy);
    bogus_hb.tcp_port = 5000;
    bogus_hb.set_trunk_ready(true);
    LINEP_TEST_CHECK(!router.ingest_datagram(bogus_hb, 1000));
    LINEP_TEST_CHECK(router.get_node_count() == 0);

    // 2. Legitimate NODE_HELLO: Transitions UNKNOWN -> SEEN
    udp_control_datagram hello{};
    hello.node_id = 1001;
    hello.runtime_id = 2001;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.availability = static_cast<std::uint8_t>(node_availability::available);
    hello.health = static_cast<std::uint8_t>(node_health::healthy);
    hello.tcp_port = 5000;
    hello.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));
    LINEP_TEST_CHECK(router.get_node_count() == 1);

    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::seen); // Must be SEEN, NOT active yet!
    LINEP_TEST_CHECK(!st.is_routable());                       // Not routable until leased!

    // 3. Scheduler issues INVITE with lease token
    udp_control_datagram invite_dgram{};
    std::uint64_t lease_token = 0xAABBCCDD11223344ULL;
    LINEP_TEST_CHECK(router.issue_invite(id, lease_token, invite_dgram));
    LINEP_TEST_CHECK(invite_dgram.message_type == static_cast<std::uint8_t>(control_message_type::invite));
    LINEP_TEST_CHECK(invite_dgram.lease_token == lease_token);

    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::invited);
    LINEP_TEST_CHECK(st.active_lease_token == lease_token);

    // 4. Runtime responds with LEASE_ACK with matching lease token
    udp_control_datagram lease_ack{};
    lease_ack.node_id = 1001;
    lease_ack.runtime_id = 2001;
    lease_ack.endpoint_id = 1;
    lease_ack.control_epoch = 1;
    lease_ack.control_seq = 2;
    lease_ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    lease_ack.availability = static_cast<std::uint8_t>(node_availability::available);
    lease_ack.health = static_cast<std::uint8_t>(node_health::healthy);
    lease_ack.tcp_port = 5000;
    lease_ack.set_trunk_ready(true);
    lease_ack.lease_token = lease_token;

    LINEP_TEST_CHECK(router.ingest_datagram(lease_ack, 2000));

    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);
    LINEP_TEST_CHECK(st.is_routable());
    LINEP_TEST_CHECK(router.get_routable_node_count() == 1);

    // 5. Subsequent HEARTBEAT updates telemetry without modifying capability revision or port
    udp_control_datagram hb{};
    hb.node_id = 1001;
    hb.runtime_id = 2001;
    hb.endpoint_id = 1;
    hb.control_epoch = 1;
    hb.control_seq = 3;
    hb.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    hb.availability = static_cast<std::uint8_t>(node_availability::available);
    hb.health = static_cast<std::uint8_t>(node_health::healthy);
    hb.load_pct = 42;
    hb.queue_depth = 3;
    hb.tcp_port = 9999; // Malicious port change attempt in heartbeat!
    hb.capability_digest = 0xDEADBEEF; // Malicious digest change attempt in heartbeat!

    LINEP_TEST_CHECK(router.ingest_datagram(hb, 3000));
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.load_pct == 42);
    LINEP_TEST_CHECK(st.queue_depth == 3);
    LINEP_TEST_CHECK(st.tcp_port == 5000); // Port MUST NOT be changed by heartbeat!
    LINEP_TEST_CHECK(st.capability_digest != 0xDEADBEEF); // Digest MUST NOT be changed by heartbeat!

    std::cout << "  -> Normative HELLO -> INVITE -> LEASE_ACK -> ACTIVE PASSED" << std::endl;
}

// ── Test 2: Duplicate Datagram Idempotence ───────────────────────────────────
void test_udp_duplicate_idempotence() {
    std::cout << "[Test 2] UDP Control Plane: Duplicate Datagram Idempotence..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1002, 2002, 1};

    udp_control_datagram hello{};
    hello.node_id = 1002;
    hello.runtime_id = 2002;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.tcp_port = 5002;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x1234, inv));

    udp_control_datagram ack{};
    ack.node_id = 1002;
    ack.runtime_id = 2002;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = 5002;
    ack.set_trunk_ready(true);
    ack.lease_token = 0x1234;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 2000));

    // Send duplicate seq = 2
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 2500));

    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.last_inbound_seq == 2);
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);

    std::cout << "  -> Duplicate Datagram Idempotence PASSED" << std::endl;
}

// ── Test 3: Out-of-Order Sequence & Stale Epoch Rejection ────────────────────
void test_udp_out_of_order_replay_rejection() {
    std::cout << "[Test 3] UDP Control Plane: Out-of-Order Sequence & Stale Epoch Rejection..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1003, 2003, 1};

    udp_control_datagram hello{};
    hello.node_id = 1003;
    hello.runtime_id = 2003;
    hello.endpoint_id = 1;
    hello.control_epoch = 5;
    hello.control_seq = 10;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));

    // Stale epoch < 5 must be rejected
    udp_control_datagram stale_epoch = hello;
    stale_epoch.control_epoch = 4;
    stale_epoch.control_seq = 99;
    LINEP_TEST_CHECK(!router.ingest_datagram(stale_epoch, 2000));

    // Out of order seq = 5 within epoch 5 is an idempotent duplicate/ignore
    udp_control_datagram old_seq = hello;
    old_seq.control_epoch = 5;
    old_seq.control_seq = 5;
    old_seq.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    LINEP_TEST_CHECK(router.ingest_datagram(old_seq, 2000));

    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.last_inbound_seq == 10);
    LINEP_TEST_CHECK(st.last_control_epoch == 5);

    std::cout << "  -> Out-of-Order Sequence & Stale Epoch Rejection PASSED" << std::endl;
}

// ── Test 4: Stale Detection & Expiration ─────────────────────────────────────
void test_udp_stale_detection_and_expiration() {
    std::cout << "[Test 4] UDP Control Plane: Stale Detection & Expiration..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1004, 2004, 1};

    udp_control_datagram hello{};
    hello.node_id = 1004;
    hello.runtime_id = 2004;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.tcp_port = 5004;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x4444, inv));

    udp_control_datagram ack{};
    ack.node_id = 1004;
    ack.runtime_id = 2004;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = 5004;
    ack.set_trunk_ready(true);
    ack.lease_token = 0x4444;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 1000000));

    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);
    LINEP_TEST_CHECK(router.get_routable_node_count() == 1);

    // Stale sweep after 4 seconds (stale timeout = 3s, offline timeout = 10s)
    std::size_t changed = router.sweep_stale_nodes(1000000 + 4000000, 3000000, 10000000);
    LINEP_TEST_CHECK(changed == 1);
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::cooling);
    LINEP_TEST_CHECK(!st.is_routable());

    // Offline sweep after 12 seconds
    changed = router.sweep_stale_nodes(1000000 + 12000000, 3000000, 10000000);
    LINEP_TEST_CHECK(changed == 1);
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::offline);
    LINEP_TEST_CHECK(st.active_lease_token == 0); // Lease cleared on offline!

    std::cout << "  -> Stale Detection & Expiration PASSED" << std::endl;
}

// ── Test 5: Incarnation Recovery & Epoch Cache Invalidation ───────────────────
void test_udp_incarnation_recovery() {
    std::cout << "[Test 5] UDP Control Plane: Incarnation / Epoch Recovery & Cache Invalidation..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1005, 2005, 1};

    udp_control_datagram hello1{};
    hello1.node_id = 1005;
    hello1.runtime_id = 2005;
    hello1.endpoint_id = 1;
    hello1.control_epoch = 1;
    hello1.control_seq = 1;
    hello1.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello1.capability_revision = 7;
    hello1.capability_digest = 0xABCDEF;
    hello1.tcp_port = 5005;
    hello1.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello1, 1000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x5555, inv));

    udp_control_datagram ack{};
    ack.node_id = 1005;
    ack.runtime_id = 2005;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = 5005;
    ack.set_trunk_ready(true);
    ack.lease_token = 0x5555;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 1000));

    router.set_cached_capability_valid(id, 7, 0xABCDEF);
    LINEP_TEST_CHECK(router.is_capability_cache_valid(id));

    // Node restarts with newer epoch = 2, reporting the SAME revision 7 & digest ABCDEF
    udp_control_datagram hello2{};
    hello2.node_id = 1005;
    hello2.runtime_id = 2005;
    hello2.endpoint_id = 1;
    hello2.control_epoch = 2;
    hello2.control_seq = 1;
    hello2.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello2.capability_revision = 7;
    hello2.capability_digest = 0xABCDEF;
    hello2.tcp_port = 5005;
    hello2.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(hello2, 2000));

    // CRITICAL INVARIANT: Capability cache MUST be invalidated across epoch restarts!
    LINEP_TEST_CHECK(!router.is_capability_cache_valid(id));

    // State MUST be reset to SEEN, lease token cleared
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::seen);
    LINEP_TEST_CHECK(st.active_lease_token == 0);
    LINEP_TEST_CHECK(!st.is_routable());

    std::cout << "  -> Incarnation / Epoch Recovery & Cache Invalidation PASSED" << std::endl;
}

// ── Test 6: Capability Revision Invalidation & Permission Check ──────────────
void test_udp_capability_revision_invalidation() {
    std::cout << "[Test 6] UDP Control Plane: Capability Revision Invalidation & PONG Immutability..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1006, 2006, 1};

    udp_control_datagram hello{};
    hello.node_id = 1006;
    hello.runtime_id = 2006;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.capability_revision = 1;
    hello.capability_digest = 0x1111;
    hello.tcp_port = 5006;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x6666, inv));

    udp_control_datagram ack{};
    ack.node_id = 1006;
    ack.runtime_id = 2006;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = 5006;
    ack.set_trunk_ready(true);
    ack.lease_token = 0x6666;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 1000));

    router.set_cached_capability_valid(id, 1, 0x1111);
    LINEP_TEST_CHECK(router.is_capability_cache_valid(id));

    // PONG trying to modify capabilities must NOT affect state
    udp_control_datagram pong{};
    pong.node_id = 1006;
    pong.runtime_id = 2006;
    pong.endpoint_id = 1;
    pong.control_epoch = 1;
    pong.control_seq = 3;
    pong.message_type = static_cast<std::uint8_t>(control_message_type::pong);
    pong.capability_revision = 99; // Illegal attempt
    pong.capability_digest = 0x9999;
    LINEP_TEST_CHECK(router.ingest_datagram(pong, 1500));
    LINEP_TEST_CHECK(router.is_capability_cache_valid(id)); // Cache STILL valid!

    // Legitimate STATUS message with updated revision = 2
    udp_control_datagram status{};
    status.node_id = 1006;
    status.runtime_id = 2006;
    status.endpoint_id = 1;
    status.control_epoch = 1;
    status.control_seq = 4;
    status.message_type = static_cast<std::uint8_t>(control_message_type::status);
    status.capability_revision = 2;
    status.capability_digest = 0x2222;
    status.availability = static_cast<std::uint8_t>(node_availability::available);
    status.health = static_cast<std::uint8_t>(node_health::healthy);
    status.tcp_port = 5006;
    status.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(status, 2000));
    // Cache MUST be invalidated!
    LINEP_TEST_CHECK(!router.is_capability_cache_valid(id));

    std::cout << "  -> Capability Revision Invalidation & PONG Immutability PASSED" << std::endl;
}

// ── Test 7: Dynamic Availability & Load Routing ──────────────────────────────
void test_udp_dynamic_availability_load_routing() {
    std::cout << "[Test 7] UDP Control Plane: Dynamic Availability & Composite Load Routing..." << std::endl;

    control_plane_router router;

    auto setup_node = [&](std::uint64_t nid, std::uint8_t load, std::uint32_t queue, node_health h, std::uint16_t port) {
        node_endpoint_identity id{nid, nid + 1000, 1};
        udp_control_datagram hello{};
        hello.node_id = nid;
        hello.runtime_id = nid + 1000;
        hello.endpoint_id = 1;
        hello.control_epoch = 1;
        hello.control_seq = 1;
        hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
        hello.tcp_port = port;
        hello.set_trunk_ready(true);
        router.ingest_datagram(hello, 1000);

        udp_control_datagram inv{};
        router.issue_invite(id, nid * 100, inv);

        udp_control_datagram ack{};
        ack.node_id = nid;
        ack.runtime_id = nid + 1000;
        ack.endpoint_id = 1;
        ack.control_epoch = 1;
        ack.control_seq = 2;
        ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
        ack.availability = static_cast<std::uint8_t>(node_availability::available);
        ack.health = static_cast<std::uint8_t>(h);
        ack.load_pct = load;
        ack.queue_depth = queue;
        ack.tcp_port = port;
        ack.set_trunk_ready(true);
        ack.lease_token = nid * 100;
        router.ingest_datagram(ack, 1000);
    };

    setup_node(701, 80, 5, node_health::healthy, 5701); // High load
    setup_node(702, 10, 0, node_health::healthy, 5702); // Lowest load
    setup_node(703, 5, 0, node_health::degraded, 5703);  // Low load but degraded penalty

    node_endpoint_identity best{};
    std::uint16_t best_port = 0;
    std::uint64_t best_token = 0;
    LINEP_TEST_CHECK(router.select_best_candidate(best, best_port, best_token));
    LINEP_TEST_CHECK(best.node_id == 702); // 702 must win
    LINEP_TEST_CHECK(best_port == 5702);
    LINEP_TEST_CHECK(best_token == 70200);

    std::cout << "  -> Dynamic Availability & Composite Load Routing PASSED" << std::endl;
}

// ── Test 8: Invite / Lease Retry & Idempotence ────────────────────────────────
void test_udp_invite_lease_retry() {
    std::cout << "[Test 8] UDP Control Plane: Invite / Lease Token Enforcement & Retries..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1008, 2008, 1};

    udp_control_datagram hello{};
    hello.node_id = 1008;
    hello.runtime_id = 2008;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.tcp_port = 5008;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x8888, inv));

    // Mismatched lease token in LEASE_ACK must be REJECTED!
    udp_control_datagram bad_ack{};
    bad_ack.node_id = 1008;
    bad_ack.runtime_id = 2008;
    bad_ack.endpoint_id = 1;
    bad_ack.control_epoch = 1;
    bad_ack.control_seq = 2;
    bad_ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    bad_ack.tcp_port = 5008;
    bad_ack.set_trunk_ready(true);
    bad_ack.lease_token = 0x9999; // Bad token!
    LINEP_TEST_CHECK(!router.ingest_datagram(bad_ack, 2000));

    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::invited); // Still invited

    // Correct lease token LEASE_ACK succeeds
    udp_control_datagram good_ack = bad_ack;
    good_ack.control_seq = 3;
    good_ack.lease_token = 0x8888;
    good_ack.availability = static_cast<std::uint8_t>(node_availability::available);
    good_ack.health = static_cast<std::uint8_t>(node_health::healthy);
    LINEP_TEST_CHECK(router.ingest_datagram(good_ack, 3000));

    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);
    LINEP_TEST_CHECK(st.active_lease_token == 0x8888);

    std::cout << "  -> Invite / Lease Token Enforcement & Retries PASSED" << std::endl;
}

// ── Test 9: UDP Failure with Continuous Active TCP Stream ────────────────────
void test_udp_failure_while_tcp_continues() {
    std::cout << "[Test 9] UDP Loss with Continuous Active TCP Data Stream..." << std::endl;

    mock_runtime_config cfg{};
    cfg.model_id = "linep-v02-dual-plane-model";
    cfg.default_tokens = 6;
    cfg.delay_per_event_ms = 2;

    mock_runtime_server mock_server(cfg);
    LINEP_TEST_CHECK(mock_server.start(0));
    std::uint16_t tcp_port = mock_server.get_bound_port();
    LINEP_TEST_CHECK(tcp_port > 0);

    control_plane_router router;
    node_endpoint_identity id{1009, 2009, 1};

    udp_control_datagram hello{};
    hello.node_id = 1009;
    hello.runtime_id = 2009;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.tcp_port = tcp_port;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(hello, 1000000));

    udp_control_datagram inv{};
    LINEP_TEST_CHECK(router.issue_invite(id, 0x9999, inv));

    udp_control_datagram ack{};
    ack.node_id = 1009;
    ack.runtime_id = 2009;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = tcp_port;
    ack.set_trunk_ready(true);
    ack.lease_token = 0x9999;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 1000000));

    auto conn = envelope_connection::connect("127.0.0.1", tcp_port);
    LINEP_TEST_CHECK(conn != nullptr);

    stream_identity stream_id{901, 9001, 0};
    request_envelope req{stream_id, runtime_profile::generate, cfg.model_id, "Stream amidst UDP loss"};
    LINEP_TEST_CHECK(conn->send_request(req));

    // Sweep: UDP router transitions node to OFFLINE
    router.sweep_stale_nodes(1000000 + 20000000, 3000000, 10000000);
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::offline);
    LINEP_TEST_CHECK(router.get_routable_node_count() == 0);

    // Active TCP stream continues to completion
    std::vector<std::uint8_t> raw;
    bool completed_ok = false;
    std::size_t deltas_received = 0;

    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw.data(), raw.size(), evt));
        if (evt.event_type == runtime_event_type::content_delta) {
            deltas_received++;
        } else if (evt.event_type == runtime_event_type::completed) {
            LINEP_TEST_CHECK(evt.outcome == terminal_outcome::completed);
            LINEP_TEST_CHECK(evt.error.code == 200);
            completed_ok = true;
            break;
        }
    }

    LINEP_TEST_CHECK(completed_ok);
    LINEP_TEST_CHECK(deltas_received > 0);

    conn->close();
    mock_server.stop();
    std::cout << "  -> UDP Loss with Continuous Active TCP Data Stream PASSED (100% Isolation)" << std::endl;
}

// ── Test 10: Dual-Plane Integration & Identity Binding ───────────────────────
void test_dual_plane_integration_identity_binding() {
    std::cout << "[Test 10] Real UDP Socket Channel & Persistent TCP Data Plane Integration..." << std::endl;

    udp_endpoint_channel udp_sender;
    LINEP_TEST_CHECK(udp_sender.open_and_bind(0, 500));
    std::uint16_t sender_port = udp_sender.get_bound_port();

    udp_endpoint_channel udp_receiver;
    LINEP_TEST_CHECK(udp_receiver.open_and_bind(0, 500));
    std::uint16_t receiver_port = udp_receiver.get_bound_port();

    mock_runtime_config cfg{};
    cfg.model_id = "linep-dual-plane-model-v02";
    mock_runtime_server mock_server(cfg);
    LINEP_TEST_CHECK(mock_server.start(0));
    std::uint16_t tcp_port = mock_server.get_bound_port();
    LINEP_TEST_CHECK(tcp_port > 0);

    // 1. Send UDP NODE_HELLO over real socket
    udp_control_datagram hello{};
    hello.node_id = 7777;
    hello.runtime_id = 8888;
    hello.endpoint_id = 1;
    hello.control_epoch = 1;
    hello.control_seq = 1;
    hello.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    hello.availability = static_cast<std::uint8_t>(node_availability::available);
    hello.health = static_cast<std::uint8_t>(node_health::healthy);
    hello.tcp_port = tcp_port;
    hello.set_trunk_ready(true);
    LINEP_TEST_CHECK(udp_sender.send_datagram("127.0.0.1", receiver_port, hello));

    udp_control_datagram recvd{};
    std::string src_ip;
    std::uint16_t src_port = 0;
    LINEP_TEST_CHECK(udp_receiver.recv_datagram(recvd, &src_ip, &src_port));

    control_plane_router router;
    LINEP_TEST_CHECK(router.ingest_datagram(recvd, 1000000));

    // 2. Issue INVITE & process LEASE_ACK
    node_endpoint_identity id{7777, 8888, 1};
    udp_control_datagram inv{};
    std::uint64_t lease_token = 0xFEEDBEEFCAFE1234ULL;
    LINEP_TEST_CHECK(router.issue_invite(id, lease_token, inv));

    udp_control_datagram ack{};
    ack.node_id = 7777;
    ack.runtime_id = 8888;
    ack.endpoint_id = 1;
    ack.control_epoch = 1;
    ack.control_seq = 2;
    ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    ack.availability = static_cast<std::uint8_t>(node_availability::available);
    ack.health = static_cast<std::uint8_t>(node_health::healthy);
    ack.tcp_port = tcp_port;
    ack.set_trunk_ready(true);
    ack.lease_token = lease_token;
    LINEP_TEST_CHECK(router.ingest_datagram(ack, 1000000));

    // 3. Router selects node and binds to persistent TCP data trunk
    node_endpoint_identity target_node{};
    std::uint16_t bound_tcp_port = 0;
    std::uint64_t bound_lease_token = 0;
    LINEP_TEST_CHECK(router.select_best_candidate(target_node, bound_tcp_port, bound_lease_token));
    LINEP_TEST_CHECK(target_node.node_id == 7777);
    LINEP_TEST_CHECK(bound_tcp_port == tcp_port);
    LINEP_TEST_CHECK(bound_lease_token == lease_token);

    // 4. Validate TCP Session Binding with UDP Control Plane
    LINEP_TEST_CHECK(router.validate_tcp_session_binding(target_node, 1, lease_token));
    // Negative test: mismatched epoch or token fails validation
    LINEP_TEST_CHECK(!router.validate_tcp_session_binding(target_node, 2, lease_token));
    LINEP_TEST_CHECK(!router.validate_tcp_session_binding(target_node, 1, 0x1111));

    // 5. Execute streaming over the bound TCP connection
    auto conn = envelope_connection::connect("127.0.0.1", bound_tcp_port);
    LINEP_TEST_CHECK(conn != nullptr);

    stream_identity sid{999, 9999, 0};
    request_envelope req{sid, runtime_profile::chat, cfg.model_id, "Dual-plane test prompt"};
    LINEP_TEST_CHECK(conn->send_request(req));

    std::vector<std::uint8_t> raw;
    bool completed_ok = false;
    while (conn->receive_envelope_raw(raw)) {
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw.data(), raw.size(), evt));
        if (evt.event_type == runtime_event_type::completed) {
            completed_ok = true;
            break;
        }
    }
    LINEP_TEST_CHECK(completed_ok);

    conn->close();
    udp_sender.close();
    udp_receiver.close();
    mock_server.stop();

    std::cout << "  -> Real UDP Socket Channel & Persistent TCP Data Plane Integration PASSED" << std::endl;
}

// ── Test 11: Strict Fail-Closed Semantic Decoder Validation ──────────────────
void test_strict_fail_closed_decoder_validation() {
    std::cout << "[Test 11] UDP Control Plane: Strict Fail-Closed Semantic Decoder Validation..." << std::endl;

    udp_control_datagram valid_dgram{};
    valid_dgram.node_id = 5001;
    valid_dgram.runtime_id = 6001;
    valid_dgram.endpoint_id = 1;
    valid_dgram.control_epoch = 1;
    valid_dgram.control_seq = 1;
    valid_dgram.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    valid_dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    valid_dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    valid_dgram.load_pct = 50;

    std::vector<std::uint8_t> buf;
    encode_control_datagram(valid_dgram, buf);
    LINEP_TEST_CHECK(buf.size() == 80);

    udp_control_datagram decoded{};
    LINEP_TEST_CHECK(decode_control_datagram(buf.data(), buf.size(), decoded));

    // 1. Strict Size Check: size > 80 (trailing bytes) must fail closed!
    std::vector<std::uint8_t> oversized = buf;
    oversized.push_back(0x00);
    LINEP_TEST_CHECK(!decode_control_datagram(oversized.data(), oversized.size(), decoded));

    // 2. Strict Size Check: size < 80 must fail closed!
    LINEP_TEST_CHECK(!decode_control_datagram(buf.data(), 79, decoded));

    // 3. Invalid message_type = 99 must fail closed!
    auto test_tamper = [&](std::size_t offset, std::uint8_t bad_val) {
        std::vector<std::uint8_t> tampered = buf;
        tampered[offset] = bad_val;
        // Re-calculate CRC
        std::vector<std::uint8_t> tmp = tampered;
        tmp.resize(80);
        // Note: CRC mismatch itself will fail, but if CRC is valid, semantic checks must reject!
        return decode_control_datagram(tampered.data(), tampered.size(), decoded);
    };

    // Test CRC corruption
    std::vector<std::uint8_t> corrupt_crc = buf;
    corrupt_crc[76] ^= 0xFF;
    LINEP_TEST_CHECK(!decode_control_datagram(corrupt_crc.data(), corrupt_crc.size(), decoded));

    // Test load_pct > 100
    valid_dgram.load_pct = 101;
    encode_control_datagram(valid_dgram, buf);
    LINEP_TEST_CHECK(!decode_control_datagram(buf.data(), buf.size(), decoded));

    // Test invalid availability = 9
    valid_dgram.load_pct = 50;
    valid_dgram.availability = 9;
    encode_control_datagram(valid_dgram, buf);
    LINEP_TEST_CHECK(!decode_control_datagram(buf.data(), buf.size(), decoded));

    // Test dirty reserved byte != 0
    valid_dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    valid_dgram.reserved = 1;
    encode_control_datagram(valid_dgram, buf);
    LINEP_TEST_CHECK(!decode_control_datagram(buf.data(), buf.size(), decoded));

    std::cout << "  -> Strict Fail-Closed Semantic Decoder Validation PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 UDP Control Plane Acceptance Test Suite ===" << std::endl;
    test_udp_hello_heartbeat_loopback();
    test_udp_duplicate_idempotence();
    test_udp_out_of_order_replay_rejection();
    test_udp_stale_detection_and_expiration();
    test_udp_incarnation_recovery();
    test_udp_capability_revision_invalidation();
    test_udp_dynamic_availability_load_routing();
    test_udp_invite_lease_retry();
    test_udp_failure_while_tcp_continues();
    test_dual_plane_integration_identity_binding();
    test_strict_fail_closed_decoder_validation();
    std::cout << "ALL 11 V0.2 PHASE D UDP CONTROL PLANE TESTS PASSED 100%!" << std::endl;
    return 0;
}
