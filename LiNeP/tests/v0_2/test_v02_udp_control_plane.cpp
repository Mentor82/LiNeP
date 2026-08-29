#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cstdlib>
#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/udp_transport.hpp"
#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/transport.hpp"

#define LINEP_TEST_CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAILED: " #expr " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while(0)

using namespace linep::v0_2;

// ── Test 1: Node HELLO / Heartbeat Loopback ──────────────────────────────────
void test_udp_hello_heartbeat_loopback() {
    std::cout << "[Test 1] UDP Control Plane: Node HELLO & Heartbeat Loopback..." << std::endl;

    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1001;
    dgram.runtime_id = 2001;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.load_pct = 15;
    dgram.queue_depth = 2;
    dgram.tcp_port = 8080;
    dgram.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(dgram, 1000000));
    LINEP_TEST_CHECK(router.get_node_count() == 1);
    LINEP_TEST_CHECK(router.get_routable_node_count() == 1);

    node_endpoint_identity id{1001, 2001, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);
    LINEP_TEST_CHECK(st.load_pct == 15);
    LINEP_TEST_CHECK(st.queue_depth == 2);
    LINEP_TEST_CHECK(st.tcp_port == 8080);
    LINEP_TEST_CHECK(st.tcp_trunk_ready);

    std::cout << "  -> Node HELLO & Heartbeat Loopback PASSED" << std::endl;
}

// ── Test 2: Duplicate Datagram Idempotence ────────────────────────────────────
void test_udp_duplicate_idempotence() {
    std::cout << "[Test 2] UDP Control Plane: Duplicate Datagram Idempotence..." << std::endl;

    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1002;
    dgram.runtime_id = 2002;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 5;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.load_pct = 20;
    dgram.tcp_port = 8081;
    dgram.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(dgram, 1000000));

    // Replay duplicate with control_seq == 5:
    dgram.load_pct = 99; // Corrupted duplicate metric payload
    LINEP_TEST_CHECK(router.ingest_datagram(dgram, 1000000));

    node_endpoint_identity id{1002, 2002, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    // Must NOT have double-applied or overwritten state with the replayed sequence!
    LINEP_TEST_CHECK(st.last_control_seq == 5);
    LINEP_TEST_CHECK(st.load_pct == 20);

    std::cout << "  -> Duplicate Datagram Idempotence PASSED" << std::endl;
}

// ── Test 3: Out-of-Order & Replay Rejection ──────────────────────────────────
void test_udp_out_of_order_replay_rejection() {
    std::cout << "[Test 3] UDP Control Plane: Out-of-Order Sequence & Stale Epoch Rejection..." << std::endl;

    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1003;
    dgram.runtime_id = 2003;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 2;
    dgram.control_seq = 10;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.load_pct = 30;
    dgram.tcp_port = 8082;
    dgram.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(dgram, 1000000));

    // 1. Stale sequence (seq 8 < seq 10) in same epoch:
    udp_control_datagram stale_seq = dgram;
    stale_seq.control_seq = 8;
    stale_seq.load_pct = 80;
    LINEP_TEST_CHECK(router.ingest_datagram(stale_seq, 1000100)); // Handled as idempotent no-op

    // 2. Stale epoch (epoch 1 < epoch 2):
    udp_control_datagram stale_epoch = dgram;
    stale_epoch.control_epoch = 1;
    stale_epoch.control_seq = 100;
    LINEP_TEST_CHECK(!router.ingest_datagram(stale_epoch, 1000200)); // Hard rejected

    node_endpoint_identity id{1003, 2003, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.last_control_epoch == 2);
    LINEP_TEST_CHECK(st.last_control_seq == 10);
    LINEP_TEST_CHECK(st.load_pct == 30);

    std::cout << "  -> Out-of-Order Sequence & Stale Epoch Rejection PASSED" << std::endl;
}

// ── Test 4: Stale Detection & Expiration ──────────────────────────────────────
void test_udp_stale_detection_and_expiration() {
    std::cout << "[Test 4] UDP Control Plane: Stale Detection & Expiration..." << std::endl;

    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1004;
    dgram.runtime_id = 2004;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.tcp_port = 8083;
    dgram.set_trunk_ready(true);

    std::uint64_t t0 = 1000000;
    LINEP_TEST_CHECK(router.ingest_datagram(dgram, t0));
    LINEP_TEST_CHECK(router.get_routable_node_count() == 1);

    // Stale timeout = 3,000,000 us (3s), Offline timeout = 10,000,000 us (10s)
    // At t0 + 4s (stale):
    std::size_t swept = router.sweep_stale_nodes(t0 + 4000000, 3000000, 10000000);
    LINEP_TEST_CHECK(swept == 1);
    LINEP_TEST_CHECK(router.get_routable_node_count() == 0); // Cooling nodes are not routable for new work!

    node_endpoint_identity id{1004, 2004, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::cooling);

    // At t0 + 12s (offline):
    swept = router.sweep_stale_nodes(t0 + 12000000, 3000000, 10000000);
    LINEP_TEST_CHECK(swept == 1);
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::offline);

    std::cout << "  -> Stale Detection & Expiration PASSED" << std::endl;
}

// ── Test 5: Incarnation Recovery ─────────────────────────────────────────────
void test_udp_incarnation_recovery() {
    std::cout << "[Test 5] UDP Control Plane: Incarnation / Epoch Recovery..." << std::endl;

    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1005;
    dgram.runtime_id = 2005;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 100;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.tcp_port = 8084;
    dgram.set_trunk_ready(true);

    std::uint64_t t0 = 1000000;
    LINEP_TEST_CHECK(router.ingest_datagram(dgram, t0));

    // Node goes offline
    router.sweep_stale_nodes(t0 + 15000000, 3000000, 10000000);
    node_endpoint_identity id{1005, 2005, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::offline);

    // Node restarts with newer epoch (epoch 2, seq 1):
    udp_control_datagram restart_dgram = dgram;
    restart_dgram.control_epoch = 2;
    restart_dgram.control_seq = 1;
    restart_dgram.tcp_port = 8085;
    LINEP_TEST_CHECK(router.ingest_datagram(restart_dgram, t0 + 20000000));

    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);
    LINEP_TEST_CHECK(st.last_control_epoch == 2);
    LINEP_TEST_CHECK(st.last_control_seq == 1);
    LINEP_TEST_CHECK(st.tcp_port == 8085);

    std::cout << "  -> Incarnation Recovery PASSED" << std::endl;
}

// ── Test 6: Capability Revision Invalidation ─────────────────────────────────
void test_udp_capability_revision_invalidation() {
    std::cout << "[Test 6] UDP Control Plane: Capability Revision Invalidation..." << std::endl;

    control_plane_router router;
    node_endpoint_identity id{1006, 2006, 1};

    // 1. Initial datagram sets capability rev 1, digest 0xAAAA
    udp_control_datagram dgram1{};
    dgram1.node_id = 1006;
    dgram1.runtime_id = 2006;
    dgram1.endpoint_id = 1;
    dgram1.control_epoch = 1;
    dgram1.control_seq = 1;
    dgram1.message_type = static_cast<std::uint8_t>(control_message_type::status);
    dgram1.capability_revision = 1;
    dgram1.capability_digest = 0xAAAA;
    dgram1.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram1.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram1.tcp_port = 8086;
    dgram1.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(dgram1, 1000000));

    // Cache initial capabilities (rev 1, digest 0xAAAA)
    router.set_cached_capability_valid(id, 1, 0xAAAA);
    LINEP_TEST_CHECK(router.is_capability_cache_valid(id));

    // 2. Datagram arrives with newer capability revision (rev 2, digest 0xBBBB)
    udp_control_datagram dgram2 = dgram1;
    dgram2.control_seq = 2;
    dgram2.capability_revision = 2;
    dgram2.capability_digest = 0xBBBB;
    LINEP_TEST_CHECK(router.ingest_datagram(dgram2, 1000100));

    // Cache with old rev 1 must be detected as INVALID (triggers TCP refresh)
    LINEP_TEST_CHECK(!router.is_capability_cache_valid(id));

    // Update cache with rev 2 -> becomes valid
    router.set_cached_capability_valid(id, 2, 0xBBBB);
    LINEP_TEST_CHECK(router.is_capability_cache_valid(id));

    std::cout << "  -> Capability Revision Invalidation PASSED" << std::endl;
}

// ── Test 7: Dynamic Availability & Load Routing ──────────────────────────────
void test_udp_dynamic_availability_load_routing() {
    std::cout << "[Test 7] UDP Control Plane: Dynamic Availability & Load Routing..." << std::endl;

    control_plane_router router;

    // Node A: load 80%, queue 5
    udp_control_datagram dgram_a{};
    dgram_a.node_id = 101;
    dgram_a.runtime_id = 201;
    dgram_a.endpoint_id = 1;
    dgram_a.control_epoch = 1;
    dgram_a.control_seq = 1;
    dgram_a.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram_a.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram_a.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram_a.load_pct = 80;
    dgram_a.queue_depth = 5;
    dgram_a.tcp_port = 9001;
    dgram_a.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(dgram_a, 1000000));

    // Node B: load 10%, queue 0
    udp_control_datagram dgram_b{};
    dgram_b.node_id = 102;
    dgram_b.runtime_id = 202;
    dgram_b.endpoint_id = 1;
    dgram_b.control_epoch = 1;
    dgram_b.control_seq = 1;
    dgram_b.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram_b.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram_b.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram_b.load_pct = 10;
    dgram_b.queue_depth = 0;
    dgram_b.tcp_port = 9002;
    dgram_b.set_trunk_ready(true);
    LINEP_TEST_CHECK(router.ingest_datagram(dgram_b, 1000000));

    node_endpoint_identity chosen{};
    std::uint16_t chosen_port = 0;
    LINEP_TEST_CHECK(router.select_best_candidate(chosen, chosen_port));
    LINEP_TEST_CHECK(chosen.node_id == 102); // Node B chosen due to lower load
    LINEP_TEST_CHECK(chosen_port == 9002);

    // Node B becomes degraded:
    dgram_b.control_seq = 2;
    dgram_b.availability = static_cast<std::uint8_t>(node_availability::degraded);
    LINEP_TEST_CHECK(router.ingest_datagram(dgram_b, 1000000));

    // Now Node A should be preferred over degraded Node B:
    LINEP_TEST_CHECK(router.select_best_candidate(chosen, chosen_port));
    LINEP_TEST_CHECK(chosen.node_id == 101);
    LINEP_TEST_CHECK(chosen_port == 9001);

    std::cout << "  -> Dynamic Availability & Load Routing PASSED" << std::endl;
}

// ── Test 8: Invite / Lease Retry & Idempotence ────────────────────────────────
void test_udp_invite_lease_retry() {
    std::cout << "[Test 8] UDP Control Plane: Invite / Lease Retry & Idempotence..." << std::endl;

    control_plane_router router;
    udp_control_datagram invite{};
    invite.node_id = 1008;
    invite.runtime_id = 2008;
    invite.endpoint_id = 1;
    invite.control_epoch = 1;
    invite.control_seq = 1;
    invite.message_type = static_cast<std::uint8_t>(control_message_type::invite);
    invite.availability = static_cast<std::uint8_t>(node_availability::available);
    invite.health = static_cast<std::uint8_t>(node_health::healthy);
    invite.tcp_port = 8088;
    invite.set_trunk_ready(true);

    LINEP_TEST_CHECK(router.ingest_datagram(invite, 1000000));

    // Acknowledge lease
    udp_control_datagram lease_ack = invite;
    lease_ack.control_seq = 2;
    lease_ack.message_type = static_cast<std::uint8_t>(control_message_type::lease_ack);
    LINEP_TEST_CHECK(router.ingest_datagram(lease_ack, 1000050));

    // Retried ACK (seq 2 retransmitted)
    LINEP_TEST_CHECK(router.ingest_datagram(lease_ack, 1000100));

    node_endpoint_identity id{1008, 2008, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::active);

    std::cout << "  -> Invite / Lease Retry & Idempotence PASSED" << std::endl;
}

// ── Test 9: UDP Failure with Continuous TCP Stream ───────────────────────────
void test_udp_failure_while_tcp_continues() {
    std::cout << "[Test 9] UDP Loss with Continuous Active TCP Data Stream..." << std::endl;

    // Start mock TCP data plane runtime
    mock_runtime_config cfg{};
    cfg.model_id = "linep-v02-dual-plane-model";
    cfg.default_tokens = 6;
    cfg.delay_per_event_ms = 2;

    mock_runtime_server mock_server(cfg);
    LINEP_TEST_CHECK(mock_server.start(0));
    std::uint16_t tcp_port = mock_server.get_bound_port();
    LINEP_TEST_CHECK(tcp_port > 0);

    // Register node in UDP control router
    control_plane_router router;
    udp_control_datagram dgram{};
    dgram.node_id = 1009;
    dgram.runtime_id = 2009;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::heartbeat);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.tcp_port = tcp_port;
    dgram.set_trunk_ready(true);

    std::uint64_t t0 = 1000000;
    LINEP_TEST_CHECK(router.ingest_datagram(dgram, t0));

    // Connect persistent TCP data stream
    auto conn = envelope_connection::connect("127.0.0.1", tcp_port);
    LINEP_TEST_CHECK(conn != nullptr);

    stream_identity stream_id{901, 9001, 0};
    request_envelope req{stream_id, runtime_profile::generate, cfg.model_id, "Stream amidst UDP loss"};
    LINEP_TEST_CHECK(conn->send_request(req));

    // CRITICAL INVARIANT: UDP Control Plane goes OFFLINE due to total loss of heartbeats!
    router.sweep_stale_nodes(t0 + 20000000, 3000000, 10000000);
    node_endpoint_identity id{1009, 2009, 1};
    control_plane_node_state st{};
    LINEP_TEST_CHECK(router.get_node_state(id, st));
    LINEP_TEST_CHECK(st.state == control_node_lifecycle::offline);
    LINEP_TEST_CHECK(router.get_routable_node_count() == 0); // Node no longer takes NEW work

    // BUT: The in-flight TCP execution MUST CONTINUE unhindered to its legitimate completed terminal state!
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

    // 1. Open real UDP channel on ephemeral port
    udp_endpoint_channel udp_sender;
    LINEP_TEST_CHECK(udp_sender.open_and_bind(0, 500));
    std::uint16_t sender_port = udp_sender.get_bound_port();

    udp_endpoint_channel udp_receiver;
    LINEP_TEST_CHECK(udp_receiver.open_and_bind(0, 500));
    std::uint16_t receiver_port = udp_receiver.get_bound_port();

    // 2. Start mock runtime TCP data plane
    mock_runtime_config cfg{};
    cfg.model_id = "linep-dual-plane-model-v02";
    mock_runtime_server mock_server(cfg);
    LINEP_TEST_CHECK(mock_server.start(0));
    std::uint16_t tcp_port = mock_server.get_bound_port();
    LINEP_TEST_CHECK(tcp_port > 0);

    // 3. Send UDP heartbeat over real socket
    udp_control_datagram dgram{};
    dgram.node_id = 7777;
    dgram.runtime_id = 8888;
    dgram.endpoint_id = 1;
    dgram.control_epoch = 1;
    dgram.control_seq = 1;
    dgram.message_type = static_cast<std::uint8_t>(control_message_type::node_hello);
    dgram.availability = static_cast<std::uint8_t>(node_availability::available);
    dgram.health = static_cast<std::uint8_t>(node_health::healthy);
    dgram.load_pct = 5;
    dgram.tcp_port = tcp_port;
    dgram.set_trunk_ready(true);

    LINEP_TEST_CHECK(udp_sender.send_datagram("127.0.0.1", receiver_port, dgram));

    // 4. Receiver reads UDP datagram over real socket and feeds router
    udp_control_datagram recvd_dgram{};
    std::string src_ip;
    std::uint16_t src_port = 0;
    LINEP_TEST_CHECK(udp_receiver.recv_datagram(recvd_dgram, &src_ip, &src_port));
    LINEP_TEST_CHECK(recvd_dgram.node_id == 7777);
    LINEP_TEST_CHECK(recvd_dgram.tcp_port == tcp_port);

    control_plane_router router;
    LINEP_TEST_CHECK(router.ingest_datagram(recvd_dgram, 1000000));

    // 5. Router selects node and binds to persistent TCP data trunk
    node_endpoint_identity target_node{};
    std::uint16_t bound_tcp_port = 0;
    LINEP_TEST_CHECK(router.select_best_candidate(target_node, bound_tcp_port));
    LINEP_TEST_CHECK(target_node.node_id == 7777);
    LINEP_TEST_CHECK(bound_tcp_port == tcp_port);

    // 6. Execute streaming over the bound TCP connection
    auto conn = envelope_connection::connect("127.0.0.1", bound_tcp_port);
    LINEP_TEST_CHECK(conn != nullptr);

    stream_identity id{999, 9999, 0};
    request_envelope req{id, runtime_profile::chat, cfg.model_id, "Dual-plane test prompt"};
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
    std::cout << "ALL 10 V0.2 PHASE D UDP CONTROL PLANE TESTS PASSED 100%!" << std::endl;
    return 0;
}
