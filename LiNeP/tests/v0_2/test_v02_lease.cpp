#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>

#include "linep/v0_2/conformance.hpp"
#include "linep/v0_2/control_plane.hpp"
#include "linep/v0_2/lease.hpp"
#include "linep/v0_2/mock_runtime.hpp"

#define LINEP_TEST_CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAILED: " #expr " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while(0)

using namespace linep::v0_2;

namespace {

udp_control_datagram node_dgram(control_message_type type, std::uint64_t epoch, std::uint64_t seq) {
    udp_control_datagram d{};
    d.message_type = static_cast<std::uint8_t>(type);
    d.node_id = 42;
    d.runtime_id = 43;
    d.endpoint_id = 1;
    d.control_epoch = epoch;
    d.control_seq = seq;
    d.availability = static_cast<std::uint8_t>(node_availability::available);
    d.health = static_cast<std::uint8_t>(node_health::healthy);
    d.tcp_port = 11435;
    d.set_trunk_ready(true);
    return d;
}

// Read a stream up to its terminal event
bool run_request(envelope_connection& conn, const stream_identity& id, event_envelope& out_terminal) {
    request_envelope req{id, runtime_profile::chat, "linep-lease-test", "lease test"};
    if (!conn.send_request(req)) {
        return false;
    }
    std::vector<std::uint8_t> raw;
    while (conn.receive_envelope_raw(raw)) {
        event_envelope evt{};
        if (!decode_event(raw.data(), raw.size(), evt)) {
            return false;
        }
        if (evt.stream == id && evt.is_terminal()) {
            out_terminal = evt;
            return true;
        }
    }
    return false;
}

} // anonymous namespace

int main() {
    std::cout << "=== LiNeP V0.2 Lease Client / Issuer Tests ===" << std::endl;

    // 1. reissue_invite: same lease while INVITED, nothing once ACTIVE or for another epoch
    {
        control_plane_router router;
        node_endpoint_identity id{42, 43, 1};
        LINEP_TEST_CHECK(router.ingest_datagram(node_dgram(control_message_type::node_hello, 5, 1), 1000));

        udp_control_datagram inv{};
        LINEP_TEST_CHECK(!router.reissue_invite(id, 5, inv)); // SEEN: nothing offered yet
        LINEP_TEST_CHECK(router.issue_invite(id, 0xABCDULL, inv));

        udp_control_datagram again{};
        LINEP_TEST_CHECK(router.reissue_invite(id, 5, again));
        LINEP_TEST_CHECK(again.lease_token == 0xABCDULL);
        LINEP_TEST_CHECK(again.control_epoch == 5);
        LINEP_TEST_CHECK(again.control_seq > inv.control_seq);
        LINEP_TEST_CHECK(!router.reissue_invite(id, 4, again)); // other incarnation

        auto ack = node_dgram(control_message_type::lease_ack, 5, 2);
        ack.lease_token = 0xABCDULL;
        LINEP_TEST_CHECK(router.ingest_datagram(ack, 2000));
        LINEP_TEST_CHECK(!router.reissue_invite(id, 5, again)); // ACTIVE: no INVITE
        std::cout << "[PASS] reissue_invite" << std::endl;
    }

    // Lease-enforcing mock runtime with its lease issuer
    lease_issuer issuer;
    LINEP_TEST_CHECK(issuer.start(0));
    std::uint16_t udp_port = issuer.get_bound_port();
    LINEP_TEST_CHECK(udp_port > 0);

    mock_runtime_config cfg{};
    cfg.model_id = "linep-conformance-model-v02";
    cfg.delay_per_event_ms = 1;
    cfg.default_tokens = 6;
    cfg.require_lease = true;
    mock_runtime_server server(cfg);
    server.set_control_plane_router(&issuer.router());
    LINEP_TEST_CHECK(server.start(0));
    std::uint16_t tcp_port = server.get_bound_port();

    lease_client_config lcfg{};
    lcfg.control_host = "127.0.0.1";
    lcfg.control_port = udp_port;
    lcfg.trunk_port = tcp_port;

    // 2. Handshake, bind, serve; renew -> stale_binding -> in-band re-bind
    {
        lease_client lease(lcfg);
        LINEP_TEST_CHECK(!lease.has_lease());
        auto unbound = envelope_connection::connect("127.0.0.1", tcp_port);
        LINEP_TEST_CHECK(unbound && !lease.bind(*unbound)); // no lease yet

        std::string err;
        LINEP_TEST_CHECK(lease.acquire(&err));
        LINEP_TEST_CHECK(lease.is_active());
        LINEP_TEST_CHECK(lease.identity().is_valid());
        LINEP_TEST_CHECK(issuer.router().validate_tcp_session_binding(
            lease.current_bind().identity, lease.current_bind().control_epoch, lease.current_bind().lease_token));

        auto conn = connect_bound("127.0.0.1", tcp_port, lease);
        LINEP_TEST_CHECK(conn != nullptr);
        event_envelope term{};
        LINEP_TEST_CHECK(run_request(*conn, stream_identity{1, 1, 0}, term));
        LINEP_TEST_CHECK(term.outcome == terminal_outcome::completed);

        session_bind_envelope old_bind = lease.current_bind();
        LINEP_TEST_CHECK(lease.renew(&err));
        LINEP_TEST_CHECK(lease.control_epoch() > old_bind.control_epoch);
        LINEP_TEST_CHECK(lease.current_bind().lease_token != old_bind.lease_token);

        LINEP_TEST_CHECK(run_request(*conn, stream_identity{2, 2, 0}, term));
        LINEP_TEST_CHECK(is_stale_binding_event(term));
        LINEP_TEST_CHECK(lease.bind(*conn));
        LINEP_TEST_CHECK(run_request(*conn, stream_identity{3, 3, 0}, term));
        LINEP_TEST_CHECK(term.outcome == terminal_outcome::completed);

        LINEP_TEST_CHECK(lease.send_heartbeat());
        lease.start_keepalive(10);
        lease.stop_keepalive();
        std::cout << "[PASS] acquire / bind / renew / re-bind" << std::endl;
    }

    // 3. Lost LEASE_ACK: an INVITED identity gets the same lease again and completes the handshake
    {
        lease_client lease(lcfg);
        std::string err;
        LINEP_TEST_CHECK(lease.request_invite(&err));
        LINEP_TEST_CHECK(lease.has_lease());
        LINEP_TEST_CHECK(!lease.is_active());
        std::uint64_t offered = lease.current_bind().lease_token;

        // A bind before LEASE_ACK is rejected
        auto early = envelope_connection::connect("127.0.0.1", tcp_port);
        LINEP_TEST_CHECK(early && lease.bind(*early));
        std::vector<std::uint8_t> raw;
        LINEP_TEST_CHECK(early->receive_envelope_raw(raw));
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw.data(), raw.size(), evt));
        LINEP_TEST_CHECK(evt.stream.is_connection_level() && evt.error.message == "lease_invalid");

        LINEP_TEST_CHECK(lease.acquire(&err)); // same epoch, still INVITED -> re-sent INVITE
        LINEP_TEST_CHECK(lease.current_bind().lease_token == offered);
        LINEP_TEST_CHECK(lease.is_active());
        std::cout << "[PASS] lost LEASE_ACK recovery" << std::endl;
    }

    // 4. Conformance with a control endpoint: 9 suites bound + dual-plane suites
    {
        conformance_runner runner("127.0.0.1", tcp_port);
        runner.set_control_endpoint("127.0.0.1", udp_port);
        auto rep = runner.run_all();
        for (const auto& r : rep.results) {
            std::cout << "  [" << (r.passed ? "PASS" : "FAIL") << "] " << r.test_name << " -> " << r.details << std::endl;
        }
        LINEP_TEST_CHECK(rep.is_all_passed());
        LINEP_TEST_CHECK(rep.total_tests == 15);
        LINEP_TEST_CHECK(rep.profiles.size() == 4);
        for (const auto& p : rep.profiles) {
            LINEP_TEST_CHECK(p.conformant);
        }

        auto dual = runner.run_dual_plane();
        LINEP_TEST_CHECK(dual.is_all_passed() && dual.total_tests == 6);
        std::cout << "[PASS] conformance with SESSION_BIND (15/15)" << std::endl;
    }

    // 5. No issuer: acquire fails with an error instead of blocking
    {
        lease_client_config dead = lcfg;
        dead.control_port = 1;
        dead.retransmit_ms = 20;
        dead.max_attempts = 2;
        lease_client lease(dead);
        std::string err;
        LINEP_TEST_CHECK(!lease.acquire(&err));
        LINEP_TEST_CHECK(!err.empty());
        LINEP_TEST_CHECK(!lease.has_lease());

        lease_client_config no_trunk = lcfg;
        no_trunk.trunk_port = 0;
        lease_client lease2(no_trunk);
        LINEP_TEST_CHECK(!lease2.acquire(&err));
        std::cout << "[PASS] acquire failure paths" << std::endl;
    }

    server.stop();
    issuer.stop();
    std::cout << "\nALL LEASE TESTS PASSED" << std::endl;
    return 0;
}
