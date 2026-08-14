#include "../src/core/framing.hpp"
#include <linep/types.hpp>
#include <linep/messages.hpp>
#include <cassert>
#include <cstdio>

static void test_udp_invite_frame() {
    static_assert(sizeof(linep::UdpInviteFrame) == 14, "UdpInviteFrame must be 14 bytes");

    auto inv = linep::core::make_udp_invite(
        /*invite_seq*/   42u,
        /*worker_id*/    10u,
        /*slot_id*/       1u,
        /*lease_ttl_ms*/ 1200u,
        /*session_tok*/  0xABCD1234u);

    assert(inv.msg_type      == static_cast<uint8_t>(linep::MsgType::INVITE));
    assert(inv.invite_seq    == 42u);
    assert(inv.worker_id     == 10u);
    assert(inv.slot_id       == 1u);
    assert(inv.lease_ttl_ms  == 1200u);
    assert(inv.session_token == 0xABCD1234u);
    assert(linep::core::validate_udp_invite(inv));

    // Corrupted field test
    linep::UdpInviteFrame bad = inv;
    bad.lease_ttl_ms = 9999u;
    assert(!linep::core::validate_udp_invite(bad));
}

static void test_udp_invite_ack_frame() {
    static_assert(sizeof(linep::UdpInviteAckFrame) == 11, "UdpInviteAckFrame must be 11 bytes");

    auto ack = linep::core::make_udp_invite_ack(
        /*invite_seq*/   42u,
        /*worker_id*/    10u,
        /*slot_id*/       1u,
        /*accepted*/      1u,
        /*session_tok*/  0xABCD1234u);

    assert(ack.msg_type      == static_cast<uint8_t>(linep::MsgType::INVITE_ACK));
    assert(ack.invite_seq    == 42u);
    assert(ack.worker_id     == 10u);
    assert(ack.accepted      == 1u);
    assert(ack.session_token == 0xABCD1234u);
    assert(linep::core::validate_udp_invite_ack(ack));

    // Invalid accepted byte (> 1)
    linep::UdpInviteAckFrame bad = ack;
    bad.accepted = 2u;
    assert(!linep::core::validate_udp_invite_ack(bad));
}

static void test_udp_heartbeat_ack_frame() {
    static_assert(sizeof(linep::UdpHeartbeatAckFrame) == 10, "UdpHeartbeatAckFrame must be 10 bytes");

    auto hb_ack = linep::core::make_udp_heartbeat_ack(
        /*hb_seq*/     99u,
        /*worker_id*/  10u,
        /*slot_id*/     1u,
        /*sched_time*/ 1714745395u);

    assert(hb_ack.msg_type            == static_cast<uint8_t>(linep::MsgType::HEARTBEAT_ACK));
    assert(hb_ack.heartbeat_seq      == 99u);
    assert(hb_ack.worker_id          == 10u);
    assert(hb_ack.scheduler_time_sec == 1714745395u);
    assert(linep::core::validate_udp_heartbeat_ack(hb_ack));

    // Corrupted CRC test
    linep::UdpHeartbeatAckFrame bad = hb_ack;
    bad.scheduler_time_sec = 0u;
    assert(!linep::core::validate_udp_heartbeat_ack(bad));
}

static void test_heartbeat_fuzz_validation() {
    // Test all edge timestamp bounds in validate_heartbeat_compact
    auto f = linep::core::make_heartbeat_compact(1u, 0u, linep::SLOT_ALIVE, 50u, 0u, 1u,
                                                 100u, 12u, 31u, 23u, 59u, 59u);
    assert(linep::core::validate_heartbeat_compact(f));

    // Month 0 or >12
    linep::HeartbeatCompact bad = f;
    bad.ts_month = 0u;
    assert(!linep::core::validate_heartbeat_compact(bad));
    bad.ts_month = 13u;
    assert(!linep::core::validate_heartbeat_compact(bad));

    // Day 0 or >31
    bad = f;
    bad.ts_day = 0u;
    assert(!linep::core::validate_heartbeat_compact(bad));
    bad.ts_day = 32u;
    assert(!linep::core::validate_heartbeat_compact(bad));

    // Hour >23
    bad = f;
    bad.ts_hour = 24u;
    assert(!linep::core::validate_heartbeat_compact(bad));

    // Minute >59
    bad = f;
    bad.ts_minute = 60u;
    assert(!linep::core::validate_heartbeat_compact(bad));

    // Second >59
    bad = f;
    bad.ts_second = 60u;
    assert(!linep::core::validate_heartbeat_compact(bad));
}

int main() {
    test_udp_invite_frame();
    test_udp_invite_ack_frame();
    test_udp_heartbeat_ack_frame();
    test_heartbeat_fuzz_validation();
    std::puts("[PASS] test_udp_control_frames");
    return 0;
}
