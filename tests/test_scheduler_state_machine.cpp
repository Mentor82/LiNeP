// Integration test: scheduler slot connection state machine SEEN -> INVITED -> ACTIVE
//
// Protocol V0.1.0 §Invite/Ack: a coworker that has sent heartbeats (SEEN) is
// not eligible for task dispatch until the scheduler sends INVITE (0x05) and
// receives INVITE_ACK (0x06), transitioning the slot to ACTIVE.
//
// All transitions are exercised here in-memory without network I/O.

#include "../src/scheduler/slot_registry.hpp"
#include "../src/scheduler/score_engine.hpp"
#include <linep/messages.hpp>
#include <cassert>
#include <chrono>
#include <cstdio>

using namespace linep::scheduler;

// Build a HeartbeatCompact that marks the slot alive+ready.
static linep::HeartbeatCompact make_hb(uint16_t wid, uint8_t sid)
{
    linep::HeartbeatCompact hb{};
    hb.worker_id  = wid;
    hb.slot_id    = sid;
    hb.slot_flags = static_cast<uint8_t>(linep::SLOT_ALIVE | linep::SLOT_READY);
    hb.load       = 10u;
    hb.queue_depth = 0u;
    return hb;
}

int main()
{
    const auto now = std::chrono::steady_clock::now();

    // ── 1. Fresh slot starts in SEEN after first heartbeat ────────────────────
    SlotState slot{};
    slot.worker_id = 1u;
    slot.slot_id   = 0u;
    // conn_state defaults to SEEN via default constructor
    assert(slot.conn_state == ConnectionState::SEEN);

    apply_heartbeat(slot, make_hb(1u, 0u));
    assert(slot.alive && slot.ready);
    assert(slot.conn_state == ConnectionState::SEEN);  // handshake not started

    // SEEN slot must NOT be eligible for dispatch.
    assert(!is_eligible(slot, now));

    // ── 2. After scheduler sends INVITE: transitions to INVITED ───────────────
    on_invite_sent(slot);
    assert(slot.conn_state == ConnectionState::INVITED);

    // INVITED slot still must NOT be eligible (ack not yet received).
    assert(!is_eligible(slot, now));

    // ── 3. After receiving INVITE_ACK: transitions to ACTIVE ─────────────────
    on_invite_ack(slot);
    assert(slot.conn_state == ConnectionState::ACTIVE);

    // ACTIVE slot IS eligible (alive, ready, not stale, not in cooldown).
    assert(is_eligible(slot, now));

    // ── 4. Idempotency: extra calls do not regress state ──────────────────────
    on_invite_sent(slot);   // already ACTIVE — no change
    assert(slot.conn_state == ConnectionState::ACTIVE);

    on_invite_ack(slot);    // already ACTIVE — no change
    assert(slot.conn_state == ConnectionState::ACTIVE);

    // ── 5. Slot expiry resets to SEEN and becomes ineligible ─────────────────
    expire_slot(slot);
    assert(slot.conn_state == ConnectionState::SEEN);
    assert(!slot.alive);
    assert(!is_eligible(slot, now));

    // ── 6. on_invite_sent must not skip SEEN (call from wrong state is no-op) ─
    SlotState s2{};
    s2.worker_id = 2u;
    // Start at INVITED directly (simulated race/bug).
    s2.conn_state = ConnectionState::INVITED;
    on_invite_ack(s2);
    assert(s2.conn_state == ConnectionState::ACTIVE);

    // on_invite_sent when already INVITED does not double-advance.
    s2.conn_state = ConnectionState::INVITED;
    on_invite_sent(s2);     // already INVITED — should remain INVITED
    assert(s2.conn_state == ConnectionState::INVITED);

    puts("[PASS] scheduler state machine SEEN -> INVITED -> ACTIVE");
    return 0;
}
