#pragma once
#include <linep/types.hpp>
#include <linep/messages.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <map>

namespace linep::scheduler {

// ── SlotKey — map key for the slot registry ──────────────────────────────────

struct SlotKey {
    uint16_t worker_id{0};
    uint8_t  slot_id{0};

    bool operator<(const SlotKey& o) const noexcept {
        if (worker_id != o.worker_id) return worker_id < o.worker_id;
        return slot_id < o.slot_id;
    }
    bool operator==(const SlotKey& o) const noexcept {
        return worker_id == o.worker_id && slot_id == o.slot_id;
    }
};

// ── ConnectionState — invite/ack handshake state ────────────────────────────
//
//   SEEN     — coworker has sent at least one valid heartbeat; no invite sent yet.
//   INVITED  — scheduler sent INVITE (0x05); awaiting INVITE_ACK (0x06).
//   ACTIVE   — INVITE_ACK received; slot is eligible for task dispatch.
enum class ConnectionState : uint8_t {
    SEEN    = 0,
    INVITED = 1,
    ACTIVE  = 2,
};

// ── SlotState — full runtime state of one inference slot ─────────────────────

struct SlotState {
    uint16_t        worker_id{0};
    uint8_t         slot_id{0};
    linep::TaskType type{linep::TASK_INSTRUCT};

    // Status flags (updated from HeartbeatCompact)
    bool alive{false};
    bool ready{false};
    bool busy{false};
    bool degraded{false};
    bool error{false};
    bool thermal_limit{false};
    bool model_loading{false};

    // Load metrics
    uint8_t  load{0};
    uint8_t  queue_depth{0};
    uint8_t  seq{0};
    uint16_t worker_score{0};

    // Performance history
    double   avg_latency_ms{0.0};
    uint32_t success_count{0};
    uint32_t error_count{0};
    uint32_t timeout_count{0};

    // Timing
    std::chrono::steady_clock::time_point last_heartbeat{};
    std::chrono::steady_clock::time_point last_used{};
    std::chrono::steady_clock::time_point cooldown_until{};

    // TCP endpoint for task dispatch
    char     ip[64]{};
    uint16_t tcp_port{0};

    // Control-plane handshake state (V0.1.0 §Invite/Ack)
    ConnectionState conn_state{ConnectionState::SEEN};
};

// ── Helpers ───────────────────────────────────────────────────────────────────

// Record that an INVITE (0x05) has been sent to this slot.
inline void on_invite_sent(SlotState& slot) noexcept
{
    if (slot.conn_state == ConnectionState::SEEN)
        slot.conn_state = ConnectionState::INVITED;
}

// Record that INVITE_ACK (0x06) was received from this slot.
inline void on_invite_ack(SlotState& slot) noexcept
{
    if (slot.conn_state == ConnectionState::INVITED)
        slot.conn_state = ConnectionState::ACTIVE;
}

// Apply a HeartbeatCompact to an existing SlotState.
inline void apply_heartbeat(SlotState& slot,
                             const linep::HeartbeatCompact& hb) noexcept
{
    slot.alive         = (hb.slot_flags & linep::SLOT_ALIVE)         != 0u;
    slot.ready         = (hb.slot_flags & linep::SLOT_READY)         != 0u;
    slot.busy          = (hb.slot_flags & linep::SLOT_BUSY)          != 0u;
    slot.degraded      = (hb.slot_flags & linep::SLOT_DEGRADED)      != 0u;
    slot.error         = (hb.slot_flags & linep::SLOT_ERROR)         != 0u;
    slot.thermal_limit = (hb.slot_flags & linep::SLOT_THERMAL_LIMIT) != 0u;
    slot.model_loading = (hb.slot_flags & linep::SLOT_MODEL_LOADING) != 0u;
    slot.load          = hb.load;
    slot.queue_depth   = hb.queue_depth;
    slot.seq           = hb.sequence;
    slot.worker_score  = hb.worker_score;
    slot.last_heartbeat = std::chrono::steady_clock::now();
}

// Mark a slot stale — used by expire_stale_slots().
// Resets conn_state to SEEN so the slot must re-handshake after recovery.
inline void expire_slot(SlotState& slot) noexcept
{
    slot.alive      = false;
    slot.ready      = false;
    slot.busy       = false;
    slot.load       = linep::LOAD_OFFLINE;
    slot.conn_state = ConnectionState::SEEN;
}

} // namespace linep::scheduler

