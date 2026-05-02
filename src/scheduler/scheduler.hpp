#pragma once
#include <linep/export.h>
#include <linep/types.hpp>
#include <linep/messages.hpp>
#include "slot_registry.hpp"
#include "task_queue.hpp"

namespace linep::scheduler {

// ── Embedding callback — injected by the orchestrator ────────────────────────
// text     : null-terminated UTF-8 result text to embed
// out_vec  : caller-allocated float buffer, at least out_dims floats
// out_dims : in: capacity; out: actual dimensions written (0 = failure)
// user_data: opaque pointer passed through unchanged
using EmbedFn = void(*)(const char* text,
                         float*       out_vec,
                         uint32_t*    out_dims,
                         void*        user_data);

// ── IScheduler — pure virtual, DLL-clean ─────────────────────────────────────
// No STL types at the ABI boundary. All std::* stays inside SchedulerImpl.

class LINEP_API IScheduler {
public:
    virtual ~IScheduler() = default;

    // Register a worker slot's TCP endpoint.
    // Called before or independently from heartbeats; sets ip/port for dispatch.
    virtual void register_slot(uint16_t worker_id, uint8_t slot_id,
                                linep::TaskType type,
                                const char* ip, uint16_t tcp_port) = 0;

    // Feed an incoming HeartbeatCompact (from UDP listener callback).
    // Thread-safe — may be called from any thread.
    virtual void apply_heartbeat(const linep::HeartbeatCompact& hb) = 0;

    // Submit a task for async dispatch.
    // callback is invoked (from the scheduler's dispatch thread) when done.
    // Returns the correlation_id assigned to this task.
    virtual uint32_t submit(linep::TaskType  type,
                             const uint8_t*  payload,
                             uint32_t        len,
                             uint32_t        timeout_ms,
                             uint32_t        max_attempts,
                             ResultCallback  callback,
                             void*           user_data) = 0;

    virtual bool start() = 0;
    virtual void stop()  = 0;

    // Optional: inject embedding provider for consensus scoring.
    // If not set, consensus falls back to first-success strategy.
    virtual void set_embedding_fn(EmbedFn fn, void* user_data) = 0;
};

LINEP_API IScheduler* create_scheduler();
LINEP_API void         destroy_scheduler(IScheduler* p);

} // namespace linep::scheduler
