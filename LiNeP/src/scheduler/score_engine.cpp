#include "score_engine.hpp"
#include <algorithm>
#include <limits>
#include <set>

namespace linep::scheduler {

bool is_eligible(const SlotState& slot,
                 std::chrono::steady_clock::time_point now) noexcept
{
    // Only ACTIVE slots have completed the invite/ack handshake.
    if (slot.conn_state != ConnectionState::ACTIVE) return false;
    if (!slot.alive)        return false;
    if (!slot.ready)        return false;
    if (slot.error)         return false;
    if (slot.model_loading) return false;
    if (slot.thermal_limit) return false;
    if (slot.load >= 90u)   return false;
    if (slot.queue_depth >= 8u) return false;
    // Slot that has never sent a heartbeat is not eligible.
    if (slot.last_heartbeat == std::chrono::steady_clock::time_point{}) return false;
    if (now > slot.last_heartbeat + HEARTBEAT_TIMEOUT) return false;
    if (now < slot.cooldown_until) return false;
    return true;
}

double score_slot(const SlotState& slot) noexcept
{
    const double norm_load  = std::min(1.0, static_cast<double>(slot.load) / 100.0);
    const double norm_queue = std::min(1.0, static_cast<double>(slot.queue_depth) / 8.0);

    const double vram_base = (slot.vram_free_mb > 0u) ? static_cast<double>(slot.vram_free_mb) : 8192.0;
    const double vram_pressure = 1.0 - std::min(1.0, vram_base / 16384.0);

    const double norm_prefix = std::min(1.0, static_cast<double>(slot.prefix_affinity) / 100.0);
    const double norm_tps    = std::min(1.0, static_cast<double>(slot.tokens_per_sec) / 100.0);

    constexpr double w_load  = 1.0;
    constexpr double w_queue = 2.0;
    constexpr double w_vram  = 1.5;
    constexpr double w_cache = 3.0;
    constexpr double w_tps   = 0.5;

    double s = (w_load * norm_load) +
               (w_queue * norm_queue) +
               (w_vram * vram_pressure) -
               (w_cache * norm_prefix) -
               (w_tps * norm_tps);

    const double norm_worker_score = std::min(1.0, static_cast<double>(slot.worker_score) / 100.0);
    s = 0.35 * norm_worker_score + 0.65 * s;

    s += (slot.avg_latency_ms / 1000.0) * 0.5;
    if (slot.busy)          s += 2.0;
    if (slot.degraded)      s += 5.0;
    if (slot.thermal_limit) s += 10.0;
    s += slot.timeout_count * 1.5;
    s += slot.error_count   * 2.5;

    return s;
}

bool is_better_tie(const SlotState& a, const SlotState& b) noexcept
{
    if (a.queue_depth != b.queue_depth)
        return a.queue_depth < b.queue_depth;
    if (a.avg_latency_ms != b.avg_latency_ms)
        return a.avg_latency_ms < b.avg_latency_ms;
    // Least-recently-used wins (promotes fairness).
    return a.last_used < b.last_used;
}

std::chrono::seconds cooldown_for(uint32_t failures) noexcept
{
    using namespace std::chrono_literals;
    if (failures <= 1u) return  5s;
    if (failures == 2u) return 30s;
    return 120s;
}

std::optional<SlotKey> select_best_slot(
    const std::map<SlotKey, SlotState>& slots,
    linep::TaskType                      task_type,
    std::chrono::steady_clock::time_point now) noexcept
{
    const auto picks = select_best_slots(slots, task_type, now, 1);
    if (picks.empty()) return std::nullopt;
    return picks.front();
}

std::vector<SlotKey> select_best_slots(
    const std::map<SlotKey, SlotState>& slots,
    linep::TaskType                      task_type,
    std::chrono::steady_clock::time_point now,
    int                                  k) noexcept
{
    if (k <= 0) return {};

    struct Candidate {
        SlotKey key;
        const SlotState* slot;
        double score;
    };

    std::vector<Candidate> candidates;
    candidates.reserve(slots.size());

    for (const auto& [key, slot] : slots) {
        if (slot.type != task_type)  continue;
        if (!is_eligible(slot, now)) continue;

        candidates.push_back(Candidate{key, &slot, score_slot(slot)});
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  if (a.score != b.score) return a.score < b.score;
                  return is_better_tie(*a.slot, *b.slot);
              });

    std::vector<SlotKey> result;
    result.reserve(static_cast<size_t>(k));
    std::set<uint16_t> used_workers;
    for (const auto& c : candidates) {
        if (used_workers.find(c.key.worker_id) != used_workers.end())
            continue;
        result.push_back(c.key);
        used_workers.insert(c.key.worker_id);
        if (static_cast<int>(result.size()) >= k)
            break;
    }
    return result;
}

} // namespace linep::scheduler
