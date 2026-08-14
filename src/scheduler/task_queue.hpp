#pragma once
#include <linep/messages.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>
#include "slot_registry.hpp"

namespace linep::scheduler {

// Plain function pointer — keeps DLL boundary clean (no std::function).
using ResultCallback = void (*)(
    uint32_t              correlation_id,
    linep::ResultStatus   status,
    const uint8_t*        payload,
    uint32_t              payload_len,
    void*                 user_data);

struct PendingTask {
    uint32_t             correlation_id{0};
    linep::TaskType      type{linep::TASK_INSTRUCT};
    std::vector<uint8_t> payload;
    uint32_t             timeout_ms{5000u};
    uint32_t             max_attempts{3u};
    uint32_t             attempt_count{0u};
    ResultCallback       callback{nullptr};
    void*                user_data{nullptr};
};

struct ActiveTask {
    PendingTask                           task;
    SlotKey                               assigned_slot;
    std::chrono::steady_clock::time_point started_at{};
};

// Bounded lock-free MPSC queue (multiple producers, single consumer).
// Returns false on push when full so callers can apply backpressure handling.
template <typename T, uint32_t Capacity>
class BoundedMpscQueue {
    static_assert(Capacity > 0, "Capacity must be > 0");

public:
    BoundedMpscQueue() {
        for (uint32_t i = 0; i < Capacity; ++i)
            slots_[i].seq.store(i, std::memory_order_relaxed);
    }

    bool push(T item) noexcept {
        uint32_t pos = head_.load(std::memory_order_relaxed);
        for (;;) {
            Slot& s = slots_[pos % Capacity];
            const uint32_t seq = s.seq.load(std::memory_order_acquire);
            const int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(pos);

            if (diff == 0) {
                if (head_.compare_exchange_weak(pos, pos + 1u,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
                    s.value = std::move(item);
                    s.seq.store(pos + 1u, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                // Queue full.
                return false;
            } else {
                pos = head_.load(std::memory_order_relaxed);
            }
        }
    }

    std::optional<T> pop() noexcept {
        Slot& s = slots_[tail_ % Capacity];
        const uint32_t seq = s.seq.load(std::memory_order_acquire);
        if (seq != tail_ + 1u)
            return std::nullopt;

        T out = std::move(s.value);
        s.seq.store(tail_ + Capacity, std::memory_order_release);
        ++tail_;
        return out;
    }

private:
    struct Slot {
        std::atomic<uint32_t> seq{0};
        T                     value{};
    };

    alignas(64) std::array<Slot, Capacity> slots_{};
    alignas(64) std::atomic<uint32_t>      head_{0};
    alignas(64) uint32_t                   tail_{0}; // single consumer only
};

} // namespace linep::scheduler
