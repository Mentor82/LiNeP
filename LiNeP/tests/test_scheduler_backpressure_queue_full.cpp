// Test: pending queue applies backpressure when full.
// We intentionally do not start the scheduler loop, so queued tasks are not drained.
#include "../src/scheduler/scheduler.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

struct CallbackState {
    std::atomic<uint32_t> callback_count{0};
    std::atomic<uint32_t> rejected_count{0};
};

void on_result(uint32_t,
               linep::ResultStatus status,
               const uint8_t*,
               uint32_t,
               void* user_data)
{
    auto* s = static_cast<CallbackState*>(user_data);
    s->callback_count.fetch_add(1u);
    if (status == linep::RESULT_REJECTED)
        s->rejected_count.fetch_add(1u);
}

} // namespace

int main()
{
    linep::scheduler::IScheduler* scheduler = linep::scheduler::create_scheduler();
    assert(scheduler != nullptr);

    CallbackState state;
    const std::vector<uint8_t> payload = {'p', 'i', 'n', 'g'};

    // SchedulerImpl queue capacity is 256 (bounded MPSC queue).
    const uint32_t queue_capacity = 256u;
    const uint32_t submit_count = queue_capacity + 32u;

    for (uint32_t i = 0; i < submit_count; ++i) {
        const uint32_t corr = scheduler->submit(
            linep::TASK_INSTRUCT,
            payload.data(),
            static_cast<uint32_t>(payload.size()),
            5000u,
            1u,
            &on_result,
            &state);
        assert(corr != 0u);
    }

    // First queue_capacity submits are buffered. Overflow is immediately rejected.
    const uint32_t expected_rejected = submit_count - queue_capacity;
    assert(state.callback_count.load() == expected_rejected);
    assert(state.rejected_count.load() == expected_rejected);

    linep::scheduler::destroy_scheduler(scheduler);

    std::puts("[PASS] test_scheduler_backpressure_queue_full");
    return 0;
}
