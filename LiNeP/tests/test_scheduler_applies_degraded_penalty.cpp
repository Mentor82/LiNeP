// Test: degraded flag adds +50 to the blended score — a degraded slot is
//       strongly avoided even when its raw load is very low.
// With worker_score defaulting to 0 in this test setup:
//   Worker 1 / load 50 / not degraded => 0.65*50 = 32.5
//   Worker 2 / load  5 / degraded     => 0.65*5 + 50 = 53.25
// Expected: Worker 1 wins.
#include "sched_helper.hpp"
#include <cassert>
#include <cstdio>
#include <map>

int main() {
    using namespace linep::scheduler;
    const auto now = std::chrono::steady_clock::now();

    auto s1 = make_good_slot(1u, 0u, linep::TASK_INSTRUCT, 50u, 0u);

    auto s2 = make_good_slot(2u, 0u, linep::TASK_INSTRUCT,  5u, 0u);
    s2.degraded = true;   // +50

    // Verify the degraded penalty increases the score (lower is better).
    assert(score_slot(s2) > score_slot(s1));

    std::map<SlotKey, SlotState> slots;
    slots[{1, 0}] = s1;
    slots[{2, 0}] = s2;

    const auto best = select_best_slot(slots, linep::TASK_INSTRUCT, now);
    assert(best.has_value());
    assert(best->worker_id == 1u);

    std::puts("[PASS] test_scheduler_applies_degraded_penalty");
    return 0;
}
