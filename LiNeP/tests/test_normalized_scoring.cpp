#include "../src/scheduler/score_engine.hpp"
#include "../src/scheduler/slot_registry.hpp"
#include <cassert>
#include <cstdio>

static void test_vram_and_prefix_affinity_scoring() {
    using namespace linep::scheduler;

    SlotState slot_high_affinity{};
    slot_high_affinity.worker_id = 1;
    slot_high_affinity.slot_id = 0;
    slot_high_affinity.load = 20;
    slot_high_affinity.queue_depth = 1;
    slot_high_affinity.vram_free_mb = 16384; // 16 GB free
    slot_high_affinity.prefix_affinity = 90; // 90% KV-cache hit
    slot_high_affinity.tokens_per_sec = 60;

    SlotState slot_low_affinity{};
    slot_low_affinity.worker_id = 2;
    slot_low_affinity.slot_id = 0;
    slot_low_affinity.load = 20;
    slot_low_affinity.queue_depth = 1;
    slot_low_affinity.vram_free_mb = 2048;  // 2 GB free (high VRAM pressure)
    slot_low_affinity.prefix_affinity = 0;   // 0% KV-cache hit
    slot_low_affinity.tokens_per_sec = 20;

    const double score_high = score_slot(slot_high_affinity);
    const double score_low  = score_slot(slot_low_affinity);

    // Lower score is better!
    assert(score_high < score_low);
}

int main() {
    test_vram_and_prefix_affinity_scoring();
    std::puts("[PASS] test_normalized_scoring");
    return 0;
}
