#include <linep_sl/v0_2/replay_window.hpp>

#include <cassert>
#include <iostream>

using namespace linep::sl::v0_2;

void test_sliding_replay_window() {
    std::cout << "[Test 1] Sliding Replay Window (128-bit Bitmap)..." << std::endl;
    sliding_replay_window win;

    // Sequence 0 is invalid
    assert(win.check(0) == replay_status::invalid_seq);
    assert(win.update(0) == replay_status::invalid_seq);

    // Initial sequence
    assert(win.check(1) == replay_status::accepted);
    assert(win.update(1) == replay_status::accepted);
    assert(win.highest_seq() == 1);

    // Duplicate check and update
    assert(win.check(1) == replay_status::duplicate);
    assert(win.update(1) == replay_status::duplicate);

    // In-order forward progression
    assert(win.check_and_update(2) == replay_status::accepted);
    assert(win.check_and_update(3) == replay_status::accepted);
    assert(win.highest_seq() == 3);

    // Out-of-order jump forward within window: seq = 10
    assert(win.check_and_update(10) == replay_status::accepted);
    assert(win.highest_seq() == 10);

    // In-window out-of-order arrivals: 7, 8, 9
    assert(win.check_and_update(8) == replay_status::accepted);
    assert(win.check_and_update(7) == replay_status::accepted);
    assert(win.check_and_update(9) == replay_status::accepted);

    // Duplicate of out-of-order arrival
    assert(win.check_and_update(8) == replay_status::duplicate);
    assert(win.check_and_update(7) == replay_status::duplicate);

    // Jump across 64-bit word boundary (e.g. seq = 80 from max = 10)
    assert(win.check_and_update(80) == replay_status::accepted);
    assert(win.highest_seq() == 80);
    assert(win.check(10) == replay_status::duplicate);
    assert(win.check(75) == replay_status::accepted);
    assert(win.check_and_update(75) == replay_status::accepted);

    // Big jump > 128 (window slide wipes old entries)
    assert(win.check_and_update(300) == replay_status::accepted);
    assert(win.highest_seq() == 300);

    // Old sequence (80, 10) is now too old (< 300 - 128)
    assert(win.check(80) == replay_status::too_old);
    assert(win.check(10) == replay_status::too_old);
    assert(win.check(1) == replay_status::too_old);

    // Sequence within new window (e.g. 250: 300 - 250 = 50 < 128)
    assert(win.check_and_update(250) == replay_status::accepted);
    assert(win.check(250) == replay_status::duplicate);

    // Reset
    win.reset();
    assert(win.highest_seq() == 0);
    assert(win.check_and_update(5) == replay_status::accepted);

    std::cout << "  -> Sliding Replay Window Tests PASSED" << std::endl;
}

void test_monotonic_stream_tracker() {
    std::cout << "[Test 2] Monotonic Stream Tracker (TCP Data Plane Invariants)..." << std::endl;
    monotonic_stream_tracker tracker;

    // Sequence 0 is invalid
    assert(!tracker.check_and_advance(0, 0, false));

    // Initial event
    assert(tracker.check_and_advance(1, 0, false));
    assert(tracker.last_event_seq() == 1);

    // Duplicate event without fragmentation -> Rejected
    assert(!tracker.check_and_advance(1, 0, false));

    // Monotonic next event
    assert(tracker.check_and_advance(2, 0, false));
    assert(tracker.last_event_seq() == 2);

    // Fragmented event: event 3, frag 0, 1, 2
    assert(tracker.check_and_advance(3, 0, true));
    assert(tracker.check_and_advance(3, 1, true));
    assert(tracker.check_and_advance(3, 2, true));
    assert(tracker.last_event_seq() == 3);
    assert(tracker.last_fragment_seq() == 2);

    // Duplicate fragment -> Rejected
    assert(!tracker.check_and_advance(3, 2, true));
    // Fragment regression -> Rejected
    assert(!tracker.check_and_advance(3, 1, true));

    // Event sequence regression (event 2 after event 3) -> Rejected
    assert(!tracker.check_and_advance(2, 0, false));

    // Monotonic next event (event 4)
    assert(tracker.check_and_advance(4, 0, false));
    assert(tracker.last_event_seq() == 4);

    std::cout << "  -> Monotonic Stream Tracker Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Replay Protection Test Suite ===" << std::endl;
    test_sliding_replay_window();
    test_monotonic_stream_tracker();
    std::cout << "ALL REPLAY PROTECTION TESTS PASSED 100%!" << std::endl;
    return 0;
}
