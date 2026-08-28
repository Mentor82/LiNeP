#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/session.hpp"
#include "linep/v0_2/envelopes.hpp"

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "TEST CHECK FAILED: " #cond " at " __FILE__ ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

using namespace linep::v0_2;

void test_concurrent_multiplexing() {
    std::cout << "[Test 1] Concurrent Logical Stream Multiplexing on One Persistent Session..." << std::endl;
    session_manager mgr;
    runtime_error err{};

    stream_identity id_a{101, 1001, 0};
    stream_identity id_b{102, 1002, 0};

    request_envelope req_a{};
    req_a.stream = id_a;
    req_a.profile = runtime_profile::chat;
    req_a.model_id = "llama-3.1-8b";
    req_a.payload = "Prompt A";

    request_envelope req_b{};
    req_b.stream = id_b;
    req_b.profile = runtime_profile::generate;
    req_b.model_id = "llama-3.1-8b";
    req_b.payload = "Prompt B";

    LINEP_TEST_CHECK(mgr.submit_request(req_a, err));
    LINEP_TEST_CHECK(mgr.submit_request(req_b, err));
    LINEP_TEST_CHECK(mgr.get_active_stream_count() == 2);

    // Interleaved dispatching: Stream A -> Stream B -> Stream A -> Stream B
    event_envelope evt_a1{};
    evt_a1.stream = id_a;
    evt_a1.event_seq = 1;
    evt_a1.event_type = runtime_event_type::content_delta;
    evt_a1.payload = "Chunk A1";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_a1, err));

    event_envelope evt_b1{};
    evt_b1.stream = id_b;
    evt_b1.event_seq = 1;
    evt_b1.event_type = runtime_event_type::content_delta;
    evt_b1.payload = "Chunk B1";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_b1, err));

    event_envelope evt_a2{};
    evt_a2.stream = id_a;
    evt_a2.event_seq = 2;
    evt_a2.event_type = runtime_event_type::content_delta;
    evt_a2.payload = "Chunk A2";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_a2, err));

    event_envelope evt_b_term{};
    evt_b_term.stream = id_b;
    evt_b_term.event_seq = 2;
    evt_b_term.event_type = runtime_event_type::completed;
    evt_b_term.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_b_term, err));

    event_envelope evt_a_term{};
    evt_a_term.stream = id_a;
    evt_a_term.event_seq = 3;
    evt_a_term.event_type = runtime_event_type::completed;
    evt_a_term.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_a_term, err));

    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_a));
    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_b));
    LINEP_TEST_CHECK(mgr.get_active_stream_count() == 0); // Both reached terminal state

    std::cout << "  -> Concurrent Multiplexing Tests PASSED" << std::endl;
}

void test_stream_isolation_on_failure() {
    std::cout << "[Test 2] Stream Isolation (Stream Failure does NOT contaminate other streams)..." << std::endl;
    session_manager mgr;
    runtime_error err{};

    stream_identity id_fail{201, 2001, 0};
    stream_identity id_ok{202, 2002, 0};

    request_envelope req_fail{id_fail, runtime_profile::chat, "llama-3.1-8b", "Prompt"};
    request_envelope req_ok{id_ok, runtime_profile::chat, "llama-3.1-8b", "Prompt"};

    LINEP_TEST_CHECK(mgr.submit_request(req_fail, err));
    LINEP_TEST_CHECK(mgr.submit_request(req_ok, err));

    // Stream 1 fails catastrophically with error event
    event_envelope evt_err{};
    evt_err.stream = id_fail;
    evt_err.event_seq = 1;
    evt_err.event_type = runtime_event_type::failed;
    evt_err.outcome = terminal_outcome::failed;
    evt_err.error.category = error_category::model_error;
    evt_err.error.code = 500;
    evt_err.error.message = "GPU Kernel Crash";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_err, err));

    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_fail));
    active_stream_state fail_state{};
    LINEP_TEST_CHECK(mgr.get_stream_state(id_fail, fail_state));
    LINEP_TEST_CHECK(fail_state.lifecycle.outcome == terminal_outcome::failed);

    // Stream 2 continues happily and completes
    event_envelope evt_ok1{};
    evt_ok1.stream = id_ok;
    evt_ok1.event_seq = 1;
    evt_ok1.event_type = runtime_event_type::content_delta;
    evt_ok1.payload = "Good output";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_ok1, err));

    event_envelope evt_ok_term{};
    evt_ok_term.stream = id_ok;
    evt_ok_term.event_seq = 2;
    evt_ok_term.event_type = runtime_event_type::completed;
    evt_ok_term.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(evt_ok_term, err));

    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_ok));
    active_stream_state ok_state{};
    LINEP_TEST_CHECK(mgr.get_stream_state(id_ok, ok_state));
    LINEP_TEST_CHECK(ok_state.lifecycle.outcome == terminal_outcome::completed);

    std::cout << "  -> Stream Isolation Tests PASSED" << std::endl;
}

void test_backpressure_inflight_limits() {
    std::cout << "[Test 3] In-Flight Stream Limits & Backpressure..." << std::endl;
    session_descriptor desc{};
    desc.limits.max_inflight_streams = 2; // Capacity of 2
    session_manager mgr(desc);
    runtime_error err{};

    stream_identity id_1{301, 3001, 0};
    stream_identity id_2{302, 3002, 0};
    stream_identity id_3{303, 3003, 0};

    request_envelope req_1{id_1, runtime_profile::chat, "llama-3.1-8b", "Prompt 1"};
    request_envelope req_2{id_2, runtime_profile::chat, "llama-3.1-8b", "Prompt 2"};
    request_envelope req_3{id_3, runtime_profile::chat, "llama-3.1-8b", "Prompt 3"};

    LINEP_TEST_CHECK(mgr.submit_request(req_1, err));
    LINEP_TEST_CHECK(mgr.submit_request(req_2, err));
    LINEP_TEST_CHECK(mgr.get_active_stream_count() == 2);

    // Third stream exceeds capacity -> must be rejected with resource_exhausted (503)
    LINEP_TEST_CHECK(!mgr.submit_request(req_3, err));
    LINEP_TEST_CHECK(err.category == error_category::resource_exhausted);
    LINEP_TEST_CHECK(err.code == 503);

    // Complete Stream 1 to free capacity
    event_envelope term_1{};
    term_1.stream = id_1;
    term_1.event_seq = 1;
    term_1.event_type = runtime_event_type::completed;
    term_1.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(term_1, err));
    LINEP_TEST_CHECK(mgr.get_active_stream_count() == 1);

    // Now Stream 3 can be submitted!
    LINEP_TEST_CHECK(mgr.submit_request(req_3, err));
    LINEP_TEST_CHECK(mgr.get_active_stream_count() == 2);

    std::cout << "  -> In-Flight Limits & Backpressure Tests PASSED" << std::endl;
}

void test_semantic_event_seq_monotonicity() {
    std::cout << "[Test 4] Semantic event_seq Monotonicity & event_seq == 0 / Replay Rejection..." << std::endl;
    session_manager mgr;
    runtime_error err{};

    stream_identity id{401, 4001, 0};
    request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Prompt"};
    LINEP_TEST_CHECK(mgr.submit_request(req, err));

    // event_seq == 0 -> REJECTED (422)
    event_envelope evt0{};
    evt0.stream = id;
    evt0.event_seq = 0;
    evt0.event_type = runtime_event_type::content_delta;
    evt0.payload = "Zero seq";
    LINEP_TEST_CHECK(!mgr.dispatch_event(evt0, err));

    event_envelope evt1{};
    evt1.stream = id;
    evt1.event_seq = 1;
    evt1.event_type = runtime_event_type::content_delta;
    evt1.payload = "Part 1";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt1, err));

    // Duplicate / Replayed event_seq 1 -> REJECTED (422)
    LINEP_TEST_CHECK(!mgr.dispatch_event(evt1, err));
    LINEP_TEST_CHECK(err.category == error_category::bad_request);
    LINEP_TEST_CHECK(err.code == 422);

    // Jump to event_seq 5 -> ACCEPTED
    event_envelope evt5{};
    evt5.stream = id;
    evt5.event_seq = 5;
    evt5.event_type = runtime_event_type::content_delta;
    evt5.payload = "Part 5";
    LINEP_TEST_CHECK(mgr.dispatch_event(evt5, err));

    // Out of order event_seq 3 (older than last accepted 5) -> REJECTED (422)
    event_envelope evt3{};
    evt3.stream = id;
    evt3.event_seq = 3;
    evt3.event_type = runtime_event_type::content_delta;
    evt3.payload = "Part 3";
    LINEP_TEST_CHECK(!mgr.dispatch_event(evt3, err));
    LINEP_TEST_CHECK(err.code == 422);

    std::cout << "  -> Semantic Sequencing Tests PASSED" << std::endl;
}

void test_targeted_cancellation() {
    std::cout << "[Test 5] Targeted Cancellation by Execution ID..." << std::endl;
    session_manager mgr;
    runtime_error err{};

    stream_identity id_1{501, 5001, 0};
    stream_identity id_2{502, 5002, 0};

    request_envelope req_1{id_1, runtime_profile::chat, "llama-3.1-8b", "Prompt 1"};
    request_envelope req_2{id_2, runtime_profile::chat, "llama-3.1-8b", "Prompt 2"};

    LINEP_TEST_CHECK(mgr.submit_request(req_1, err));
    LINEP_TEST_CHECK(mgr.submit_request(req_2, err));

    // Cancel ONLY execution_id 5001
    std::size_t cancelled_count = 0;
    LINEP_TEST_CHECK(mgr.cancel_execution(5001, "User Cancel", cancelled_count));
    LINEP_TEST_CHECK(cancelled_count == 1);

    active_stream_state s1{}, s2{};
    LINEP_TEST_CHECK(mgr.get_stream_state(id_1, s1));
    LINEP_TEST_CHECK(mgr.get_stream_state(id_2, s2));

    // Invariant: cancel_requested is NON-terminal!
    LINEP_TEST_CHECK(s1.lifecycle.state == lifecycle_state::cancel_requested);
    LINEP_TEST_CHECK(!s1.lifecycle.has_terminal_outcome);
    LINEP_TEST_CHECK(s2.lifecycle.state == lifecycle_state::accepted);

    // Terminal cancel event arrives for Stream 1
    event_envelope cancel_term{};
    cancel_term.stream = id_1;
    cancel_term.event_seq = 1;
    cancel_term.event_type = runtime_event_type::cancelled;
    cancel_term.outcome = terminal_outcome::cancelled;
    LINEP_TEST_CHECK(mgr.dispatch_event(cancel_term, err));

    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_1));
    LINEP_TEST_CHECK(mgr.get_stream_state(id_1, s1));
    LINEP_TEST_CHECK(s1.lifecycle.outcome == terminal_outcome::cancelled);

    // Stream 2 finishes normally with completed
    event_envelope s2_term{};
    s2_term.stream = id_2;
    s2_term.event_seq = 1;
    s2_term.event_type = runtime_event_type::completed;
    s2_term.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(s2_term, err));
    LINEP_TEST_CHECK(mgr.is_stream_terminal(id_2));

    std::cout << "  -> Targeted Cancellation Tests PASSED" << std::endl;
}

void test_bounded_buffer_protection() {
    std::cout << "[Test 6] Bounded Buffer Overload Protection..." << std::endl;
    session_descriptor desc{};
    desc.limits.max_buffered_bytes_per_stream = 100; // 100 bytes limit
    session_manager mgr(desc);
    runtime_error err{};

    stream_identity id{601, 6001, 0};
    request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Prompt"};
    LINEP_TEST_CHECK(mgr.submit_request(req, err));

    event_envelope evt1{};
    evt1.stream = id;
    evt1.event_seq = 1;
    evt1.event_type = runtime_event_type::content_delta;
    evt1.payload = std::string(60, 'A'); // 60 bytes
    LINEP_TEST_CHECK(mgr.dispatch_event(evt1, err));

    event_envelope evt2{};
    evt2.stream = id;
    evt2.event_seq = 2;
    evt2.event_type = runtime_event_type::content_delta;
    evt2.payload = std::string(50, 'B'); // 60 + 50 = 110 > 100 -> REJECTED (507)
    LINEP_TEST_CHECK(!mgr.dispatch_event(evt2, err));
    LINEP_TEST_CHECK(err.category == error_category::resource_exhausted);
    LINEP_TEST_CHECK(err.code == 507);

    std::cout << "  -> Bounded Buffer Protection Tests PASSED" << std::endl;
}

void test_single_authoritative_terminal_outcome() {
    std::cout << "[Test 7] Exactly One Authoritative Terminal Outcome per Execution..." << std::endl;
    session_manager mgr;
    runtime_error err{};

    stream_identity id{701, 7001, 0};
    request_envelope req{id, runtime_profile::chat, "llama-3.1-8b", "Prompt"};
    LINEP_TEST_CHECK(mgr.submit_request(req, err));

    event_envelope term{};
    term.stream = id;
    term.event_seq = 1;
    term.event_type = runtime_event_type::completed;
    term.outcome = terminal_outcome::completed;
    LINEP_TEST_CHECK(mgr.dispatch_event(term, err));
    LINEP_TEST_CHECK(mgr.is_stream_terminal(id));

    // Attempting to send ANY further event (even another terminal or delta) -> REJECTED (410)
    event_envelope post_term{};
    post_term.stream = id;
    post_term.event_seq = 2;
    post_term.event_type = runtime_event_type::content_delta;
    post_term.payload = "Late token";
    LINEP_TEST_CHECK(!mgr.dispatch_event(post_term, err));
    LINEP_TEST_CHECK(err.code == 410);

    event_envelope second_term{};
    second_term.stream = id;
    second_term.event_seq = 3;
    second_term.event_type = runtime_event_type::failed;
    second_term.outcome = terminal_outcome::failed;
    LINEP_TEST_CHECK(!mgr.dispatch_event(second_term, err));
    LINEP_TEST_CHECK(err.code == 410);

    std::cout << "  -> Single Terminal Outcome Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP V0.2 Persistent Session & Multiplexing Test Suite ===" << std::endl;
    test_concurrent_multiplexing();
    test_stream_isolation_on_failure();
    test_backpressure_inflight_limits();
    test_semantic_event_seq_monotonicity();
    test_targeted_cancellation();
    test_bounded_buffer_protection();
    test_single_authoritative_terminal_outcome();
    std::cout << "ALL V0.2 PHASE B SESSION MULTIPLEXING TESTS PASSED 100%!" << std::endl;
    return 0;
}
