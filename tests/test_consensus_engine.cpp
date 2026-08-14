#include "../src/scheduler/consensus_engine.hpp"
#include <cassert>
#include <cstdio>

static void test_post_completion_majority_vote() {
    using namespace linep::scheduler;

    std::vector<std::string> responses = {
        "Result Alpha",
        "Result Alpha",
        "Result Beta"
    };

    ConsensusConfig cfg{};
    cfg.mode = ConsensusMode::POST_COMPLETION;
    cfg.min_replicas = 2;

    auto result = evaluate_post_completion_consensus(responses, cfg);
    assert(result.level == linep::CONSENSUS_PARTIAL); // 2 out of 3 agree
    assert(result.winner_text == "Result Alpha");
    assert(result.agreeing_count == 2);
}

static void test_unanimous_consensus() {
    using namespace linep::scheduler;

    std::vector<std::string> responses = {
        "Exact Match Output",
        "Exact Match Output",
        "Exact Match Output"
    };

    auto result = evaluate_post_completion_consensus(responses);
    assert(result.level == linep::CONSENSUS_STRONG); // 3 out of 3 agree
    assert(result.confidence == 1.0);
}

static void test_cosine_similarity() {
    using namespace linep::scheduler;

    float vec_a[] = {1.0f, 0.0f, 0.0f};
    float vec_b[] = {1.0f, 0.0f, 0.0f};
    float vec_c[] = {0.0f, 1.0f, 0.0f};

    double sim_ab = compute_cosine_similarity(vec_a, vec_b, 3);
    double sim_ac = compute_cosine_similarity(vec_a, vec_c, 3);

    assert(sim_ab > 0.999);
    assert(sim_ac < 0.001);
}

static void test_semantic_checkpoint_detection() {
    using namespace linep::scheduler;

    assert(is_semantic_checkpoint("Paragraph finished.\n\n") == true);
    assert(is_semantic_checkpoint("Done reasoning </reasoning>") == true);
    assert(is_semantic_checkpoint("partial sentence...") == false);
}

int main() {
    test_post_completion_majority_vote();
    test_unanimous_consensus();
    test_cosine_similarity();
    test_semantic_checkpoint_detection();
    std::puts("[PASS] test_consensus_engine");
    return 0;
}
