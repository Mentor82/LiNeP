#pragma once
#include <linep/messages.hpp>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace linep::scheduler {

enum class ConsensusMode : uint8_t {
    POST_COMPLETION    = 0, // Evaluate complete responses after FINAL_FRAGMENT
    BOUNDED_CHECKPOINT = 1, // Evaluate stream chunks at semantic checkpoints (e.g. \n\n or JSON end)
};

struct ConsensusConfig {
    ConsensusMode mode{ConsensusMode::POST_COMPLETION};
    double        cos_threshold{0.85}; // Calibrated per Vector Space Contract (#5)
    uint32_t      min_replicas{2};
};

struct ConsensusResult {
    ConsensusLevel level{CONSENSUS_FAILED};
    std::string    winner_text;
    double         confidence{0.0};
    uint32_t       agreeing_count{0};
    uint32_t       total_responses{0};
};

// Computes dot product / cosine similarity between two float vectors
inline double compute_cosine_similarity(const float* vec_a,
                                        const float* vec_b,
                                        size_t dim) noexcept
{
    if (!vec_a || !vec_b || dim == 0) return 0.0;
    double dot = 0.0, norm_a = 0.0, norm_b = 0.0;
    for (size_t i = 0; i < dim; ++i) {
        dot    += static_cast<double>(vec_a[i]) * static_cast<double>(vec_b[i]);
        norm_a += static_cast<double>(vec_a[i]) * static_cast<double>(vec_a[i]);
        norm_b += static_cast<double>(vec_b[i]) * static_cast<double>(vec_b[i]);
    }
    if (norm_a <= 0.0 || norm_b <= 0.0) return 0.0;
    return dot / (std::sqrt(norm_a) * std::sqrt(norm_b));
}

// Evaluates post-completion consensus across N text responses
inline ConsensusResult evaluate_post_completion_consensus(
    const std::vector<std::string>& responses,
    const ConsensusConfig& config = {})
{
    ConsensusResult res{};
    res.total_responses = static_cast<uint32_t>(responses.size());
    if (responses.size() < config.min_replicas) {
        res.level = CONSENSUS_FAILED;
        return res;
    }

    // Exact string majority vote
    std::map<std::string, uint32_t> counts;
    for (const auto& r : responses) {
        counts[r]++;
    }

    uint32_t max_count = 0;
    std::string winner;
    for (const auto& [text, count] : counts) {
        if (count > max_count) {
            max_count = count;
            winner = text;
        }
    }

    res.winner_text    = winner;
    res.agreeing_count = max_count;
    res.confidence     = static_cast<double>(max_count) / static_cast<double>(responses.size());

    if (max_count == responses.size()) {
        res.level = CONSENSUS_STRONG;
    } else if (max_count >= (responses.size() * 2 + 2) / 3) {
        res.level = CONSENSUS_PARTIAL;
    } else {
        res.level = CONSENSUS_FAILED;
    }

    return res;
}

// Evaluates bounded streaming consensus at semantic checkpoints
inline bool is_semantic_checkpoint(const std::string& chunk) noexcept {
    return chunk.find("\n\n") != std::string::npos ||
           chunk.find("}\n") != std::string::npos ||
           chunk.find("</reasoning>") != std::string::npos;
}

} // namespace linep::scheduler
