#pragma once

#include <cstdint>
#include <string>

namespace linep::v0_2 {

enum class embedding_normalization : std::uint8_t {
    none = 0,
    l2 = 1,
};

enum class embedding_distance_metric : std::uint8_t {
    unspecified = 0,
    cosine = 1,
    dot = 2,
    euclidean = 3,
};

struct embedding_space_descriptor {
    std::string embedding_space_id;
    std::string model_id;
    std::string model_revision;
    std::uint32_t dimensions{};
    embedding_normalization normalization{embedding_normalization::none};
    embedding_distance_metric distance_metric{embedding_distance_metric::unspecified};
};

// Equal dimensions alone never imply compatible vector spaces.
inline bool compatible_embedding_space(const embedding_space_descriptor& a,
                                       const embedding_space_descriptor& b) {
    return !a.embedding_space_id.empty() &&
           a.embedding_space_id == b.embedding_space_id;
}

} // namespace linep::v0_2
