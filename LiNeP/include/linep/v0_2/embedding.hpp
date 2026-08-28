#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

constexpr std::uint32_t LINEP_V02_MAX_EMBEDDING_DIMENSIONS = 65536;

struct embedding_space_descriptor {
    std::string embedding_space_id;
    std::string model_id;
    std::string model_revision;
    std::uint32_t dimensions{};
    embedding_normalization normalization{embedding_normalization::none};
    embedding_distance_metric distance_metric{embedding_distance_metric::unspecified};

    bool operator==(const embedding_space_descriptor& other) const noexcept {
        return embedding_space_id == other.embedding_space_id &&
               model_id == other.model_id &&
               model_revision == other.model_revision &&
               dimensions == other.dimensions &&
               normalization == other.normalization &&
               distance_metric == other.distance_metric;
    }
};

// V0.2 Rule: Equal dimensions alone NEVER imply compatible vector spaces.
inline bool compatible_embedding_space(const embedding_space_descriptor& a,
                                       const embedding_space_descriptor& b) noexcept {
    return !a.embedding_space_id.empty() &&
           a.embedding_space_id == b.embedding_space_id &&
           a.dimensions == b.dimensions &&
           a.dimensions > 0;
}

struct embedding_result_payload {
    embedding_space_descriptor space;
    std::vector<float> vector;

    bool is_valid() const noexcept {
        return !space.embedding_space_id.empty() &&
               space.dimensions > 0 &&
               vector.size() == space.dimensions;
    }
};

} // namespace linep::v0_2
