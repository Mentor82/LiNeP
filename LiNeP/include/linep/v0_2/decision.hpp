#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace linep::v0_2 {

// DECISION Hard and Soft Framing Budgets
constexpr std::size_t LINEP_V02_MAX_DECISION_STRING_BYTES = 256;
constexpr std::size_t LINEP_V02_MAX_DECISION_MODELS       = 1024;
constexpr std::size_t LINEP_V02_DECISION_FRAME_CEILING    = 1044480; // 1 MiB - 4 KiB
constexpr std::size_t LINEP_V02_DECISION_BODY_BUDGET_SL1  = 1044393; // B_result
constexpr std::size_t LINEP_V02_DECISION_BODY_BUDGET_PLAIN= 1044417;

// DECISION Model Descriptor for Envelope 4 Capabilities (Positional Pfad A)
struct decision_model_descriptor {
    std::string model_id;
    std::string model_revision;
    std::string decision_type; // e.g. "choice,score,noul" or GGUF metadata string

    bool is_valid() const noexcept {
        return !model_id.empty() && model_id.size() <= LINEP_V02_MAX_DECISION_STRING_BYTES &&
               model_revision.size() <= LINEP_V02_MAX_DECISION_STRING_BYTES &&
               !decision_type.empty() && decision_type.size() <= LINEP_V02_MAX_DECISION_STRING_BYTES;
    }

    bool operator==(const decision_model_descriptor& other) const noexcept {
        return model_id == other.model_id &&
               model_revision == other.model_revision &&
               decision_type == other.decision_type;
    }
};

} // namespace linep::v0_2
