#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/embedding.hpp"

namespace linep::v0_2 {

enum class capability_state : std::uint8_t {
    unsupported = 0,
    supported = 1,
};

enum class availability_state : std::uint8_t {
    unknown = 0,
    unavailable = 1,
    available = 2,
    degraded = 3,
};

enum class authorization_state : std::uint8_t {
    unknown = 0,
    denied = 1,
    allowed = 2,
};

struct capability_status {
    capability_state capability{capability_state::unsupported};
    availability_state availability{availability_state::unknown};
    authorization_state authorization{authorization_state::unknown};

    // V0.2 rule: An operation is only operable if supported, currently available, and authorized.
    bool is_operable() const noexcept {
        return capability == capability_state::supported &&
               (availability == availability_state::available || availability == availability_state::degraded) &&
               authorization == authorization_state::allowed;
    }
};

struct runtime_capabilities_descriptor {
    std::vector<runtime_profile> supported_profiles;
    std::uint32_t max_context_tokens{0};
    std::uint32_t max_output_tokens{0};
    bool supports_streaming{true};
    bool supports_cancellation{true};
    bool supports_tool_calling{false};
    bool supports_reasoning_deltas{false};
    std::vector<std::string> supported_models;
    std::vector<embedding_space_descriptor> supported_embedding_spaces;

    bool supports_profile(runtime_profile profile) const noexcept {
        for (auto p : supported_profiles) {
            if (p == profile) return true;
        }
        return false;
    }
};

} // namespace linep::v0_2
