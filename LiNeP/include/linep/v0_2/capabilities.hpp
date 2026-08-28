#pragma once

#include <cstdint>

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
};

// V0.2 rule: capability, current availability, and authorization are separate facts.

} // namespace linep::v0_2
