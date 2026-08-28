#pragma once

#include <cstdint>
#include "linep/v0_2/runtime_types.hpp"

namespace linep::v0_2 {

enum class lifecycle_state : std::uint8_t {
    received = 1,
    accepted = 2,
    started = 3,
    cancel_requested = 4,
    terminal = 5,
};

struct lifecycle_status {
    lifecycle_state state{lifecycle_state::received};
    terminal_outcome outcome{terminal_outcome::unknown};
    bool has_terminal_outcome{false};
};

// cancel_requested is intentionally non-terminal.
// Exactly one authoritative logical terminal outcome is allowed per execution attempt.

} // namespace linep::v0_2
