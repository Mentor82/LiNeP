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

    // V0.2 Invariant rules:
    // 1. cancel_requested is intentionally NON-terminal.
    // 2. Once in terminal state, no further state transitions are permitted.
    // 3. Exactly one authoritative logical terminal outcome is allowed per execution attempt.
    bool can_transition_to(lifecycle_state next_state) const noexcept {
        if (state == lifecycle_state::terminal) {
            return false; // Terminal state is immutable
        }
        switch (state) {
            case lifecycle_state::received:
                return next_state == lifecycle_state::accepted ||
                       next_state == lifecycle_state::cancel_requested ||
                       next_state == lifecycle_state::terminal;
            case lifecycle_state::accepted:
                return next_state == lifecycle_state::started ||
                       next_state == lifecycle_state::cancel_requested ||
                       next_state == lifecycle_state::terminal;
            case lifecycle_state::started:
                return next_state == lifecycle_state::cancel_requested ||
                       next_state == lifecycle_state::terminal;
            case lifecycle_state::cancel_requested:
                return next_state == lifecycle_state::terminal; // cancel_requested -> terminal
            default:
                return false;
        }
    }

    bool transition_to(lifecycle_state next_state, terminal_outcome out = terminal_outcome::unknown) noexcept {
        if (!can_transition_to(next_state)) {
            return false;
        }
        if (next_state == lifecycle_state::terminal) {
            if (out == terminal_outcome::unknown) {
                return false; // Must provide a concrete terminal outcome (completed, cancelled, or failed)
            }
            state = lifecycle_state::terminal;
            outcome = out;
            has_terminal_outcome = true;
            return true;
        }
        state = next_state;
        return true;
    }
};

} // namespace linep::v0_2
