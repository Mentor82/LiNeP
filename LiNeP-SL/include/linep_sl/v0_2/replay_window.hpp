#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace linep::sl::v0_2 {

enum class replay_status : std::uint8_t {
    accepted = 0,
    duplicate = 1,
    too_old = 2,
    invalid_seq = 3,
};

// 128-bit sliding bitmap replay window for out-of-order UDP control datagrams
class sliding_replay_window {
public:
    static constexpr std::size_t window_size = 128;

    constexpr sliding_replay_window() noexcept = default;

    replay_status check(std::uint64_t seq) const noexcept;
    replay_status update(std::uint64_t seq) noexcept;
    replay_status check_and_update(std::uint64_t seq) noexcept;

    std::uint64_t highest_seq() const noexcept { return max_seq_; }
    void reset() noexcept;

private:
    std::uint64_t max_seq_{0};
    std::array<std::uint64_t, 2> bitmap_{{0, 0}}; // 128 bits
};

// Monotonic stream sequence tracker for in-order TCP data streams
class monotonic_stream_tracker {
public:
    constexpr monotonic_stream_tracker() noexcept = default;

    bool check_and_advance(
        std::uint64_t event_seq,
        std::uint64_t fragment_seq,
        bool has_fragment_seq) noexcept;

    std::uint64_t last_event_seq() const noexcept { return last_event_seq_; }
    std::uint64_t last_fragment_seq() const noexcept { return last_fragment_seq_; }
    void reset() noexcept;

private:
    std::uint64_t last_event_seq_{0};
    std::uint64_t last_fragment_seq_{0};
    bool has_started_{false};
};

} // namespace linep::sl::v0_2
