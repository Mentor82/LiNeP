#include <linep_sl/v0_2/replay_window.hpp>

namespace linep::sl::v0_2 {

replay_status sliding_replay_window::check(std::uint64_t seq) const noexcept {
    if (seq == 0) {
        return replay_status::invalid_seq;
    }

    if (max_seq_ == 0) {
        return replay_status::accepted;
    }

    if (seq > max_seq_) {
        return replay_status::accepted;
    }

    const std::uint64_t diff = max_seq_ - seq;
    if (diff >= window_size) {
        return replay_status::too_old;
    }

    const std::size_t word_idx = diff / 64;
    const std::size_t bit_idx = diff % 64;
    if ((bitmap_[word_idx] & (1ULL << bit_idx)) != 0) {
        return replay_status::duplicate;
    }

    return replay_status::accepted;
}

replay_status sliding_replay_window::update(std::uint64_t seq) noexcept {
    if (seq == 0) {
        return replay_status::invalid_seq;
    }

    if (max_seq_ == 0) {
        max_seq_ = seq;
        bitmap_[0] = 1ULL;
        bitmap_[1] = 0;
        return replay_status::accepted;
    }

    if (seq > max_seq_) {
        const std::uint64_t diff = seq - max_seq_;
        if (diff >= window_size) {
            bitmap_[0] = 1ULL;
            bitmap_[1] = 0;
        } else if (diff >= 64) {
            bitmap_[1] = (bitmap_[0] << (diff - 64));
            bitmap_[0] = 1ULL;
        } else {
            bitmap_[1] = (bitmap_[1] << diff) | (bitmap_[0] >> (64 - diff));
            bitmap_[0] = (bitmap_[0] << diff) | 1ULL;
        }
        max_seq_ = seq;
        return replay_status::accepted;
    }

    const std::uint64_t diff = max_seq_ - seq;
    if (diff >= window_size) {
        return replay_status::too_old;
    }

    const std::size_t word_idx = diff / 64;
    const std::size_t bit_idx = diff % 64;
    if ((bitmap_[word_idx] & (1ULL << bit_idx)) != 0) {
        return replay_status::duplicate;
    }

    bitmap_[word_idx] |= (1ULL << bit_idx);
    return replay_status::accepted;
}

replay_status sliding_replay_window::check_and_update(std::uint64_t seq) noexcept {
    const auto status = check(seq);
    if (status != replay_status::accepted) {
        return status;
    }
    return update(seq);
}

void sliding_replay_window::reset() noexcept {
    max_seq_ = 0;
    bitmap_[0] = 0;
    bitmap_[1] = 0;
}

bool monotonic_stream_tracker::check_and_advance(
    std::uint64_t event_seq,
    std::uint64_t fragment_seq,
    bool has_fragment_seq) noexcept {
    if (event_seq == 0) {
        return false;
    }

    if (!has_started_) {
        if (has_fragment_seq && fragment_seq != 0) {
            return false;
        }
        last_event_seq_ = event_seq;
        last_fragment_seq_ = fragment_seq;
        has_started_ = true;
        return true;
    }

    if (event_seq > last_event_seq_) {
        if (has_fragment_seq && fragment_seq != 0) {
            return false;
        }
        last_event_seq_ = event_seq;
        last_fragment_seq_ = fragment_seq;
        return true;
    }

    if (event_seq == last_event_seq_) {
        if (!has_fragment_seq) {
            return false;
        }
        if (fragment_seq <= last_fragment_seq_) {
            return false;
        }
        last_fragment_seq_ = fragment_seq;
        return true;
    }

    return false; // event_seq < last_event_seq_ (regression)
}

void monotonic_stream_tracker::reset() noexcept {
    last_event_seq_ = 0;
    last_fragment_seq_ = 0;
    has_started_ = false;
}

} // namespace linep::sl::v0_2
