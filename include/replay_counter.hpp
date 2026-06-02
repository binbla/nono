#ifndef REPLAY_COUNTER_HPP
#define REPLAY_COUNTER_HPP
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>

#include "types.hpp"

namespace wg {

class ReplayCounter {
   public:
    ReplayCounter() = default;

    ReplayCounter(const ReplayCounter&) = delete;
    ReplayCounter& operator=(const ReplayCounter&) = delete;

    // Returns true only once for each counter value that is still inside the
    // replay window. Call this after AEAD authentication succeeds.
    bool check(uint64_t counter) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!can_accept_unlocked(counter)) {
            return false;
        }

        if (!initialized_) {
            initialized_ = true;
            highest_ = counter;
            mark_unlocked(counter);
            return true;
        }

        if (counter > highest_) {
            clear_advanced_words_unlocked(highest_, counter);
            highest_ = counter;
        }

        mark_unlocked(counter);
        return true;
    }

    bool would_accept(uint64_t counter) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return can_accept_unlocked(counter);
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        bitmap_.fill(0);
        highest_ = 0;
        initialized_ = false;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return !initialized_;
    }

    uint64_t highest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return highest_;
    }

   private:
    static constexpr size_t word_bits = 64;
    static constexpr size_t bitmap_words = WINDOW_SIZE / word_bits;

    bool can_accept_unlocked(uint64_t counter) const {
        if (counter >= REJECT_AFTER_MESSAGES) {
            return false;
        }

        if (!initialized_) {
            return true;
        }

        if (counter > highest_) {
            return true;
        }

        const uint64_t backtrack = highest_ - counter;
        if (backtrack >= WINDOW_SIZE) {
            return false;
        }

        return !is_marked_unlocked(counter);
    }

    bool is_marked_unlocked(uint64_t counter) const {
        const size_t word = word_index(counter);
        const uint64_t mask = bit_mask(counter);
        return (bitmap_[word] & mask) != 0;
    }

    void mark_unlocked(uint64_t counter) {
        bitmap_[word_index(counter)] |= bit_mask(counter);
    }

    void clear_advanced_words_unlocked(uint64_t old_highest,
                                       uint64_t new_highest) {
        const uint64_t advance = new_highest - old_highest;
        if (advance >= WINDOW_SIZE) {
            bitmap_.fill(0);
            return;
        }

        const uint64_t old_word = old_highest / word_bits;
        const uint64_t new_word = new_highest / word_bits;
        for (uint64_t word = old_word + 1; word <= new_word; ++word) {
            bitmap_[word % bitmap_words] = 0;
        }
    }

    static constexpr size_t word_index(uint64_t counter) {
        return static_cast<size_t>((counter / word_bits) % bitmap_words);
    }

    static constexpr uint64_t bit_mask(uint64_t counter) {
        return uint64_t{1} << (counter % word_bits);
    }

    mutable std::mutex mutex_;
    std::array<uint64_t, bitmap_words> bitmap_{};
    uint64_t highest_ = 0;
    bool initialized_ = false;
};

}  // namespace wg

#endif  // REPLAY_COUNTER_HPP
