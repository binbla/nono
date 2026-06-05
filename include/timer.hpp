#ifndef TIMER_HPP
#define TIMER_HPP
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace wg {

class TimerManager {
    // TimerManager 只负责“什么时候执行什么回调”。
   public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;
    using TaskId = uint64_t;
    using Callback = std::function<void()>;

    static constexpr TaskId invalid_task_id = 0;

    TaskId schedule_after(Duration delay, Callback callback,
                          std::string name = {}) {
        return add_task(delay, Duration{}, false, std::move(callback),
                        std::move(name));
    }

    TaskId schedule_every(Duration interval, Callback callback,
                          std::string name = {}, bool run_immediately = false) {
        if (interval <= Duration{}) {
            return invalid_task_id;
        }

        const Duration first_delay = run_immediately ? Duration{} : interval;
        return add_task(first_delay, interval, true, std::move(callback),
                        std::move(name));
    }

    bool cancel(TaskId id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it =
            std::find_if(tasks_.begin(), tasks_.end(),
                         [id](const TimerTask& task) { return task.id == id; });
        if (it == tasks_.end()) {
            return false;
        }

        tasks_.erase(it);
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        tasks_.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tasks_.size();
    }

    bool empty() const { return size() == 0; }

    void poll() {
        std::vector<Callback> due_callbacks;
        const TimePoint now = Clock::now();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (TimerTask& task : tasks_) {
                if (now < task.next_run) {
                    continue;
                }

                due_callbacks.push_back(task.callback);
                if (task.repeating) {
                    task.next_run = now + task.interval;
                } else {
                    task.cancelled = true;
                }
            }

            tasks_.erase(std::remove_if(tasks_.begin(), tasks_.end(),
                                        [](const TimerTask& task) {
                                            return task.cancelled;
                                        }),
                         tasks_.end());
        }

        for (Callback& callback : due_callbacks) {
            if (callback) {
                callback();
            }
        }
    }

    Duration time_until_next(Duration fallback) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tasks_.empty()) {
            return fallback;
        }

        const TimePoint now = Clock::now();
        TimePoint next = tasks_.front().next_run;
        for (const TimerTask& task : tasks_) {
            if (task.next_run < next) {
                next = task.next_run;
            }
        }

        if (next <= now) {
            return Duration{};
        }
        return next - now;
    }

   private:
    struct TimerTask {
        TaskId id = invalid_task_id;
        std::string name;
        TimePoint next_run{};
        Duration interval{};
        bool repeating = false;
        bool cancelled = false;
        Callback callback;
    };

    TaskId add_task(Duration first_delay, Duration interval, bool repeating,
                    Callback callback, std::string name) {
        if (!callback || first_delay < Duration{}) {
            return invalid_task_id;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        const TaskId id = next_id_++;
        tasks_.push_back(TimerTask{
            .id = id,
            .name = std::move(name),
            .next_run = Clock::now() + first_delay,
            .interval = interval,
            .repeating = repeating,
            .cancelled = false,
            .callback = std::move(callback),
        });
        return id;
    }

    mutable std::mutex mutex_;
    TaskId next_id_ = 1;
    std::vector<TimerTask> tasks_;
};

}  // namespace wg

#endif  // TIMER_HPP
