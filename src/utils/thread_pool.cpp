#include "ntm/utils/thread_pool.hpp"

#include <algorithm>

namespace ntm::utils {

using namespace std;

ThreadPool::ThreadPool(size_t num_threads, size_t max_queue_size)
    : max_queue_size_(max<size_t>(1, max_queue_size)) {
    const size_t clamped_threads = clamp(num_threads, kMinThreads, kMaxThreads);
    workers_.reserve(clamped_threads);

    for (size_t i = 0; i < clamped_threads; ++i) {
        workers_.emplace_back([this, i]() {
            this->worker_loop(i);
        });
    }
}

ThreadPool::~ThreadPool() noexcept {
    shutdown();
}

void ThreadPool::enqueue_task(function<void()> task) {
    {
        unique_lock<mutex> lock(queue_mutex_);
        if (stop_accepting_.load(memory_order_acquire)) {
            throw runtime_error("Cannot submit task to a stopped ThreadPool");
        }

        cv_space_available_.wait(lock, [this]() {
            return stop_accepting_.load(memory_order_relaxed) ||
                   tasks_.size() < max_queue_size_;
        });

        if (stop_accepting_.load(memory_order_acquire)) {
            throw runtime_error("Cannot submit task to a stopped ThreadPool");
        }

        tasks_.push(move(task));
    }
    cv_task_available_.notify_one();
}

void ThreadPool::worker_loop(size_t /*worker_id*/) {
    while (true) {
        function<void()> task;
        {
            unique_lock<mutex> lock(queue_mutex_);
            cv_task_available_.wait(lock, [this]() {
                return abort_immediately_.load(memory_order_relaxed) ||
                       stop_accepting_.load(memory_order_relaxed) ||
                       !tasks_.empty();
            });

            if (abort_immediately_.load(memory_order_acquire)) {
                return;
            }

            if (stop_accepting_.load(memory_order_acquire) && tasks_.empty()) {
                return;
            }

            task = move(tasks_.front());
            tasks_.pop();
        }
        cv_space_available_.notify_one();

        active_tasks_.fetch_add(1, memory_order_relaxed);
        try {
            task();
        } catch (...) {
            // packaged_task already captures exceptions into its future.
            // Catch block ensures worker thread never terminates unexpectedly.
        }
        active_tasks_.fetch_sub(1, memory_order_relaxed);
    }
}

void ThreadPool::shutdown() noexcept {
    bool expected = false;
    if (stop_accepting_.compare_exchange_strong(expected, true, memory_order_acq_rel)) {
        cv_task_available_.notify_all();
        cv_space_available_.notify_all();
    }

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            try {
                worker.join();
            } catch (...) {
            }
        }
    }
}

void ThreadPool::cancel_pending() noexcept {
    {
        lock_guard<mutex> lock(queue_mutex_);
        stop_accepting_.store(true, memory_order_release);
        abort_immediately_.store(true, memory_order_release);
        queue<function<void()>> empty;
        swap(tasks_, empty);
    }
    cv_task_available_.notify_all();
    cv_space_available_.notify_all();
    shutdown();
}

bool ThreadPool::is_stopped() const noexcept {
    return stop_accepting_.load(memory_order_acquire);
}

size_t ThreadPool::worker_count() const noexcept {
    return workers_.size();
}

size_t ThreadPool::pending_tasks() const noexcept {
    lock_guard<mutex> lock(queue_mutex_);
    return tasks_.size();
}

size_t ThreadPool::active_tasks() const noexcept {
    return active_tasks_.load(memory_order_relaxed);
}

} // namespace ntm::utils
