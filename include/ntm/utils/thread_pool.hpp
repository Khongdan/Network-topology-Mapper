#ifndef NTM_UTILS_THREAD_POOL_HPP
#define NTM_UTILS_THREAD_POOL_HPP

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace ntm::utils {

using namespace std;

class ThreadPool {
public:
    static constexpr size_t kMinThreads = 1;
    static constexpr size_t kMaxThreads = 128;
    static constexpr size_t kDefaultMaxQueueSize = 16384;

    explicit ThreadPool(size_t num_threads = 8,
                        size_t max_queue_size = kDefaultMaxQueueSize);
    ~ThreadPool() noexcept;

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    template <class F, class... Args>
    auto submit(F&& f, Args&&... args)
        -> future<invoke_result_t<F, Args...>> {
        using return_type = invoke_result_t<F, Args...>;

        auto bound_tuple = make_tuple(forward<F>(f), forward<Args>(args)...);
        auto task = make_shared<packaged_task<return_type()>>(
            [ tup = move(bound_tuple) ]() mutable -> return_type {
                return apply([](auto&& fn, auto&&... fn_args) -> return_type {
                    return invoke(forward<decltype(fn)>(fn),
                                  forward<decltype(fn_args)>(fn_args)...);
                }, move(tup));
            }
        );

        future<return_type> res = task->get_future();
        enqueue_task([task]() { (*task)(); });
        return res;
    }

    void shutdown() noexcept;
    void cancel_pending() noexcept;

    [[nodiscard]] bool is_stopped() const noexcept;
    [[nodiscard]] size_t worker_count() const noexcept;
    [[nodiscard]] size_t pending_tasks() const noexcept;
    [[nodiscard]] size_t active_tasks() const noexcept;

private:
    void enqueue_task(function<void()> task);
    void worker_loop(size_t worker_id);

    size_t max_queue_size_;
    mutable mutex queue_mutex_;
    condition_variable cv_task_available_;
    condition_variable cv_space_available_;
    queue<function<void()>> tasks_;

#if defined(__cpp_lib_jthread) && (__cpp_lib_jthread >= 201911L)
    vector<jthread> workers_;
#else
    vector<thread> workers_;
#endif

    atomic<bool> stop_accepting_{false};
    atomic<bool> abort_immediately_{false};
    atomic<size_t> active_tasks_{0};
};

} // namespace ntm::utils

#endif // NTM_UTILS_THREAD_POOL_HPP
