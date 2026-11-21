#ifndef NTM_UTILS_RATE_LIMITER_HPP
#define NTM_UTILS_RATE_LIMITER_HPP

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace ntm::utils {

using namespace std;
using namespace chrono;

struct RateLimitConfig {
    uint32_t max_requests_per_sec{50};
    size_t max_concurrent_probes{16};
    uint32_t timeout_ms{1500};
    uint32_t retry_count{1};
    uint32_t batch_delay_ms{20};
};

class RateLimiter {
public:
    class ScopedProbePermit {
    public:
        explicit ScopedProbePermit(RateLimiter& limiter);
        ~ScopedProbePermit() noexcept;

        ScopedProbePermit(const ScopedProbePermit&) = delete;
        ScopedProbePermit& operator=(const ScopedProbePermit&) = delete;
        ScopedProbePermit(ScopedProbePermit&& other) noexcept;
        ScopedProbePermit& operator=(ScopedProbePermit&&) = delete;

    private:
        RateLimiter* limiter_{nullptr};
    };

    explicit RateLimiter(const RateLimitConfig& config = RateLimitConfig{});

    void acquire_token();
    [[nodiscard]] ScopedProbePermit acquire_permit();

    [[nodiscard]] const RateLimitConfig& config() const noexcept;
    [[nodiscard]] size_t active_probes() const noexcept;

private:
    void enter_concurrency_slot();
    void leave_concurrency_slot() noexcept;

    RateLimitConfig config_;
    nanoseconds min_interval_;

    mutable mutex rate_mutex_;
    steady_clock::time_point next_allowed_time_;

    mutable mutex concurrency_mutex_;
    condition_variable concurrency_cv_;
    size_t active_probes_{0};
};

} // namespace ntm::utils

#endif // NTM_UTILS_RATE_LIMITER_HPP
