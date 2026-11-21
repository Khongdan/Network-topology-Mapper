#include "ntm/utils/rate_limiter.hpp"

#include <algorithm>
#include <thread>

namespace ntm::utils {

using namespace std;
using namespace chrono;

RateLimiter::ScopedProbePermit::ScopedProbePermit(RateLimiter& limiter)
    : limiter_(&limiter) {
    limiter_->enter_concurrency_slot();
    limiter_->acquire_token();
}

RateLimiter::ScopedProbePermit::~ScopedProbePermit() noexcept {
    if (limiter_ != nullptr) {
        limiter_->leave_concurrency_slot();
    }
}

RateLimiter::ScopedProbePermit::ScopedProbePermit(ScopedProbePermit&& other) noexcept
    : limiter_(other.limiter_) {
    other.limiter_ = nullptr;
}

RateLimiter::RateLimiter(const RateLimitConfig& config)
    : config_(config) {
    config_.max_requests_per_sec = clamp<uint32_t>(config_.max_requests_per_sec, 1U, 5000U);
    config_.max_concurrent_probes = clamp<size_t>(config_.max_concurrent_probes, 1U, 256U);
    config_.timeout_ms = clamp<uint32_t>(config_.timeout_ms, 50U, 30000U);
    config_.retry_count = min<uint32_t>(config_.retry_count, 3U);

    min_interval_ = nanoseconds(1'000'000'000ULL / config_.max_requests_per_sec);
    next_allowed_time_ = steady_clock::now();
}

void RateLimiter::acquire_token() {
    steady_clock::time_point wait_until;
    {
        lock_guard<mutex> lock(rate_mutex_);
        const auto now = steady_clock::now();
        if (now >= next_allowed_time_) {
            wait_until = now;
            next_allowed_time_ = now + min_interval_;
        } else {
            wait_until = next_allowed_time_;
            next_allowed_time_ += min_interval_;
        }
    }

    const auto now = steady_clock::now();
    if (wait_until > now) {
        this_thread::sleep_until(wait_until);
    }
}

RateLimiter::ScopedProbePermit RateLimiter::acquire_permit() {
    return ScopedProbePermit(*this);
}

void RateLimiter::enter_concurrency_slot() {
    unique_lock<mutex> lock(concurrency_mutex_);
    concurrency_cv_.wait(lock, [this]() {
        return active_probes_ < config_.max_concurrent_probes;
    });
    ++active_probes_;
}

void RateLimiter::leave_concurrency_slot() noexcept {
    {
        lock_guard<mutex> lock(concurrency_mutex_);
        if (active_probes_ > 0) {
            --active_probes_;
        }
    }
    concurrency_cv_.notify_one();
}

const RateLimitConfig& RateLimiter::config() const noexcept {
    return config_;
}

size_t RateLimiter::active_probes() const noexcept {
    lock_guard<mutex> lock(concurrency_mutex_);
    return active_probes_;
}

} // namespace ntm::utils
