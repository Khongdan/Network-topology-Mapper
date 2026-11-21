#include "ntm/utils/logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ntm::utils {

using namespace std;
using namespace chrono;

Logger& Logger::instance() noexcept {
    static Logger logger_instance;
    return logger_instance;
}

void Logger::set_level(LogLevel level) noexcept {
    lock_guard<mutex> lock(mutex_);
    current_level_ = level;
}

LogLevel Logger::level() const noexcept {
    lock_guard<mutex> lock(mutex_);
    return current_level_;
}

void Logger::set_quiet(bool quiet) noexcept {
    lock_guard<mutex> lock(mutex_);
    quiet_ = quiet;
}

bool Logger::is_quiet() const noexcept {
    lock_guard<mutex> lock(mutex_);
    return quiet_;
}

string_view Logger::level_to_string(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR:   return "ERROR";
        case LogLevel::NONE:    return "NONE";
    }
    return "INFO";
}

void Logger::log(LogLevel level, string_view component, string_view message) {
    lock_guard<mutex> lock(mutex_);
    if (quiet_ || level < current_level_ || current_level_ == LogLevel::NONE) {
        return;
    }

    const auto now = system_clock::now();
    const auto now_time_t = system_clock::to_time_t(now);
    const auto now_ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &now_time_t);
#else
    localtime_r(&now_time_t, &tm_buf);
#endif

    ostringstream oss;
    oss << '[' << put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << '.' << setfill('0') << setw(3) << now_ms.count() << "] "
        << '[' << left << setw(5) << setfill(' ') << level_to_string(level) << "] "
        << '[' << component << "] "
        << message << '\n';

    ostream& out = (level >= LogLevel::WARNING) ? cerr : cout;
    out << oss.str();
    out.flush();
}

void Logger::debug(string_view component, string_view message) {
    log(LogLevel::DEBUG, component, message);
}

void Logger::info(string_view component, string_view message) {
    log(LogLevel::INFO, component, message);
}

void Logger::warn(string_view component, string_view message) {
    log(LogLevel::WARNING, component, message);
}

void Logger::error(string_view component, string_view message) {
    log(LogLevel::ERROR, component, message);
}

} // namespace ntm::utils
