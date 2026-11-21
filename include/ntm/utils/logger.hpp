#ifndef NTM_UTILS_LOGGER_HPP
#define NTM_UTILS_LOGGER_HPP

#include <mutex>
#include <ostream>
#include <string>
#include <string_view>

namespace ntm::utils {

using namespace std;

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    NONE = 4
};

class Logger {
public:
    static Logger& instance() noexcept;

    void set_level(LogLevel level) noexcept;
    [[nodiscard]] LogLevel level() const noexcept;

    void set_quiet(bool quiet) noexcept;
    [[nodiscard]] bool is_quiet() const noexcept;

    void log(LogLevel level, string_view component, string_view message);

    void debug(string_view component, string_view message);
    void info(string_view component, string_view message);
    void warn(string_view component, string_view message);
    void error(string_view component, string_view message);

    [[nodiscard]] static string_view level_to_string(LogLevel level) noexcept;

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    mutable mutex mutex_;
    LogLevel current_level_{LogLevel::INFO};
    bool quiet_{false};
};

} // namespace ntm::utils

#endif // NTM_UTILS_LOGGER_HPP
