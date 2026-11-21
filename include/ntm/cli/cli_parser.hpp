#ifndef NTM_CLI_CLI_PARSER_HPP
#define NTM_CLI_CLI_PARSER_HPP

#include "ntm/discovery/discovery_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace ntm::cli {

using namespace std;
using namespace ntm::discovery;

enum class ExitCode : int {
    Success = 0,
    InvalidArguments = 1,
    InterfaceError = 2,
    ScopeViolation = 3,
    RuntimeError = 4
};

struct CliOptions {
    bool show_help{false};
    bool list_interfaces{false};
    bool auto_discover{false};
    bool verbose{false};
    bool dry_run{false};

    optional<string> interface_name;
    optional<string> target_cidr;
    optional<string> target_list;
    optional<string> custom_oui_file;
    optional<string> output_json_path;
    optional<string> output_dot_path;

    vector<DiscoveryMethod> methods{
        DiscoveryMethod::ARP,
        DiscoveryMethod::ICMP,
        DiscoveryMethod::TCP
    };
    vector<uint16_t> tcp_ports{22, 80, 443, 8080};

    size_t threads{8};
    uint32_t rate_rps{50};
    uint32_t timeout_ms{1500};
};

struct CliParseResult {
    bool ok{false};
    CliOptions options;
    string error_message;
};

class CliParser {
public:
    [[nodiscard]] static CliParseResult parse(int argc, const char* const* argv);
    [[nodiscard]] static CliParseResult parse(const vector<string>& args);

    static void print_help(ostream& out, string_view program_name = "ntm");
};

} // namespace ntm::cli

#endif // NTM_CLI_CLI_PARSER_HPP
