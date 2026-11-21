#include "ntm/cli/cli_parser.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace ntm::cli {

using namespace std;
using namespace ntm::discovery;

namespace {

string to_lower_copy(string_view sv) {
    string out;
    out.reserve(sv.size());
    for (char c : sv) {
        out.push_back(static_cast<char>(tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

optional<uint64_t> parse_uint64(string_view sv) noexcept {
    if (sv.empty()) {
        return nullopt;
    }
    uint64_t val = 0;
    for (char c : sv) {
        if (c < '0' || c > '9') {
            return nullopt;
        }
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (val > (UINT64_MAX - digit) / 10ULL) {
            return nullopt;
        }
        val = val * 10ULL + digit;
    }
    return val;
}

optional<vector<DiscoveryMethod>> parse_methods_csv(string_view csv) {
    if (csv.empty()) {
        return nullopt;
    }
    vector<DiscoveryMethod> methods;
    size_t start = 0;

    while (start <= csv.size()) {
        const size_t comma = csv.find(',', start);
        const string token = to_lower_copy(
            (comma == string_view::npos) ? csv.substr(start) : csv.substr(start, comma - start));

        DiscoveryMethod m;
        if (token == "arp") {
            m = DiscoveryMethod::ARP;
        } else if (token == "icmp") {
            m = DiscoveryMethod::ICMP;
        } else if (token == "tcp") {
            m = DiscoveryMethod::TCP;
        } else {
            return nullopt;
        }

        if (find(methods.begin(), methods.end(), m) == methods.end()) {
            methods.push_back(m);
        }

        if (comma == string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    if (methods.empty()) {
        return nullopt;
    }
    return methods;
}

optional<vector<uint16_t>> parse_ports_csv(string_view csv) {
    if (csv.empty()) {
        return nullopt;
    }
    vector<uint16_t> ports;
    size_t start = 0;

    while (start <= csv.size()) {
        const size_t comma = csv.find(',', start);
        const string_view token =
            (comma == string_view::npos) ? csv.substr(start) : csv.substr(start, comma - start);

        const auto p_opt = parse_uint64(token);
        if (!p_opt.has_value() || *p_opt == 0 || *p_opt > 65535ULL) {
            return nullopt;
        }

        const auto port = static_cast<uint16_t>(*p_opt);
        if (find(ports.begin(), ports.end(), port) == ports.end()) {
            ports.push_back(port);
        }

        if (comma == string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    if (ports.empty() || ports.size() > 32) {
        return nullopt;
    }
    return ports;
}

} // namespace

CliParseResult CliParser::parse(int argc, const char* const* argv) {
    vector<string> args;
    if (argc > 1 && argv != nullptr) {
        args.reserve(static_cast<size_t>(argc - 1));
        for (int i = 1; i < argc; ++i) {
            if (argv[i] != nullptr) {
                args.emplace_back(argv[i]);
            }
        }
    }
    return parse(args);
}

CliParseResult CliParser::parse(const vector<string>& args) {
    CliParseResult result;
    if (args.empty()) {
        result.ok = true;
        result.options.show_help = true;
        return result;
    }

    for (size_t i = 0; i < args.size(); ++i) {
        const string& arg = args[i];

        auto require_value = [&](const char* flag_name) -> optional<string> {
            if (i + 1 >= args.size() || args[i + 1].empty()) {
                result.error_message = string("Missing value for option ") + flag_name;
                return nullopt;
            }
            ++i;
            return args[i];
        };

        if (arg == "--help" || arg == "-h") {
            result.options.show_help = true;
        } else if (arg == "--interfaces") {
            result.options.list_interfaces = true;
        } else if (arg == "--auto") {
            result.options.auto_discover = true;
        } else if (arg == "--verbose" || arg == "-v") {
            result.options.verbose = true;
        } else if (arg == "--dry-run") {
            result.options.dry_run = true;
        } else if (arg == "--interface" || arg == "-i") {
            auto val = require_value("--interface");
            if (!val.has_value()) return result;
            result.options.interface_name = *val;
        } else if (arg == "--target") {
            auto val = require_value("--target");
            if (!val.has_value()) return result;
            result.options.target_cidr = *val;
        } else if (arg == "--targets") {
            auto val = require_value("--targets");
            if (!val.has_value()) return result;
            result.options.target_list = *val;
        } else if (arg == "--methods") {
            auto val = require_value("--methods");
            if (!val.has_value()) return result;
            auto parsed = parse_methods_csv(*val);
            if (!parsed.has_value()) {
                result.error_message =
                    "Invalid --methods value '" + *val + "'. Expected comma-separated subset of: arp,icmp,tcp";
                return result;
            }
            result.options.methods = move(*parsed);
        } else if (arg == "--ports") {
            auto val = require_value("--ports");
            if (!val.has_value()) return result;
            auto parsed = parse_ports_csv(*val);
            if (!parsed.has_value()) {
                result.error_message =
                    "Invalid --ports value '" + *val +
                    "'. Expected 1..32 comma-separated TCP ports in range 1..65535.";
                return result;
            }
            result.options.tcp_ports = move(*parsed);
        } else if (arg == "--threads") {
            auto val = require_value("--threads");
            if (!val.has_value()) return result;
            auto num = parse_uint64(*val);
            if (!num.has_value() || *num < 1 || *num > 128) {
                result.error_message =
                    "Invalid --threads value '" + *val + "'. Allowed range: 1..128.";
                return result;
            }
            result.options.threads = static_cast<size_t>(*num);
        } else if (arg == "--rate") {
            auto val = require_value("--rate");
            if (!val.has_value()) return result;
            auto num = parse_uint64(*val);
            if (!num.has_value() || *num < 1 || *num > 5000) {
                result.error_message =
                    "Invalid --rate value '" + *val + "'. Allowed range: 1..5000 requests/sec.";
                return result;
            }
            result.options.rate_rps = static_cast<uint32_t>(*num);
        } else if (arg == "--timeout") {
            auto val = require_value("--timeout");
            if (!val.has_value()) return result;
            auto num = parse_uint64(*val);
            if (!num.has_value() || *num < 50 || *num > 30000) {
                result.error_message =
                    "Invalid --timeout value '" + *val + "'. Allowed range: 50..30000 ms.";
                return result;
            }
            result.options.timeout_ms = static_cast<uint32_t>(*num);
        } else if (arg == "--oui-file") {
            auto val = require_value("--oui-file");
            if (!val.has_value()) return result;
            result.options.custom_oui_file = *val;
        } else if (arg == "--output-json") {
            auto val = require_value("--output-json");
            if (!val.has_value()) return result;
            result.options.output_json_path = *val;
        } else if (arg == "--output-dot") {
            auto val = require_value("--output-dot");
            if (!val.has_value()) return result;
            result.options.output_dot_path = *val;
        } else {
            result.error_message = "Unknown option: '" + arg + "'. Run 'ntm --help' for usage.";
            return result;
        }
    }

    if (result.options.target_cidr.has_value() && result.options.target_list.has_value()) {
        result.error_message =
            "Options --target (CIDR) and --targets (IP list) are mutually exclusive.";
        return result;
    }

    result.ok = true;
    return result;
}

void CliParser::print_help(ostream& out, string_view program_name) {
    out << "Network Topology Mapper (NTM) v1.0.0\n"
        << "LAN Host Discovery & Evidence-Based Topology Inference CLI\n\n"
        << "USAGE:\n"
        << "  " << program_name << " [OPTIONS]\n\n"
        << "OPTIONS:\n"
        << "  -h, --help                 Show this help message and exit\n"
        << "  --interfaces               List detected local network interfaces and exit\n"
        << "  -i, --interface <name>     Specify network interface to use (e.g., eth0, ens33)\n"
        << "  --auto                     Auto-detect active LAN interface and scan its subnet\n"
        << "  --target <CIDR>            Scan a specific CIDR block within authorized scope\n"
        << "                             (e.g., 192.168.2.0/24)\n"
        << "  --targets <IP1,IP2,...>    Scan a comma-separated list of IPv4 addresses\n"
        << "                             (e.g., 192.168.2.1,192.168.2.10)\n"
        << "  --methods <m1,m2,...>      Discovery methods to use (default: arp,icmp,tcp)\n"
        << "  --ports <p1,p2,...>        TCP probe ports (default: 22,80,443,8080; max 32 ports)\n"
        << "  --threads <N>              Worker thread count (default: 8, range: 1..128)\n"
        << "  --rate <RPS>               Max probe requests per second (default: 50, range: 1..5000)\n"
        << "  --timeout <ms>             Per-probe timeout in milliseconds (default: 1500)\n"
        << "  --oui-file <path>          Path to custom local IEEE OUI CSV database\n"
        << "  --output-json <file.json>  Export full scan & topology result to JSON\n"
        << "  --output-dot <file.dot>    Export topology graph to Graphviz DOT format\n"
        << "  -v, --verbose              Enable detailed DEBUG logging\n"
        << "  --dry-run                  Validate interface, scope, and targets without sending packets\n\n"
        << "EXAMPLES:\n"
        << "  " << program_name << " --interfaces\n"
        << "  " << program_name << " --interface eth0 --auto --output-json result.json --output-dot topology.dot\n"
        << "  " << program_name << " --interface eth0 --target 192.168.2.0/24 --methods arp,icmp,tcp\n"
        << "  " << program_name << " --interface eth0 --targets 192.168.2.1,192.168.2.10 --dry-run\n";
}

} // namespace ntm::cli
