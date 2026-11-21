#include "ntm/cli/cli_parser.hpp"
#include "ntm/discovery/discovery_engine.hpp"
#include "ntm/discovery/oui_lookup.hpp"
#include "ntm/export/exporter.hpp"
#include "ntm/net/interface_discovery.hpp"
#include "ntm/net/ip_address.hpp"
#include "ntm/net/scope_validator.hpp"
#include "ntm/topology/topology_inference.hpp"
#include "ntm/utils/logger.hpp"

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#endif

using namespace std;
using namespace ntm::utils;
using namespace ntm::net;
using namespace ntm::discovery;
using namespace ntm::topology;
using namespace ntm::export_out;
using namespace ntm::cli;

namespace {

#if defined(_WIN32)
class ScopedWinsock {
public:
    ScopedWinsock() noexcept {
        WSADATA wsa_data{};
        initialized_ = (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0);
    }
    ~ScopedWinsock() noexcept {
        if (initialized_) {
            WSACleanup();
        }
    }
    ScopedWinsock(const ScopedWinsock&) = delete;
    ScopedWinsock& operator=(const ScopedWinsock&) = delete;

private:
    bool initialized_{false};
};
#endif

optional<NetworkInterface> select_network_interface(
    const vector<NetworkInterface>& all_interfaces,
    const CliOptions& opts) {
    if (opts.interface_name.has_value()) {
        auto found = InterfaceDiscovery::find_by_name(all_interfaces, *opts.interface_name);
        if (!found.has_value()) {
            Logger::instance().error(
                "Main", "Specified interface '" + *opts.interface_name + "' was not found.");
            TerminalRenderer::render_interfaces_table(all_interfaces, cerr);
            return nullopt;
        }
        if (!found->is_usable_lan_candidate()) {
            Logger::instance().error(
                "Main",
                "Interface '" + found->name +
                "' is either DOWN, loopback, or lacks a valid LAN IPv4 configuration.");
            return nullopt;
        }
        return found;
    }

    const auto candidates = InterfaceDiscovery::filter_lan_candidates(all_interfaces);
    if (candidates.empty()) {
        Logger::instance().error(
            "Main", "No usable active non-loopback IPv4 LAN interfaces found.");
        TerminalRenderer::render_interfaces_table(all_interfaces, cerr);
        return nullopt;
    }

    if (candidates.size() == 1) {
        return candidates.front();
    }

    if (opts.auto_discover) {
        vector<NetworkInterface> primary_physical;
        for (const auto& c : candidates) {
            if (c.type == InterfaceType::Physical && c.default_gateway.has_value()) {
                primary_physical.push_back(c);
            }
        }
        if (primary_physical.size() == 1) {
            Logger::instance().info(
                "Main",
                "Auto-selected primary physical interface '" + primary_physical.front().name +
                "' with default gateway " + primary_physical.front().default_gateway->to_string());
            return primary_physical.front();
        }
    }

    TerminalRenderer::render_interfaces_table(candidates, cout);
    cout << "Multiple active network interfaces detected.\n"
         << "Please select an interface by number (1.." << candidates.size()
         << "), or re-run with '--interface <name>': ";
    cout.flush();

    string input_line;
    if (!getline(cin, input_line) || input_line.empty()) {
        Logger::instance().error(
            "Main", "No interface selected. Use 'ntm --interface <name>' to specify one explicitly.");
        return nullopt;
    }

    try {
        const size_t choice = stoul(input_line);
        if (choice >= 1 && choice <= candidates.size()) {
            return candidates[choice - 1];
        }
    } catch (...) {
    }

    Logger::instance().error("Main", "Invalid interface selection.");
    return nullopt;
}

} // namespace

int main(int argc, char* argv[]) {
#if defined(_WIN32)
    ScopedWinsock winsock_guard;
#endif

    const auto parse_res = CliParser::parse(argc, argv);
    if (!parse_res.ok) {
        cerr << "[ERROR] " << parse_res.error_message << "\n\n";
        CliParser::print_help(cerr);
        return static_cast<int>(ExitCode::InvalidArguments);
    }

    const auto& opts = parse_res.options;
    if (opts.show_help) {
        CliParser::print_help(cout);
        return static_cast<int>(ExitCode::Success);
    }

    Logger::instance().set_level(opts.verbose ? LogLevel::DEBUG : LogLevel::INFO);

    const auto all_interfaces = InterfaceDiscovery::discover_interfaces();
    if (opts.list_interfaces) {
        TerminalRenderer::render_interfaces_table(all_interfaces, cout);
        return static_cast<int>(ExitCode::Success);
    }

    if (!opts.auto_discover &&
        !opts.interface_name.has_value() &&
        !opts.target_cidr.has_value() &&
        !opts.target_list.has_value()) {
        cerr << "[ERROR] No scan target or action specified. Use '--auto', '--interface <name>', "
             << "'--target <CIDR>', or '--targets <IPs>'.\n\n";
        CliParser::print_help(cerr);
        return static_cast<int>(ExitCode::InvalidArguments);
    }

    const auto selected_iface_opt = select_network_interface(all_interfaces, opts);
    if (!selected_iface_opt.has_value()) {
        return static_cast<int>(ExitCode::InterfaceError);
    }
    const NetworkInterface selected_iface = *selected_iface_opt;

    Logger::instance().info(
        "Main",
        "Using interface '" + selected_iface.name + "' (" +
        selected_iface.ipv4.to_string() + "/" +
        to_string(selected_iface.cidr_prefix) + ")");

    ScopeValidator scope_validator(ScopeValidator::kDefaultMaxTargets);
    scope_validator.add_authorized_subnet(selected_iface.subnet_cidr());

    ScopeValidationResult scope_result;
    string target_spec_label;

    if (opts.target_cidr.has_value()) {
        target_spec_label = *opts.target_cidr;
        const auto cidr_opt = CIDRBlock::parse(*opts.target_cidr);
        if (!cidr_opt.has_value()) {
            Logger::instance().error(
                "ScopeValidator", "Invalid CIDR format: '" + *opts.target_cidr + "'");
            return static_cast<int>(ExitCode::InvalidArguments);
        }
        scope_result = scope_validator.validate_cidr(*cidr_opt);
    } else if (opts.target_list.has_value()) {
        target_spec_label = *opts.target_list;
        const auto list_opt = parse_ip_target_list(*opts.target_list);
        if (!list_opt.has_value()) {
            Logger::instance().error(
                "ScopeValidator", "Invalid IP target list: '" + *opts.target_list + "'");
            return static_cast<int>(ExitCode::InvalidArguments);
        }
        scope_result = scope_validator.validate_target_list(*list_opt);
    } else {
        const CIDRBlock auto_cidr = selected_iface.subnet_cidr();
        target_spec_label = auto_cidr.to_string();
        scope_result = scope_validator.validate_cidr(auto_cidr);
    }

    if (!scope_result.valid) {
        Logger::instance().error("ScopeValidator", scope_result.error_message);
        return static_cast<int>(ExitCode::ScopeViolation);
    }

    Logger::instance().info(
        "ScopeValidator",
        "Scope check passed: " + to_string(scope_result.approved_targets.size()) +
        " target IP(s) approved within authorized subnet " +
        selected_iface.subnet_cidr().to_string());

    if (opts.dry_run) {
        cout << "\n=== NTM Dry-Run Validation Report ===\n"
             << "  Selected Interface : " << selected_iface.name
             << " (" << selected_iface.ipv4.to_string() << "/"
             << static_cast<unsigned>(selected_iface.cidr_prefix) << ")\n"
             << "  Interface Type     : "
             << InterfaceDiscovery::interface_type_to_string(selected_iface.type) << '\n'
             << "  Interface MAC      : "
             << (selected_iface.mac.is_zero() ? "-" : selected_iface.mac.to_string()) << '\n'
             << "  Default Gateway    : "
             << (selected_iface.default_gateway.has_value()
                 ? selected_iface.default_gateway->to_string()
                 : "-") << '\n'
             << "  Authorized Scope   : " << selected_iface.subnet_cidr().to_string() << '\n'
             << "  Target Spec        : " << target_spec_label << '\n'
             << "  Approved Host Count: " << scope_result.approved_targets.size() << '\n'
             << "  First Approved IP  : " << scope_result.approved_targets.front().to_string() << '\n'
             << "  Last Approved IP   : " << scope_result.approved_targets.back().to_string() << '\n'
             << "  Worker Threads     : " << opts.threads << '\n'
             << "  Rate Limit         : " << opts.rate_rps << " req/s\n"
             << "  Probe Timeout      : " << opts.timeout_ms << " ms\n"
             << "  Status             : DRY-RUN COMPLETE (0 packets sent)\n\n";
        return static_cast<int>(ExitCode::Success);
    }

    OuiLookup oui_lookup;
    if (opts.custom_oui_file.has_value()) {
        if (!oui_lookup.load_from_file(*opts.custom_oui_file)) {
            Logger::instance().warn(
                "OuiLookup",
                "Failed to load custom OUI file '" + *opts.custom_oui_file +
                "'; continuing with built-in OUI database.");
        } else {
            Logger::instance().info(
                "OuiLookup",
                "Loaded custom OUI database from '" + *opts.custom_oui_file + "' (" +
                to_string(oui_lookup.entry_count()) + " prefixes)");
        }
    }

    DiscoveryConfig disc_cfg;
    disc_cfg.local_interface = selected_iface;
    disc_cfg.enabled_methods = opts.methods;
    disc_cfg.tcp_ports = opts.tcp_ports;
    disc_cfg.worker_threads = opts.threads;
    disc_cfg.rate_limit.max_requests_per_sec = opts.rate_rps;
    disc_cfg.rate_limit.max_concurrent_probes = min<size_t>(opts.threads * 2, 64);
    disc_cfg.rate_limit.timeout_ms = opts.timeout_ms;
    disc_cfg.rate_limit.retry_count = 1;

    DiscoveryCoordinator coordinator(disc_cfg);
    const DiscoverySummary summary = coordinator.execute(scope_result.approved_targets);

    TopologyInferenceEngine inference_engine(selected_iface, oui_lookup);
    const TopologyGraph graph = inference_engine.build_topology(summary);

    ExportContext export_ctx;
    export_ctx.local_interface = selected_iface;
    export_ctx.target_specification = target_spec_label;
    export_ctx.discovery_summary = summary;
    export_ctx.timestamp_utc = TopologyInferenceEngine::current_iso8601_utc();

    TerminalRenderer::render_host_table(graph, cout);
    TerminalRenderer::render_topology_summary(graph, export_ctx, cout);

    if (opts.output_json_path.has_value()) {
        string err;
        if (!JsonExporter::write_to_file(graph, export_ctx, *opts.output_json_path, &err)) {
            Logger::instance().error("JsonExporter", err);
            return static_cast<int>(ExitCode::RuntimeError);
        }
        Logger::instance().info(
            "JsonExporter", "Exported topology JSON to '" + *opts.output_json_path + "'");
    }

    if (opts.output_dot_path.has_value()) {
        string err;
        if (!DotExporter::write_to_file(graph, *opts.output_dot_path, &err)) {
            Logger::instance().error("DotExporter", err);
            return static_cast<int>(ExitCode::RuntimeError);
        }
        Logger::instance().info(
            "DotExporter",
            "Exported Graphviz DOT to '" + *opts.output_dot_path +
            "' (render PNG with: dot -Tpng " + *opts.output_dot_path + " -o topology.png)");
    }

    return static_cast<int>(ExitCode::Success);
}
