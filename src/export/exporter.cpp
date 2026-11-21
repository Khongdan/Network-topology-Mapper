#include "ntm/export/exporter.hpp"
#include "ntm/topology/topology_inference.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace ntm::export_out {

using namespace std;
using namespace ntm::net;
using namespace ntm::discovery;
using namespace ntm::topology;
using nlohmann::json;

namespace {

string escape_dot_string(string_view input) {
    string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n' || c == '\r') {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

string format_rtt(const optional<double>& rtt_ms) {
    if (!rtt_ms.has_value()) {
        return "-";
    }
    ostringstream oss;
    oss << fixed << setprecision(2) << *rtt_ms << " ms";
    return oss.str();
}

} // namespace

// ============================================================================
// TerminalRenderer
// ============================================================================

void TerminalRenderer::render_interfaces_table(
    const vector<NetworkInterface>& interfaces,
    ostream& out) {
    out << "\n=== Local Network Interfaces ===\n";
    if (interfaces.empty()) {
        out << "No IPv4 network interfaces detected.\n";
        return;
    }

    out << left
        << setw(6)  << "Index"
        << setw(16) << "Name"
        << setw(18) << "IPv4/Prefix"
        << setw(19) << "MAC Address"
        << setw(16) << "Type"
        << setw(8)  << "State"
        << setw(16) << "Default GW"
        << '\n';
    out << string(99, '-') << '\n';

    for (const auto& iface : interfaces) {
        const string ip_cidr =
            iface.ipv4.to_string() + "/" + to_string(iface.cidr_prefix);
        const string mac_str = iface.mac.is_zero() ? "-" : iface.mac.to_string();
        const string gw_str =
            iface.default_gateway.has_value() ? iface.default_gateway->to_string() : "-";
        const string state_str = iface.is_up ? "UP" : "DOWN";

        out << left
            << setw(6)  << iface.index
            << setw(16) << iface.name.substr(0, 15)
            << setw(18) << ip_cidr
            << setw(19) << mac_str
            << setw(16) << InterfaceDiscovery::interface_type_to_string(iface.type)
            << setw(8)  << state_str
            << setw(16) << gw_str
            << '\n';
    }
    out << '\n';
}

void TerminalRenderer::render_host_table(
    const TopologyGraph& graph,
    ostream& out) {
    const auto& nodes = graph.nodes();

    size_t w_ip = 15;
    size_t w_mac = 17;
    size_t w_host = 16;
    size_t w_vendor = 22;
    size_t w_type = 16;
    size_t w_status = 12;
    size_t w_rtt = 10;

    for (const auto& n : nodes) {
        w_ip = max(w_ip, n.ipv4.to_string().size());
        if (n.hostname.has_value()) {
            w_host = min<size_t>(32, max(w_host, n.hostname->size()));
        }
        w_vendor = min<size_t>(28, max(w_vendor, n.vendor.size()));
    }

    auto print_sep = [&]() {
        out << "+-" << string(w_ip, '-')
            << "-+-" << string(w_mac, '-')
            << "-+-" << string(w_host, '-')
            << "-+-" << string(w_vendor, '-')
            << "-+-" << string(w_type, '-')
            << "-+-" << string(w_status, '-')
            << "-+-" << string(w_rtt, '-')
            << "-+\n";
    };

    out << "\n=== Discovered Hosts ===\n";
    print_sep();
    out << "| " << left << setw(static_cast<int>(w_ip))     << "IP"
        << " | " << left << setw(static_cast<int>(w_mac))    << "MAC"
        << " | " << left << setw(static_cast<int>(w_host))   << "Hostname"
        << " | " << left << setw(static_cast<int>(w_vendor)) << "Vendor"
        << " | " << left << setw(static_cast<int>(w_type))   << "Type"
        << " | " << left << setw(static_cast<int>(w_status)) << "Status"
        << " | " << left << setw(static_cast<int>(w_rtt))    << "RTT"
        << " |\n";
    print_sep();

    for (const auto& n : nodes) {
        const string mac_str =
            (n.mac.has_value() && !n.mac->is_zero()) ? n.mac->to_string() : "-";
        const string host_str =
            (n.hostname.has_value() && !n.hostname->empty())
                ? n.hostname->substr(0, w_host)
                : "-";
        const string vendor_str =
            n.vendor.empty() ? "Unknown Vendor" : n.vendor.substr(0, w_vendor);
        const string type_str(TopologyGraph::host_type_to_string(n.host_type));
        const string status_str(TopologyGraph::discovery_status_to_string(n.status));
        const string rtt_str = format_rtt(n.rtt_ms);

        out << "| " << left << setw(static_cast<int>(w_ip))     << n.ipv4.to_string()
            << " | " << left << setw(static_cast<int>(w_mac))    << mac_str
            << " | " << left << setw(static_cast<int>(w_host))   << host_str
            << " | " << left << setw(static_cast<int>(w_vendor)) << vendor_str
            << " | " << left << setw(static_cast<int>(w_type))   << type_str
            << " | " << left << setw(static_cast<int>(w_status)) << status_str
            << " | " << left << setw(static_cast<int>(w_rtt))    << rtt_str
            << " |\n";
    }
    print_sep();
}

void TerminalRenderer::render_topology_summary(
    const TopologyGraph& graph,
    const ExportContext& context,
    ostream& out) {
    out << "\n=== Topology Links (Evidence-Based) ===\n";
    if (graph.links().empty()) {
        out << "No external topology links discovered.\n";
    } else {
        for (const auto& link : graph.links()) {
            const auto src = graph.find_node_by_id(link.source_node_id);
            const auto dst = graph.find_node_by_id(link.destination_node_id);
            const string src_label = src.has_value() ? src->ipv4.to_string() : link.source_node_id;
            const string dst_label = dst.has_value() ? dst->ipv4.to_string() : link.destination_node_id;

            out << "  " << src_label << " <---> " << dst_label
                << " [" << TopologyGraph::relation_status_to_string(link.relation_status) << "]"
                << " [Type: " << TopologyGraph::link_type_to_string(link.link_type) << "]"
                << " [Confidence: " << TopologyGraph::confidence_level_to_string(link.confidence_level)
                << " (" << fixed << setprecision(2) << link.confidence_score << ")]"
                << " [Evidence: " << link.evidence_source << "]\n";
        }
    }

    size_t observed_count = 0;
    size_t inferred_count = 0;
    size_t unknown_count = 0;
    for (const auto& link : graph.links()) {
        if (link.relation_status == LinkRelationStatus::ObservedLink) {
            ++observed_count;
        } else if (link.relation_status == LinkRelationStatus::InferredLink) {
            ++inferred_count;
        } else {
            ++unknown_count;
        }
    }

    out << "\n=== Scan Summary ===\n"
        << "  Interface        : " << context.local_interface.name
        << " (" << context.local_interface.ipv4.to_string() << "/"
        << static_cast<unsigned>(context.local_interface.cidr_prefix) << ")\n"
        << "  Targets Probed   : " << context.discovery_summary.total_targets_probed << '\n'
        << "  Total Graph Nodes: " << graph.node_count() << '\n'
        << "  Total Graph Links: " << graph.link_count()
        << " (Observed: " << observed_count
        << ", Inferred: " << inferred_count
        << ", Unknown: " << unknown_count << ")\n"
        << "  Elapsed Time     : " << fixed << setprecision(3)
        << context.discovery_summary.elapsed_seconds << " s\n\n";
}

// ============================================================================
// JsonExporter
// ============================================================================

string JsonExporter::to_json_string(
    const TopologyGraph& graph,
    const ExportContext& context,
    int indent) {
    const string ts = context.timestamp_utc.empty()
        ? TopologyInferenceEngine::current_iso8601_utc()
        : context.timestamp_utc;

    json root;
    root["schema_version"] = string(kSchemaVersion);
    root["metadata"] = {
        {"tool_name", "Network Topology Mapper (NTM)"},
        {"tool_version", "1.0.0"},
        {"timestamp_utc", ts}
    };

    json methods_arr = json::array();
    for (const auto m : context.discovery_summary.active_methods) {
        methods_arr.push_back(string(DiscoveryCoordinator::method_to_string(m)));
    }

    root["scan_configuration"] = {
        {"target_specification", context.target_specification},
        {"active_discovery_methods", methods_arr},
        {"warnings", context.discovery_summary.warnings}
    };

    root["local_interface"] = {
        {"name", context.local_interface.name},
        {"index", context.local_interface.index},
        {"ipv4", context.local_interface.ipv4.to_string()},
        {"cidr_prefix", context.local_interface.cidr_prefix},
        {"subnet", context.local_interface.subnet_cidr().to_string()},
        {"mac", context.local_interface.mac.is_zero() ? "" : context.local_interface.mac.to_string()},
        {"type", string(InterfaceDiscovery::interface_type_to_string(context.local_interface.type))},
        {"is_up", context.local_interface.is_up},
        {"default_gateway", context.local_interface.default_gateway.has_value()
            ? json(context.local_interface.default_gateway->to_string())
            : json(nullptr)}
    };

    json hosts_arr = json::array();
    for (const auto& node : graph.nodes()) {
        json h;
        h["id"] = node.id;
        h["ipv4"] = node.ipv4.to_string();
        h["mac"] = (node.mac.has_value() && !node.mac->is_zero())
            ? json(node.mac->to_string())
            : json(nullptr);
        h["hostname"] = (node.hostname.has_value() && !node.hostname->empty())
            ? json(*node.hostname)
            : json(nullptr);
        h["vendor"] = node.vendor;
        h["host_type"] = string(TopologyGraph::host_type_to_string(node.host_type));
        h["classification_reasons"] = node.classification_reasons;
        h["discovery_status"] =
            string(TopologyGraph::discovery_status_to_string(node.status));
        h["rtt_ms"] = node.rtt_ms.has_value() ? json(*node.rtt_ms) : json(nullptr);
        h["interface"] = node.interface_name;
        h["first_seen"] = node.first_seen;
        h["last_seen"] = node.last_seen;
        h["discovery_methods"] = node.discovery_methods;
        h["open_tcp_ports"] = node.open_tcp_ports;
        h["confidence_score"] = node.confidence_score;
        hosts_arr.push_back(move(h));
    }
    root["hosts"] = move(hosts_arr);

    json links_arr = json::array();
    size_t observed_links = 0;
    size_t inferred_links = 0;
    size_t unknown_links = 0;

    for (const auto& link : graph.links()) {
        if (link.relation_status == LinkRelationStatus::ObservedLink) {
            ++observed_links;
        } else if (link.relation_status == LinkRelationStatus::InferredLink) {
            ++inferred_links;
        } else {
            ++unknown_links;
        }

        json l;
        l["source_node"] = link.source_node_id;
        l["destination_node"] = link.destination_node_id;
        l["link_type"] = string(TopologyGraph::link_type_to_string(link.link_type));
        l["evidence_source"] = link.evidence_source;
        l["collection_method"] = link.collection_method;
        l["relation_status"] =
            string(TopologyGraph::relation_status_to_string(link.relation_status));
        l["confidence_level"] =
            string(TopologyGraph::confidence_level_to_string(link.confidence_level));
        l["confidence_score"] = link.confidence_score;
        l["description"] = link.description;
        links_arr.push_back(move(l));
    }
    root["links"] = move(links_arr);

    root["scan_statistics"] = {
        {"total_targets_probed", context.discovery_summary.total_targets_probed},
        {"responsive_hosts_count", context.discovery_summary.responsive_hosts_count},
        {"total_graph_nodes", graph.node_count()},
        {"total_graph_links", graph.link_count()},
        {"observed_links_count", observed_links},
        {"inferred_links_count", inferred_links},
        {"unknown_relationships_count", unknown_links},
        {"elapsed_seconds", context.discovery_summary.elapsed_seconds}
    };

    return root.dump(indent);
}

bool JsonExporter::write_to_file(
    const TopologyGraph& graph,
    const ExportContext& context,
    string_view file_path,
    string* error_message) {
    const string payload = to_json_string(graph, context, 2);
    if (payload.size() > kMaxOutputBytes) {
        if (error_message != nullptr) {
            *error_message = "Generated JSON exceeds maximum allowed output file size limit.";
        }
        return false;
    }

    ofstream out{string(file_path), ios::out | ios::trunc};
    if (!out.is_open()) {
        if (error_message != nullptr) {
            *error_message = "Unable to open JSON output file for writing: " + string(file_path);
        }
        return false;
    }

    out << payload << '\n';
    if (!out.good()) {
        if (error_message != nullptr) {
            *error_message = "I/O error while writing JSON output file: " + string(file_path);
        }
        return false;
    }
    return true;
}

// ============================================================================
// DotExporter
// ============================================================================

string DotExporter::to_dot_string(
    const TopologyGraph& graph,
    string_view graph_title) {
    ostringstream dot;
    dot << "graph \"" << escape_dot_string(graph_title) << "\" {\n";
    dot << "  graph [rankdir=LR, fontname=\"Helvetica\", fontsize=11, "
        << "label=\"Network Topology Mapper (NTM v1.0) - Evidence-Based Topology\", labelloc=t];\n";
    dot << "  node [fontname=\"Helvetica\", fontsize=10, style=\"filled\"];\n";
    dot << "  edge [fontname=\"Helvetica\", fontsize=9];\n\n";

    for (const auto& node : graph.nodes()) {
        string shape = "box";
        string fillcolor = "#e0f3f8";
        string style = "filled,rounded";

        switch (node.host_type) {
            case HostType::LocalHost:
                shape = "doubleoctagon";
                fillcolor = "#d9f0d3";
                style = "filled";
                break;
            case HostType::DefaultGateway:
                shape = "diamond";
                fillcolor = "#fee090";
                style = "filled";
                break;
            case HostType::LANHost:
                shape = "box";
                fillcolor = "#e0f3f8";
                style = "filled,rounded";
                break;
            case HostType::ReachableHost:
                shape = "ellipse";
                fillcolor = "#f7f7f7";
                style = "filled";
                break;
            case HostType::UnknownHost:
                shape = "octagon";
                fillcolor = "#efefef";
                style = "filled,dashed";
                break;
        }

        ostringstream label;
        label << "[" << TopologyGraph::host_type_to_string(node.host_type) << "]\\n";
        label << "IP: " << node.ipv4.to_string();
        if (node.hostname.has_value() && !node.hostname->empty()) {
            label << "\\nHost: " << escape_dot_string(*node.hostname);
        }
        if (node.mac.has_value() && !node.mac->is_zero()) {
            label << "\\nMAC: " << node.mac->to_string();
        }
        if (!node.vendor.empty() && node.vendor != "Unknown Vendor") {
            label << "\\nVendor: " << escape_dot_string(node.vendor);
        }

        dot << "  \"" << escape_dot_string(node.id) << "\" ["
            << "shape=" << shape << ", "
            << "style=\"" << style << "\", "
            << "fillcolor=\"" << fillcolor << "\", "
            << "label=\"" << label.str() << "\"];\n";
    }

    dot << '\n';

    for (const auto& link : graph.links()) {
        if (link.relation_status == LinkRelationStatus::UnknownRelationship) {
            continue;
        }

        string edge_style = "dashed";
        string edge_color = "#2166ac";
        string penwidth = "1.5";

        if (link.relation_status == LinkRelationStatus::ObservedLink) {
            edge_style = "solid";
            edge_color = "#1b7837";
            penwidth = "2.2";
        }

        ostringstream edge_label;
        edge_label << TopologyGraph::relation_status_to_string(link.relation_status)
                   << "\\nMethod: " << escape_dot_string(link.collection_method)
                   << " (Conf: " << fixed << setprecision(2) << link.confidence_score << ")";

        dot << "  \"" << escape_dot_string(link.source_node_id) << "\" -- \""
            << escape_dot_string(link.destination_node_id) << "\" ["
            << "style=\"" << edge_style << "\", "
            << "color=\"" << edge_color << "\", "
            << "penwidth=" << penwidth << ", "
            << "label=\"" << edge_label.str() << "\"];\n";
    }

    dot << "}\n";
    return dot.str();
}

bool DotExporter::write_to_file(
    const TopologyGraph& graph,
    string_view file_path,
    string* error_message) {
    const string payload = to_dot_string(graph);
    if (payload.size() > kMaxOutputBytes) {
        if (error_message != nullptr) {
            *error_message = "Generated DOT exceeds maximum allowed output file size limit.";
        }
        return false;
    }

    ofstream out{string(file_path), ios::out | ios::trunc};
    if (!out.is_open()) {
        if (error_message != nullptr) {
            *error_message = "Unable to open DOT output file for writing: " + string(file_path);
        }
        return false;
    }

    out << payload;
    if (!out.good()) {
        if (error_message != nullptr) {
            *error_message = "I/O error while writing DOT output file: " + string(file_path);
        }
        return false;
    }
    return true;
}

} // namespace ntm::export_out
