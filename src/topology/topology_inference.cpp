#include "ntm/topology/topology_inference.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ntm::topology {

using namespace std;
using namespace chrono;
using namespace ntm::net;
using namespace ntm::discovery;

namespace {

bool has_method(
    const vector<DiscoveryMethod>& methods,
    DiscoveryMethod target) noexcept {
    return find(methods.begin(), methods.end(), target) != methods.end();
}

} // namespace

TopologyInferenceEngine::TopologyInferenceEngine(
    NetworkInterface local_interface,
    const OuiLookup& oui_lookup,
    InferenceOptions options)
    : local_iface_(move(local_interface)),
      oui_lookup_(oui_lookup),
      options_(options) {}

string TopologyInferenceEngine::current_iso8601_utc() {
    const auto now = system_clock::now();
    const auto now_time_t = system_clock::to_time_t(now);
    tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now_time_t);
#else
    gmtime_r(&now_time_t, &tm_utc);
#endif
    ostringstream oss;
    oss << put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

HostNode TopologyInferenceEngine::classify_discovered_host(
    const HostDiscoveryRecord& record,
    const string& iso_timestamp) const {
    HostNode node;
    node.id = TopologyGraph::make_node_id(record.ip);
    node.ipv4 = record.ip;
    node.mac = record.mac;
    node.hostname = record.hostname;
    node.interface_name = local_iface_.name;
    node.first_seen = iso_timestamp;
    node.last_seen = iso_timestamp;
    node.rtt_ms = record.best_rtt_ms;
    node.open_tcp_ports = record.open_ports;

    if (node.mac.has_value() && !node.mac->is_zero()) {
        node.vendor = oui_lookup_.lookup_or_default(*node.mac, "Unknown Vendor");
    } else {
        node.vendor = "Unknown Vendor";
    }

    for (const auto m : record.successful_methods) {
        node.discovery_methods.emplace_back(DiscoveryCoordinator::method_to_string(m));
    }

    const bool is_local_ip = (record.ip == local_iface_.ipv4);
    const bool is_default_gw = (local_iface_.default_gateway.has_value() &&
                                record.ip == *local_iface_.default_gateway);
    const bool in_local_subnet = local_iface_.subnet_cidr().contains(record.ip);
    const bool has_arp_reply = has_method(record.successful_methods, DiscoveryMethod::ARP);
    const bool has_arp_cache = has_method(record.successful_methods, DiscoveryMethod::OS_ARP_CACHE);
    const bool has_icmp = has_method(record.successful_methods, DiscoveryMethod::ICMP);
    const bool has_tcp = has_method(record.successful_methods, DiscoveryMethod::TCP);
    const bool has_l2_mac = node.mac.has_value() && !node.mac->is_zero();

    if (is_local_ip) {
        node.host_type = HostType::LocalHost;
        node.status = DiscoveryStatus::Active;
        node.confidence_score = 1.0;
        node.classification_reasons.push_back(
            "Matches local network interface IPv4 (" + local_iface_.name + ")");
        return node;
    }

    if (!record.reachable) {
        node.host_type = HostType::UnknownHost;
        node.status = DiscoveryStatus::Unresponsive;
        node.confidence_score = 0.0;
        node.classification_reasons.push_back(
            "No response to any configured discovery probe; offline or filtered by firewall");
        return node;
    }

    node.status = DiscoveryStatus::Active;

    double score = 0.40;
    if (has_arp_reply) {
        score += 0.35;
        node.classification_reasons.push_back("Verified direct Layer-2 ARP reply");
    } else if (has_arp_cache && has_l2_mac) {
        score += 0.25;
        node.classification_reasons.push_back("Layer-2 MAC present in OS neighbor cache");
    }
    if (has_icmp) {
        score += 0.15;
        node.classification_reasons.push_back("Verified Layer-3 ICMP Echo reply");
    }
    if (has_tcp) {
        score += 0.15;
        node.classification_reasons.push_back("Verified Layer-4 TCP stack response");
    }
    if (in_local_subnet) {
        node.classification_reasons.push_back(
            "IPv4 belongs to local subnet " + local_iface_.subnet_cidr().to_string());
    }

    if (is_default_gw) {
        node.host_type = HostType::DefaultGateway;
        score += 0.20;
        node.classification_reasons.push_back(
            "Matches OS routing table default gateway for interface " + local_iface_.name);
    } else if (in_local_subnet && has_l2_mac) {
        node.host_type = HostType::LANHost;
        node.classification_reasons.push_back(
            "Confirmed Layer-2 MAC adjacency within local broadcast domain");
    } else {
        node.host_type = HostType::ReachableHost;
        node.classification_reasons.push_back(
            "Responded at Layer-3/Layer-4 without confirmed Layer-2 MAC address");
    }

    node.confidence_score = clamp(score, 0.10, 0.99);
    return node;
}

TopologyGraph TopologyInferenceEngine::build_topology(
    const DiscoverySummary& discovery_summary) const {
    TopologyGraph graph;
    const string timestamp = current_iso8601_utc();

    HostNode local_node;
    local_node.id = TopologyGraph::make_node_id(local_iface_.ipv4);
    local_node.ipv4 = local_iface_.ipv4;
    if (!local_iface_.mac.is_zero()) {
        local_node.mac = local_iface_.mac;
        local_node.vendor = oui_lookup_.lookup_or_default(local_iface_.mac, "Local Interface NIC");
    } else {
        local_node.vendor = "Local Interface NIC";
    }
    local_node.hostname = ReverseDnsResolver::resolve_ptr(local_iface_.ipv4);
    local_node.host_type = HostType::LocalHost;
    local_node.status = DiscoveryStatus::Active;
    local_node.rtt_ms = 0.0;
    local_node.interface_name = local_iface_.name;
    local_node.first_seen = timestamp;
    local_node.last_seen = timestamp;
    local_node.discovery_methods = {"LOCAL_IFACE"};
    local_node.confidence_score = 1.0;
    local_node.classification_reasons = {
        "Active scanning interface (" + local_iface_.name + ") obtained via OS interface configuration"
    };

    graph.add_node(local_node);

    for (const auto& rec : discovery_summary.records) {
        if (rec.ip == local_iface_.ipv4) {
            continue;
        }
        if (!rec.reachable && !options_.include_unresponsive_hosts) {
            continue;
        }

        HostNode host_node = classify_discovered_host(rec, timestamp);
        graph.add_node(host_node);

        const bool has_arp_reply = has_method(rec.successful_methods, DiscoveryMethod::ARP);
        const bool has_arp_cache = has_method(rec.successful_methods, DiscoveryMethod::OS_ARP_CACHE);
        const bool has_icmp      = has_method(rec.successful_methods, DiscoveryMethod::ICMP);
        const bool has_tcp       = has_method(rec.successful_methods, DiscoveryMethod::TCP);

        if (!rec.reachable) {
            if (options_.record_unknown_relationships) {
                NetworkLink unknown_link;
                unknown_link.source_node_id = local_node.id;
                unknown_link.destination_node_id = host_node.id;
                unknown_link.link_type = LinkType::UnknownAdjacency;
                unknown_link.evidence_source = "No protocol response";
                unknown_link.collection_method = "Active Probing";
                unknown_link.relation_status = LinkRelationStatus::UnknownRelationship;
                unknown_link.confidence_level = ConfidenceLevel::Low;
                unknown_link.confidence_score = 0.0;
                unknown_link.description =
                    "Host did not respond; connectivity relationship is unknown.";
                graph.add_link(move(unknown_link));
            }
            continue;
        }

        if (host_node.host_type == HostType::DefaultGateway) {
            NetworkLink gw_link;
            gw_link.source_node_id = local_node.id;
            gw_link.destination_node_id = host_node.id;

            if (has_arp_reply) {
                gw_link.link_type = LinkType::L3DefaultGatewayRoute;
                gw_link.evidence_source = "AF_PACKET ARP Reply + OS Routing Table (/proc/net/route)";
                gw_link.collection_method = "ARP + Routing Table";
                gw_link.relation_status = LinkRelationStatus::ObservedLink;
                gw_link.confidence_level = ConfidenceLevel::High;
                gw_link.confidence_score = 0.98;
                gw_link.description =
                    "Directly observed L2 ARP adjacency to verified L3 Default Gateway on " +
                    local_iface_.name + " (physical switch hops unqueried in v1.0).";
            } else {
                gw_link.link_type = LinkType::L3DefaultGatewayRoute;
                gw_link.evidence_source = "OS Routing Table (/proc/net/route) + L3/L4 Reachability";
                gw_link.collection_method = has_icmp ? "ICMP + Route" : "TCP + Route";
                gw_link.relation_status = LinkRelationStatus::InferredLink;
                gw_link.confidence_level = ConfidenceLevel::High;
                gw_link.confidence_score = 0.88;
                gw_link.description =
                    "Inferred default gateway link from kernel routing table and active L3/L4 response.";
            }
            graph.add_link(move(gw_link));
            continue;
        }

        if (has_arp_reply) {
            NetworkLink l2_link;
            l2_link.source_node_id = local_node.id;
            l2_link.destination_node_id = host_node.id;
            l2_link.link_type = LinkType::L2BroadcastDomainMember;
            l2_link.evidence_source = "AF_PACKET Layer-2 ARP Reply";
            l2_link.collection_method = "ARP";
            l2_link.relation_status = LinkRelationStatus::ObservedLink;
            l2_link.confidence_level = ConfidenceLevel::High;
            l2_link.confidence_score = 0.95;
            l2_link.description =
                "Observed direct Layer-2 ARP Reply on broadcast domain of " + local_iface_.name +
                " (intermediate L2 switches cannot be identified without LLDP/CDP/SNMP).";
            graph.add_link(move(l2_link));
        } else if (has_arp_cache && host_node.mac.has_value()) {
            NetworkLink cache_link;
            cache_link.source_node_id = local_node.id;
            cache_link.destination_node_id = host_node.id;
            cache_link.link_type = LinkType::L2BroadcastDomainMember;
            cache_link.evidence_source = "OS Neighbor Cache (/proc/net/arp) + L3/L4 Probe";
            cache_link.collection_method = "OS_ARP_CACHE";
            cache_link.relation_status = LinkRelationStatus::InferredLink;
            cache_link.confidence_level = ConfidenceLevel::Medium;
            cache_link.confidence_score = 0.78;
            cache_link.description =
                "Inferred Layer-2 broadcast domain membership from kernel ARP cache and active probe.";
            graph.add_link(move(cache_link));
        } else if (has_icmp || has_tcp) {
            NetworkLink l3_link;
            l3_link.source_node_id = local_node.id;
            l3_link.destination_node_id = host_node.id;
            l3_link.link_type = LinkType::L3RoutedReachability;
            l3_link.evidence_source = has_icmp
                ? "Layer-3 ICMP Echo Reply (No L2 MAC observed)"
                : "Layer-4 TCP Probe Response (No L2 MAC observed)";
            l3_link.collection_method = has_icmp ? "ICMP" : "TCP";
            l3_link.relation_status = LinkRelationStatus::InferredLink;
            l3_link.confidence_level = ConfidenceLevel::Medium;
            l3_link.confidence_score = 0.60;
            l3_link.description =
                "Inferred IP reachability from L3/L4 response; Layer-2 MAC adjacency unknown.";
            graph.add_link(move(l3_link));
        }
    }

    return graph;
}

} // namespace ntm::topology
