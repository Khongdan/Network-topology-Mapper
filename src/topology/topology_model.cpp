#include "ntm/topology/topology_model.hpp"

#include <algorithm>
#include <sstream>

namespace ntm::topology {

using namespace std;
using namespace ntm::net;

string TopologyGraph::make_node_id(const IPv4Address& ip) {
    const auto oct = ip.octets();
    ostringstream oss;
    oss << "host_" << static_cast<unsigned>(oct[0]) << '_'
        << static_cast<unsigned>(oct[1]) << '_'
        << static_cast<unsigned>(oct[2]) << '_'
        << static_cast<unsigned>(oct[3]);
    return oss.str();
}

string_view TopologyGraph::host_type_to_string(HostType type) noexcept {
    switch (type) {
        case HostType::LocalHost:      return "Local Host";
        case HostType::DefaultGateway: return "Default Gateway";
        case HostType::LANHost:        return "LAN Host";
        case HostType::ReachableHost:  return "Reachable Host";
        case HostType::UnknownHost:    return "Unknown Host";
    }
    return "Unknown Host";
}

string_view TopologyGraph::discovery_status_to_string(DiscoveryStatus status) noexcept {
    switch (status) {
        case DiscoveryStatus::Active:       return "Active";
        case DiscoveryStatus::Unresponsive: return "Unresponsive";
        case DiscoveryStatus::Unknown:      return "Unknown";
    }
    return "Unknown";
}

string_view TopologyGraph::relation_status_to_string(LinkRelationStatus status) noexcept {
    switch (status) {
        case LinkRelationStatus::ObservedLink:        return "Observed Link";
        case LinkRelationStatus::InferredLink:        return "Inferred Link";
        case LinkRelationStatus::UnknownRelationship: return "Unknown Relationship";
    }
    return "Unknown Relationship";
}

string_view TopologyGraph::link_type_to_string(LinkType type) noexcept {
    switch (type) {
        case LinkType::L2BroadcastDomainMember: return "L2_BROADCAST_DOMAIN_MEMBER";
        case LinkType::L3DefaultGatewayRoute:   return "L3_DEFAULT_GATEWAY_ROUTE";
        case LinkType::L3RoutedReachability:    return "L3_ROUTED_REACHABILITY";
        case LinkType::L2SwitchPortAdjacency:   return "L2_SWITCH_PORT_ADJACENCY";
        case LinkType::UnknownAdjacency:        return "UNKNOWN_ADJACENCY";
    }
    return "UNKNOWN_ADJACENCY";
}

string_view TopologyGraph::confidence_level_to_string(ConfidenceLevel level) noexcept {
    switch (level) {
        case ConfidenceLevel::High:   return "High";
        case ConfidenceLevel::Medium: return "Medium";
        case ConfidenceLevel::Low:    return "Low";
    }
    return "Low";
}

bool TopologyGraph::has_node(string_view node_id) const noexcept {
    return node_index_by_id_.find(string(node_id)) != node_index_by_id_.end();
}

bool TopologyGraph::add_node(HostNode node) {
    if (node.id.empty()) {
        node.id = make_node_id(node.ipv4);
    }

    if (has_node(node.id) ||
        node_index_by_ip_.find(node.ipv4.to_host_order()) != node_index_by_ip_.end()) {
        return false;
    }

    const size_t idx = nodes_.size();
    node_index_by_id_[node.id] = idx;
    node_index_by_ip_[node.ipv4.to_host_order()] = idx;
    adjacency_list_.try_emplace(node.id);
    nodes_.push_back(move(node));
    return true;
}

void TopologyGraph::upsert_node(HostNode node) {
    if (node.id.empty()) {
        node.id = make_node_id(node.ipv4);
    }
    if (auto it = node_index_by_id_.find(node.id); it != node_index_by_id_.end()) {
        const uint32_t old_ip = nodes_[it->second].ipv4.to_host_order();
        node_index_by_ip_.erase(old_ip);
        node_index_by_ip_[node.ipv4.to_host_order()] = it->second;
        nodes_[it->second] = move(node);
        return;
    }
    add_node(move(node));
}

bool TopologyGraph::remove_node(string_view node_id) {
    const string id_str(node_id);
    auto it = node_index_by_id_.find(id_str);
    if (it == node_index_by_id_.end()) {
        return false;
    }

    const size_t idx = it->second;
    nodes_.erase(nodes_.begin() + static_cast<ptrdiff_t>(idx));

    links_.erase(
        remove_if(links_.begin(), links_.end(), [&id_str](const NetworkLink& link) {
            return link.source_node_id == id_str || link.destination_node_id == id_str;
        }),
        links_.end());

    rebuild_adjacency();
    return true;
}

bool TopologyGraph::has_link(
    string_view source_id,
    string_view destination_id) const noexcept {
    for (const auto& link : links_) {
        const bool same_dir = (link.source_node_id == source_id &&
                               link.destination_node_id == destination_id);
        const bool rev_dir = (link.source_node_id == destination_id &&
                              link.destination_node_id == source_id);
        if (same_dir || rev_dir) {
            return true;
        }
    }
    return false;
}

bool TopologyGraph::add_link(NetworkLink link) {
    if (link.source_node_id.empty() ||
        link.destination_node_id.empty() ||
        link.source_node_id == link.destination_node_id) {
        return false;
    }

    if (!has_node(link.source_node_id) || !has_node(link.destination_node_id)) {
        return false;
    }

    if (has_link(link.source_node_id, link.destination_node_id)) {
        return false;
    }

    adjacency_list_[link.source_node_id].push_back(link.destination_node_id);
    adjacency_list_[link.destination_node_id].push_back(link.source_node_id);
    links_.push_back(move(link));
    return true;
}

bool TopologyGraph::remove_link(string_view source_id, string_view destination_id) {
    const auto old_size = links_.size();
    links_.erase(
        remove_if(links_.begin(), links_.end(),
                  [source_id, destination_id](const NetworkLink& l) {
                      return (l.source_node_id == source_id &&
                              l.destination_node_id == destination_id) ||
                             (l.source_node_id == destination_id &&
                              l.destination_node_id == source_id);
                  }),
        links_.end());

    if (links_.size() == old_size) {
        return false;
    }
    rebuild_adjacency();
    return true;
}

optional<HostNode> TopologyGraph::find_node_by_id(string_view node_id) const {
    auto it = node_index_by_id_.find(string(node_id));
    if (it == node_index_by_id_.end()) {
        return nullopt;
    }
    return nodes_[it->second];
}

optional<HostNode> TopologyGraph::find_node_by_ip(const IPv4Address& ip) const {
    auto it = node_index_by_ip_.find(ip.to_host_order());
    if (it == node_index_by_ip_.end()) {
        return nullopt;
    }
    return nodes_[it->second];
}

optional<HostNode> TopologyGraph::find_node_by_mac(const MACAddress& mac) const {
    if (mac.is_zero()) {
        return nullopt;
    }
    for (const auto& node : nodes_) {
        if (node.mac.has_value() && *node.mac == mac) {
            return node;
        }
    }
    return nullopt;
}

vector<NetworkLink> TopologyGraph::incident_links(string_view node_id) const {
    vector<NetworkLink> result;
    for (const auto& link : links_) {
        if (link.source_node_id == node_id || link.destination_node_id == node_id) {
            result.push_back(link);
        }
    }
    return result;
}

vector<string> TopologyGraph::adjacent_node_ids(string_view node_id) const {
    auto it = adjacency_list_.find(string(node_id));
    if (it == adjacency_list_.end()) {
        return {};
    }
    return it->second;
}

void TopologyGraph::rebuild_adjacency() {
    node_index_by_id_.clear();
    node_index_by_ip_.clear();
    adjacency_list_.clear();

    for (size_t i = 0; i < nodes_.size(); ++i) {
        node_index_by_id_[nodes_[i].id] = i;
        node_index_by_ip_[nodes_[i].ipv4.to_host_order()] = i;
        adjacency_list_.try_emplace(nodes_[i].id);
    }

    for (const auto& link : links_) {
        adjacency_list_[link.source_node_id].push_back(link.destination_node_id);
        adjacency_list_[link.destination_node_id].push_back(link.source_node_id);
    }
}

} // namespace ntm::topology
