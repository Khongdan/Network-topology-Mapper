#ifndef NTM_TOPOLOGY_TOPOLOGY_MODEL_HPP
#define NTM_TOPOLOGY_TOPOLOGY_MODEL_HPP

#include "ntm/net/ip_address.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ntm::topology {

using namespace std;
using namespace ntm::net;

enum class HostType {
    LocalHost,
    DefaultGateway,
    LANHost,
    ReachableHost,
    UnknownHost
};

enum class DiscoveryStatus {
    Active,
    Unresponsive,
    Unknown
};

enum class LinkRelationStatus {
    ObservedLink,
    InferredLink,
    UnknownRelationship
};

enum class LinkType {
    L2BroadcastDomainMember,
    L3DefaultGatewayRoute,
    L3RoutedReachability,
    L2SwitchPortAdjacency,
    UnknownAdjacency
};

enum class ConfidenceLevel {
    High,
    Medium,
    Low
};

struct HostNode {
    string id;
    IPv4Address ipv4;
    optional<MACAddress> mac;
    optional<string> hostname;
    string vendor{"Unknown Vendor"};
    HostType host_type{HostType::UnknownHost};
    vector<string> classification_reasons;
    DiscoveryStatus status{DiscoveryStatus::Unknown};
    optional<double> rtt_ms;
    string interface_name;
    string first_seen;
    string last_seen;
    vector<string> discovery_methods;
    vector<uint16_t> open_tcp_ports;
    double confidence_score{0.0};
};

struct NetworkLink {
    string source_node_id;
    string destination_node_id;
    LinkType link_type{LinkType::UnknownAdjacency};
    string evidence_source;
    string collection_method;
    LinkRelationStatus relation_status{LinkRelationStatus::UnknownRelationship};
    ConfidenceLevel confidence_level{ConfidenceLevel::Low};
    double confidence_score{0.0};
    string description;
};

class TopologyGraph {
public:
    TopologyGraph() = default;

    bool add_node(HostNode node);
    void upsert_node(HostNode node);
    bool remove_node(string_view node_id);

    bool add_link(NetworkLink link);
    bool remove_link(string_view source_id, string_view destination_id);

    [[nodiscard]] bool has_node(string_view node_id) const noexcept;
    [[nodiscard]] bool has_link(string_view source_id,
                                string_view destination_id) const noexcept;

    [[nodiscard]] optional<HostNode> find_node_by_id(string_view node_id) const;
    [[nodiscard]] optional<HostNode> find_node_by_ip(const IPv4Address& ip) const;
    [[nodiscard]] optional<HostNode> find_node_by_mac(const MACAddress& mac) const;

    [[nodiscard]] const vector<HostNode>& nodes() const noexcept { return nodes_; }
    [[nodiscard]] const vector<NetworkLink>& links() const noexcept { return links_; }

    [[nodiscard]] vector<NetworkLink> incident_links(string_view node_id) const;
    [[nodiscard]] vector<string> adjacent_node_ids(string_view node_id) const;
    [[nodiscard]] const unordered_map<string, vector<string>>&
        adjacency_list() const noexcept {
        return adjacency_list_;
    }

    [[nodiscard]] size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] size_t link_count() const noexcept { return links_.size(); }

    [[nodiscard]] static string make_node_id(const IPv4Address& ip);
    [[nodiscard]] static string_view host_type_to_string(HostType type) noexcept;
    [[nodiscard]] static string_view discovery_status_to_string(DiscoveryStatus status) noexcept;
    [[nodiscard]] static string_view relation_status_to_string(LinkRelationStatus status) noexcept;
    [[nodiscard]] static string_view link_type_to_string(LinkType type) noexcept;
    [[nodiscard]] static string_view confidence_level_to_string(ConfidenceLevel level) noexcept;

private:
    void rebuild_adjacency();

    vector<HostNode> nodes_;
    vector<NetworkLink> links_;
    unordered_map<string, size_t> node_index_by_id_;
    unordered_map<uint32_t, size_t> node_index_by_ip_;
    unordered_map<string, vector<string>> adjacency_list_;
};

} // namespace ntm::topology

#endif // NTM_TOPOLOGY_TOPOLOGY_MODEL_HPP
