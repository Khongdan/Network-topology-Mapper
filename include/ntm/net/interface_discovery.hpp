#ifndef NTM_NET_INTERFACE_DISCOVERY_HPP
#define NTM_NET_INTERFACE_DISCOVERY_HPP

#include "ntm/net/ip_address.hpp"

#include <cstdint>
#include <istream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ntm::net {

using namespace std;

enum class InterfaceType {
    Physical,
    Loopback,
    VPN,
    Bridge,
    VirtualDocker,
    Unknown
};

struct NetworkInterface {
    string name;
    int index{0};
    MACAddress mac;
    IPv4Address ipv4;
    IPv4Address netmask;
    uint8_t cidr_prefix{0};
    optional<IPv4Address> broadcast;
    bool is_up{false};
    bool is_running{false};
    optional<IPv4Address> default_gateway;
    InterfaceType type{InterfaceType::Unknown};

    [[nodiscard]] CIDRBlock subnet_cidr() const noexcept {
        return CIDRBlock(ipv4, cidr_prefix);
    }

    [[nodiscard]] bool is_usable_lan_candidate() const noexcept {
        return is_up && !ipv4.is_unspecified() && !ipv4.is_loopback() &&
               type != InterfaceType::Loopback;
    }
};

class InterfaceDiscovery {
public:
    [[nodiscard]] static vector<NetworkInterface> discover_interfaces();

    [[nodiscard]] static optional<NetworkInterface> find_by_name(
        const vector<NetworkInterface>& interfaces,
        string_view name);

    [[nodiscard]] static vector<NetworkInterface> filter_lan_candidates(
        const vector<NetworkInterface>& interfaces);

    [[nodiscard]] static string_view interface_type_to_string(InterfaceType type) noexcept;

    [[nodiscard]] static InterfaceType classify_interface_name(
        string_view if_name,
        bool is_loopback_flag,
        bool is_point_to_point_flag) noexcept;

    [[nodiscard]] static map<string, IPv4Address> parse_proc_net_route_stream(
        istream& route_stream);
};

} // namespace ntm::net

#endif // NTM_NET_INTERFACE_DISCOVERY_HPP
