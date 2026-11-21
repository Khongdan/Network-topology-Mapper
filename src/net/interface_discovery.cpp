#include "ntm/net/interface_discovery.hpp"
#include "ntm/utils/logger.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>

#if defined(__linux__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

namespace ntm::net {

using namespace std;
using namespace ntm::utils;

namespace {

bool starts_with(string_view str, string_view prefix) noexcept {
    return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

} // namespace

string_view InterfaceDiscovery::interface_type_to_string(InterfaceType type) noexcept {
    switch (type) {
        case InterfaceType::Physical:      return "Physical";
        case InterfaceType::Loopback:      return "Loopback";
        case InterfaceType::VPN:           return "VPN";
        case InterfaceType::Bridge:        return "Bridge";
        case InterfaceType::VirtualDocker: return "Virtual/Docker";
        case InterfaceType::Unknown:       return "Unknown";
    }
    return "Unknown";
}

InterfaceType InterfaceDiscovery::classify_interface_name(
    string_view if_name,
    bool is_loopback_flag,
    bool is_point_to_point_flag) noexcept {
    if (is_loopback_flag || if_name == "lo" || starts_with(if_name, "lo:")) {
        return InterfaceType::Loopback;
    }
    if (is_point_to_point_flag ||
        starts_with(if_name, "tun") ||
        starts_with(if_name, "tap") ||
        starts_with(if_name, "wg") ||
        starts_with(if_name, "tailscale") ||
        starts_with(if_name, "zt") ||
        starts_with(if_name, "ppp")) {
        return InterfaceType::VPN;
    }
    if (starts_with(if_name, "docker") ||
        starts_with(if_name, "veth") ||
        starts_with(if_name, "br-") ||
        starts_with(if_name, "vmnet") ||
        starts_with(if_name, "vboxnet")) {
        return InterfaceType::VirtualDocker;
    }
    if (starts_with(if_name, "br") ||
        starts_with(if_name, "virbr")) {
        return InterfaceType::Bridge;
    }
    if (starts_with(if_name, "eth") ||
        starts_with(if_name, "en") ||
        starts_with(if_name, "em") ||
        starts_with(if_name, "wl") ||
        starts_with(if_name, "ww")) {
        return InterfaceType::Physical;
    }
    return InterfaceType::Unknown;
}

map<string, IPv4Address> InterfaceDiscovery::parse_proc_net_route_stream(
    istream& route_stream) {
    map<string, IPv4Address> gateways;
    string line;

    if (!getline(route_stream, line)) {
        return gateways;
    }

    while (getline(route_stream, line)) {
        if (line.empty()) {
            continue;
        }
        istringstream iss(line);
        string iface;
        string dest_hex;
        string gw_hex;
        unsigned int flags = 0;

        if (!(iss >> iface >> dest_hex >> gw_hex >> hex >> flags)) {
            continue;
        }

        if (dest_hex == "00000000" && (flags & 0x0003U) == 0x0003U) {
            try {
                const auto raw_gw = static_cast<uint32_t>(stoul(gw_hex, nullptr, 16));
                const IPv4Address gw_ip = IPv4Address::from_network_order(raw_gw);
                if (!gw_ip.is_unspecified()) {
                    gateways[iface] = gw_ip;
                }
            } catch (...) {
                continue;
            }
        }
    }

    return gateways;
}

vector<NetworkInterface> InterfaceDiscovery::discover_interfaces() {
    vector<NetworkInterface> result;

#if defined(__linux__)
    map<string, IPv4Address> default_gateways;
    {
        ifstream route_file("/proc/net/route");
        if (route_file.is_open()) {
            default_gateways = parse_proc_net_route_stream(route_file);
        }
    }

    ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0 || ifap == nullptr) {
        Logger::instance().error("InterfaceDiscovery", "getifaddrs() failed on Linux");
        return result;
    }
    unique_ptr<ifaddrs, decltype(&freeifaddrs)> ifap_guard(ifap, &freeifaddrs);

    map<string, MACAddress> mac_map;
    map<string, int> index_map;

    for (ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == nullptr || ifa->ifa_addr == nullptr) {
            continue;
        }
        const string if_name(ifa->ifa_name);
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            const auto* sll = reinterpret_cast<const sockaddr_ll*>(ifa->ifa_addr);
            index_map[if_name] = sll->sll_ifindex;
            if (sll->sll_halen == 6) {
                MACAddress::Bytes b{};
                memcpy(b.data(), sll->sll_addr, 6);
                mac_map[if_name] = MACAddress(b);
            }
        }
    }

    const int ioctl_fd = ::socket(AF_INET, SOCK_DGRAM, 0);

    for (ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == nullptr || ifa->ifa_addr == nullptr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        NetworkInterface net_if;
        net_if.name = ifa->ifa_name;
        net_if.is_up = (ifa->ifa_flags & IFF_UP) != 0;
        net_if.is_running = (ifa->ifa_flags & IFF_RUNNING) != 0;

        const bool is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
        const bool is_ptp = (ifa->ifa_flags & IFF_POINTOPOINT) != 0;

        const auto* sin_addr = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        net_if.ipv4 = IPv4Address::from_network_order(sin_addr->sin_addr.s_addr);

        if (ifa->ifa_netmask != nullptr) {
            const auto* sin_mask = reinterpret_cast<const sockaddr_in*>(ifa->ifa_netmask);
            net_if.netmask = IPv4Address::from_network_order(sin_mask->sin_addr.s_addr);
            net_if.cidr_prefix = CIDRBlock::netmask_to_prefix(net_if.netmask).value_or(24);
        }

        if ((ifa->ifa_flags & IFF_BROADCAST) != 0 && ifa->ifa_broadaddr != nullptr) {
            const auto* sin_bcast = reinterpret_cast<const sockaddr_in*>(ifa->ifa_broadaddr);
            net_if.broadcast = IPv4Address::from_network_order(sin_bcast->sin_addr.s_addr);
        } else if (net_if.cidr_prefix > 0 && net_if.cidr_prefix <= 30) {
            net_if.broadcast = CIDRBlock(net_if.ipv4, net_if.cidr_prefix).broadcast_address();
        }

        if (auto it = mac_map.find(net_if.name); it != mac_map.end()) {
            net_if.mac = it->second;
        } else if (ioctl_fd >= 0) {
            ifreq ifr{};
            strncpy(ifr.ifr_name, net_if.name.c_str(), IFNAMSIZ - 1);
            if (::ioctl(ioctl_fd, SIOCGIFHWADDR, &ifr) == 0) {
                MACAddress::Bytes b{};
                memcpy(b.data(), ifr.ifr_hwaddr.sa_data, 6);
                net_if.mac = MACAddress(b);
            }
        }

        if (auto it = index_map.find(net_if.name); it != index_map.end()) {
            net_if.index = it->second;
        } else {
            net_if.index = static_cast<int>(if_nametoindex(net_if.name.c_str()));
        }

        if (auto gw_it = default_gateways.find(net_if.name); gw_it != default_gateways.end()) {
            net_if.default_gateway = gw_it->second;
        }

        net_if.type = classify_interface_name(net_if.name, is_loopback, is_ptp);
        const filesystem::path sys_path = filesystem::path("/sys/class/net") / net_if.name;
        error_code ec;
        if (filesystem::exists(sys_path / "bridge", ec)) {
            net_if.type = InterfaceType::Bridge;
        } else if (net_if.type == InterfaceType::Unknown &&
                   filesystem::exists(sys_path / "device", ec)) {
            net_if.type = InterfaceType::Physical;
        }

        result.push_back(move(net_if));
    }

    if (ioctl_fd >= 0) {
        ::close(ioctl_fd);
    }

#elif defined(_WIN32)
    ULONG buf_len = 16384;
    vector<uint8_t> buffer(buf_len);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(buf_len);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &buf_len);
    }

    if (ret == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES cur = addresses; cur != nullptr; cur = cur->Next) {
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = cur->FirstUnicastAddress;
                 ua != nullptr; ua = ua->Next) {
                if (ua->Address.lpSockaddr == nullptr ||
                    ua->Address.lpSockaddr->sa_family != AF_INET) {
                    continue;
                }

                NetworkInterface net_if;
                net_if.name = cur->AdapterName ? cur->AdapterName : "unknown";
                if (cur->FriendlyName != nullptr) {
                    wstring ws(cur->FriendlyName);
                    string ascii_name;
                    for (wchar_t wc : ws) {
                        if (wc >= 32 && wc < 127) {
                            ascii_name.push_back(static_cast<char>(wc));
                        }
                    }
                    if (!ascii_name.empty()) {
                        net_if.name = ascii_name;
                    }
                }
                net_if.index = static_cast<int>(cur->IfIndex);
                net_if.is_up = (cur->OperStatus == IfOperStatusUp);
                net_if.is_running = net_if.is_up;

                if (cur->PhysicalAddressLength == 6) {
                    MACAddress::Bytes b{};
                    memcpy(b.data(), cur->PhysicalAddress, 6);
                    net_if.mac = MACAddress(b);
                }

                const auto* sin = reinterpret_cast<const sockaddr_in*>(ua->Address.lpSockaddr);
                net_if.ipv4 = IPv4Address::from_network_order(sin->sin_addr.s_addr);
                net_if.cidr_prefix = min<uint8_t>(ua->OnLinkPrefixLength, 32U);
                net_if.netmask = IPv4Address(CIDRBlock::prefix_to_mask_uint32(net_if.cidr_prefix));

                const CIDRBlock cidr(net_if.ipv4, net_if.cidr_prefix);
                if (net_if.cidr_prefix <= 30) {
                    net_if.broadcast = cidr.broadcast_address();
                }

                if (cur->FirstGatewayAddress != nullptr &&
                    cur->FirstGatewayAddress->Address.lpSockaddr != nullptr &&
                    cur->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET) {
                    const auto* gw_sin = reinterpret_cast<const sockaddr_in*>(
                        cur->FirstGatewayAddress->Address.lpSockaddr);
                    net_if.default_gateway =
                        IPv4Address::from_network_order(gw_sin->sin_addr.s_addr);
                }

                if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    net_if.type = InterfaceType::Loopback;
                } else if (cur->IfType == IF_TYPE_TUNNEL || cur->IfType == IF_TYPE_PPP) {
                    net_if.type = InterfaceType::VPN;
                } else if (cur->IfType == IF_TYPE_ETHERNET_CSMACD ||
                           cur->IfType == IF_TYPE_IEEE80211) {
                    net_if.type = InterfaceType::Physical;
                } else {
                    net_if.type = classify_interface_name(net_if.name, false, false);
                }

                result.push_back(move(net_if));
            }
        }
    }
#endif

    return result;
}

optional<NetworkInterface> InterfaceDiscovery::find_by_name(
    const vector<NetworkInterface>& interfaces,
    string_view name) {
    for (const auto& iface : interfaces) {
        if (iface.name == name) {
            return iface;
        }
    }
    return nullopt;
}

vector<NetworkInterface> InterfaceDiscovery::filter_lan_candidates(
    const vector<NetworkInterface>& interfaces) {
    vector<NetworkInterface> candidates;
    for (const auto& iface : interfaces) {
        if (iface.is_usable_lan_candidate()) {
            candidates.push_back(iface);
        }
    }
    return candidates;
}

} // namespace ntm::net
