#ifndef NTM_DISCOVERY_DISCOVERY_ENGINE_HPP
#define NTM_DISCOVERY_DISCOVERY_ENGINE_HPP

#include "ntm/net/interface_discovery.hpp"
#include "ntm/net/ip_address.hpp"
#include "ntm/utils/rate_limiter.hpp"
#include "ntm/utils/thread_pool.hpp"

#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ntm::discovery {

using namespace std;
using namespace ntm::net;
using namespace ntm::utils;

enum class DiscoveryMethod {
    ARP,
    ICMP,
    TCP,
    OS_ARP_CACHE
};

enum class ProbeOutcome {
    Responded,
    TcpConnectionRefused,
    Timeout,
    Unreachable,
    PermissionDenied,
    OutOfSubnetScope,
    SocketError
};

enum class TcpPortState {
    Open,
    Refused,
    Timeout,
    Error
};

struct ProbeResult {
    DiscoveryMethod method{DiscoveryMethod::ICMP};
    ProbeOutcome outcome{ProbeOutcome::Timeout};
    IPv4Address target_ip;
    optional<MACAddress> observed_mac;
    optional<double> rtt_ms;
    vector<uint16_t> open_tcp_ports;
    vector<uint16_t> refused_tcp_ports;
    string detail;

    [[nodiscard]] bool indicates_host_alive() const noexcept {
        return outcome == ProbeOutcome::Responded ||
               outcome == ProbeOutcome::TcpConnectionRefused;
    }
};

struct HostDiscoveryRecord {
    IPv4Address ip;
    optional<MACAddress> mac;
    optional<string> hostname;
    bool reachable{false};
    optional<double> best_rtt_ms;
    vector<DiscoveryMethod> successful_methods;
    vector<ProbeResult> probe_results;
    vector<uint16_t> open_ports;
};

class IDiscoveryProbe {
public:
    virtual ~IDiscoveryProbe() = default;

    [[nodiscard]] virtual DiscoveryMethod method() const noexcept = 0;
    [[nodiscard]] virtual string_view name() const noexcept = 0;
    [[nodiscard]] virtual bool check_permissions(string* error_reason = nullptr) const = 0;
    [[nodiscard]] virtual ProbeResult probe(
        const IPv4Address& target_ip,
        uint32_t timeout_ms) = 0;
};

struct L2NeighborObservation {
    string local_interface;
    string chassis_id;
    string port_id;
    string system_name;
    string protocol_source;
};

class IL2TopologyProtocolPlugin {
public:
    virtual ~IL2TopologyProtocolPlugin() = default;
    [[nodiscard]] virtual string_view protocol_name() const noexcept = 0;
    [[nodiscard]] virtual vector<L2NeighborObservation> collect_observations(
        const NetworkInterface& iface,
        uint32_t timeout_ms) = 0;
};

class ArpDiscoveryProbe final : public IDiscoveryProbe {
public:
    explicit ArpDiscoveryProbe(NetworkInterface local_interface);

    [[nodiscard]] DiscoveryMethod method() const noexcept override { return DiscoveryMethod::ARP; }
    [[nodiscard]] string_view name() const noexcept override { return "ARP"; }
    [[nodiscard]] bool check_permissions(string* error_reason = nullptr) const override;
    [[nodiscard]] ProbeResult probe(
        const IPv4Address& target_ip,
        uint32_t timeout_ms) override;

private:
    NetworkInterface iface_;
};

class IcmpDiscoveryProbe final : public IDiscoveryProbe {
public:
    IcmpDiscoveryProbe() = default;

    [[nodiscard]] DiscoveryMethod method() const noexcept override { return DiscoveryMethod::ICMP; }
    [[nodiscard]] string_view name() const noexcept override { return "ICMP"; }
    [[nodiscard]] bool check_permissions(string* error_reason = nullptr) const override;
    [[nodiscard]] ProbeResult probe(
        const IPv4Address& target_ip,
        uint32_t timeout_ms) override;
};

class TcpConnectProbe final : public IDiscoveryProbe {
public:
    explicit TcpConnectProbe(vector<uint16_t> ports = {22, 80, 443, 8080});

    [[nodiscard]] DiscoveryMethod method() const noexcept override { return DiscoveryMethod::TCP; }
    [[nodiscard]] string_view name() const noexcept override { return "TCP"; }
    [[nodiscard]] bool check_permissions(string* error_reason = nullptr) const override;
    [[nodiscard]] ProbeResult probe(
        const IPv4Address& target_ip,
        uint32_t timeout_ms) override;

    [[nodiscard]] static TcpPortState probe_single_port(
        const IPv4Address& target_ip,
        uint16_t port,
        uint32_t timeout_ms,
        double* out_rtt_ms = nullptr);

private:
    vector<uint16_t> ports_;
};

class ReverseDnsResolver {
public:
    [[nodiscard]] static optional<string> resolve_ptr(const IPv4Address& ip) noexcept;
};

class OsArpCacheReader {
public:
    [[nodiscard]] static map<IPv4Address, MACAddress> read_system_arp_cache(
        string_view interface_filter = "");

    [[nodiscard]] static map<IPv4Address, MACAddress> parse_proc_net_arp_stream(
        istream& arp_stream,
        string_view interface_filter = "");
};

struct DiscoveryConfig {
    NetworkInterface local_interface;
    vector<DiscoveryMethod> enabled_methods{
        DiscoveryMethod::ARP,
        DiscoveryMethod::ICMP,
        DiscoveryMethod::TCP
    };
    vector<uint16_t> tcp_ports{22, 80, 443, 8080};
    bool enable_reverse_dns{true};
    size_t worker_threads{8};
    RateLimitConfig rate_limit{};
};

struct DiscoverySummary {
    vector<HostDiscoveryRecord> records;
    vector<DiscoveryMethod> active_methods;
    vector<string> warnings;
    size_t total_targets_probed{0};
    size_t responsive_hosts_count{0};
    double elapsed_seconds{0.0};
};

class DiscoveryCoordinator {
public:
    explicit DiscoveryCoordinator(DiscoveryConfig config);

    [[nodiscard]] DiscoverySummary execute(const vector<IPv4Address>& targets);

    [[nodiscard]] static string_view method_to_string(DiscoveryMethod method) noexcept;

private:
    DiscoveryConfig config_;
};

} // namespace ntm::discovery

#endif // NTM_DISCOVERY_DISCOVERY_ENGINE_HPP
