#include "ntm/discovery/discovery_engine.hpp"
#include "ntm/discovery/packet_headers.hpp"
#include "ntm/utils/logger.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <future>
#include <mutex>
#include <sstream>
#include <thread>

#if defined(__linux__)
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
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

namespace ntm::discovery {

using namespace std;
using namespace chrono;
using namespace ntm::net;
using namespace ntm::utils;

namespace {

atomic<uint16_t> g_icmp_sequence{1};

#if defined(__linux__)
class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}
    ~ScopedFd() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_;
};
#endif

} // namespace

string_view DiscoveryCoordinator::method_to_string(DiscoveryMethod method) noexcept {
    switch (method) {
        case DiscoveryMethod::ARP:          return "ARP";
        case DiscoveryMethod::ICMP:         return "ICMP";
        case DiscoveryMethod::TCP:          return "TCP";
        case DiscoveryMethod::OS_ARP_CACHE: return "OS_ARP_CACHE";
    }
    return "UNKNOWN";
}

// ============================================================================
// ArpDiscoveryProbe
// ============================================================================

ArpDiscoveryProbe::ArpDiscoveryProbe(NetworkInterface local_interface)
    : iface_(move(local_interface)) {}

bool ArpDiscoveryProbe::check_permissions(string* error_reason) const {
#if defined(__linux__)
    ScopedFd fd(::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP)));
    if (!fd.valid()) {
        if (error_reason != nullptr) {
            if (errno == EPERM || errno == EACCES) {
                *error_reason =
                    "ARP raw socket (AF_PACKET) requires CAP_NET_RAW capability "
                    "(e.g., 'sudo setcap cap_net_raw+ep ./ntm').";
            } else {
                *error_reason = string("AF_PACKET socket failed: ") + strerror(errno);
            }
        }
        return false;
    }
    return true;
#else
    if (error_reason != nullptr) {
        *error_reason = "AF_PACKET raw ARP socket is only supported natively on Linux.";
    }
    return false;
#endif
}

ProbeResult ArpDiscoveryProbe::probe(
    const IPv4Address& target_ip,
    uint32_t timeout_ms) {
    ProbeResult result;
    result.method = DiscoveryMethod::ARP;
    result.target_ip = target_ip;

    if (!iface_.subnet_cidr().contains(target_ip)) {
        result.outcome = ProbeOutcome::OutOfSubnetScope;
        result.detail = "Target IP is outside local interface subnet; Layer-2 ARP aborted.";
        return result;
    }

    if (iface_.mac.is_zero() || iface_.index <= 0) {
        result.outcome = ProbeOutcome::SocketError;
        result.detail = "Local interface lacks valid hardware MAC or interface index.";
        return result;
    }

#if defined(__linux__)
    ScopedFd fd(::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP)));
    if (!fd.valid()) {
        if (errno == EPERM || errno == EACCES) {
            result.outcome = ProbeOutcome::PermissionDenied;
            result.detail = "Permission denied opening AF_PACKET socket (CAP_NET_RAW required).";
        } else {
            result.outcome = ProbeOutcome::SocketError;
            result.detail = string("socket(AF_PACKET) error: ") + strerror(errno);
        }
        return result;
    }

    sockaddr_ll bind_addr{};
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ARP);
    bind_addr.sll_ifindex = iface_.index;

    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        result.outcome = ProbeOutcome::SocketError;
        result.detail = string("bind(AF_PACKET) failed: ") + strerror(errno);
        return result;
    }

    const auto frame = PacketCodec::build_arp_request_frame(
        iface_.mac, iface_.ipv4, target_ip);

    sockaddr_ll dst_addr{};
    dst_addr.sll_family = AF_PACKET;
    dst_addr.sll_protocol = htons(ETH_P_ARP);
    dst_addr.sll_ifindex = iface_.index;
    dst_addr.sll_halen = ETH_ALEN;
    memset(dst_addr.sll_addr, 0xFF, ETH_ALEN);

    const auto start_time = steady_clock::now();
    const ssize_t sent = ::sendto(
        fd.get(),
        frame.data(),
        frame.size(),
        0,
        reinterpret_cast<const sockaddr*>(&dst_addr),
        sizeof(dst_addr));

    if (sent < 0 || static_cast<size_t>(sent) != frame.size()) {
        result.outcome = ProbeOutcome::SocketError;
        result.detail = string("ARP sendto() failed: ") + strerror(errno);
        return result;
    }

    const auto deadline = start_time + milliseconds(timeout_ms);
    array<uint8_t, 1514> recv_buf{};

    while (true) {
        const auto now = steady_clock::now();
        if (now >= deadline) {
            result.outcome = ProbeOutcome::Timeout;
            result.detail = "No ARP Reply within timeout.";
            break;
        }

        const auto remaining_ms = duration_cast<milliseconds>(deadline - now).count();

        pollfd pfd{};
        pfd.fd = fd.get();
        pfd.events = POLLIN;

        const int pr = ::poll(&pfd, 1, static_cast<int>(max<long long>(1, remaining_ms)));
        if (pr == 0) {
            result.outcome = ProbeOutcome::Timeout;
            result.detail = "No ARP Reply within timeout.";
            break;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result.outcome = ProbeOutcome::SocketError;
            result.detail = string("poll() failed: ") + strerror(errno);
            break;
        }

        const ssize_t rlen = ::recvfrom(
            fd.get(), recv_buf.data(), recv_buf.size(), 0, nullptr, nullptr);
        if (rlen <= 0) {
            continue;
        }

        const auto parsed_arp = PacketCodec::parse_arp_ethernet_frame(
            recv_buf.data(), static_cast<size_t>(rlen));

        if (!parsed_arp.has_value()) {
            continue;
        }

        if (parsed_arp->operation == kArpOpReply &&
            parsed_arp->sender_ip == target_ip &&
            !parsed_arp->sender_mac.is_zero()) {
            const auto end_time = steady_clock::now();
            const double rtt = duration<double, milli>(end_time - start_time).count();

            result.outcome = ProbeOutcome::Responded;
            result.observed_mac = parsed_arp->sender_mac;
            result.rtt_ms = rtt;
            result.detail = "Direct Layer-2 ARP Reply received (" +
                            parsed_arp->sender_mac.to_string() + ")";
            return result;
        }
    }

    return result;
#else
    (void)timeout_ms;
    result.outcome = ProbeOutcome::PermissionDenied;
    result.detail = "AF_PACKET ARP requires Linux.";
    return result;
#endif
}

// ============================================================================
// IcmpDiscoveryProbe
// ============================================================================

bool IcmpDiscoveryProbe::check_permissions(string* error_reason) const {
#if defined(__linux__)
    ScopedFd raw_fd(::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    if (raw_fd.valid()) {
        return true;
    }
    ScopedFd dgram_fd(::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP));
    if (dgram_fd.valid()) {
        return true;
    }
    if (error_reason != nullptr) {
        if (errno == EPERM || errno == EACCES) {
            *error_reason =
                "ICMP socket requires CAP_NET_RAW capability or net.ipv4.ping_group_range permission.";
        } else {
            *error_reason = string("ICMP socket creation failed: ") + strerror(errno);
        }
    }
    return false;
#else
    if (error_reason != nullptr) {
        *error_reason = "POSIX Raw ICMP probe is only active on Linux.";
    }
    return false;
#endif
}

ProbeResult IcmpDiscoveryProbe::probe(
    const IPv4Address& target_ip,
    uint32_t timeout_ms) {
    ProbeResult result;
    result.method = DiscoveryMethod::ICMP;
    result.target_ip = target_ip;

#if defined(__linux__)
    bool is_raw_socket = true;
    int sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        is_raw_socket = false;
    }

    ScopedFd fd(sock);
    if (!fd.valid()) {
        if (errno == EPERM || errno == EACCES) {
            result.outcome = ProbeOutcome::PermissionDenied;
            result.detail = "Permission denied opening ICMP socket (CAP_NET_RAW required).";
        } else {
            result.outcome = ProbeOutcome::SocketError;
            result.detail = string("socket(IPPROTO_ICMP) failed: ") + strerror(errno);
        }
        return result;
    }

    const uint16_t ident = static_cast<uint16_t>(::getpid() & 0xFFFF);
    const uint16_t seq = g_icmp_sequence.fetch_add(1, memory_order_relaxed);
    const auto packet = PacketCodec::build_icmp_echo_request(ident, seq);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_ip.to_network_order();

    const auto start_time = steady_clock::now();
    const ssize_t sent = ::sendto(
        fd.get(),
        packet.data(),
        packet.size(),
        0,
        reinterpret_cast<const sockaddr*>(&dst),
        sizeof(dst));

    if (sent < 0) {
        if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
            result.outcome = ProbeOutcome::Unreachable;
            result.detail = string("ICMP destination unreachable: ") + strerror(errno);
        } else {
            result.outcome = ProbeOutcome::SocketError;
            result.detail = string("ICMP sendto() failed: ") + strerror(errno);
        }
        return result;
    }

    const auto deadline = start_time + milliseconds(timeout_ms);
    array<uint8_t, 1024> recv_buf{};

    while (true) {
        const auto now = steady_clock::now();
        if (now >= deadline) {
            result.outcome = ProbeOutcome::Timeout;
            result.detail = "ICMP Echo Request timed out (note: host may filter ICMP).";
            break;
        }

        const auto remaining_ms = duration_cast<milliseconds>(deadline - now).count();

        pollfd pfd{};
        pfd.fd = fd.get();
        pfd.events = POLLIN;

        const int pr = ::poll(&pfd, 1, static_cast<int>(max<long long>(1, remaining_ms)));
        if (pr == 0) {
            result.outcome = ProbeOutcome::Timeout;
            result.detail = "ICMP Echo Request timed out.";
            break;
        }
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result.outcome = ProbeOutcome::SocketError;
            result.detail = string("ICMP poll() error: ") + strerror(errno);
            break;
        }

        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        const ssize_t rlen = ::recvfrom(
            fd.get(),
            recv_buf.data(),
            recv_buf.size(),
            0,
            reinterpret_cast<sockaddr*>(&from_addr),
            &from_len);

        if (rlen <= 0) {
            continue;
        }

        const IPv4Address sender_ip =
            IPv4Address::from_network_order(from_addr.sin_addr.s_addr);

        const auto parsed_icmp = PacketCodec::parse_icmp_packet(
            recv_buf.data(),
            static_cast<size_t>(rlen),
            is_raw_socket);

        if (!parsed_icmp.has_value()) {
            continue;
        }

        if (parsed_icmp->type == kIcmpTypeEchoReply &&
            sender_ip == target_ip &&
            parsed_icmp->sequence == seq &&
            (!is_raw_socket || parsed_icmp->identifier == ident)) {
            const auto end_time = steady_clock::now();
            const double rtt = duration<double, milli>(end_time - start_time).count();

            result.outcome = ProbeOutcome::Responded;
            result.rtt_ms = rtt;
            result.detail = "ICMP Echo Reply verified (seq=" + to_string(seq) + ")";
            return result;
        }

        if (parsed_icmp->type == kIcmpTypeDestUnreachable) {
            result.outcome = ProbeOutcome::Unreachable;
            result.detail = "ICMP Destination Unreachable received from " + sender_ip.to_string();
            return result;
        }
    }

    return result;
#else
    (void)timeout_ms;
    result.outcome = ProbeOutcome::PermissionDenied;
    result.detail = "POSIX Raw ICMP requires Linux.";
    return result;
#endif
}

// ============================================================================
// TcpConnectProbe
// ============================================================================

TcpConnectProbe::TcpConnectProbe(vector<uint16_t> ports)
    : ports_(move(ports)) {
    if (ports_.empty()) {
        ports_ = {22, 80, 443, 8080};
    }
}

bool TcpConnectProbe::check_permissions(string* /*error_reason*/) const {
    return true;
}

TcpPortState TcpConnectProbe::probe_single_port(
    const IPv4Address& target_ip,
    uint16_t port,
    uint32_t timeout_ms,
    double* out_rtt_ms) {
#if defined(__linux__)
    ScopedFd fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd.valid()) {
        return TcpPortState::Error;
    }

    const int flags = ::fcntl(fd.get(), F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK) < 0) {
        return TcpPortState::Error;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = target_ip.to_network_order();

    const auto start_time = steady_clock::now();
    const int rc = ::connect(fd.get(), reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (rc == 0) {
        if (out_rtt_ms != nullptr) {
            const auto end_time = steady_clock::now();
            *out_rtt_ms = duration<double, milli>(end_time - start_time).count();
        }
        return TcpPortState::Open;
    }

    if (errno != EINPROGRESS) {
        if (errno == ECONNREFUSED) {
            if (out_rtt_ms != nullptr) {
                const auto end_time = steady_clock::now();
                *out_rtt_ms = duration<double, milli>(end_time - start_time).count();
            }
            return TcpPortState::Refused;
        }
        return TcpPortState::Error;
    }

    pollfd pfd{};
    pfd.fd = fd.get();
    pfd.events = POLLOUT;

    const int pr = ::poll(&pfd, 1, static_cast<int>(timeout_ms));
    if (pr == 0) {
        return TcpPortState::Timeout;
    }
    if (pr < 0) {
        return TcpPortState::Error;
    }

    int so_error = 0;
    socklen_t err_len = sizeof(so_error);
    if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &err_len) < 0) {
        return TcpPortState::Error;
    }

    const auto end_time = steady_clock::now();
    if (out_rtt_ms != nullptr) {
        *out_rtt_ms = duration<double, milli>(end_time - start_time).count();
    }

    if (so_error == 0) {
        return TcpPortState::Open;
    }
    if (so_error == ECONNREFUSED) {
        return TcpPortState::Refused;
    }
    return TcpPortState::Timeout;

#elif defined(_WIN32)
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return TcpPortState::Error;
    }

    u_long non_blocking = 1;
    if (::ioctlsocket(sock, FIONBIO, &non_blocking) != 0) {
        ::closesocket(sock);
        return TcpPortState::Error;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = target_ip.to_network_order();

    const auto start_time = steady_clock::now();
    const int rc = ::connect(sock, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    if (rc == 0) {
        if (out_rtt_ms != nullptr) {
            const auto end_time = steady_clock::now();
            *out_rtt_ms = duration<double, milli>(end_time - start_time).count();
        }
        ::closesocket(sock);
        return TcpPortState::Open;
    }

    const int wsa_err = WSAGetLastError();
    if (wsa_err != WSAEWOULDBLOCK && wsa_err != WSAEINPROGRESS) {
        ::closesocket(sock);
        return (wsa_err == WSAECONNREFUSED) ? TcpPortState::Refused : TcpPortState::Error;
    }

    fd_set write_set;
    fd_set except_set;
    FD_ZERO(&write_set);
    FD_ZERO(&except_set);
    FD_SET(sock, &write_set);
    FD_SET(sock, &except_set);

    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout_ms / 1000U);
    tv.tv_usec = static_cast<long>((timeout_ms % 1000U) * 1000U);

    const int sr = ::select(0, nullptr, &write_set, &except_set, &tv);
    if (sr == 0) {
        ::closesocket(sock);
        return TcpPortState::Timeout;
    }
    if (sr == SOCKET_ERROR) {
        ::closesocket(sock);
        return TcpPortState::Error;
    }

    int so_error = 0;
    int err_len = sizeof(so_error);
    ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &err_len);
    ::closesocket(sock);

    const auto end_time = steady_clock::now();
    if (out_rtt_ms != nullptr) {
        *out_rtt_ms = duration<double, milli>(end_time - start_time).count();
    }

    if (so_error == 0 && FD_ISSET(sock, &write_set)) {
        return TcpPortState::Open;
    }
    if (so_error == WSAECONNREFUSED) {
        return TcpPortState::Refused;
    }
    return TcpPortState::Timeout;
#endif
}

ProbeResult TcpConnectProbe::probe(
    const IPv4Address& target_ip,
    uint32_t timeout_ms) {
    ProbeResult result;
    result.method = DiscoveryMethod::TCP;
    result.target_ip = target_ip;
    result.outcome = ProbeOutcome::Timeout;

    const uint32_t per_port_timeout = max<uint32_t>(
        150U, timeout_ms / static_cast<uint32_t>(max<size_t>(1, ports_.size())));

    optional<double> min_rtt;

    for (uint16_t port : ports_) {
        double rtt = 0.0;
        const TcpPortState state = probe_single_port(target_ip, port, per_port_timeout, &rtt);
        if (state == TcpPortState::Open) {
            result.open_tcp_ports.push_back(port);
            if (!min_rtt.has_value() || rtt < *min_rtt) {
                min_rtt = rtt;
            }
        } else if (state == TcpPortState::Refused) {
            result.refused_tcp_ports.push_back(port);
            if (!min_rtt.has_value() || rtt < *min_rtt) {
                min_rtt = rtt;
            }
        }
    }

    if (!result.open_tcp_ports.empty()) {
        result.outcome = ProbeOutcome::Responded;
        result.rtt_ms = min_rtt;
        ostringstream oss;
        oss << "TCP SYN-ACK Open on port(s): ";
        for (size_t i = 0; i < result.open_tcp_ports.size(); ++i) {
            if (i > 0) oss << ',';
            oss << result.open_tcp_ports[i];
        }
        result.detail = oss.str();
    } else if (!result.refused_tcp_ports.empty()) {
        result.outcome = ProbeOutcome::TcpConnectionRefused;
        result.rtt_ms = min_rtt;
        result.detail = "TCP RST (Connection Refused) proves host IP stack is active.";
    } else {
        result.outcome = ProbeOutcome::Timeout;
        result.detail = "All configured TCP probe ports timed out.";
    }

    return result;
}

// ============================================================================
// ReverseDnsResolver
// ============================================================================

optional<string> ReverseDnsResolver::resolve_ptr(const IPv4Address& ip) noexcept {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip.to_network_order();

    array<char, NI_MAXHOST> host_buf{};
    const int rc = ::getnameinfo(
        reinterpret_cast<const sockaddr*>(&sa),
        sizeof(sa),
        host_buf.data(),
        static_cast<socklen_t>(host_buf.size()),
        nullptr,
        0,
        NI_NAMEREQD);

    if (rc != 0) {
        return nullopt;
    }

    string hostname(host_buf.data());
    if (hostname.empty() || hostname == ip.to_string()) {
        return nullopt;
    }
    return hostname;
}

// ============================================================================
// OsArpCacheReader
// ============================================================================

map<IPv4Address, MACAddress> OsArpCacheReader::parse_proc_net_arp_stream(
    istream& arp_stream,
    string_view interface_filter) {
    map<IPv4Address, MACAddress> cache;
    string line;

    if (!getline(arp_stream, line)) {
        return cache;
    }

    while (getline(arp_stream, line)) {
        if (line.empty()) {
            continue;
        }
        istringstream iss(line);
        string ip_str;
        string hw_type;
        string flags_str;
        string mac_str;
        string mask_str;
        string dev_str;

        if (!(iss >> ip_str >> hw_type >> flags_str >> mac_str >> mask_str >> dev_str)) {
            continue;
        }

        if (!interface_filter.empty() && dev_str != interface_filter) {
            continue;
        }

        if (flags_str == "0x0" || flags_str == "0x00") {
            continue;
        }

        const auto ip_opt = IPv4Address::parse(ip_str);
        const auto mac_opt = MACAddress::parse(mac_str);

        if (ip_opt.has_value() && mac_opt.has_value() && !mac_opt->is_zero()) {
            cache[*ip_opt] = *mac_opt;
        }
    }

    return cache;
}

map<IPv4Address, MACAddress> OsArpCacheReader::read_system_arp_cache(
    string_view interface_filter) {
#if defined(__linux__)
    ifstream arp_file("/proc/net/arp");
    if (!arp_file.is_open()) {
        return {};
    }
    return parse_proc_net_arp_stream(arp_file, interface_filter);
#else
    (void)interface_filter;
    return {};
#endif
}

// ============================================================================
// DiscoveryCoordinator
// ============================================================================

DiscoveryCoordinator::DiscoveryCoordinator(DiscoveryConfig config)
    : config_(move(config)) {}

DiscoverySummary DiscoveryCoordinator::execute(const vector<IPv4Address>& targets) {
    const auto start_clock = steady_clock::now();
    DiscoverySummary summary;
    summary.total_targets_probed = targets.size();

    if (targets.empty()) {
        return summary;
    }

    vector<shared_ptr<IDiscoveryProbe>> active_probes;
    for (DiscoveryMethod method : config_.enabled_methods) {
        shared_ptr<IDiscoveryProbe> probe;
        if (method == DiscoveryMethod::ARP) {
            probe = make_shared<ArpDiscoveryProbe>(config_.local_interface);
        } else if (method == DiscoveryMethod::ICMP) {
            probe = make_shared<IcmpDiscoveryProbe>();
        } else if (method == DiscoveryMethod::TCP) {
            probe = make_shared<TcpConnectProbe>(config_.tcp_ports);
        }

        if (!probe) {
            continue;
        }

        string perm_error;
        if (probe->check_permissions(&perm_error)) {
            active_probes.push_back(probe);
            summary.active_methods.push_back(method);
        } else {
            const string warn_msg =
                "Discovery method [" + string(probe->name()) + "] unavailable: " + perm_error;
            summary.warnings.push_back(warn_msg);
            Logger::instance().warn("DiscoveryCoordinator", warn_msg);
        }
    }

    if (active_probes.empty()) {
        const string fallback_msg =
            "No raw socket privileges available; automatically falling back to unprivileged TCP Connect Probe.";
        summary.warnings.push_back(fallback_msg);
        Logger::instance().warn("DiscoveryCoordinator", fallback_msg);

        active_probes.push_back(make_shared<TcpConnectProbe>(config_.tcp_ports));
        summary.active_methods.push_back(DiscoveryMethod::TCP);
    }

    ThreadPool pool(config_.worker_threads);
    RateLimiter limiter(config_.rate_limit);

    vector<future<HostDiscoveryRecord>> futures;
    futures.reserve(targets.size());

    for (const auto& ip : targets) {
        if (ip == config_.local_interface.ipv4) {
            continue;
        }

        futures.push_back(pool.submit([this, ip, &active_probes, &limiter]() {
            HostDiscoveryRecord record;
            record.ip = ip;

            for (const auto& probe : active_probes) {
                ProbeResult pr;
                const uint32_t max_attempts = 1U + limiter.config().retry_count;

                for (uint32_t attempt = 0; attempt < max_attempts; ++attempt) {
                    auto permit = limiter.acquire_permit();
                    pr = probe->probe(ip, limiter.config().timeout_ms);
                    if (pr.indicates_host_alive() ||
                        pr.outcome == ProbeOutcome::PermissionDenied ||
                        pr.outcome == ProbeOutcome::OutOfSubnetScope) {
                        break;
                    }
                }

                if (pr.indicates_host_alive()) {
                    record.reachable = true;
                    record.successful_methods.push_back(probe->method());

                    if (pr.observed_mac.has_value() && !pr.observed_mac->is_zero()) {
                        record.mac = pr.observed_mac;
                    }
                    if (pr.rtt_ms.has_value()) {
                        if (!record.best_rtt_ms.has_value() || *pr.rtt_ms < *record.best_rtt_ms) {
                            record.best_rtt_ms = pr.rtt_ms;
                        }
                    }
                    for (uint16_t port : pr.open_tcp_ports) {
                        if (find(record.open_ports.begin(), record.open_ports.end(), port) ==
                            record.open_ports.end()) {
                            record.open_ports.push_back(port);
                        }
                    }
                }

                record.probe_results.push_back(move(pr));
            }

            if (record.reachable && config_.enable_reverse_dns) {
                record.hostname = ReverseDnsResolver::resolve_ptr(ip);
            }

            return record;
        }));
    }

    map<IPv4Address, HostDiscoveryRecord> record_map;
    for (auto& fut : futures) {
        try {
            HostDiscoveryRecord rec = fut.get();
            record_map[rec.ip] = move(rec);
        } catch (const exception& ex) {
            Logger::instance().error("DiscoveryCoordinator", ex.what());
        }
    }

    const auto arp_cache = OsArpCacheReader::read_system_arp_cache(config_.local_interface.name);
    for (auto& [ip, rec] : record_map) {
        if (!rec.mac.has_value()) {
            if (auto it = arp_cache.find(ip); it != arp_cache.end()) {
                rec.mac = it->second;
                rec.reachable = true;
                if (find(rec.successful_methods.begin(),
                         rec.successful_methods.end(),
                         DiscoveryMethod::OS_ARP_CACHE) == rec.successful_methods.end()) {
                    rec.successful_methods.push_back(DiscoveryMethod::OS_ARP_CACHE);
                }
                if (config_.enable_reverse_dns && !rec.hostname.has_value()) {
                    rec.hostname = ReverseDnsResolver::resolve_ptr(ip);
                }
            }
        }
    }

    summary.records.reserve(record_map.size());
    for (auto& [ip, rec] : record_map) {
        if (rec.reachable) {
            ++summary.responsive_hosts_count;
        }
        summary.records.push_back(move(rec));
    }

    const auto end_clock = steady_clock::now();
    summary.elapsed_seconds = duration<double>(end_clock - start_clock).count();

    return summary;
}

} // namespace ntm::discovery
