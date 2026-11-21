#include "ntm/net/ip_address.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace ntm::net {

using namespace std;

namespace {

string_view trim_view(string_view sv) noexcept {
    while (!sv.empty() && isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return sv;
}

optional<uint8_t> parse_decimal_octet(string_view sv) noexcept {
    if (sv.empty() || sv.size() > 3) {
        return nullopt;
    }
    if (sv.size() > 1 && sv.front() == '0') {
        return nullopt;
    }
    uint32_t val = 0;
    for (char c : sv) {
        if (c < '0' || c > '9') {
            return nullopt;
        }
        val = val * 10U + static_cast<uint32_t>(c - '0');
    }
    if (val > 255U) {
        return nullopt;
    }
    return static_cast<uint8_t>(val);
}

optional<uint8_t> parse_hex_byte(string_view sv) noexcept {
    if (sv.size() != 2) {
        return nullopt;
    }
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    const int hi = hex_val(sv[0]);
    const int lo = hex_val(sv[1]);
    if (hi < 0 || lo < 0) {
        return nullopt;
    }
    return static_cast<uint8_t>((hi << 4) | lo);
}

} // namespace

optional<IPv4Address> IPv4Address::parse(string_view str) noexcept {
    str = trim_view(str);
    if (str.empty()) {
        return nullopt;
    }

    array<uint8_t, 4> oct{};
    size_t start = 0;

    for (size_t i = 0; i < 4; ++i) {
        const size_t dot = str.find('.', start);
        if (i < 3 && dot == string_view::npos) {
            return nullopt;
        }
        if (i == 3 && dot != string_view::npos) {
            return nullopt;
        }
        const string_view part = (i < 3)
            ? str.substr(start, dot - start)
            : str.substr(start);

        const auto parsed = parse_decimal_octet(part);
        if (!parsed.has_value()) {
            return nullopt;
        }
        oct[i] = *parsed;
        start = dot + 1;
    }

    return IPv4Address(oct[0], oct[1], oct[2], oct[3]);
}

IPv4Address IPv4Address::from_network_order(uint32_t net_order) noexcept {
    return IPv4Address(ntohl(net_order));
}

uint32_t IPv4Address::to_network_order() const noexcept {
    return htonl(host_order_);
}

array<uint8_t, 4> IPv4Address::octets() const noexcept {
    return {
        static_cast<uint8_t>((host_order_ >> 24U) & 0xFFU),
        static_cast<uint8_t>((host_order_ >> 16U) & 0xFFU),
        static_cast<uint8_t>((host_order_ >> 8U) & 0xFFU),
        static_cast<uint8_t>(host_order_ & 0xFFU)
    };
}

string IPv4Address::to_string() const {
    const auto oct = octets();
    ostringstream oss;
    oss << static_cast<unsigned>(oct[0]) << '.'
        << static_cast<unsigned>(oct[1]) << '.'
        << static_cast<unsigned>(oct[2]) << '.'
        << static_cast<unsigned>(oct[3]);
    return oss.str();
}

bool IPv4Address::is_unspecified() const noexcept {
    return (host_order_ & 0xFF000000U) == 0x00000000U;
}

bool IPv4Address::is_loopback() const noexcept {
    return (host_order_ & 0xFF000000U) == 0x7F000000U;
}

bool IPv4Address::is_private_rfc1918() const noexcept {
    if ((host_order_ & 0xFF000000U) == 0x0A000000U) {
        return true;
    }
    if ((host_order_ & 0xFFF00000U) == 0xAC100000U) {
        return true;
    }
    if ((host_order_ & 0xFFFF0000U) == 0xC0A80000U) {
        return true;
    }
    return false;
}

bool IPv4Address::is_link_local() const noexcept {
    return (host_order_ & 0xFFFF0000U) == 0xA9FE0000U;
}

bool IPv4Address::is_cgnat() const noexcept {
    return (host_order_ & 0xFFC00000U) == 0x64400000U;
}

bool IPv4Address::is_multicast() const noexcept {
    return (host_order_ & 0xF0000000U) == 0xE0000000U;
}

bool IPv4Address::is_limited_broadcast() const noexcept {
    return host_order_ == 0xFFFFFFFFU;
}

bool IPv4Address::is_reserved() const noexcept {
    return ((host_order_ & 0xF0000000U) == 0xF0000000U) && !is_limited_broadcast();
}

optional<MACAddress> MACAddress::parse(string_view str) noexcept {
    str = trim_view(str);
    if (str.size() != 17) {
        return nullopt;
    }

    const char sep = str[2];
    if (sep != ':' && sep != '-') {
        return nullopt;
    }

    Bytes out{};
    for (size_t i = 0; i < 6; ++i) {
        const size_t pos = i * 3;
        if (i > 0 && str[pos - 1] != sep) {
            return nullopt;
        }
        const auto byte_opt = parse_hex_byte(str.substr(pos, 2));
        if (!byte_opt.has_value()) {
            return nullopt;
        }
        out[i] = *byte_opt;
    }

    return MACAddress(out);
}

string MACAddress::to_string() const {
    ostringstream oss;
    oss << uppercase << hex << setfill('0');
    for (size_t i = 0; i < bytes_.size(); ++i) {
        if (i > 0) {
            oss << ':';
        }
        oss << setw(2) << static_cast<unsigned>(bytes_[i]);
    }
    return oss.str();
}

string MACAddress::to_compact_hex() const {
    ostringstream oss;
    oss << uppercase << hex << setfill('0');
    for (uint8_t b : bytes_) {
        oss << setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

bool MACAddress::is_zero() const noexcept {
    return all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0; });
}

bool MACAddress::is_broadcast() const noexcept {
    return all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0xFFU; });
}

bool MACAddress::is_multicast() const noexcept {
    return (bytes_[0] & 0x01U) != 0 && !is_broadcast();
}

bool MACAddress::is_locally_administered() const noexcept {
    return (bytes_[0] & 0x02U) != 0 && !is_broadcast();
}

CIDRBlock::CIDRBlock(IPv4Address address, uint8_t prefix_length) noexcept
    : input_address_(address),
      prefix_length_(min<uint8_t>(prefix_length, 32U)) {}

uint32_t CIDRBlock::prefix_to_mask_uint32(uint8_t prefix_length) noexcept {
    if (prefix_length == 0) {
        return 0x00000000U;
    }
    if (prefix_length >= 32) {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32U - prefix_length);
}

optional<uint8_t> CIDRBlock::netmask_to_prefix(IPv4Address mask) noexcept {
    const uint32_t m = mask.to_host_order();
    if (m == 0) {
        return 0;
    }
    const uint32_t inverted = ~m;
    if ((inverted & (inverted + 1U)) != 0U) {
        return nullopt;
    }
    uint8_t bits = 0;
    uint32_t temp = m;
    while ((temp & 0x80000000U) != 0U) {
        ++bits;
        temp <<= 1U;
    }
    return bits;
}

optional<CIDRBlock> CIDRBlock::parse(string_view cidr_str) noexcept {
    cidr_str = trim_view(cidr_str);
    const size_t slash = cidr_str.find('/');
    if (slash == string_view::npos || slash == 0 || slash + 1 >= cidr_str.size()) {
        return nullopt;
    }

    const auto ip_opt = IPv4Address::parse(cidr_str.substr(0, slash));
    if (!ip_opt.has_value()) {
        return nullopt;
    }

    const string_view prefix_part = cidr_str.substr(slash + 1);
    if (prefix_part.size() > 2) {
        return nullopt;
    }
    if (prefix_part.size() > 1 && prefix_part.front() == '0') {
        return nullopt;
    }

    uint32_t prefix_val = 0;
    for (char c : prefix_part) {
        if (c < '0' || c > '9') {
            return nullopt;
        }
        prefix_val = prefix_val * 10U + static_cast<uint32_t>(c - '0');
    }
    if (prefix_val > 32U) {
        return nullopt;
    }

    return CIDRBlock(*ip_opt, static_cast<uint8_t>(prefix_val));
}

IPv4Address CIDRBlock::subnet_mask() const noexcept {
    return IPv4Address(prefix_to_mask_uint32(prefix_length_));
}

IPv4Address CIDRBlock::network_address() const noexcept {
    const uint32_t mask = prefix_to_mask_uint32(prefix_length_);
    return IPv4Address(input_address_.to_host_order() & mask);
}

IPv4Address CIDRBlock::broadcast_address() const noexcept {
    const uint32_t mask = prefix_to_mask_uint32(prefix_length_);
    const uint32_t net = input_address_.to_host_order() & mask;
    return IPv4Address(net | (~mask));
}

uint64_t CIDRBlock::total_addresses() const noexcept {
    return 1ULL << (32U - prefix_length_);
}

uint64_t CIDRBlock::usable_host_count() const noexcept {
    if (prefix_length_ == 32) {
        return 1ULL;
    }
    if (prefix_length_ == 31) {
        return 2ULL;
    }
    const uint64_t total = total_addresses();
    return (total >= 2ULL) ? (total - 2ULL) : 0ULL;
}

bool CIDRBlock::contains(IPv4Address ip) const noexcept {
    const uint32_t mask = prefix_to_mask_uint32(prefix_length_);
    return (ip.to_host_order() & mask) == (input_address_.to_host_order() & mask);
}

bool CIDRBlock::is_network_address(IPv4Address ip) const noexcept {
    if (prefix_length_ >= 31) {
        return false;
    }
    return ip == network_address();
}

bool CIDRBlock::is_directed_broadcast(IPv4Address ip) const noexcept {
    if (prefix_length_ >= 31) {
        return false;
    }
    return ip == broadcast_address();
}

optional<vector<IPv4Address>> CIDRBlock::expand_hosts(size_t max_hosts) const {
    const uint64_t count = usable_host_count();
    if (count > max_hosts) {
        return nullopt;
    }

    vector<IPv4Address> hosts;
    hosts.reserve(static_cast<size_t>(count));

    if (prefix_length_ == 32) {
        hosts.push_back(network_address());
        return hosts;
    }

    if (prefix_length_ == 31) {
        const uint32_t net = network_address().to_host_order();
        hosts.emplace_back(net);
        hosts.emplace_back(net + 1U);
        return hosts;
    }

    const uint32_t first_host = network_address().to_host_order() + 1U;
    const uint32_t last_host = broadcast_address().to_host_order() - 1U;

    for (uint64_t cur = first_host; cur <= last_host; ++cur) {
        hosts.emplace_back(static_cast<uint32_t>(cur));
    }
    return hosts;
}

string CIDRBlock::to_string() const {
    ostringstream oss;
    oss << network_address().to_string() << '/' << static_cast<unsigned>(prefix_length_);
    return oss.str();
}

optional<vector<IPv4Address>> parse_ip_target_list(
    string_view csv_targets,
    size_t max_targets) {
    csv_targets = trim_view(csv_targets);
    if (csv_targets.empty()) {
        return nullopt;
    }

    vector<IPv4Address> result;
    size_t start = 0;

    while (start <= csv_targets.size()) {
        const size_t comma = csv_targets.find(',', start);
        const string_view token = (comma == string_view::npos)
            ? csv_targets.substr(start)
            : csv_targets.substr(start, comma - start);

        const auto ip_opt = IPv4Address::parse(token);
        if (!ip_opt.has_value()) {
            return nullopt;
        }

        if (find(result.begin(), result.end(), *ip_opt) == result.end()) {
            if (result.size() >= max_targets) {
                return nullopt;
            }
            result.push_back(*ip_opt);
        }

        if (comma == string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    if (result.empty()) {
        return nullopt;
    }
    return result;
}

} // namespace ntm::net
