#ifndef NTM_NET_IP_ADDRESS_HPP
#define NTM_NET_IP_ADDRESS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ntm::net {

using namespace std;

class IPv4Address {
public:
    constexpr IPv4Address() noexcept : host_order_(0) {}
    constexpr explicit IPv4Address(uint32_t host_order_value) noexcept
        : host_order_(host_order_value) {}
    constexpr IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept
        : host_order_((static_cast<uint32_t>(a) << 24U) |
                      (static_cast<uint32_t>(b) << 16U) |
                      (static_cast<uint32_t>(c) << 8U) |
                      static_cast<uint32_t>(d)) {}

    [[nodiscard]] static optional<IPv4Address> parse(string_view str) noexcept;
    [[nodiscard]] static IPv4Address from_network_order(uint32_t net_order) noexcept;

    [[nodiscard]] constexpr uint32_t to_host_order() const noexcept { return host_order_; }
    [[nodiscard]] uint32_t to_network_order() const noexcept;
    [[nodiscard]] array<uint8_t, 4> octets() const noexcept;
    [[nodiscard]] string to_string() const;

    [[nodiscard]] bool is_unspecified() const noexcept;       // 0.0.0.0/8
    [[nodiscard]] bool is_loopback() const noexcept;          // 127.0.0.0/8
    [[nodiscard]] bool is_private_rfc1918() const noexcept;   // 10/8, 172.16/12, 192.168/16
    [[nodiscard]] bool is_link_local() const noexcept;        // 169.254.0.0/16
    [[nodiscard]] bool is_cgnat() const noexcept;             // 100.64.0.0/10
    [[nodiscard]] bool is_multicast() const noexcept;         // 224.0.0.0/4
    [[nodiscard]] bool is_limited_broadcast() const noexcept; // 255.255.255.255
    [[nodiscard]] bool is_reserved() const noexcept;          // 240.0.0.0/4 (excluding 255.255.255.255)

    constexpr bool operator==(const IPv4Address& other) const noexcept {
        return host_order_ == other.host_order_;
    }
    constexpr bool operator!=(const IPv4Address& other) const noexcept {
        return host_order_ != other.host_order_;
    }
    constexpr bool operator<(const IPv4Address& other) const noexcept {
        return host_order_ < other.host_order_;
    }
    constexpr bool operator<=(const IPv4Address& other) const noexcept {
        return host_order_ <= other.host_order_;
    }
    constexpr bool operator>(const IPv4Address& other) const noexcept {
        return host_order_ > other.host_order_;
    }
    constexpr bool operator>=(const IPv4Address& other) const noexcept {
        return host_order_ >= other.host_order_;
    }

private:
    uint32_t host_order_;
};

class MACAddress {
public:
    using Bytes = array<uint8_t, 6>;

    constexpr MACAddress() noexcept : bytes_{0, 0, 0, 0, 0, 0} {}
    constexpr explicit MACAddress(const Bytes& bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] static optional<MACAddress> parse(string_view str) noexcept;

    [[nodiscard]] constexpr const Bytes& bytes() const noexcept { return bytes_; }
    [[nodiscard]] string to_string() const;
    [[nodiscard]] string to_compact_hex() const;

    [[nodiscard]] bool is_zero() const noexcept;
    [[nodiscard]] bool is_broadcast() const noexcept;
    [[nodiscard]] bool is_multicast() const noexcept;
    [[nodiscard]] bool is_locally_administered() const noexcept;

    constexpr bool operator==(const MACAddress& other) const noexcept {
        return bytes_ == other.bytes_;
    }
    constexpr bool operator!=(const MACAddress& other) const noexcept {
        return bytes_ != other.bytes_;
    }
    constexpr bool operator<(const MACAddress& other) const noexcept {
        return bytes_ < other.bytes_;
    }

private:
    Bytes bytes_;
};

class CIDRBlock {
public:
    static constexpr size_t kDefaultMaxExpansion = 4096;

    CIDRBlock(IPv4Address address, uint8_t prefix_length) noexcept;

    [[nodiscard]] static optional<CIDRBlock> parse(string_view cidr_str) noexcept;
    [[nodiscard]] static optional<uint8_t> netmask_to_prefix(IPv4Address mask) noexcept;
    [[nodiscard]] static uint32_t prefix_to_mask_uint32(uint8_t prefix_length) noexcept;

    [[nodiscard]] IPv4Address input_address() const noexcept { return input_address_; }
    [[nodiscard]] uint8_t prefix_length() const noexcept { return prefix_length_; }
    [[nodiscard]] IPv4Address subnet_mask() const noexcept;
    [[nodiscard]] IPv4Address network_address() const noexcept;
    [[nodiscard]] IPv4Address broadcast_address() const noexcept;

    [[nodiscard]] uint64_t total_addresses() const noexcept;
    [[nodiscard]] uint64_t usable_host_count() const noexcept;

    [[nodiscard]] bool contains(IPv4Address ip) const noexcept;
    [[nodiscard]] bool is_network_address(IPv4Address ip) const noexcept;
    [[nodiscard]] bool is_directed_broadcast(IPv4Address ip) const noexcept;

    [[nodiscard]] optional<vector<IPv4Address>> expand_hosts(
        size_t max_hosts = kDefaultMaxExpansion) const;

    [[nodiscard]] string to_string() const;

    bool operator==(const CIDRBlock& other) const noexcept {
        return network_address() == other.network_address() &&
               prefix_length_ == other.prefix_length_;
    }

private:
    IPv4Address input_address_;
    uint8_t prefix_length_;
};

[[nodiscard]] optional<vector<IPv4Address>> parse_ip_target_list(
    string_view csv_targets,
    size_t max_targets = CIDRBlock::kDefaultMaxExpansion);

} // namespace ntm::net

#endif // NTM_NET_IP_ADDRESS_HPP
