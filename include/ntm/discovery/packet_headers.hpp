#ifndef NTM_DISCOVERY_PACKET_HEADERS_HPP
#define NTM_DISCOVERY_PACKET_HEADERS_HPP

#include "ntm/net/ip_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ntm::discovery {

using namespace std;
using namespace ntm::net;

constexpr uint16_t kEtherTypeArp = 0x0806;
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kArpHardwareEthernet = 1;
constexpr uint16_t kArpOpRequest = 1;
constexpr uint16_t kArpOpReply = 2;

constexpr size_t kEthernetHeaderSize = 14;
constexpr size_t kArpPayloadSize = 28;
constexpr size_t kArpEthernetFrameSize = kEthernetHeaderSize + kArpPayloadSize; // 42 bytes
constexpr size_t kIcmpHeaderSize = 8;
constexpr size_t kMinIPv4HeaderSize = 20;

constexpr uint8_t kIcmpTypeEchoReply = 0;
constexpr uint8_t kIcmpTypeDestUnreachable = 3;
constexpr uint8_t kIcmpTypeEchoRequest = 8;
constexpr uint8_t kIcmpTypeTimeExceeded = 11;

struct ArpPacketInfo {
    uint16_t operation{0};
    MACAddress sender_mac;
    IPv4Address sender_ip;
    MACAddress target_mac;
    IPv4Address target_ip;
};

struct IcmpEchoInfo {
    uint8_t type{0};
    uint8_t code{0};
    uint16_t checksum{0};
    uint16_t identifier{0};
    uint16_t sequence{0};
    vector<uint8_t> payload;
};

class PacketCodec {
public:
    [[nodiscard]] static uint16_t compute_rfc1071_checksum(
        const uint8_t* data,
        size_t length) noexcept;

    [[nodiscard]] static bool verify_rfc1071_checksum(
        const uint8_t* data,
        size_t length) noexcept;

    [[nodiscard]] static array<uint8_t, kArpEthernetFrameSize> build_arp_request_frame(
        const MACAddress& sender_mac,
        const IPv4Address& sender_ip,
        const IPv4Address& target_ip) noexcept;

    [[nodiscard]] static optional<ArpPacketInfo> parse_arp_ethernet_frame(
        const uint8_t* buffer,
        size_t length) noexcept;

    [[nodiscard]] static vector<uint8_t> build_icmp_echo_request(
        uint16_t identifier,
        uint16_t sequence,
        const vector<uint8_t>& payload = {0x4E, 0x54, 0x4D, 0x31});

    [[nodiscard]] static optional<IcmpEchoInfo> parse_icmp_packet(
        const uint8_t* buffer,
        size_t length,
        bool has_ipv4_header = true) noexcept;
};

} // namespace ntm::discovery

#endif // NTM_DISCOVERY_PACKET_HEADERS_HPP
