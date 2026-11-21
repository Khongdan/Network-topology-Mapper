#include "ntm/discovery/packet_headers.hpp"

#include <cstring>

namespace ntm::discovery {

using namespace std;
using namespace ntm::net;

namespace {

constexpr uint16_t read_be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) |
                                  static_cast<uint16_t>(p[1]));
}

constexpr void write_be16(uint8_t* p, uint16_t val) noexcept {
    p[0] = static_cast<uint8_t>((val >> 8U) & 0xFFU);
    p[1] = static_cast<uint8_t>(val & 0xFFU);
}

constexpr uint32_t read_be32(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24U) |
           (static_cast<uint32_t>(p[1]) << 16U) |
           (static_cast<uint32_t>(p[2]) << 8U) |
           static_cast<uint32_t>(p[3]);
}

constexpr void write_be32(uint8_t* p, uint32_t val) noexcept {
    p[0] = static_cast<uint8_t>((val >> 24U) & 0xFFU);
    p[1] = static_cast<uint8_t>((val >> 16U) & 0xFFU);
    p[2] = static_cast<uint8_t>((val >> 8U) & 0xFFU);
    p[3] = static_cast<uint8_t>(val & 0xFFU);
}

} // namespace

uint16_t PacketCodec::compute_rfc1071_checksum(
    const uint8_t* data,
    size_t length) noexcept {
    if (data == nullptr || length == 0) {
        return 0xFFFFU;
    }

    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < length) {
        sum += read_be16(data + i);
        i += 2;
    }

    if (i < length) {
        sum += static_cast<uint16_t>(static_cast<uint16_t>(data[i]) << 8U);
    }

    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<uint16_t>(~sum & 0xFFFFU);
}

bool PacketCodec::verify_rfc1071_checksum(
    const uint8_t* data,
    size_t length) noexcept {
    if (data == nullptr || length < kIcmpHeaderSize) {
        return false;
    }
    return compute_rfc1071_checksum(data, length) == 0;
}

array<uint8_t, kArpEthernetFrameSize> PacketCodec::build_arp_request_frame(
    const MACAddress& sender_mac,
    const IPv4Address& sender_ip,
    const IPv4Address& target_ip) noexcept {
    array<uint8_t, kArpEthernetFrameSize> frame{};

    // Ethernet II Header (14 bytes)
    memset(frame.data(), 0xFF, 6);
    memcpy(frame.data() + 6, sender_mac.bytes().data(), 6);
    write_be16(frame.data() + 12, kEtherTypeArp);

    // ARP Payload (28 bytes)
    uint8_t* arp = frame.data() + kEthernetHeaderSize;
    write_be16(arp + 0, kArpHardwareEthernet);
    write_be16(arp + 2, kEtherTypeIPv4);
    arp[4] = 6;
    arp[5] = 4;
    write_be16(arp + 6, kArpOpRequest);

    memcpy(arp + 8, sender_mac.bytes().data(), 6);
    write_be32(arp + 14, sender_ip.to_host_order());
    memset(arp + 18, 0x00, 6);
    write_be32(arp + 24, target_ip.to_host_order());

    return frame;
}

optional<ArpPacketInfo> PacketCodec::parse_arp_ethernet_frame(
    const uint8_t* buffer,
    size_t length) noexcept {
    if (buffer == nullptr || length < kArpEthernetFrameSize) {
        return nullopt;
    }

    const uint16_t ether_type = read_be16(buffer + 12);
    if (ether_type != kEtherTypeArp) {
        return nullopt;
    }

    const uint8_t* arp = buffer + kEthernetHeaderSize;
    const uint16_t htype = read_be16(arp + 0);
    const uint16_t ptype = read_be16(arp + 2);
    const uint8_t hlen = arp[4];
    const uint8_t plen = arp[5];
    const uint16_t oper = read_be16(arp + 6);

    if (htype != kArpHardwareEthernet || ptype != kEtherTypeIPv4 || hlen != 6 || plen != 4) {
        return nullopt;
    }
    if (oper != kArpOpRequest && oper != kArpOpReply) {
        return nullopt;
    }

    ArpPacketInfo info;
    info.operation = oper;

    MACAddress::Bytes sha{};
    memcpy(sha.data(), arp + 8, 6);
    info.sender_mac = MACAddress(sha);
    info.sender_ip = IPv4Address(read_be32(arp + 14));

    MACAddress::Bytes tha{};
    memcpy(tha.data(), arp + 18, 6);
    info.target_mac = MACAddress(tha);
    info.target_ip = IPv4Address(read_be32(arp + 24));

    return info;
}

vector<uint8_t> PacketCodec::build_icmp_echo_request(
    uint16_t identifier,
    uint16_t sequence,
    const vector<uint8_t>& payload) {
    vector<uint8_t> packet(kIcmpHeaderSize + payload.size(), 0);

    packet[0] = kIcmpTypeEchoRequest;
    packet[1] = 0;
    write_be16(packet.data() + 2, 0);
    write_be16(packet.data() + 4, identifier);
    write_be16(packet.data() + 6, sequence);

    if (!payload.empty()) {
        memcpy(packet.data() + kIcmpHeaderSize, payload.data(), payload.size());
    }

    const uint16_t csum = compute_rfc1071_checksum(packet.data(), packet.size());
    write_be16(packet.data() + 2, csum);

    return packet;
}

optional<IcmpEchoInfo> PacketCodec::parse_icmp_packet(
    const uint8_t* buffer,
    size_t length,
    bool has_ipv4_header) noexcept {
    if (buffer == nullptr) {
        return nullopt;
    }

    size_t offset = 0;
    if (has_ipv4_header) {
        if (length < kMinIPv4HeaderSize + kIcmpHeaderSize) {
            return nullopt;
        }
        const uint8_t version = (buffer[0] >> 4U) & 0x0FU;
        const uint8_t ihl = buffer[0] & 0x0FU;
        if (version != 4 || ihl < 5) {
            return nullopt;
        }
        offset = static_cast<size_t>(ihl) * 4U;
        if (length < offset + kIcmpHeaderSize) {
            return nullopt;
        }
    } else {
        if (length < kIcmpHeaderSize) {
            return nullopt;
        }
    }

    const uint8_t* icmp_ptr = buffer + offset;
    const size_t icmp_len = length - offset;

    if (!verify_rfc1071_checksum(icmp_ptr, icmp_len)) {
        return nullopt;
    }

    IcmpEchoInfo info;
    info.type = icmp_ptr[0];
    info.code = icmp_ptr[1];
    info.checksum = read_be16(icmp_ptr + 2);
    info.identifier = read_be16(icmp_ptr + 4);
    info.sequence = read_be16(icmp_ptr + 6);

    if (icmp_len > kIcmpHeaderSize) {
        info.payload.assign(icmp_ptr + kIcmpHeaderSize, icmp_ptr + icmp_len);
    }

    return info;
}

} // namespace ntm::discovery
