#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "ntm/cli/cli_parser.hpp"
#include "ntm/discovery/discovery_engine.hpp"
#include "ntm/discovery/oui_lookup.hpp"
#include "ntm/discovery/packet_headers.hpp"
#include "ntm/export/exporter.hpp"
#include "ntm/net/interface_discovery.hpp"
#include "ntm/net/ip_address.hpp"
#include "ntm/net/scope_validator.hpp"
#include "ntm/topology/topology_inference.hpp"
#include "ntm/topology/topology_model.hpp"
#include "ntm/utils/rate_limiter.hpp"
#include "ntm/utils/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;
using namespace chrono;
using namespace ntm::utils;
using namespace ntm::net;
using namespace ntm::discovery;
using namespace ntm::topology;
using namespace ntm::export_out;
using namespace ntm::cli;
using nlohmann::json;

namespace {

// ============================================================================
// 1. CIDR Tests
// ============================================================================

TEST(CidrTests, ParseValidCidr) {
    const auto cidr_opt = CIDRBlock::parse("192.168.2.15/24");
    ASSERT_TRUE(cidr_opt.has_value());
    EXPECT_EQ(cidr_opt->prefix_length(), 24);
    EXPECT_EQ(cidr_opt->network_address().to_string(), "192.168.2.0");
    EXPECT_EQ(cidr_opt->broadcast_address().to_string(), "192.168.2.255");
    EXPECT_EQ(cidr_opt->subnet_mask().to_string(), "255.255.255.0");
    EXPECT_EQ(cidr_opt->usable_host_count(), 254ULL);
    EXPECT_EQ(cidr_opt->to_string(), "192.168.2.0/24");
}

TEST(CidrTests, ParseInvalidCidr) {
    EXPECT_FALSE(CIDRBlock::parse("").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.0").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.0/").has_value());
    EXPECT_FALSE(CIDRBlock::parse("/24").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.0/33").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.0/-1").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.256/24").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.2.0/02").has_value());
    EXPECT_FALSE(CIDRBlock::parse("192.168.01.1/24").has_value());
}

TEST(CidrTests, SubnetMembershipAndBoundaries) {
    const auto cidr    = CIDRBlock::parse("192.168.10.0/24").value();
    const auto inside1 = IPv4Address::parse("192.168.10.1").value();
    const auto inside2 = IPv4Address::parse("192.168.10.254").value();
    const auto net_ip  = IPv4Address::parse("192.168.10.0").value();
    const auto bcast   = IPv4Address::parse("192.168.10.255").value();
    const auto outside = IPv4Address::parse("192.168.11.1").value();

    EXPECT_TRUE(cidr.contains(inside1));
    EXPECT_TRUE(cidr.contains(inside2));
    EXPECT_TRUE(cidr.contains(net_ip));
    EXPECT_TRUE(cidr.contains(bcast));
    EXPECT_FALSE(cidr.contains(outside));

    EXPECT_TRUE(cidr.is_network_address(net_ip));
    EXPECT_TRUE(cidr.is_directed_broadcast(bcast));
    EXPECT_FALSE(cidr.is_network_address(inside1));
}

TEST(CidrTests, PrefixEdgeCases_0_24_30_32) {
    // Prefix /0
    const auto cidr0 = CIDRBlock::parse("10.20.30.40/0").value();
    EXPECT_EQ(cidr0.subnet_mask().to_string(), "0.0.0.0");
    EXPECT_EQ(cidr0.network_address().to_string(), "0.0.0.0");
    EXPECT_EQ(cidr0.broadcast_address().to_string(), "255.255.255.255");
    EXPECT_EQ(cidr0.total_addresses(), 4294967296ULL);
    EXPECT_FALSE(cidr0.expand_hosts().has_value());

    // Prefix /24
    const auto cidr24 = CIDRBlock::parse("192.168.1.100/24").value();
    EXPECT_EQ(cidr24.usable_host_count(), 254ULL);
    const auto hosts24 = cidr24.expand_hosts();
    ASSERT_TRUE(hosts24.has_value());
    EXPECT_EQ(hosts24->size(), 254U);
    EXPECT_EQ(hosts24->front().to_string(), "192.168.1.1");
    EXPECT_EQ(hosts24->back().to_string(), "192.168.1.254");

    // Prefix /30
    const auto cidr30 = CIDRBlock::parse("172.16.0.4/30").value();
    EXPECT_EQ(cidr30.network_address().to_string(), "172.16.0.4");
    EXPECT_EQ(cidr30.broadcast_address().to_string(), "172.16.0.7");
    EXPECT_EQ(cidr30.usable_host_count(), 2ULL);
    const auto hosts30 = cidr30.expand_hosts();
    ASSERT_TRUE(hosts30.has_value());
    ASSERT_EQ(hosts30->size(), 2U);
    EXPECT_EQ((*hosts30)[0].to_string(), "172.16.0.5");
    EXPECT_EQ((*hosts30)[1].to_string(), "172.16.0.6");

    // Prefix /32
    const auto cidr32 = CIDRBlock::parse("192.168.2.99/32").value();
    EXPECT_EQ(cidr32.network_address().to_string(), "192.168.2.99");
    EXPECT_EQ(cidr32.broadcast_address().to_string(), "192.168.2.99");
    EXPECT_EQ(cidr32.usable_host_count(), 1ULL);
    const auto hosts32 = cidr32.expand_hosts();
    ASSERT_TRUE(hosts32.has_value());
    ASSERT_EQ(hosts32->size(), 1U);
    EXPECT_EQ((*hosts32)[0].to_string(), "192.168.2.99");
}

// ============================================================================
// 2. Network & Packet Tests
// ============================================================================

TEST(NetworkTests, IPv4ConversionAndClassification) {
    const auto ip = IPv4Address::parse("192.168.2.10");
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->to_host_order(), 0xC0A8020AU);
    EXPECT_EQ(IPv4Address::from_network_order(ip->to_network_order()), *ip);
    EXPECT_TRUE(ip->is_private_rfc1918());
    EXPECT_FALSE(ip->is_loopback());
    EXPECT_FALSE(ip->is_multicast());

    EXPECT_TRUE(IPv4Address::parse("127.0.0.1")->is_loopback());
    EXPECT_TRUE(IPv4Address::parse("224.0.0.251")->is_multicast());
    EXPECT_TRUE(IPv4Address::parse("255.255.255.255")->is_limited_broadcast());
    EXPECT_FALSE(IPv4Address::parse("8.8.8.8")->is_private_rfc1918());
}

TEST(NetworkTests, MacAddressParsingAndNormalization) {
    const auto mac1 = MACAddress::parse("24:5a:4c:11:22:33");
    ASSERT_TRUE(mac1.has_value());
    EXPECT_EQ(mac1->to_string(), "24:5A:4C:11:22:33");
    EXPECT_EQ(mac1->to_compact_hex(), "245A4C112233");
    EXPECT_FALSE(mac1->is_zero());
    EXPECT_FALSE(mac1->is_broadcast());

    const auto mac2 = MACAddress::parse("24-5A-4C-11-22-33");
    ASSERT_TRUE(mac2.has_value());
    EXPECT_EQ(*mac1, *mac2);

    const auto bcast_mac = MACAddress::parse("FF:FF:FF:FF:FF:FF");
    ASSERT_TRUE(bcast_mac.has_value());
    EXPECT_TRUE(bcast_mac->is_broadcast());

    EXPECT_FALSE(MACAddress::parse("24:5A:4C:11:22").has_value());
    EXPECT_FALSE(MACAddress::parse("24:5A:4C:11:22:GG").has_value());
    EXPECT_FALSE(MACAddress::parse("24:5A-4C:11:22:33").has_value());
}

TEST(NetworkTests, IcmpChecksumAndPacketRoundtrip) {
    const uint16_t ident = 0x1234;
    const uint16_t seq = 0x0007;
    const vector<uint8_t> payload = {'N', 'T', 'M', '_', 'T', 'E', 'S', 'T'};

    const auto icmp_pkt = PacketCodec::build_icmp_echo_request(ident, seq, payload);
    ASSERT_EQ(icmp_pkt.size(), kIcmpHeaderSize + payload.size());

    EXPECT_TRUE(PacketCodec::verify_rfc1071_checksum(icmp_pkt.data(), icmp_pkt.size()));

    const auto parsed = PacketCodec::parse_icmp_packet(
        icmp_pkt.data(), icmp_pkt.size(), false);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->type, kIcmpTypeEchoRequest);
    EXPECT_EQ(parsed->code, 0);
    EXPECT_EQ(parsed->identifier, ident);
    EXPECT_EQ(parsed->sequence, seq);
    EXPECT_EQ(parsed->payload, payload);

    auto corrupted = icmp_pkt;
    corrupted.back() ^= 0xFFU;
    EXPECT_FALSE(PacketCodec::verify_rfc1071_checksum(corrupted.data(), corrupted.size()));
    EXPECT_FALSE(PacketCodec::parse_icmp_packet(
        corrupted.data(), corrupted.size(), false).has_value());
}

TEST(NetworkTests, ArpPacketSerializationAndParsing) {
    const auto sender_mac = MACAddress::parse("00:1B:21:AA:BB:CC").value();
    const auto sender_ip  = IPv4Address::parse("192.168.2.10").value();
    const auto target_ip  = IPv4Address::parse("192.168.2.1").value();

    const auto frame = PacketCodec::build_arp_request_frame(
        sender_mac, sender_ip, target_ip);
    ASSERT_EQ(frame.size(), kArpEthernetFrameSize);

    const auto parsed = PacketCodec::parse_arp_ethernet_frame(
        frame.data(), frame.size());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->operation, kArpOpRequest);
    EXPECT_EQ(parsed->sender_mac, sender_mac);
    EXPECT_EQ(parsed->sender_ip, sender_ip);
    EXPECT_EQ(parsed->target_ip, target_ip);
    EXPECT_TRUE(parsed->target_mac.is_zero());
}

TEST(NetworkTests, PacketBoundsValidation) {
    array<uint8_t, 20> short_buf{};
    EXPECT_FALSE(PacketCodec::parse_arp_ethernet_frame(
        short_buf.data(), short_buf.size()).has_value());
    EXPECT_FALSE(PacketCodec::parse_arp_ethernet_frame(nullptr, 100).has_value());

    EXPECT_FALSE(PacketCodec::parse_icmp_packet(
        short_buf.data(), 7, false).has_value());
    EXPECT_FALSE(PacketCodec::parse_icmp_packet(
        short_buf.data(), 20, true).has_value());
}

TEST(NetworkTests, ScopeValidatorEnforcement) {
    ScopeValidator validator(1024);
    const auto auth_cidr = CIDRBlock::parse("192.168.2.0/24").value();
    validator.add_authorized_subnet(auth_cidr);

    EXPECT_TRUE(validator.is_ip_permitted(IPv4Address::parse("192.168.2.1").value()));
    EXPECT_TRUE(validator.is_ip_permitted(IPv4Address::parse("192.168.2.254").value()));

    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("127.0.0.1").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("224.0.0.1").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("255.255.255.255").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("192.168.2.0").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("192.168.2.255").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("192.168.3.1").value()));
    EXPECT_FALSE(validator.is_ip_permitted(IPv4Address::parse("8.8.8.8").value()));
}

// ============================================================================
// 3. Topology & Inference Tests
// ============================================================================

TEST(TopologyTests, NodeAndLinkManagementAndDuplicates) {
    TopologyGraph graph;

    HostNode node1;
    node1.ipv4 = IPv4Address::parse("192.168.2.10").value();
    node1.id = TopologyGraph::make_node_id(node1.ipv4);
    node1.mac = MACAddress::parse("00:1B:21:11:22:33").value();
    node1.host_type = HostType::LocalHost;

    HostNode node2;
    node2.ipv4 = IPv4Address::parse("192.168.2.1").value();
    node2.id = TopologyGraph::make_node_id(node2.ipv4);
    node2.mac = MACAddress::parse("24:5A:4C:AA:BB:CC").value();
    node2.host_type = HostType::DefaultGateway;

    EXPECT_TRUE(graph.add_node(node1));
    EXPECT_TRUE(graph.add_node(node2));
    EXPECT_FALSE(graph.add_node(node1));
    EXPECT_EQ(graph.node_count(), 2U);

    ASSERT_TRUE(graph.find_node_by_ip(node2.ipv4).has_value());
    ASSERT_TRUE(graph.find_node_by_mac(*node2.mac).has_value());
    EXPECT_EQ(graph.find_node_by_mac(*node2.mac)->id, node2.id);

    NetworkLink link;
    link.source_node_id = node1.id;
    link.destination_node_id = node2.id;
    link.link_type = LinkType::L3DefaultGatewayRoute;
    link.relation_status = LinkRelationStatus::ObservedLink;
    link.evidence_source = "AF_PACKET ARP Reply + /proc/net/route";
    link.confidence_level = ConfidenceLevel::High;
    link.confidence_score = 0.98;

    EXPECT_TRUE(graph.add_link(link));
    EXPECT_FALSE(graph.add_link(link));
    NetworkLink reverse_link = link;
    swap(reverse_link.source_node_id, reverse_link.destination_node_id);
    EXPECT_FALSE(graph.add_link(reverse_link));
    EXPECT_EQ(graph.link_count(), 1U);

    const auto neighbors = graph.adjacent_node_ids(node1.id);
    ASSERT_EQ(neighbors.size(), 1U);
    EXPECT_EQ(neighbors.front(), node2.id);
}

TEST(TopologyTests, EvidenceBasedInferenceDoesNotFabricatePeerLinks) {
    NetworkInterface local_iface;
    local_iface.name = "eth0";
    local_iface.index = 2;
    local_iface.ipv4 = IPv4Address::parse("192.168.2.10").value();
    local_iface.cidr_prefix = 24;
    local_iface.mac = MACAddress::parse("00:1B:21:11:22:33").value();
    local_iface.is_up = true;
    local_iface.default_gateway = IPv4Address::parse("192.168.2.1").value();

    OuiLookup oui;
    TopologyInferenceEngine engine(local_iface, oui);

    DiscoverySummary summary;

    HostDiscoveryRecord gw_rec;
    gw_rec.ip = IPv4Address::parse("192.168.2.1").value();
    gw_rec.reachable = true;
    gw_rec.best_rtt_ms = 0.85;
    gw_rec.successful_methods = {DiscoveryMethod::ICMP};
    summary.records.push_back(gw_rec);

    HostDiscoveryRecord host_a;
    host_a.ip = IPv4Address::parse("192.168.2.20").value();
    host_a.mac = MACAddress::parse("24:5A:4C:01:02:03").value();
    host_a.reachable = true;
    host_a.best_rtt_ms = 0.42;
    host_a.successful_methods = {DiscoveryMethod::ARP};
    summary.records.push_back(host_a);

    HostDiscoveryRecord host_b;
    host_b.ip = IPv4Address::parse("192.168.2.30").value();
    host_b.mac = MACAddress::parse("B8:27:EB:04:05:06").value();
    host_b.reachable = true;
    host_b.best_rtt_ms = 0.55;
    host_b.successful_methods = {DiscoveryMethod::ARP};
    summary.records.push_back(host_b);

    const auto graph = engine.build_topology(summary);
    EXPECT_EQ(graph.node_count(), 4U);
    EXPECT_EQ(graph.link_count(), 3U);

    const string gw_id     = TopologyGraph::make_node_id(gw_rec.ip);
    const string host_a_id = TopologyGraph::make_node_id(host_a.ip);
    const string host_b_id = TopologyGraph::make_node_id(host_b.ip);

    EXPECT_FALSE(graph.has_link(host_a_id, host_b_id));

    for (const auto& link : graph.links()) {
        if (link.destination_node_id == gw_id) {
            EXPECT_EQ(link.relation_status, LinkRelationStatus::InferredLink);
        } else if (link.destination_node_id == host_a_id || link.destination_node_id == host_b_id) {
            EXPECT_EQ(link.relation_status, LinkRelationStatus::ObservedLink);
        }
    }
}

// ============================================================================
// 4. Concurrency Tests
// ============================================================================

TEST(ConcurrencyTests, ThreadPoolExecutionAndShutdown) {
    ThreadPool pool(4);
    atomic<int> counter{0};
    vector<future<int>> futures;

    for (int i = 1; i <= 40; ++i) {
        futures.push_back(pool.submit([i, &counter]() {
            counter.fetch_add(1, memory_order_relaxed);
            return i * 2;
        }));
    }

    int sum = 0;
    for (auto& f : futures) {
        sum += f.get();
    }
    EXPECT_EQ(counter.load(), 40);
    EXPECT_EQ(sum, 40 * 41);

    pool.shutdown();
    EXPECT_TRUE(pool.is_stopped());

    EXPECT_THROW(pool.submit([]() { return 1; }), runtime_error);
}

TEST(ConcurrencyTests, ThreadPoolTaskExceptionHandling) {
    ThreadPool pool(2);

    auto failing_future = pool.submit([]() -> int {
        throw invalid_argument("Simulated probe failure");
    });

    EXPECT_THROW(failing_future.get(), invalid_argument);

    auto recovery_future = pool.submit([]() { return 42; });
    EXPECT_EQ(recovery_future.get(), 42);
}

TEST(ConcurrencyTests, RateLimiterPacingAndConcurrency) {
    RateLimitConfig cfg;
    cfg.max_requests_per_sec = 100; // 10 ms interval
    cfg.max_concurrent_probes = 2;

    RateLimiter limiter(cfg);

    const auto t0 = steady_clock::now();
    for (int i = 0; i < 4; ++i) {
        auto permit = limiter.acquire_permit();
        EXPECT_LE(limiter.active_probes(), 2U);
    }
    const auto elapsed_ms = duration_cast<milliseconds>(steady_clock::now() - t0).count();

    EXPECT_GE(elapsed_ms, 20);
    EXPECT_EQ(limiter.active_probes(), 0U);
}

// ============================================================================
// 5. Export & OUI Tests
// ============================================================================

TEST(ExportTests, JsonAndDotSerializationAndMissingFields) {
    TopologyGraph graph;

    const string empty_json_str = JsonExporter::to_json_string(graph);
    const auto empty_parsed = json::parse(empty_json_str);
    EXPECT_EQ(empty_parsed["schema_version"], "1.0.0");
    EXPECT_TRUE(empty_parsed["hosts"].empty());
    EXPECT_TRUE(empty_parsed["links"].empty());

    HostNode local_node;
    local_node.ipv4 = IPv4Address::parse("192.168.2.10").value();
    local_node.id = TopologyGraph::make_node_id(local_node.ipv4);
    local_node.host_type = HostType::LocalHost;
    local_node.status = DiscoveryStatus::Active;
    graph.add_node(local_node);

    HostNode lan_node;
    lan_node.ipv4 = IPv4Address::parse("192.168.2.50").value();
    lan_node.id = TopologyGraph::make_node_id(lan_node.ipv4);
    lan_node.host_type = HostType::LANHost;
    lan_node.status = DiscoveryStatus::Active;
    lan_node.vendor = "";
    graph.add_node(lan_node);

    HostNode unk_node;
    unk_node.ipv4 = IPv4Address::parse("192.168.2.99").value();
    unk_node.id = TopologyGraph::make_node_id(unk_node.ipv4);
    unk_node.host_type = HostType::UnknownHost;
    unk_node.status = DiscoveryStatus::Unresponsive;
    graph.add_node(unk_node);

    NetworkLink observed_link;
    observed_link.source_node_id = local_node.id;
    observed_link.destination_node_id = lan_node.id;
    observed_link.link_type = LinkType::L2BroadcastDomainMember;
    observed_link.relation_status = LinkRelationStatus::ObservedLink;
    observed_link.collection_method = "ARP";
    observed_link.evidence_source = "AF_PACKET ARP Reply";
    observed_link.confidence_level = ConfidenceLevel::High;
    observed_link.confidence_score = 0.95;
    graph.add_link(observed_link);

    NetworkLink unknown_link;
    unknown_link.source_node_id = local_node.id;
    unknown_link.destination_node_id = unk_node.id;
    unknown_link.link_type = LinkType::UnknownAdjacency;
    unknown_link.relation_status = LinkRelationStatus::UnknownRelationship;
    unknown_link.collection_method = "None";
    unknown_link.evidence_source = "No response";
    unknown_link.confidence_level = ConfidenceLevel::Low;
    unknown_link.confidence_score = 0.0;
    graph.add_link(unknown_link);

    const string json_str = JsonExporter::to_json_string(graph);
    const auto parsed_json = json::parse(json_str);
    EXPECT_EQ(parsed_json["hosts"].size(), 3U);
    EXPECT_EQ(parsed_json["links"].size(), 2U);
    EXPECT_TRUE(parsed_json["hosts"][1]["hostname"].is_null());

    const string dot_str = DotExporter::to_dot_string(graph);
    EXPECT_NE(dot_str.find("doubleoctagon"), string::npos);
    EXPECT_NE(dot_str.find("style=\"solid\""), string::npos);
    EXPECT_EQ(dot_str.find("Unknown Relationship"), string::npos);

    ostringstream term_out;
    TerminalRenderer::render_host_table(graph, term_out);
    EXPECT_NE(term_out.str().find("192.168.2.50"), string::npos);
}

TEST(ExportTests, OuiLongestPrefixLookup_24_28_36Bit) {
    OuiLookup oui;
    istringstream custom_csv(
        "70B3D5,IEEE Base 24-Bit\n"
        "70B3D51,MA-M 28-Bit Vendor\n"
        "70B3D51F2,MA-S 36-Bit Specific Vendor\n"
    );
    EXPECT_EQ(oui.load_from_stream(custom_csv), 3U);

    const auto mac36 = MACAddress::parse("70:B3:D5:1F:20:01").value();
    EXPECT_EQ(oui.lookup_or_default(mac36), "MA-S 36-Bit Specific Vendor");

    const auto mac28 = MACAddress::parse("70:B3:D5:1A:00:01").value();
    EXPECT_EQ(oui.lookup_or_default(mac28), "MA-M 28-Bit Vendor");

    const auto mac24 = MACAddress::parse("70:B3:D5:99:00:01").value();
    EXPECT_EQ(oui.lookup_or_default(mac24), "IEEE Base 24-Bit");
}

} // namespace
