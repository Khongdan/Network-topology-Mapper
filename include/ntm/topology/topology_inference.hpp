#ifndef NTM_TOPOLOGY_TOPOLOGY_INFERENCE_HPP
#define NTM_TOPOLOGY_TOPOLOGY_INFERENCE_HPP

#include "ntm/discovery/discovery_engine.hpp"
#include "ntm/discovery/oui_lookup.hpp"
#include "ntm/net/interface_discovery.hpp"
#include "ntm/topology/topology_model.hpp"

#include <string>
#include <vector>

namespace ntm::topology {

using namespace std;
using namespace ntm::net;
using namespace ntm::discovery;

struct InferenceOptions {
    bool include_unresponsive_hosts{false};
    bool record_unknown_relationships{false};
};

class TopologyInferenceEngine {
public:
    TopologyInferenceEngine(
        NetworkInterface local_interface,
        const OuiLookup& oui_lookup,
        InferenceOptions options = InferenceOptions{});

    [[nodiscard]] TopologyGraph build_topology(
        const DiscoverySummary& discovery_summary) const;

    [[nodiscard]] HostNode classify_discovered_host(
        const HostDiscoveryRecord& record,
        const string& iso_timestamp) const;

    [[nodiscard]] static string current_iso8601_utc();

private:
    NetworkInterface local_iface_;
    const OuiLookup& oui_lookup_;
    InferenceOptions options_;
};

} // namespace ntm::topology

#endif // NTM_TOPOLOGY_TOPOLOGY_INFERENCE_HPP
