#ifndef NTM_EXPORT_EXPORTER_HPP
#define NTM_EXPORT_EXPORTER_HPP

#include "ntm/discovery/discovery_engine.hpp"
#include "ntm/net/interface_discovery.hpp"
#include "ntm/topology/topology_model.hpp"

#include <cstddef>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace ntm::export_out {

using namespace std;
using namespace ntm::net;
using namespace ntm::discovery;
using namespace ntm::topology;

struct ExportContext {
    NetworkInterface local_interface;
    string target_specification;
    DiscoverySummary discovery_summary;
    string timestamp_utc;
};

class TerminalRenderer {
public:
    static void render_interfaces_table(
        const vector<NetworkInterface>& interfaces,
        ostream& out);

    static void render_host_table(
        const TopologyGraph& graph,
        ostream& out);

    static void render_topology_summary(
        const TopologyGraph& graph,
        const ExportContext& context,
        ostream& out);
};

class JsonExporter {
public:
    static constexpr string_view kSchemaVersion = "1.0.0";
    static constexpr size_t kMaxOutputBytes = 32ULL * 1024ULL * 1024ULL; // 32 MB limit

    [[nodiscard]] static string to_json_string(
        const TopologyGraph& graph,
        const ExportContext& context = ExportContext{},
        int indent = 2);

    [[nodiscard]] static bool write_to_file(
        const TopologyGraph& graph,
        const ExportContext& context,
        string_view file_path,
        string* error_message = nullptr);
};

class DotExporter {
public:
    static constexpr size_t kMaxOutputBytes = 16ULL * 1024ULL * 1024ULL; // 16 MB limit

    [[nodiscard]] static string to_dot_string(
        const TopologyGraph& graph,
        string_view graph_title = "NTM_Network_Topology");

    [[nodiscard]] static bool write_to_file(
        const TopologyGraph& graph,
        string_view file_path,
        string* error_message = nullptr);
};

} // namespace ntm::export_out

#endif // NTM_EXPORT_EXPORTER_HPP
