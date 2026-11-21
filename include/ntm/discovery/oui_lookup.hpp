#ifndef NTM_DISCOVERY_OUI_LOOKUP_HPP
#define NTM_DISCOVERY_OUI_LOOKUP_HPP

#include "ntm/net/ip_address.hpp"

#include <cstddef>
#include <istream>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ntm::discovery {

using namespace std;
using namespace ntm::net;

class OuiLookup {
public:
    OuiLookup();

    bool load_from_file(string_view file_path);
    size_t load_from_stream(istream& input);

    void insert_prefix(string_view hex_prefix, string_view vendor_name);

    [[nodiscard]] optional<string> lookup(const MACAddress& mac) const;
    [[nodiscard]] string lookup_or_default(
        const MACAddress& mac,
        string_view default_vendor = "Unknown Vendor") const;

    [[nodiscard]] size_t entry_count() const noexcept;

private:
    void load_builtin_defaults();

    // Key: normalized uppercase hex prefix of length 6 (24-bit), 7 (28-bit), or 9 (36-bit)
    unordered_map<string, string> prefix_table_;
};

} // namespace ntm::discovery

#endif // NTM_DISCOVERY_OUI_LOOKUP_HPP
