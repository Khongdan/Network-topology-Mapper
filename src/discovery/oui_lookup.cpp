#include "ntm/discovery/oui_lookup.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace ntm::discovery {

using namespace std;
using namespace ntm::net;

namespace {

string normalize_hex_prefix(string_view raw) {
    string clean;
    clean.reserve(raw.size());
    for (char c : raw) {
        if (isxdigit(static_cast<unsigned char>(c))) {
            clean.push_back(static_cast<char>(toupper(static_cast<unsigned char>(c))));
        }
    }
    return clean;
}

string trim_copy(string_view sv) {
    while (!sv.empty() && isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    while (!sv.empty() && isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return string(sv);
}

} // namespace

OuiLookup::OuiLookup() {
    load_builtin_defaults();
#if defined(NTM_DEFAULT_OUI_PATH)
    load_from_file(NTM_DEFAULT_OUI_PATH);
#endif
}

void OuiLookup::load_builtin_defaults() {
    insert_prefix("00000C", "Cisco Systems Inc");
    insert_prefix("000142", "Cisco Systems Inc");
    insert_prefix("001B63", "Apple Inc");
    insert_prefix("3C22FB", "Apple Inc");
    insert_prefix("005056", "VMware Inc");
    insert_prefix("000C29", "VMware Inc");
    insert_prefix("080027", "PCS Systemtechnik GmbH (VirtualBox)");
    insert_prefix("525400", "QEMU / KVM Virtual NIC");
    insert_prefix("00155D", "Microsoft Corporation (Hyper-V)");
    insert_prefix("0242AC", "Docker Container Bridge");
    insert_prefix("001B21", "Intel Corporate");
    insert_prefix("00E04C", "Realtek Semiconductor Corp");
    insert_prefix("001422", "Dell Inc");
    insert_prefix("0017A4", "Hewlett Packard Enterprise");
    insert_prefix("B827EB", "Raspberry Pi Foundation");
    insert_prefix("DCA632", "Raspberry Pi Trading Ltd");
    insert_prefix("245A4C", "Ubiquiti Inc");
    insert_prefix("788A20", "Ubiquiti Inc");
    insert_prefix("4C5E0C", "MikroTikls SIA");
    insert_prefix("64D154", "MikroTikls SIA");
    insert_prefix("50C7BF", "TP-Link Technologies Co Ltd");
    insert_prefix("70B3D51", "IEEE Registration Authority (MA-M 28-bit Sample)");
    insert_prefix("70B3D51F2", "Embedded Labs Ltd (MA-S 36-bit Sample)");
}

void OuiLookup::insert_prefix(string_view hex_prefix, string_view vendor_name) {
    const string norm = normalize_hex_prefix(hex_prefix);
    const string vendor = trim_copy(vendor_name);
    if ((norm.size() == 6 || norm.size() == 7 || norm.size() == 9) && !vendor.empty()) {
        prefix_table_[norm] = vendor;
    }
}

size_t OuiLookup::load_from_stream(istream& input) {
    size_t loaded = 0;
    string line;

    while (getline(input, line)) {
        const string trimmed = trim_copy(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            continue;
        }
        const size_t comma = trimmed.find(',');
        if (comma == string::npos || comma == 0 || comma + 1 >= trimmed.size()) {
            continue;
        }
        const string prefix = normalize_hex_prefix(trimmed.substr(0, comma));
        const string vendor = trim_copy(trimmed.substr(comma + 1));

        if ((prefix.size() == 6 || prefix.size() == 7 || prefix.size() == 9) && !vendor.empty()) {
            prefix_table_[prefix] = vendor;
            ++loaded;
        }
    }

    return loaded;
}

bool OuiLookup::load_from_file(string_view file_path) {
    ifstream file{string(file_path)};
    if (!file.is_open()) {
        return false;
    }
    return load_from_stream(file) > 0;
}

optional<string> OuiLookup::lookup(const MACAddress& mac) const {
    if (mac.is_zero() || mac.is_broadcast()) {
        return nullopt;
    }

    const string hex12 = mac.to_compact_hex();

    // 1. Check 36-bit MA-S (9 hex digits)
    if (auto it36 = prefix_table_.find(hex12.substr(0, 9)); it36 != prefix_table_.end()) {
        return it36->second;
    }

    // 2. Check 28-bit MA-M (7 hex digits)
    if (auto it28 = prefix_table_.find(hex12.substr(0, 7)); it28 != prefix_table_.end()) {
        return it28->second;
    }

    // 3. Check 24-bit MA-L (6 hex digits)
    if (auto it24 = prefix_table_.find(hex12.substr(0, 6)); it24 != prefix_table_.end()) {
        return it24->second;
    }

    return nullopt;
}

string OuiLookup::lookup_or_default(
    const MACAddress& mac,
    string_view default_vendor) const {
    if (mac.is_zero()) {
        return string(default_vendor);
    }
    if (auto found = lookup(mac); found.has_value()) {
        return *found;
    }
    if (mac.is_locally_administered()) {
        return "Locally Administered / Randomized MAC";
    }
    return string(default_vendor);
}

size_t OuiLookup::entry_count() const noexcept {
    return prefix_table_.size();
}

} // namespace ntm::discovery
