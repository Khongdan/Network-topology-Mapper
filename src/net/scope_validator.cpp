#include "ntm/net/scope_validator.hpp"

#include <algorithm>
#include <sstream>

namespace ntm::net {

using namespace std;

ScopeValidator::ScopeValidator(size_t max_targets)
    : max_targets_(clamp<size_t>(max_targets, 1U, kHardMaxTargets)) {}

void ScopeValidator::add_authorized_subnet(const CIDRBlock& subnet) {
    if (find(authorized_subnets_.begin(), authorized_subnets_.end(), subnet) ==
        authorized_subnets_.end()) {
        authorized_subnets_.push_back(subnet);
    }
}

void ScopeValidator::clear_authorized_subnets() noexcept {
    authorized_subnets_.clear();
}

const vector<CIDRBlock>& ScopeValidator::authorized_subnets() const noexcept {
    return authorized_subnets_;
}

bool ScopeValidator::is_ip_permitted(IPv4Address ip, string* reason) const {
    auto set_reason = [reason](string msg) {
        if (reason != nullptr) {
            *reason = move(msg);
        }
    };

    if (ip.is_unspecified()) {
        set_reason("Address " + ip.to_string() + " is in unspecified range (0.0.0.0/8)");
        return false;
    }
    if (ip.is_loopback()) {
        set_reason("Address " + ip.to_string() + " is a loopback address (127.0.0.0/8)");
        return false;
    }
    if (ip.is_multicast()) {
        set_reason("Address " + ip.to_string() + " is a multicast address (224.0.0.0/4)");
        return false;
    }
    if (ip.is_limited_broadcast()) {
        set_reason("Address " + ip.to_string() + " is limited broadcast (255.255.255.255)");
        return false;
    }
    if (ip.is_reserved()) {
        set_reason("Address " + ip.to_string() + " is in reserved Class E range (240.0.0.0/4)");
        return false;
    }
    if (!ip.is_private_rfc1918() && !ip.is_link_local() && !ip.is_cgnat()) {
        set_reason("Address " + ip.to_string() +
                   " is a public/external IPv4 address outside private/lab ranges");
        return false;
    }

    if (authorized_subnets_.empty()) {
        set_reason("No authorized subnet scope configured in ScopeValidator");
        return false;
    }

    for (const auto& subnet : authorized_subnets_) {
        if (subnet.contains(ip)) {
            if (subnet.is_network_address(ip)) {
                set_reason("Address " + ip.to_string() +
                           " is the network address of subnet " + subnet.to_string());
                return false;
            }
            if (subnet.is_directed_broadcast(ip)) {
                set_reason("Address " + ip.to_string() +
                           " is the directed broadcast address of subnet " + subnet.to_string());
                return false;
            }
            return true;
        }
    }

    set_reason("Address " + ip.to_string() +
               " is outside the authorized local subnet scope (cross-gateway scanning blocked)");
    return false;
}

ScopeValidationResult ScopeValidator::validate_cidr(const CIDRBlock& target_cidr) const {
    ScopeValidationResult res;

    if (target_cidr.prefix_length() < 20) {
        ostringstream oss;
        oss << "Subnet " << target_cidr.to_string() << " is too large ("
            << target_cidr.usable_host_count()
            << " hosts). Maximum allowed targets per scan is " << max_targets_
            << " (minimum prefix /20 or smaller required).";
        res.error_message = oss.str();
        return res;
    }

    const uint64_t host_count = target_cidr.usable_host_count();
    if (host_count == 0) {
        res.error_message = "Subnet " + target_cidr.to_string() + " contains 0 usable hosts.";
        return res;
    }
    if (host_count > max_targets_) {
        ostringstream oss;
        oss << "Subnet " << target_cidr.to_string() << " expands to " << host_count
            << " hosts, which exceeds the resource limit of " << max_targets_ << " hosts.";
        res.error_message = oss.str();
        return res;
    }

    const auto expanded_opt = target_cidr.expand_hosts(max_targets_);
    if (!expanded_opt.has_value()) {
        res.error_message = "Failed to expand target CIDR " + target_cidr.to_string();
        return res;
    }

    return validate_target_list(*expanded_opt);
}

ScopeValidationResult ScopeValidator::validate_target_list(
    const vector<IPv4Address>& targets) const {
    ScopeValidationResult res;

    if (targets.empty()) {
        res.error_message = "Target list is empty.";
        return res;
    }

    if (targets.size() > max_targets_) {
        ostringstream oss;
        oss << "Target list size (" << targets.size()
            << ") exceeds maximum allowed targets (" << max_targets_ << ").";
        res.error_message = oss.str();
        return res;
    }

    res.approved_targets.reserve(targets.size());
    for (const auto& ip : targets) {
        string reason;
        if (!is_ip_permitted(ip, &reason)) {
            res.valid = false;
            res.error_message = "Scope validation failed: " + reason;
            res.approved_targets.clear();
            return res;
        }
        res.approved_targets.push_back(ip);
    }

    res.valid = true;
    return res;
}

} // namespace ntm::net
