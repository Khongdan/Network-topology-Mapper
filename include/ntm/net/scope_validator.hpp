#ifndef NTM_NET_SCOPE_VALIDATOR_HPP
#define NTM_NET_SCOPE_VALIDATOR_HPP

#include "ntm/net/ip_address.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ntm::net {

using namespace std;

struct ScopeValidationResult {
    bool valid{false};
    string error_message;
    vector<IPv4Address> approved_targets;
    vector<string> warnings;
};

class ScopeValidator {
public:
    static constexpr size_t kDefaultMaxTargets = 1024;
    static constexpr size_t kHardMaxTargets = 4096;

    explicit ScopeValidator(size_t max_targets = kDefaultMaxTargets);

    void add_authorized_subnet(const CIDRBlock& subnet);
    void clear_authorized_subnets() noexcept;
    [[nodiscard]] const vector<CIDRBlock>& authorized_subnets() const noexcept;

    [[nodiscard]] bool is_ip_permitted(IPv4Address ip, string* reason = nullptr) const;

    [[nodiscard]] ScopeValidationResult validate_cidr(const CIDRBlock& target_cidr) const;
    [[nodiscard]] ScopeValidationResult validate_target_list(
        const vector<IPv4Address>& targets) const;

private:
    size_t max_targets_;
    vector<CIDRBlock> authorized_subnets_;
};

} // namespace ntm::net

#endif // NTM_NET_SCOPE_VALIDATOR_HPP
