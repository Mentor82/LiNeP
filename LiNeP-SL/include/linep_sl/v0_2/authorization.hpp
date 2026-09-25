#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <linep/v0_2/capabilities.hpp>
#include <linep/v0_2/runtime_types.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

namespace linep::sl::v0_2 {

enum class capability_flags : std::uint64_t {
    none           = 0,
    generate       = 1ULL << 0,
    chat           = 1ULL << 1,
    embed          = 1ULL << 2,
    stream_output  = 1ULL << 3,
    reasoning      = 1ULL << 4,
    cancel         = 1ULL << 5,
    tool_invoke    = 1ULL << 6,
    metrics_read   = 1ULL << 7,
    runtime_manage = 1ULL << 8,
    administer     = 1ULL << 9,
    all            = 0xFFFFFFFFFFFFFFFFULL,
};

inline constexpr capability_flags operator|(capability_flags a, capability_flags b) noexcept {
    return static_cast<capability_flags>(
        static_cast<std::uint64_t>(a) | static_cast<std::uint64_t>(b));
}

inline constexpr capability_flags operator&(capability_flags a, capability_flags b) noexcept {
    return static_cast<capability_flags>(
        static_cast<std::uint64_t>(a) & static_cast<std::uint64_t>(b));
}

inline constexpr capability_flags operator~(capability_flags a) noexcept {
    return static_cast<capability_flags>(~static_cast<std::uint64_t>(a));
}

inline constexpr capability_flags operator^(capability_flags a, capability_flags b) noexcept {
    return static_cast<capability_flags>(
        static_cast<std::uint64_t>(a) ^ static_cast<std::uint64_t>(b));
}

inline constexpr bool has_capability(capability_flags set, capability_flags required) noexcept {
    return (set & required) == required;
}

enum class resource_kind : std::uint8_t {
    unknown = 0,
    model = 1,
    embedding_space = 2,
    tool = 3,
    runtime = 4,
    system = 5,
};

struct resource_identifier {
    resource_kind kind{resource_kind::unknown};
    std::string name;

    bool is_valid() const noexcept;
    bool matches(const resource_identifier& target) const noexcept;
};

struct execution_constraints {
    std::uint32_t max_allowed_tokens{0};    // 0 = unconstrained by policy
    float max_allowed_temperature{0.0f};    // 0.0 = unconstrained
    bool disallow_streaming{false};
    bool disallow_reasoning{false};
};

struct authorization_request {
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};
    std::vector<std::string> roles;
    security_action action{security_action::unknown};
    resource_identifier resource;
    linep::v0_2::runtime_profile profile{linep::v0_2::runtime_profile::generate};
    std::uint32_t requested_tokens{0};
    float requested_temperature{0.0f};
    bool streaming_requested{false};
    bool reasoning_requested{false};
    std::string tool_name;
};

enum class authorization_outcome : std::uint8_t {
    deny = 0,
    allow = 1,
};

struct authorization_decision {
    authorization_outcome outcome{authorization_outcome::deny};
    std::string reason_code;
    capability_flags granted_capabilities{capability_flags::none};
    execution_constraints effective_constraints;

    bool is_allowed() const noexcept { return outcome == authorization_outcome::allow; }
};

struct subject_policy {
    std::uint64_t subject_id{0};
    std::uint32_t trust_domain_id{0};
    capability_flags capabilities{capability_flags::none};
    std::vector<resource_identifier> allowed_resources;
    execution_constraints constraints;
};

struct role_policy {
    std::string role_name;
    capability_flags capabilities{capability_flags::none};
    std::vector<resource_identifier> allowed_resources;
    execution_constraints constraints;
};

class policy_authorizer {
public:
    policy_authorizer() = default;

    void add_subject_policy(const subject_policy& policy);
    void add_role_policy(const role_policy& policy);
    void clear_policies() noexcept;

    // Evaluates permissions deny-by-default
    authorization_decision authorize(const authorization_request& req) const noexcept;

    // Maps runtime advertised capabilities into validation inputs, never direct grants
    bool validate_against_advertised_capabilities(
        const authorization_request& req,
        const linep::v0_2::runtime_capabilities_descriptor& advertised_caps,
        authorization_decision& out_decision) const noexcept;

private:
    std::unordered_map<std::uint64_t, subject_policy> subject_policies_;
    std::unordered_map<std::string, role_policy> role_policies_;
};

} // namespace linep::sl::v0_2
