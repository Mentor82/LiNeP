#include <linep_sl/v0_2/authorization.hpp>
#include <algorithm>

namespace linep::sl::v0_2 {

bool resource_identifier::is_valid() const noexcept {
    return kind != resource_kind::unknown && !name.empty();
}

bool resource_identifier::matches(const resource_identifier& target) const noexcept {
    if (kind != target.kind && kind != resource_kind::system) {
        return false;
    }
    if (name == "*" || name == target.name) {
        return true;
    }
    return false;
}

void policy_authorizer::add_subject_policy(const subject_policy& policy) {
    subject_policies_[policy.subject_id] = policy;
}

void policy_authorizer::add_role_policy(const role_policy& policy) {
    role_policies_[policy.role_name] = policy;
}

void policy_authorizer::clear_policies() noexcept {
    subject_policies_.clear();
    role_policies_.clear();
}

authorization_decision policy_authorizer::authorize(const authorization_request& req) const noexcept {
    // Deny unknown actions by default
    if (req.action == security_action::unknown) {
        return {authorization_outcome::deny, "action_unknown", capability_flags::none, {}};
    }
    if (req.subject_id == 0 || req.trust_domain_id == 0) {
        return {authorization_outcome::deny, "unauthenticated_subject", capability_flags::none, {}};
    }

    capability_flags required_cap = capability_flags::none;
    switch (req.action) {
        case security_action::execute:
            if (req.profile == linep::v0_2::runtime_profile::generate) {
                required_cap = capability_flags::generate;
            } else if (req.profile == linep::v0_2::runtime_profile::chat) {
                required_cap = capability_flags::chat;
            } else if (req.profile == linep::v0_2::runtime_profile::embed) {
                required_cap = capability_flags::embed;
            } else {
                return {authorization_outcome::deny, "profile_unsupported", capability_flags::none, {}};
            }
            break;
        case security_action::emit_output:
            required_cap = capability_flags::stream_output;
            break;
        case security_action::cancel:
            required_cap = capability_flags::cancel;
            break;
        case security_action::invoke_tool:
            required_cap = capability_flags::tool_invoke;
            break;
        case security_action::read_metrics:
            required_cap = capability_flags::metrics_read;
            break;
        case security_action::manage_runtime:
            required_cap = capability_flags::runtime_manage;
            break;
        case security_action::administer:
            required_cap = capability_flags::administer;
            break;
        case security_action::advertise:
        case security_action::report_liveness:
        case security_action::manage_lease:
            required_cap = capability_flags::runtime_manage;
            break;
        default:
            return {authorization_outcome::deny, "action_unrecognized", capability_flags::none, {}};
    }

    if (req.streaming_requested) {
        required_cap = required_cap | capability_flags::stream_output;
    }
    if (req.reasoning_requested) {
        required_cap = required_cap | capability_flags::reasoning;
    }

    // Aggregate capabilities and allowed resources across subject and roles
    capability_flags effective_caps = capability_flags::none;
    std::vector<resource_identifier> effective_resources;
    execution_constraints effective_constraints{};
    bool policy_found = false;

    auto sub_it = subject_policies_.find(req.subject_id);
    if (sub_it != subject_policies_.end() && sub_it->second.trust_domain_id == req.trust_domain_id) {
        policy_found = true;
        effective_caps = effective_caps | sub_it->second.capabilities;
        effective_resources.insert(
            effective_resources.end(),
            sub_it->second.allowed_resources.begin(),
            sub_it->second.allowed_resources.end());
        effective_constraints = sub_it->second.constraints;
    }

    for (const auto& role_name : req.roles) {
        auto role_it = role_policies_.find(role_name);
        if (role_it != role_policies_.end()) {
            policy_found = true;
            effective_caps = effective_caps | role_it->second.capabilities;
            effective_resources.insert(
                effective_resources.end(),
                role_it->second.allowed_resources.begin(),
                role_it->second.allowed_resources.end());
            // Combine constraints conservatively
            if (role_it->second.constraints.max_allowed_tokens > 0) {
                if (effective_constraints.max_allowed_tokens == 0 ||
                    role_it->second.constraints.max_allowed_tokens < effective_constraints.max_allowed_tokens) {
                    effective_constraints.max_allowed_tokens = role_it->second.constraints.max_allowed_tokens;
                }
            }
            if (role_it->second.constraints.max_allowed_temperature > 0.0f) {
                if (effective_constraints.max_allowed_temperature == 0.0f ||
                    role_it->second.constraints.max_allowed_temperature < effective_constraints.max_allowed_temperature) {
                    effective_constraints.max_allowed_temperature = role_it->second.constraints.max_allowed_temperature;
                }
            }
            if (role_it->second.constraints.disallow_streaming) {
                effective_constraints.disallow_streaming = true;
            }
            if (role_it->second.constraints.disallow_reasoning) {
                effective_constraints.disallow_reasoning = true;
            }
        }
    }

    if (!policy_found) {
        return {authorization_outcome::deny, "no_policy_found", capability_flags::none, {}};
    }

    // Verify required capability
    if (!has_capability(effective_caps, required_cap)) {
        return {authorization_outcome::deny, "capability_missing", effective_caps, effective_constraints};
    }

    // Verify resource access
    bool resource_permitted = false;
    for (const auto& allowed : effective_resources) {
        if (allowed.matches(req.resource)) {
            resource_permitted = true;
            break;
        }
    }

    if (!resource_permitted) {
        return {authorization_outcome::deny, "resource_not_permitted", effective_caps, effective_constraints};
    }

    // Verify execution constraints
    if (effective_constraints.max_allowed_tokens > 0 &&
        req.requested_tokens > effective_constraints.max_allowed_tokens) {
        return {authorization_outcome::deny, "max_tokens_exceeded", effective_caps, effective_constraints};
    }

    if (effective_constraints.max_allowed_temperature > 0.0f &&
        req.requested_temperature > effective_constraints.max_allowed_temperature) {
        return {authorization_outcome::deny, "temperature_exceeded", effective_caps, effective_constraints};
    }

    if (effective_constraints.disallow_streaming && req.streaming_requested) {
        return {authorization_outcome::deny, "streaming_disallowed", effective_caps, effective_constraints};
    }

    if (effective_constraints.disallow_reasoning && req.reasoning_requested) {
        return {authorization_outcome::deny, "reasoning_disallowed", effective_caps, effective_constraints};
    }

    return {authorization_outcome::allow, "ok", effective_caps, effective_constraints};
}

bool policy_authorizer::validate_against_advertised_capabilities(
    const authorization_request& req,
    const linep::v0_2::runtime_capabilities_descriptor& advertised_caps,
    authorization_decision& out_decision) const noexcept {
    // Rule: Advertised runtime capabilities NEVER grant permissions.
    // They only provide negative bounds on what the underlying runtime can execute.
    out_decision = authorize(req);
    if (!out_decision.is_allowed()) {
        return false;
    }

    if (req.action == security_action::execute) {
        if (req.resource.kind == resource_kind::model) {
            bool model_supported = false;
            for (const auto& m : advertised_caps.supported_models) {
                if (m == req.resource.name) {
                    model_supported = true;
                    break;
                }
            }
            if (!model_supported) {
                out_decision = {authorization_outcome::deny, "model_not_supported_by_runtime",
                                out_decision.granted_capabilities, out_decision.effective_constraints};
                return false;
            }
        }

        bool profile_supported = false;
        for (const auto& p : advertised_caps.supported_profiles) {
            if (p == req.profile) {
                profile_supported = true;
                break;
            }
        }
        if (!profile_supported) {
            out_decision = {authorization_outcome::deny, "profile_not_supported_by_runtime",
                            out_decision.granted_capabilities, out_decision.effective_constraints};
            return false;
        }

        if (req.streaming_requested && !advertised_caps.supports_streaming) {
            out_decision = {authorization_outcome::deny, "streaming_not_supported_by_runtime",
                            out_decision.granted_capabilities, out_decision.effective_constraints};
            return false;
        }

        if (req.reasoning_requested && !advertised_caps.supports_reasoning_deltas) {
            out_decision = {authorization_outcome::deny, "reasoning_not_supported_by_runtime",
                            out_decision.granted_capabilities, out_decision.effective_constraints};
            return false;
        }

        if (req.profile == linep::v0_2::runtime_profile::embed &&
            req.resource.kind == resource_kind::embedding_space) {
            bool space_supported = false;
            for (const auto& sp : advertised_caps.supported_embedding_spaces) {
                if (sp.embedding_space_id == req.resource.name) {
                    space_supported = true;
                    break;
                }
            }
            if (!space_supported) {
                out_decision = {authorization_outcome::deny, "embedding_space_not_supported_by_runtime",
                                out_decision.granted_capabilities, out_decision.effective_constraints};
                return false;
            }
        }
    }

    if (req.action == security_action::cancel && !advertised_caps.supports_cancellation) {
        out_decision = {authorization_outcome::deny, "cancellation_not_supported_by_runtime",
                        out_decision.granted_capabilities, out_decision.effective_constraints};
        return false;
    }

    return true;
}

} // namespace linep::sl::v0_2
