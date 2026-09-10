#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <linep/v0_2/control_plane.hpp>
#include <linep/v0_2/runtime_types.hpp>
#include <linep_sl/v0_2/authenticator.hpp>
#include <linep_sl/v0_2/replay_window.hpp>
#include <linep_sl/v0_2/security_contract.hpp>

namespace linep::sl::v0_2 {

constexpr std::uint8_t GROUP_AUTH_MAGIC[8] = {'L', 'N', 'S', '2', 'G', 'R', 'P', 0x00};

enum class group_type : std::uint8_t {
    unknown = 0,
    ephemeral_task = 1,
    long_lived_worker = 2,
    quorum_consensus = 3,
    federation_boundary = 4,
};

enum class group_state : std::uint8_t {
    active = 0,
    suspended = 1,
    closed = 2,
};

enum class member_role : std::uint8_t {
    unknown = 0,
    coordinator = 1,
    worker_primary = 2,
    worker_redundant = 3,
    validator = 4,
    observer = 5,
};

enum class member_status : std::uint8_t {
    unknown = 0,
    active = 1,
    suspended = 2,
    removed = 3,
    quarantined = 4,
};

enum class group_operation_type : std::uint8_t {
    unknown = 0,
    create = 1,
    add_member = 2,
    remove_member = 3,
    update_role = 4,
    rekey = 5,
    close = 6,
};

enum class group_verification_status : std::uint8_t {
    ok = 0,
    group_not_found = 1,
    group_inactive = 2,
    stale_epoch = 3,
    future_epoch = 4,
    member_not_found = 5,
    member_not_active = 6,
    signature_invalid = 7,
    digest_failed = 8,
    replay_rejected = 9,
    binding_invalid = 10,
    suite_unsupported = 11,
};

struct security_group_member {
    linep::v0_2::node_endpoint_identity endpoint;
    std::uint32_t trust_domain_id{0};
    std::uint64_t subject_id{0};
    member_role role{member_role::worker_primary};
    member_status status{member_status::active};
    std::uint64_t joined_epoch{0};
    std::uint64_t credential_revision{0};
    std::uint64_t added_at_us{0};

    bool is_valid() const noexcept {
        return endpoint.node_id != 0 && endpoint.runtime_id != 0 &&
               endpoint.endpoint_id != 0 && trust_domain_id != 0 &&
               subject_id != 0 && role != member_role::unknown &&
               status != member_status::unknown;
    }

    bool is_active() const noexcept {
        return is_valid() && status == member_status::active;
    }
};

using group_member = security_group_member;

struct group_context {
    std::uint64_t group_id{0};
    std::uint64_t group_epoch{0};
    group_type type{group_type::ephemeral_task};
    crypto_suite suite{crypto_suite::hmac_sha256_128};
    group_state state{group_state::active};
    std::uint64_t created_at_us{0};
    std::uint64_t epoch_advanced_at_us{0};
    std::vector<security_group_member> members;
    std::vector<std::uint8_t> confirmed_transcript_hash;
    std::vector<std::uint8_t> epoch_secret;

    bool is_valid() const noexcept {
        return group_id != 0 && group_epoch != 0 &&
               type != group_type::unknown &&
               suite != crypto_suite::none &&
               !members.empty() &&
               !epoch_secret.empty();
    }
};

struct group_message_binding {
    std::uint64_t group_id{0};
    std::uint64_t group_epoch{0};
    linep::v0_2::node_endpoint_identity sender_endpoint;
    std::uint32_t sender_trust_domain_id{0};
    std::uint64_t sender_subject_id{0};
    data_message_class message_class{data_message_class::unknown};
    digest_algorithm digest{digest_algorithm::sha256};
    std::vector<std::uint8_t> content_digest;
    std::uint64_t message_seq{0};

    bool is_valid() const noexcept {
        return group_id != 0 && group_epoch != 0 &&
               sender_endpoint.node_id != 0 && sender_endpoint.runtime_id != 0 &&
               sender_endpoint.endpoint_id != 0 && sender_trust_domain_id != 0 &&
               sender_subject_id != 0 && message_class != data_message_class::unknown &&
               digest != digest_algorithm::unknown && !content_digest.empty() &&
               message_seq != 0;
    }
};

bool encode_group_authenticator_input(
    const group_message_binding& binding,
    std::vector<std::uint8_t>& out);

class group_security_manager {
public:
    group_security_manager() = default;

    // Create a new cryptographic group with coordinator as initial member in epoch 1
    bool create_group(
        std::uint64_t group_id,
        group_type type,
        crypto_suite suite,
        const group_member& coordinator,
        const std::vector<std::uint8_t>& initial_secret,
        std::uint64_t now_us) noexcept;

    // Add a new member, advances group_epoch and derives new epoch secret
    bool add_member(
        std::uint64_t group_id,
        const group_member& new_member,
        std::uint64_t now_us) noexcept;

    // Evict/remove member, advances group_epoch and derives new epoch secret (forward secrecy)
    bool remove_member(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        std::uint64_t now_us) noexcept;

    // Update member role (e.g., promote redundant worker to primary)
    bool update_member_role(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        member_role new_role,
        std::uint64_t now_us) noexcept;

    // Advance epoch and rekey group
    bool rekey_group(
        std::uint64_t group_id,
        std::uint64_t now_us) noexcept;

    // Close group permanently
    bool close_group(
        std::uint64_t group_id,
        std::uint64_t now_us) noexcept;

    // Inspect group context
    bool get_group_context(
        std::uint64_t group_id,
        group_context& out_ctx) const noexcept;

    // Check if an endpoint is an active member of group at current epoch
    bool is_member_active(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint) const noexcept;

    // Sign message under group epoch key
    bool sign_group_message(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        std::vector<std::uint8_t>& out_tag) const noexcept;

    // Verify incoming group message with replay protection and epoch validation
    group_verification_status verify_group_message(
        std::uint64_t group_id,
        std::uint64_t epoch,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        const std::vector<std::uint8_t>& tag,
        std::uint64_t now_us) noexcept;

    std::size_t get_group_count() const noexcept;
    std::size_t get_active_group_count() const noexcept;

private:
    struct member_replay_key {
        std::uint64_t group_id{0};
        std::uint64_t epoch{0};
        linep::v0_2::node_endpoint_identity endpoint;

        bool operator==(const member_replay_key& other) const noexcept {
            return group_id == other.group_id &&
                   epoch == other.epoch &&
                   endpoint == other.endpoint;
        }
    };

    struct member_replay_key_hash {
        std::size_t operator()(const member_replay_key& k) const noexcept {
            std::size_t h1 = std::hash<std::uint64_t>{}(k.group_id);
            std::size_t h2 = std::hash<std::uint64_t>{}(k.epoch);
            std::size_t h3 = linep::v0_2::node_endpoint_hash{}(k.endpoint);
            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };

    std::unordered_map<std::uint64_t, group_context> groups_;
    std::unordered_map<member_replay_key, sliding_replay_window, member_replay_key_hash> replay_windows_;
};

} // namespace linep::sl::v0_2
