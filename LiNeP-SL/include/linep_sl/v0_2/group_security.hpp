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

// RFC 9420 Section 5 - Ciphersuite Identifiers (16-bit)
enum class mls_ciphersuite : std::uint16_t {
    unknown = 0x0000,
    mls_128_dhkemx25519_aes128gcm_sha256_ed25519 = 0x0001,
    mls_128_dhkemp256_aes128gcm_sha256_p256 = 0x0002,
    mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 = 0x0003,
    mls_256_dhkemx448_aes256gcm_sha512_ed448 = 0x0004,
    mls_256_dhkemp384_aes256gcm_sha384_p384 = 0x0005,
    mls_256_dhkemp521_aes256gcm_sha512_p521 = 0x0006,
    mls_256_dhkemx448_chacha20poly1305_sha512_ed448 = 0x0007,
};

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

enum class group_protection_mode : std::uint8_t {
    unknown = 0,
    authenticated_only = 1,             // PublicMessage / Integrity & authenticity
    confidential_and_authenticated = 2, // PrivateMessage / Encrypted payload + Auth tag
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
    decryption_failed = 12,
    impersonation_detected = 13,
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
    std::vector<std::uint8_t> public_key;

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

// RFC 9420 Section 6.1 GroupContext — Public Authenticated State (No secret key material!)
struct group_context {
    std::uint64_t group_id{0};
    std::uint64_t group_epoch{0};
    group_type type{group_type::ephemeral_task};
    mls_ciphersuite ciphersuite{mls_ciphersuite::mls_128_dhkemx25519_aes128gcm_sha256_ed25519};
    group_state state{group_state::active};
    std::uint64_t created_at_us{0};
    std::uint64_t epoch_advanced_at_us{0};
    std::vector<security_group_member> members;
    std::vector<std::uint8_t> execution_group_state_hash;
    std::vector<std::uint8_t> tree_hash;
    std::vector<std::uint8_t> confirmed_transcript_hash;

    bool is_valid() const noexcept {
        return group_id != 0 && group_epoch != 0 &&
               type != group_type::unknown &&
               ciphersuite != mls_ciphersuite::unknown &&
               !members.empty() &&
               !confirmed_transcript_hash.empty();
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
    std::uint32_t ratchet_generation{0};

    bool is_valid() const noexcept {
        return group_id != 0 && group_epoch != 0 &&
               sender_endpoint.node_id != 0 && sender_endpoint.runtime_id != 0 &&
               sender_endpoint.endpoint_id != 0 && sender_trust_domain_id != 0 &&
               sender_subject_id != 0 && message_class != data_message_class::unknown &&
               digest != digest_algorithm::unknown && !content_digest.empty() &&
               message_seq != 0;
    }
};

struct protected_group_message {
    std::uint64_t group_id{0};
    std::uint64_t group_epoch{0};
    group_protection_mode mode{group_protection_mode::authenticated_only};
    linep::v0_2::node_endpoint_identity sender_endpoint;
    std::uint64_t message_seq{0};
    std::uint32_t ratchet_generation{0};
    std::vector<std::uint8_t> ciphertext_or_payload;
    std::vector<std::uint8_t> authentication_tag;

    bool is_valid() const noexcept {
        return group_id != 0 && group_epoch != 0 &&
               mode != group_protection_mode::unknown &&
               sender_endpoint.node_id != 0 &&
               message_seq != 0 &&
               !authentication_tag.empty();
    }
};

bool encode_group_authenticator_input(
    const group_message_binding& binding,
    std::vector<std::uint8_t>& out);

// Provider-neutral interface for group cryptography (RFC 9420 state machine or reference engine)
class group_crypto_provider {
public:
    virtual ~group_crypto_provider() = default;

    virtual bool create_group(
        std::uint64_t group_id,
        group_type type,
        mls_ciphersuite suite,
        const security_group_member& coordinator,
        const std::vector<std::uint8_t>& init_secret,
        std::uint64_t now_us) noexcept = 0;

    virtual bool add_member(
        std::uint64_t group_id,
        const security_group_member& new_member,
        const std::vector<std::uint8_t>& member_public_key,
        const std::vector<std::uint8_t>& join_entropy,
        std::uint64_t now_us) noexcept = 0;

    virtual bool remove_member(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        const std::vector<std::uint8_t>& fresh_commit_entropy,
        std::uint64_t now_us) noexcept = 0;

    virtual bool update_member_role(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        member_role new_role,
        std::uint64_t now_us) noexcept = 0;

    virtual bool rekey_group(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& updating_member,
        const std::vector<std::uint8_t>& fresh_update_entropy,
        std::uint64_t now_us) noexcept = 0;

    virtual bool close_group(
        std::uint64_t group_id,
        std::uint64_t now_us) noexcept = 0;

    virtual bool get_group_context(
        std::uint64_t group_id,
        group_context& out_ctx) const noexcept = 0;

    virtual bool is_member_active(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint) const noexcept = 0;

    virtual bool protect(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        group_protection_mode mode,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        protected_group_message& out_msg) noexcept = 0;

    virtual group_verification_status unprotect(
        const protected_group_message& in_msg,
        const linep::v0_2::node_endpoint_identity& receiver_endpoint,
        data_message_class expected_class,
        std::vector<std::uint8_t>& out_payload,
        std::uint64_t now_us) noexcept = 0;

    virtual std::size_t get_group_count() const noexcept = 0;
    virtual std::size_t get_active_group_count() const noexcept = 0;
};

// Factory for reference implementation
std::unique_ptr<group_crypto_provider> create_reference_group_crypto_provider();

// High-level manager orchestrating execution groups over a pluggable crypto provider
class group_security_manager {
public:
    explicit group_security_manager(std::unique_ptr<group_crypto_provider> provider = nullptr);

    bool create_group(
        std::uint64_t group_id,
        group_type type,
        mls_ciphersuite suite,
        const security_group_member& coordinator,
        const std::vector<std::uint8_t>& init_secret = {},
        std::uint64_t now_us = 0) noexcept;

    bool add_member(
        std::uint64_t group_id,
        const security_group_member& new_member,
        const std::vector<std::uint8_t>& member_public_key = {},
        const std::vector<std::uint8_t>& join_entropy = {},
        std::uint64_t now_us = 0) noexcept;

    bool remove_member(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        const std::vector<std::uint8_t>& fresh_commit_entropy = {},
        std::uint64_t now_us = 0) noexcept;

    bool update_member_role(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        member_role new_role,
        std::uint64_t now_us = 0) noexcept;

    bool rekey_group(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& updating_member,
        const std::vector<std::uint8_t>& fresh_update_entropy = {},
        std::uint64_t now_us = 0) noexcept;

    bool close_group(
        std::uint64_t group_id,
        std::uint64_t now_us = 0) noexcept;

    bool get_group_context(
        std::uint64_t group_id,
        group_context& out_ctx) const noexcept;

    bool is_member_active(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint) const noexcept;

    bool protect_group_message(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        group_protection_mode mode,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        protected_group_message& out_msg) noexcept;

    group_verification_status unprotect_group_message(
        const protected_group_message& in_msg,
        const linep::v0_2::node_endpoint_identity& receiver_endpoint,
        data_message_class expected_class,
        std::vector<std::uint8_t>& out_payload,
        std::uint64_t now_us = 0) noexcept;

    // Backward-compatible signing & verification helpers (authenticated-only)
    bool sign_group_message(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        std::vector<std::uint8_t>& out_tag) noexcept;

    group_verification_status verify_group_message(
        std::uint64_t group_id,
        std::uint64_t epoch,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        const std::vector<std::uint8_t>& tag,
        std::uint64_t now_us = 0) noexcept;

    std::size_t get_group_count() const noexcept;
    std::size_t get_active_group_count() const noexcept;

private:
    std::unique_ptr<group_crypto_provider> provider_;
};

} // namespace linep::sl::v0_2
