#include <linep_sl/v0_2/group_security.hpp>

#include <algorithm>
#include <cstring>
#include <random>
#include <utility>
#include <vector>

namespace linep::sl::v0_2 {

namespace {

inline void append_u16(std::vector<std::uint8_t>& buf, std::uint16_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
}

inline void append_u32(std::vector<std::uint8_t>& buf, std::uint32_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

inline void append_u64(std::vector<std::uint8_t>& buf, std::uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

std::vector<std::uint8_t> generate_secure_entropy(std::size_t count = 32) {
    std::vector<std::uint8_t> buf(count);
    std::random_device rd;
    for (std::size_t i = 0; i < count; ++i) {
        buf[i] = static_cast<std::uint8_t>(rd() & 0xFF);
    }
    return buf;
}

bool derive_kdf_secret(
    const std::vector<std::uint8_t>& parent_key,
    const std::string& label,
    const std::vector<std::uint8_t>& context_info,
    std::vector<std::uint8_t>& out_derived_key) {
    std::vector<std::uint8_t> kdf_input;
    kdf_input.insert(kdf_input.end(), label.begin(), label.end());
    kdf_input.insert(kdf_input.end(), context_info.begin(), context_info.end());

    auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
    if (!auth) {
        return false;
    }
    return auth->sign(kdf_input, parent_key, out_derived_key);
}

} // namespace

bool encode_group_authenticator_input(
    const group_message_binding& binding,
    std::vector<std::uint8_t>& out) {
    out.clear();
    if (!binding.is_valid()) {
        return false;
    }

    out.reserve(128 + binding.content_digest.size());
    out.insert(out.end(), GROUP_AUTH_MAGIC, GROUP_AUTH_MAGIC + 8);
    out.push_back(0x00); // Version Major
    out.push_back(0x02); // Version Minor

    append_u64(out, binding.group_id);
    append_u64(out, binding.group_epoch);
    append_u64(out, binding.sender_endpoint.node_id);
    append_u64(out, binding.sender_endpoint.runtime_id);
    append_u32(out, binding.sender_endpoint.endpoint_id);
    append_u32(out, binding.sender_trust_domain_id);
    append_u64(out, binding.sender_subject_id);
    out.push_back(static_cast<std::uint8_t>(binding.message_class));
    out.push_back(static_cast<std::uint8_t>(binding.digest));
    append_u64(out, binding.message_seq);
    append_u32(out, binding.ratchet_generation);

    append_u16(out, static_cast<std::uint16_t>(binding.content_digest.size()));
    out.insert(out.end(), binding.content_digest.begin(), binding.content_digest.end());

    return true;
}

// ---------------------------------------------------------------------------
// Reference Group Crypto Provider Implementation (RFC 9420 Semantics Engine)
// ---------------------------------------------------------------------------
class reference_group_crypto_provider : public group_crypto_provider {
public:
    reference_group_crypto_provider() = default;

    bool create_group(
        std::uint64_t group_id,
        group_type type,
        mls_ciphersuite suite,
        const security_group_member& coordinator,
        const std::vector<std::uint8_t>& init_secret,
        std::uint64_t now_us) noexcept override {
        if (group_id == 0 || type == group_type::unknown || suite == mls_ciphersuite::unknown ||
            !coordinator.is_active() || coordinator.role != member_role::coordinator ||
            groups_.find(group_id) != groups_.end()) {
            return false;
        }

        std::vector<std::uint8_t> secret = init_secret.empty() ? generate_secure_entropy(32) : init_secret;

        // Calculate initial public transcript hash
        std::vector<std::uint8_t> init_transcript_input;
        append_u64(init_transcript_input, group_id);
        init_transcript_input.push_back(static_cast<std::uint8_t>(type));
        append_u16(init_transcript_input, static_cast<std::uint16_t>(suite));
        append_u64(init_transcript_input, coordinator.endpoint.node_id);
        append_u64(init_transcript_input, coordinator.endpoint.runtime_id);
        append_u32(init_transcript_input, coordinator.endpoint.endpoint_id);
        append_u64(init_transcript_input, coordinator.subject_id);

        std::vector<std::uint8_t> transcript_hash;
        if (!compute_sha256_digest(init_transcript_input.data(), init_transcript_input.size(), transcript_hash)) {
            return false;
        }

        // Derive Epoch 1 Secret
        std::vector<std::uint8_t> epoch_1_secret;
        if (!derive_kdf_secret(secret, "MLS_EPOCH_1_INIT", transcript_hash, epoch_1_secret)) {
            return false;
        }

        // Generate Coordinator Leaf Secret
        std::vector<std::uint8_t> coord_leaf_info;
        append_u64(coord_leaf_info, coordinator.endpoint.node_id);
        append_u64(coord_leaf_info, coordinator.endpoint.runtime_id);
        append_u32(coord_leaf_info, coordinator.endpoint.endpoint_id);

        std::vector<std::uint8_t> coord_leaf_secret;
        if (!derive_kdf_secret(secret, "MLS_MEMBER_LEAF_SECRET", coord_leaf_info, coord_leaf_secret)) {
            return false;
        }

        group_context ctx;
        ctx.group_id = group_id;
        ctx.group_epoch = 1;
        ctx.type = type;
        ctx.ciphersuite = suite;
        ctx.state = group_state::active;
        ctx.created_at_us = now_us;
        ctx.epoch_advanced_at_us = now_us;

        security_group_member coord_copy = coordinator;
        coord_copy.joined_epoch = 1;
        coord_copy.added_at_us = now_us;
        ctx.members.push_back(coord_copy);

        ctx.confirmed_transcript_hash = transcript_hash;
        ctx.execution_group_state_hash = transcript_hash;
        ctx.tree_hash = transcript_hash;

        internal_group_state state;
        state.context = std::move(ctx);
        state.epoch_secret = std::move(epoch_1_secret);
        state.member_leaf_secrets[coordinator.endpoint] = std::move(coord_leaf_secret);
        state.sender_ratchets[coordinator.endpoint] = 0;

        groups_.emplace(group_id, std::move(state));
        return true;
    }

    bool add_member(
        std::uint64_t group_id,
        const security_group_member& new_member,
        const std::vector<std::uint8_t>& member_public_key,
        const std::vector<std::uint8_t>& join_entropy,
        std::uint64_t now_us) noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active ||
            !new_member.is_valid()) {
            return false;
        }

        auto& state = it->second;
        auto& ctx = state.context;

        for (const auto& m : ctx.members) {
            if (m.endpoint == new_member.endpoint && m.status == member_status::active) {
                return false;
            }
        }

        std::uint64_t next_epoch = ctx.group_epoch + 1;
        std::vector<std::uint8_t> entropy = join_entropy.empty() ? generate_secure_entropy(32) : join_entropy;

        // Update public transcript hash (MLS Add Proposal + Commit)
        std::vector<std::uint8_t> op_input = ctx.confirmed_transcript_hash;
        op_input.push_back(static_cast<std::uint8_t>(group_operation_type::add_member));
        append_u64(op_input, next_epoch);
        append_u64(op_input, new_member.endpoint.node_id);
        append_u64(op_input, new_member.endpoint.runtime_id);
        append_u32(op_input, new_member.endpoint.endpoint_id);
        append_u64(op_input, new_member.subject_id);
        op_input.push_back(static_cast<std::uint8_t>(new_member.role));

        std::vector<std::uint8_t> next_transcript;
        if (!compute_sha256_digest(op_input.data(), op_input.size(), next_transcript)) {
            return false;
        }

        // Derive Next Epoch Secret mixing parent secret with fresh join entropy
        std::vector<std::uint8_t> kdf_context = next_transcript;
        kdf_context.insert(kdf_context.end(), entropy.begin(), entropy.end());

        std::vector<std::uint8_t> next_epoch_secret;
        if (!derive_kdf_secret(state.epoch_secret, "MLS_EPOCH_ADVANCE_ADD", kdf_context, next_epoch_secret)) {
            return false;
        }

        // Generate private leaf secret for the new member
        std::vector<std::uint8_t> member_leaf_info;
        append_u64(member_leaf_info, new_member.endpoint.node_id);
        append_u64(member_leaf_info, new_member.endpoint.runtime_id);
        append_u32(member_leaf_info, new_member.endpoint.endpoint_id);

        std::vector<std::uint8_t> member_leaf_secret;
        if (!derive_kdf_secret(entropy, "MLS_MEMBER_LEAF_SECRET", member_leaf_info, member_leaf_secret)) {
            return false;
        }

        security_group_member member_copy = new_member;
        member_copy.status = member_status::active;
        member_copy.joined_epoch = next_epoch;
        member_copy.added_at_us = now_us;
        member_copy.public_key = member_public_key;
        ctx.members.push_back(member_copy);

        ctx.group_epoch = next_epoch;
        ctx.confirmed_transcript_hash = next_transcript;
        ctx.execution_group_state_hash = next_transcript;
        ctx.tree_hash = next_transcript;
        ctx.epoch_advanced_at_us = now_us;

        state.epoch_secret = std::move(next_epoch_secret);
        state.member_leaf_secrets[new_member.endpoint] = std::move(member_leaf_secret);
        state.sender_ratchets[new_member.endpoint] = 0;

        return true;
    }

    bool remove_member(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        const std::vector<std::uint8_t>& fresh_commit_entropy,
        std::uint64_t now_us) noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active) {
            return false;
        }

        auto& state = it->second;
        auto& ctx = state.context;
        bool found = false;

        for (auto& m : ctx.members) {
            if (m.endpoint == endpoint && m.status == member_status::active) {
                m.status = member_status::removed;
                found = true;
                break;
            }
        }

        if (!found) {
            return false;
        }

        std::uint64_t next_epoch = ctx.group_epoch + 1;
        std::vector<std::uint8_t> commit_secret = fresh_commit_entropy.empty() ? generate_secure_entropy(32) : fresh_commit_entropy;

        // Erase evicted member's private leaf secret from state
        state.member_leaf_secrets.erase(endpoint);
        state.sender_ratchets.erase(endpoint);

        // Update public transcript hash (MLS Remove Proposal + Commit)
        std::vector<std::uint8_t> op_input = ctx.confirmed_transcript_hash;
        op_input.push_back(static_cast<std::uint8_t>(group_operation_type::remove_member));
        append_u64(op_input, next_epoch);
        append_u64(op_input, endpoint.node_id);
        append_u64(op_input, endpoint.runtime_id);
        append_u32(op_input, endpoint.endpoint_id);

        std::vector<std::uint8_t> next_transcript;
        if (!compute_sha256_digest(op_input.data(), op_input.size(), next_transcript)) {
            return false;
        }

        // Derive Next Epoch Secret with fresh commit entropy (Forward Secrecy!)
        // The evicted member who only knows epoch_secret_N cannot compute epoch_secret_(N+1) without commit_secret!
        std::vector<std::uint8_t> kdf_context = next_transcript;
        kdf_context.insert(kdf_context.end(), commit_secret.begin(), commit_secret.end());

        std::vector<std::uint8_t> next_epoch_secret;
        if (!derive_kdf_secret(state.epoch_secret, "MLS_EPOCH_ADVANCE_REMOVE", kdf_context, next_epoch_secret)) {
            return false;
        }

        ctx.group_epoch = next_epoch;
        ctx.confirmed_transcript_hash = next_transcript;
        ctx.execution_group_state_hash = next_transcript;
        ctx.tree_hash = next_transcript;
        ctx.epoch_advanced_at_us = now_us;

        state.epoch_secret = std::move(next_epoch_secret);
        return true;
    }

    bool update_member_role(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint,
        member_role new_role,
        std::uint64_t now_us) noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active ||
            new_role == member_role::unknown) {
            return false;
        }

        auto& state = it->second;
        auto& ctx = state.context;
        bool found = false;

        for (auto& m : ctx.members) {
            if (m.endpoint == endpoint && m.status == member_status::active) {
                m.role = new_role;
                found = true;
                break;
            }
        }

        if (!found) {
            return false;
        }

        // Application-layer role changes mutate execution_group_state_hash
        std::vector<std::uint8_t> op_input = ctx.execution_group_state_hash;
        op_input.push_back(static_cast<std::uint8_t>(group_operation_type::update_role));
        append_u64(op_input, ctx.group_epoch);
        append_u64(op_input, endpoint.node_id);
        append_u64(op_input, endpoint.runtime_id);
        append_u32(op_input, endpoint.endpoint_id);
        op_input.push_back(static_cast<std::uint8_t>(new_role));

        std::vector<std::uint8_t> next_state_hash;
        if (!compute_sha256_digest(op_input.data(), op_input.size(), next_state_hash)) {
            return false;
        }

        ctx.execution_group_state_hash = std::move(next_state_hash);
        return true;
    }

    bool rekey_group(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& updating_member,
        const std::vector<std::uint8_t>& fresh_update_entropy,
        std::uint64_t now_us) noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active) {
            return false;
        }

        auto& state = it->second;
        auto& ctx = state.context;

        bool active_member = false;
        for (const auto& m : ctx.members) {
            if (m.endpoint == updating_member && m.status == member_status::active) {
                active_member = true;
                break;
            }
        }
        if (!active_member) {
            return false;
        }

        std::uint64_t next_epoch = ctx.group_epoch + 1;
        std::vector<std::uint8_t> update_secret = fresh_update_entropy.empty() ? generate_secure_entropy(32) : fresh_update_entropy;

        // Update updating member's leaf secret
        std::vector<std::uint8_t> member_leaf_info;
        append_u64(member_leaf_info, updating_member.node_id);
        append_u64(member_leaf_info, updating_member.runtime_id);
        append_u32(member_leaf_info, updating_member.endpoint_id);

        std::vector<std::uint8_t> new_leaf_secret;
        if (!derive_kdf_secret(update_secret, "MLS_MEMBER_LEAF_UPDATE", member_leaf_info, new_leaf_secret)) {
            return false;
        }
        state.member_leaf_secrets[updating_member] = std::move(new_leaf_secret);

        // Update transcript (MLS Update Proposal + Commit)
        std::vector<std::uint8_t> op_input = ctx.confirmed_transcript_hash;
        op_input.push_back(static_cast<std::uint8_t>(group_operation_type::rekey));
        append_u64(op_input, next_epoch);
        append_u64(op_input, updating_member.node_id);
        append_u64(op_input, updating_member.runtime_id);
        append_u32(op_input, updating_member.endpoint_id);

        std::vector<std::uint8_t> next_transcript;
        if (!compute_sha256_digest(op_input.data(), op_input.size(), next_transcript)) {
            return false;
        }

        // Post-Compromise Security (PCS) derivation
        std::vector<std::uint8_t> kdf_context = next_transcript;
        kdf_context.insert(kdf_context.end(), update_secret.begin(), update_secret.end());

        std::vector<std::uint8_t> next_epoch_secret;
        if (!derive_kdf_secret(state.epoch_secret, "MLS_EPOCH_ADVANCE_REKEY", kdf_context, next_epoch_secret)) {
            return false;
        }

        ctx.group_epoch = next_epoch;
        ctx.confirmed_transcript_hash = next_transcript;
        ctx.execution_group_state_hash = next_transcript;
        ctx.tree_hash = next_transcript;
        ctx.epoch_advanced_at_us = now_us;

        state.epoch_secret = std::move(next_epoch_secret);
        return true;
    }

    bool close_group(
        std::uint64_t group_id,
        std::uint64_t now_us) noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state == group_state::closed) {
            return false;
        }

        // Secure state erasure
        it->second.context.state = group_state::closed;
        std::fill(it->second.epoch_secret.begin(), it->second.epoch_secret.end(), 0x00);
        it->second.member_leaf_secrets.clear();
        it->second.sender_ratchets.clear();
        return true;
    }

    bool get_group_context(
        std::uint64_t group_id,
        group_context& out_ctx) const noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end()) {
            return false;
        }
        out_ctx = it->second.context; // Copies ONLY public authenticated state!
        return true;
    }

    bool is_member_active(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& endpoint) const noexcept override {
        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active) {
            return false;
        }

        for (const auto& m : it->second.context.members) {
            if (m.endpoint == endpoint && m.status == member_status::active) {
                return true;
            }
        }
        return false;
    }

    bool protect(
        std::uint64_t group_id,
        const linep::v0_2::node_endpoint_identity& sender_endpoint,
        group_protection_mode mode,
        data_message_class msg_class,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t message_seq,
        protected_group_message& out_msg) noexcept override {
        out_msg = {};

        auto it = groups_.find(group_id);
        if (it == groups_.end() || it->second.context.state != group_state::active ||
            message_seq == 0 || mode == group_protection_mode::unknown) {
            return false;
        }

        auto& state = it->second;
        const auto& ctx = state.context;

        const security_group_member* sender = nullptr;
        for (const auto& m : ctx.members) {
            if (m.endpoint == sender_endpoint && m.status == member_status::active) {
                sender = &m;
                break;
            }
        }
        if (!sender) {
            return false;
        }

        auto leaf_it = state.member_leaf_secrets.find(sender_endpoint);
        if (leaf_it == state.member_leaf_secrets.end()) {
            return false;
        }

        // Advance sender cryptographic ratchet generation
        std::uint32_t generation = ++state.sender_ratchets[sender_endpoint];

        // Derive sender-specific per-generation message key (Anti-Impersonation!)
        std::vector<std::uint8_t> sender_info;
        append_u64(sender_info, sender_endpoint.node_id);
        append_u64(sender_info, sender_endpoint.runtime_id);
        append_u32(sender_info, sender_endpoint.endpoint_id);
        append_u32(sender_info, generation);

        std::vector<std::uint8_t> sender_signing_key;
        if (!derive_kdf_secret(leaf_it->second, "MLS_SENDER_SIGNING_KEY", state.epoch_secret, sender_signing_key)) {
            return false;
        }

        std::vector<std::uint8_t> msg_key;
        if (!derive_kdf_secret(sender_signing_key, "MLS_MESSAGE_KEY", sender_info, msg_key)) {
            return false;
        }

        std::vector<std::uint8_t> final_payload;
        if (mode == group_protection_mode::confidential_and_authenticated) {
            // Encrypt payload using epoch traffic stream
            std::vector<std::uint8_t> keystream;
            if (!derive_kdf_secret(state.epoch_secret, "MLS_ENCRYPT_STREAM", sender_info, keystream)) {
                return false;
            }
            final_payload.resize(payload.size());
            for (std::size_t i = 0; i < payload.size(); ++i) {
                final_payload[i] = payload[i] ^ keystream[i % keystream.size()];
            }
        } else {
            final_payload = payload;
        }

        std::vector<std::uint8_t> content_digest;
        if (!compute_sha256_digest(final_payload.data(), final_payload.size(), content_digest)) {
            return false;
        }

        group_message_binding binding;
        binding.group_id = group_id;
        binding.group_epoch = ctx.group_epoch;
        binding.sender_endpoint = sender_endpoint;
        binding.sender_trust_domain_id = sender->trust_domain_id;
        binding.sender_subject_id = sender->subject_id;
        binding.message_class = msg_class;
        binding.digest = digest_algorithm::sha256;
        binding.content_digest = std::move(content_digest);
        binding.message_seq = message_seq;
        binding.ratchet_generation = generation;

        if (!binding.is_valid()) {
            return false;
        }

        std::vector<std::uint8_t> auth_input;
        if (!encode_group_authenticator_input(binding, auth_input)) {
            return false;
        }

        auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
        if (!auth) {
            return false;
        }

        std::vector<std::uint8_t> tag;
        if (!auth->sign(auth_input, msg_key, tag)) {
            return false;
        }

        out_msg.group_id = group_id;
        out_msg.group_epoch = ctx.group_epoch;
        out_msg.mode = mode;
        out_msg.sender_endpoint = sender_endpoint;
        out_msg.message_seq = message_seq;
        out_msg.ratchet_generation = generation;
        out_msg.ciphertext_or_payload = std::move(final_payload);
        out_msg.authentication_tag = std::move(tag);

        return true;
    }

    group_verification_status unprotect(
        const protected_group_message& in_msg,
        const linep::v0_2::node_endpoint_identity& receiver_endpoint,
        data_message_class expected_class,
        std::vector<std::uint8_t>& out_payload,
        std::uint64_t now_us) noexcept override {
        out_payload.clear();

        auto it = groups_.find(in_msg.group_id);
        if (it == groups_.end()) {
            return group_verification_status::group_not_found;
        }

        auto& state = it->second;
        const auto& ctx = state.context;
        if (ctx.state != group_state::active) {
            return group_verification_status::group_inactive;
        }

        if (in_msg.group_epoch < ctx.group_epoch) {
            return group_verification_status::stale_epoch;
        }
        if (in_msg.group_epoch > ctx.group_epoch) {
            return group_verification_status::future_epoch;
        }

        const security_group_member* sender = nullptr;
        for (const auto& m : ctx.members) {
            if (m.endpoint == in_msg.sender_endpoint) {
                sender = &m;
                break;
            }
        }
        if (!sender) {
            return group_verification_status::member_not_found;
        }
        if (sender->status != member_status::active) {
            return group_verification_status::member_not_active;
        }

        auto leaf_it = state.member_leaf_secrets.find(in_msg.sender_endpoint);
        if (leaf_it == state.member_leaf_secrets.end()) {
            return group_verification_status::impersonation_detected;
        }

        // Check sliding replay window per (group_id, epoch, sender_endpoint)
        member_replay_key rkey{in_msg.group_id, in_msg.group_epoch, in_msg.sender_endpoint};
        auto& win = replay_windows_[rkey];
        if (win.check(in_msg.message_seq) != replay_status::accepted) {
            return group_verification_status::replay_rejected;
        }

        // Derive expected sender-specific per-generation message key
        std::vector<std::uint8_t> sender_info;
        append_u64(sender_info, in_msg.sender_endpoint.node_id);
        append_u64(sender_info, in_msg.sender_endpoint.runtime_id);
        append_u32(sender_info, in_msg.sender_endpoint.endpoint_id);
        append_u32(sender_info, in_msg.ratchet_generation);

        std::vector<std::uint8_t> sender_signing_key;
        if (!derive_kdf_secret(leaf_it->second, "MLS_SENDER_SIGNING_KEY", state.epoch_secret, sender_signing_key)) {
            return group_verification_status::suite_unsupported;
        }

        std::vector<std::uint8_t> msg_key;
        if (!derive_kdf_secret(sender_signing_key, "MLS_MESSAGE_KEY", sender_info, msg_key)) {
            return group_verification_status::suite_unsupported;
        }

        std::vector<std::uint8_t> content_digest;
        if (!compute_sha256_digest(in_msg.ciphertext_or_payload.data(), in_msg.ciphertext_or_payload.size(), content_digest)) {
            return group_verification_status::digest_failed;
        }

        group_message_binding binding;
        binding.group_id = in_msg.group_id;
        binding.group_epoch = in_msg.group_epoch;
        binding.sender_endpoint = in_msg.sender_endpoint;
        binding.sender_trust_domain_id = sender->trust_domain_id;
        binding.sender_subject_id = sender->subject_id;
        binding.message_class = expected_class;
        binding.digest = digest_algorithm::sha256;
        binding.content_digest = std::move(content_digest);
        binding.message_seq = in_msg.message_seq;
        binding.ratchet_generation = in_msg.ratchet_generation;

        if (!binding.is_valid()) {
            return group_verification_status::binding_invalid;
        }

        std::vector<std::uint8_t> auth_input;
        if (!encode_group_authenticator_input(binding, auth_input)) {
            return group_verification_status::binding_invalid;
        }

        auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
        if (!auth) {
            return group_verification_status::suite_unsupported;
        }

        if (!auth->verify(auth_input, msg_key, in_msg.authentication_tag)) {
            return group_verification_status::signature_invalid;
        }

        if (in_msg.mode == group_protection_mode::confidential_and_authenticated) {
            // Decrypt payload
            std::vector<std::uint8_t> keystream;
            if (!derive_kdf_secret(state.epoch_secret, "MLS_ENCRYPT_STREAM", sender_info, keystream)) {
                return group_verification_status::decryption_failed;
            }
            out_payload.resize(in_msg.ciphertext_or_payload.size());
            for (std::size_t i = 0; i < in_msg.ciphertext_or_payload.size(); ++i) {
                out_payload[i] = in_msg.ciphertext_or_payload[i] ^ keystream[i % keystream.size()];
            }
        } else {
            out_payload = in_msg.ciphertext_or_payload;
        }

        win.update(in_msg.message_seq);
        return group_verification_status::ok;
    }

    std::size_t get_group_count() const noexcept override {
        return groups_.size();
    }

    std::size_t get_active_group_count() const noexcept override {
        std::size_t count = 0;
        for (const auto& kv : groups_) {
            if (kv.second.context.state == group_state::active) {
                ++count;
            }
        }
        return count;
    }

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

    struct internal_group_state {
        group_context context;
        std::vector<std::uint8_t> epoch_secret;
        std::unordered_map<linep::v0_2::node_endpoint_identity, std::vector<std::uint8_t>, linep::v0_2::node_endpoint_hash> member_leaf_secrets;
        std::unordered_map<linep::v0_2::node_endpoint_identity, std::uint32_t, linep::v0_2::node_endpoint_hash> sender_ratchets;
    };

    std::unordered_map<std::uint64_t, internal_group_state> groups_;
    std::unordered_map<member_replay_key, sliding_replay_window, member_replay_key_hash> replay_windows_;
};

std::unique_ptr<group_crypto_provider> create_reference_group_crypto_provider() {
    return std::make_unique<reference_group_crypto_provider>();
}

// ---------------------------------------------------------------------------
// Group Security Manager Orchestration
// ---------------------------------------------------------------------------
group_security_manager::group_security_manager(std::unique_ptr<group_crypto_provider> provider)
    : provider_(provider ? std::move(provider) : create_reference_group_crypto_provider()) {}

bool group_security_manager::create_group(
    std::uint64_t group_id,
    group_type type,
    mls_ciphersuite suite,
    const security_group_member& coordinator,
    const std::vector<std::uint8_t>& init_secret,
    std::uint64_t now_us) noexcept {
    return provider_->create_group(group_id, type, suite, coordinator, init_secret, now_us);
}

bool group_security_manager::add_member(
    std::uint64_t group_id,
    const security_group_member& new_member,
    const std::vector<std::uint8_t>& member_public_key,
    const std::vector<std::uint8_t>& join_entropy,
    std::uint64_t now_us) noexcept {
    return provider_->add_member(group_id, new_member, member_public_key, join_entropy, now_us);
}

bool group_security_manager::remove_member(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint,
    const std::vector<std::uint8_t>& fresh_commit_entropy,
    std::uint64_t now_us) noexcept {
    return provider_->remove_member(group_id, endpoint, fresh_commit_entropy, now_us);
}

bool group_security_manager::update_member_role(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint,
    member_role new_role,
    std::uint64_t now_us) noexcept {
    return provider_->update_member_role(group_id, endpoint, new_role, now_us);
}

bool group_security_manager::rekey_group(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& updating_member,
    const std::vector<std::uint8_t>& fresh_update_entropy,
    std::uint64_t now_us) noexcept {
    return provider_->rekey_group(group_id, updating_member, fresh_update_entropy, now_us);
}

bool group_security_manager::close_group(
    std::uint64_t group_id,
    std::uint64_t now_us) noexcept {
    return provider_->close_group(group_id, now_us);
}

bool group_security_manager::get_group_context(
    std::uint64_t group_id,
    group_context& out_ctx) const noexcept {
    return provider_->get_group_context(group_id, out_ctx);
}

bool group_security_manager::is_member_active(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint) const noexcept {
    return provider_->is_member_active(group_id, endpoint);
}

bool group_security_manager::protect_group_message(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& sender_endpoint,
    group_protection_mode mode,
    data_message_class msg_class,
    const std::vector<std::uint8_t>& payload,
    std::uint64_t message_seq,
    protected_group_message& out_msg) noexcept {
    return provider_->protect(group_id, sender_endpoint, mode, msg_class, payload, message_seq, out_msg);
}

group_verification_status group_security_manager::unprotect_group_message(
    const protected_group_message& in_msg,
    const linep::v0_2::node_endpoint_identity& receiver_endpoint,
    data_message_class expected_class,
    std::vector<std::uint8_t>& out_payload,
    std::uint64_t now_us) noexcept {
    return provider_->unprotect(in_msg, receiver_endpoint, expected_class, out_payload, now_us);
}

bool group_security_manager::sign_group_message(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& sender_endpoint,
    data_message_class msg_class,
    const std::vector<std::uint8_t>& payload,
    std::uint64_t message_seq,
    std::vector<std::uint8_t>& out_tag) noexcept {
    protected_group_message msg;
    if (!provider_->protect(group_id, sender_endpoint, group_protection_mode::authenticated_only, msg_class, payload, message_seq, msg)) {
        return false;
    }
    out_tag = std::move(msg.authentication_tag);
    return true;
}

group_verification_status group_security_manager::verify_group_message(
    std::uint64_t group_id,
    std::uint64_t epoch,
    const linep::v0_2::node_endpoint_identity& sender_endpoint,
    data_message_class msg_class,
    const std::vector<std::uint8_t>& payload,
    std::uint64_t message_seq,
    const std::vector<std::uint8_t>& tag,
    std::uint64_t now_us) noexcept {
    protected_group_message msg;
    msg.group_id = group_id;
    msg.group_epoch = epoch;
    msg.mode = group_protection_mode::authenticated_only;
    msg.sender_endpoint = sender_endpoint;
    msg.message_seq = message_seq;
    msg.ratchet_generation = static_cast<std::uint32_t>(message_seq); // backward compatible generation map
    msg.ciphertext_or_payload = payload;
    msg.authentication_tag = tag;

    std::vector<std::uint8_t> out_payload;
    return provider_->unprotect(msg, sender_endpoint, msg_class, out_payload, now_us);
}

std::size_t group_security_manager::get_group_count() const noexcept {
    return provider_->get_group_count();
}

std::size_t group_security_manager::get_active_group_count() const noexcept {
    return provider_->get_active_group_count();
}

} // namespace linep::sl::v0_2
