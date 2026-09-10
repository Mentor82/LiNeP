#include <linep_sl/v0_2/group_security.hpp>

#include <algorithm>
#include <cstring>
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

// Derive a next-epoch key using HMAC-SHA256
bool derive_epoch_secret(
    const std::vector<std::uint8_t>& parent_secret,
    const std::string& label,
    std::uint64_t epoch,
    const std::vector<std::uint8_t>& transcript_hash,
    std::vector<std::uint8_t>& out_epoch_secret) {
    std::vector<std::uint8_t> kdf_input;
    kdf_input.insert(kdf_input.end(), label.begin(), label.end());
    append_u64(kdf_input, epoch);
    kdf_input.insert(kdf_input.end(), transcript_hash.begin(), transcript_hash.end());

    auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
    if (!auth) {
        return false;
    }
    // We derive a 32-byte secret using HMAC-SHA256
    return auth->sign(kdf_input, parent_secret, out_epoch_secret);
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

    append_u16(out, static_cast<std::uint16_t>(binding.content_digest.size()));
    out.insert(out.end(), binding.content_digest.begin(), binding.content_digest.end());

    return true;
}

bool group_security_manager::create_group(
    std::uint64_t group_id,
    group_type type,
    crypto_suite suite,
    const group_member& coordinator,
    const std::vector<std::uint8_t>& initial_secret,
    std::uint64_t now_us) noexcept {
    if (group_id == 0 || type == group_type::unknown || suite == crypto_suite::none ||
        !coordinator.is_active() || coordinator.role != member_role::coordinator ||
        initial_secret.empty() || groups_.find(group_id) != groups_.end()) {
        return false;
    }

    // Initial transcript calculation
    std::vector<std::uint8_t> init_transcript_input;
    append_u64(init_transcript_input, group_id);
    init_transcript_input.push_back(static_cast<std::uint8_t>(type));
    init_transcript_input.push_back(static_cast<std::uint8_t>(suite));
    append_u64(init_transcript_input, coordinator.endpoint.node_id);
    append_u64(init_transcript_input, coordinator.endpoint.runtime_id);
    append_u32(init_transcript_input, coordinator.endpoint.endpoint_id);
    append_u64(init_transcript_input, coordinator.subject_id);
    init_transcript_input.insert(init_transcript_input.end(), initial_secret.begin(), initial_secret.end());

    std::vector<std::uint8_t> transcript_hash;
    if (!compute_sha256_digest(init_transcript_input.data(), init_transcript_input.size(), transcript_hash)) {
        return false;
    }

    std::vector<std::uint8_t> epoch_1_secret;
    if (!derive_epoch_secret(initial_secret, "LNS2_GROUP_INIT_EPOCH", 1, transcript_hash, epoch_1_secret)) {
        return false;
    }

    group_context ctx;
    ctx.group_id = group_id;
    ctx.group_epoch = 1;
    ctx.type = type;
    ctx.suite = suite;
    ctx.state = group_state::active;
    ctx.created_at_us = now_us;
    ctx.epoch_advanced_at_us = now_us;

    group_member coord_copy = coordinator;
    coord_copy.joined_epoch = 1;
    coord_copy.added_at_us = now_us;
    ctx.members.push_back(coord_copy);

    ctx.confirmed_transcript_hash = std::move(transcript_hash);
    ctx.epoch_secret = std::move(epoch_1_secret);

    groups_.emplace(group_id, std::move(ctx));
    return true;
}

bool group_security_manager::add_member(
    std::uint64_t group_id,
    const group_member& new_member,
    std::uint64_t now_us) noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active ||
        !new_member.is_valid()) {
        return false;
    }

    auto& ctx = it->second;

    // Check if member endpoint is already actively present
    for (const auto& m : ctx.members) {
        if (m.endpoint == new_member.endpoint && m.status == member_status::active) {
            return false;
        }
    }

    std::uint64_t next_epoch = ctx.group_epoch + 1;

    // Update transcript hash
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

    std::vector<std::uint8_t> next_secret;
    if (!derive_epoch_secret(ctx.epoch_secret, "LNS2_GROUP_ADD_MEMBER", next_epoch, next_transcript, next_secret)) {
        return false;
    }

    group_member member_copy = new_member;
    member_copy.status = member_status::active;
    member_copy.joined_epoch = next_epoch;
    member_copy.added_at_us = now_us;
    ctx.members.push_back(member_copy);

    ctx.group_epoch = next_epoch;
    ctx.confirmed_transcript_hash = std::move(next_transcript);
    ctx.epoch_secret = std::move(next_secret);
    ctx.epoch_advanced_at_us = now_us;
    return true;
}

bool group_security_manager::remove_member(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint,
    std::uint64_t now_us) noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active) {
        return false;
    }

    auto& ctx = it->second;
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

    // Update transcript hash with removal commit
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

    std::vector<std::uint8_t> next_secret;
    if (!derive_epoch_secret(ctx.epoch_secret, "LNS2_GROUP_REMOVE_MEMBER", next_epoch, next_transcript, next_secret)) {
        return false;
    }

    ctx.group_epoch = next_epoch;
    ctx.confirmed_transcript_hash = std::move(next_transcript);
    ctx.epoch_secret = std::move(next_secret);
    ctx.epoch_advanced_at_us = now_us;
    return true;
}

bool group_security_manager::update_member_role(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint,
    member_role new_role,
    std::uint64_t now_us) noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active ||
        new_role == member_role::unknown) {
        return false;
    }

    auto& ctx = it->second;
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

    std::vector<std::uint8_t> op_input = ctx.confirmed_transcript_hash;
    op_input.push_back(static_cast<std::uint8_t>(group_operation_type::update_role));
    append_u64(op_input, ctx.group_epoch);
    append_u64(op_input, endpoint.node_id);
    append_u64(op_input, endpoint.runtime_id);
    append_u32(op_input, endpoint.endpoint_id);
    op_input.push_back(static_cast<std::uint8_t>(new_role));

    std::vector<std::uint8_t> next_transcript;
    if (!compute_sha256_digest(op_input.data(), op_input.size(), next_transcript)) {
        return false;
    }

    ctx.confirmed_transcript_hash = std::move(next_transcript);
    return true;
}

bool group_security_manager::rekey_group(
    std::uint64_t group_id,
    std::uint64_t now_us) noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active) {
        return false;
    }

    auto& ctx = it->second;
    std::uint64_t next_epoch = ctx.group_epoch + 1;

    std::vector<std::uint8_t> op_input = ctx.confirmed_transcript_hash;
    op_input.push_back(static_cast<std::uint8_t>(group_operation_type::rekey));
    append_u64(op_input, next_epoch);
    append_u64(op_input, now_us);

    std::vector<std::uint8_t> next_transcript;
    if (!compute_sha256_digest(op_input.data(), op_input.size(), next_transcript)) {
        return false;
    }

    std::vector<std::uint8_t> next_secret;
    if (!derive_epoch_secret(ctx.epoch_secret, "LNS2_GROUP_REKEY", next_epoch, next_transcript, next_secret)) {
        return false;
    }

    ctx.group_epoch = next_epoch;
    ctx.confirmed_transcript_hash = std::move(next_transcript);
    ctx.epoch_secret = std::move(next_secret);
    ctx.epoch_advanced_at_us = now_us;
    return true;
}

bool group_security_manager::close_group(
    std::uint64_t group_id,
    std::uint64_t now_us) noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state == group_state::closed) {
        return false;
    }

    it->second.state = group_state::closed;
    return true;
}

bool group_security_manager::get_group_context(
    std::uint64_t group_id,
    group_context& out_ctx) const noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end()) {
        return false;
    }
    out_ctx = it->second;
    return true;
}

bool group_security_manager::is_member_active(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& endpoint) const noexcept {
    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active) {
        return false;
    }

    for (const auto& m : it->second.members) {
        if (m.endpoint == endpoint && m.status == member_status::active) {
            return true;
        }
    }
    return false;
}

bool group_security_manager::sign_group_message(
    std::uint64_t group_id,
    const linep::v0_2::node_endpoint_identity& sender_endpoint,
    data_message_class msg_class,
    const std::vector<std::uint8_t>& payload,
    std::uint64_t message_seq,
    std::vector<std::uint8_t>& out_tag) const noexcept {
    out_tag.clear();

    auto it = groups_.find(group_id);
    if (it == groups_.end() || it->second.state != group_state::active || message_seq == 0) {
        return false;
    }

    const auto& ctx = it->second;

    // Find active sender in group
    const group_member* sender = nullptr;
    for (const auto& m : ctx.members) {
        if (m.endpoint == sender_endpoint && m.status == member_status::active) {
            sender = &m;
            break;
        }
    }

    if (!sender) {
        return false;
    }

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(payload.data(), payload.size(), content_digest)) {
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

    if (!binding.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_group_authenticator_input(binding, auth_input)) {
        return false;
    }

    auto auth = create_authenticator(ctx.suite);
    if (!auth) {
        return false;
    }

    return auth->sign(auth_input, ctx.epoch_secret, out_tag);
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
    auto it = groups_.find(group_id);
    if (it == groups_.end()) {
        return group_verification_status::group_not_found;
    }

    const auto& ctx = it->second;
    if (ctx.state != group_state::active) {
        return group_verification_status::group_inactive;
    }

    if (epoch < ctx.group_epoch) {
        return group_verification_status::stale_epoch;
    }
    if (epoch > ctx.group_epoch) {
        return group_verification_status::future_epoch;
    }

    const group_member* sender = nullptr;
    for (const auto& m : ctx.members) {
        if (m.endpoint == sender_endpoint) {
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

    // Replay protection per (group_id, epoch, sender_endpoint)
    member_replay_key rkey{group_id, epoch, sender_endpoint};
    auto& win = replay_windows_[rkey];
    if (win.check(message_seq) != replay_status::accepted) {
        return group_verification_status::replay_rejected;
    }

    std::vector<std::uint8_t> content_digest;
    if (!compute_sha256_digest(payload.data(), payload.size(), content_digest)) {
        return group_verification_status::digest_failed;
    }

    group_message_binding binding;
    binding.group_id = group_id;
    binding.group_epoch = epoch;
    binding.sender_endpoint = sender_endpoint;
    binding.sender_trust_domain_id = sender->trust_domain_id;
    binding.sender_subject_id = sender->subject_id;
    binding.message_class = msg_class;
    binding.digest = digest_algorithm::sha256;
    binding.content_digest = std::move(content_digest);
    binding.message_seq = message_seq;

    if (!binding.is_valid()) {
        return group_verification_status::binding_invalid;
    }

    std::vector<std::uint8_t> auth_input;
    if (!encode_group_authenticator_input(binding, auth_input)) {
        return group_verification_status::binding_invalid;
    }

    auto auth = create_authenticator(ctx.suite);
    if (!auth) {
        return group_verification_status::suite_unsupported;
    }

    if (!auth->verify(auth_input, ctx.epoch_secret, tag)) {
        return group_verification_status::signature_invalid;
    }

    win.update(message_seq);
    return group_verification_status::ok;
}

std::size_t group_security_manager::get_group_count() const noexcept {
    return groups_.size();
}

std::size_t group_security_manager::get_active_group_count() const noexcept {
    std::size_t count = 0;
    for (const auto& kv : groups_) {
        if (kv.second.state == group_state::active) {
            ++count;
        }
    }
    return count;
}

} // namespace linep::sl::v0_2
