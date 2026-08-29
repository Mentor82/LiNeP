#include "linep/v0_2/control_plane.hpp"
#include <cstring>
#include <algorithm>

namespace linep::v0_2 {

namespace {

// Standard IEEE 802.3 CRC-32 calculation
std::uint32_t calc_crc32(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int k = 0; k < 8; ++k) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

inline void write_u16(std::uint8_t* dst, std::uint16_t v) noexcept {
    dst[0] = static_cast<std::uint8_t>(v & 0xFF);
    dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}

inline void write_u32(std::uint8_t* dst, std::uint32_t v) noexcept {
    dst[0] = static_cast<std::uint8_t>(v & 0xFF);
    dst[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    dst[2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    dst[3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
}

inline void write_u64(std::uint8_t* dst, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    }
}

inline std::uint16_t read_u16(const std::uint8_t* src) noexcept {
    return static_cast<std::uint16_t>(src[0]) |
          (static_cast<std::uint16_t>(src[1]) << 8);
}

inline std::uint32_t read_u32(const std::uint8_t* src) noexcept {
    return static_cast<std::uint32_t>(src[0]) |
          (static_cast<std::uint32_t>(src[1]) << 8) |
          (static_cast<std::uint32_t>(src[2]) << 16) |
          (static_cast<std::uint32_t>(src[3]) << 24);
}

inline std::uint64_t read_u64(const std::uint8_t* src) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(src[i]) << (i * 8));
    }
    return v;
}

} // anonymous namespace

void encode_control_datagram(const udp_control_datagram& dgram, std::vector<std::uint8_t>& out_buf) {
    out_buf.resize(LINEP_V02_UDP_DATAGRAM_SIZE, 0);
    std::uint8_t* p = out_buf.data();

    write_u32(p + 0, dgram.magic);
    p[4] = dgram.version_major;
    p[5] = dgram.version_minor;
    p[6] = dgram.message_type;
    p[7] = dgram.flags;
    write_u64(p + 8, dgram.node_id);
    write_u64(p + 16, dgram.runtime_id);
    write_u32(p + 24, dgram.endpoint_id);
    write_u64(p + 28, dgram.control_seq);
    write_u64(p + 36, dgram.control_epoch);
    p[44] = dgram.availability;
    p[45] = dgram.health;
    p[46] = dgram.load_pct;
    p[47] = dgram.reserved;
    write_u32(p + 48, dgram.queue_depth);
    write_u32(p + 52, dgram.capability_revision);
    write_u64(p + 56, dgram.capability_digest);
    write_u16(p + 64, dgram.tcp_port);
    write_u16(p + 66, dgram.reserved2);
    write_u64(p + 68, dgram.timestamp_us);

    // Calculate CRC32 over the first 76 bytes
    std::uint32_t crc = calc_crc32(p, 76);
    write_u32(p + 76, crc);
}

bool decode_control_datagram(const std::uint8_t* data, std::size_t size, udp_control_datagram& out_dgram) {
    if (!data || size < LINEP_V02_UDP_DATAGRAM_SIZE) {
        return false;
    }

    std::uint32_t expected_crc = read_u32(data + 76);
    std::uint32_t actual_crc = calc_crc32(data, 76);
    if (expected_crc != actual_crc) {
        return false; // Fail closed on CRC32 mismatch
    }

    out_dgram.magic = read_u32(data + 0);
    if (out_dgram.magic != LINEP_V02_UDP_MAGIC) {
        return false;
    }

    out_dgram.version_major = data[4];
    out_dgram.version_minor = data[5];
    if (out_dgram.version_major != 0 || out_dgram.version_minor != 2) {
        return false;
    }

    out_dgram.message_type = data[6];
    out_dgram.flags = data[7];
    out_dgram.node_id = read_u64(data + 8);
    out_dgram.runtime_id = read_u64(data + 16);
    out_dgram.endpoint_id = read_u32(data + 24);
    out_dgram.control_seq = read_u64(data + 28);
    out_dgram.control_epoch = read_u64(data + 36);
    out_dgram.availability = data[44];
    out_dgram.health = data[45];
    out_dgram.load_pct = data[46];
    out_dgram.reserved = data[47];
    out_dgram.queue_depth = read_u32(data + 48);
    out_dgram.capability_revision = read_u32(data + 52);
    out_dgram.capability_digest = read_u64(data + 56);
    out_dgram.tcp_port = read_u16(data + 64);
    out_dgram.reserved2 = read_u16(data + 66);
    out_dgram.timestamp_us = read_u64(data + 68);
    out_dgram.crc32 = expected_crc;

    return true;
}

// ── control_plane_router Implementation ──────────────────────────────────────

bool control_plane_router::ingest_datagram(const udp_control_datagram& dgram, std::uint64_t current_time_us) {
    if (dgram.node_id == 0) {
        return false;
    }

    node_endpoint_identity id{dgram.node_id, dgram.runtime_id, dgram.endpoint_id};

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    if (it == nodes_.end()) {
        // New node discovered
        control_plane_node_state node{};
        node.identity = id;
        node.state = control_node_lifecycle::seen;
        node.last_control_epoch = dgram.control_epoch;
        node.last_control_seq = dgram.control_seq;
        node.availability = static_cast<node_availability>(dgram.availability);
        node.health = static_cast<node_health>(dgram.health);
        node.load_pct = dgram.load_pct;
        node.queue_depth = dgram.queue_depth;
        node.capability_revision = dgram.capability_revision;
        node.capability_digest = dgram.capability_digest;
        node.tcp_port = dgram.tcp_port;
        node.tcp_trunk_ready = dgram.is_trunk_ready();
        node.last_seen_us = current_time_us;

        if (dgram.is_trunk_ready() && dgram.availability == static_cast<std::uint8_t>(node_availability::available)) {
            node.state = control_node_lifecycle::active;
        }

        nodes_[id] = node;
        return true;
    }

    auto& node = it->second;

    // Epoch & Monotonic Sequence Invariant:
    if (dgram.control_epoch < node.last_control_epoch) {
        // Stale epoch from older incarnation -> ignore / reject
        return false;
    }

    if (dgram.control_epoch > node.last_control_epoch) {
        // Newer epoch: node restarted or upgraded incarnation
        node.last_control_epoch = dgram.control_epoch;
        node.last_control_seq = dgram.control_seq;
        node.state = control_node_lifecycle::seen; // Reset lifecycle on restart
    } else {
        // Same epoch: check sequence monotonicity
        if (dgram.control_seq <= node.last_control_seq) {
            // Duplicate or replayed datagram -> idempotent no-op
            return true;
        }
        node.last_control_seq = dgram.control_seq;
    }

    node.availability = static_cast<node_availability>(dgram.availability);
    node.health = static_cast<node_health>(dgram.health);
    node.load_pct = dgram.load_pct;
    node.queue_depth = dgram.queue_depth;
    node.capability_revision = dgram.capability_revision;
    node.capability_digest = dgram.capability_digest;
    node.tcp_port = dgram.tcp_port;
    node.tcp_trunk_ready = dgram.is_trunk_ready();
    node.last_seen_us = current_time_us;

    // State machine updates
    if (node.availability == node_availability::unavailable) {
        node.state = control_node_lifecycle::cooling;
    } else if (node.health == node_health::unhealthy) {
        node.state = control_node_lifecycle::cooling;
    } else if (node.health == node_health::degraded || node.availability == node_availability::degraded) {
        node.state = control_node_lifecycle::degraded;
    } else if (node.tcp_trunk_ready && node.tcp_port > 0) {
        node.state = control_node_lifecycle::active;
    }

    return true;
}

bool control_plane_router::select_best_candidate(node_endpoint_identity& out_node, std::uint16_t& out_tcp_port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const control_plane_node_state* best_node = nullptr;
    std::uint64_t lowest_score = UINT64_MAX;

    for (const auto& pair : nodes_) {
        const auto& node = pair.second;
        if (!node.is_routable()) {
            continue;
        }

        // Composite routing score: lower is better
        std::uint64_t score = (static_cast<std::uint64_t>(node.load_pct) * 10u) +
                              (static_cast<std::uint64_t>(node.queue_depth) * 50u);

        if (node.health == node_health::degraded) {
            score += 5000u;
        }
        if (node.availability == node_availability::degraded) {
            score += 5000u;
        }

        if (score < lowest_score) {
            lowest_score = score;
            best_node = &node;
        }
    }

    if (!best_node) {
        return false;
    }

    out_node = best_node->identity;
    out_tcp_port = best_node->tcp_port;
    return true;
}

std::size_t control_plane_router::sweep_stale_nodes(std::uint64_t current_time_us, std::uint64_t stale_timeout_us, std::uint64_t offline_timeout_us) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t transition_count = 0;

    for (auto& pair : nodes_) {
        auto& node = pair.second;
        if (current_time_us < node.last_seen_us) {
            continue;
        }
        std::uint64_t elapsed = current_time_us - node.last_seen_us;

        if (elapsed > offline_timeout_us) {
            if (node.state != control_node_lifecycle::offline) {
                node.state = control_node_lifecycle::offline;
                transition_count++;
            }
        } else if (elapsed > stale_timeout_us) {
            if (node.state == control_node_lifecycle::active || node.state == control_node_lifecycle::degraded) {
                node.state = control_node_lifecycle::cooling;
                transition_count++;
            }
        }
    }

    return transition_count;
}

bool control_plane_router::is_capability_cache_valid(const node_endpoint_identity& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto nit = nodes_.find(id);
    if (nit == nodes_.end()) {
        return false;
    }
    auto cit = capability_cache_.find(id);
    if (cit == capability_cache_.end()) {
        return false;
    }
    return cit->second.first == nit->second.capability_revision &&
           cit->second.second == nit->second.capability_digest;
}

void control_plane_router::set_cached_capability_valid(const node_endpoint_identity& id, std::uint32_t rev, std::uint64_t digest) {
    std::lock_guard<std::mutex> lock(mutex_);
    capability_cache_[id] = {rev, digest};
}

std::size_t control_plane_router::get_node_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nodes_.size();
}

std::size_t control_plane_router::get_routable_node_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t count = 0;
    for (const auto& pair : nodes_) {
        if (pair.second.is_routable()) {
            count++;
        }
    }
    return count;
}

bool control_plane_router::get_node_state(const node_endpoint_identity& id, control_plane_node_state& out_state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    if (it == nodes_.end()) {
        return false;
    }
    out_state = it->second;
    return true;
}

} // namespace linep::v0_2
