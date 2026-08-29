#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace linep::v0_2 {

constexpr std::uint32_t LINEP_V02_UDP_MAGIC = 0x504E4C55; // "ULNP" (UDP LiNeP V0.2)
constexpr std::size_t LINEP_V02_UDP_DATAGRAM_SIZE = 80;   // Fixed 80-byte MTU-safe datagram

enum class control_message_type : std::uint8_t {
    unknown = 0,
    node_hello = 1,
    heartbeat = 2,
    status = 3,
    invite = 4,
    lease_ack = 5,
    ping = 6,
    pong = 7,
};

enum class node_availability : std::uint8_t {
    unknown = 0,
    unavailable = 1,
    available = 2,
    degraded = 3,
};

enum class node_health : std::uint8_t {
    unknown = 0,
    healthy = 1,
    degraded = 2,
    unhealthy = 3,
};

enum class control_node_lifecycle : std::uint8_t {
    unknown = 0,
    seen = 1,
    invited = 2,
    active = 3,
    degraded = 4,
    cooling = 5,
    offline = 6,
};

#pragma pack(push, 1)
struct udp_control_datagram {
    std::uint32_t magic{LINEP_V02_UDP_MAGIC};
    std::uint8_t version_major{0};
    std::uint8_t version_minor{2};
    std::uint8_t message_type{0};
    std::uint8_t flags{0}; // Bit 0: trunk_ready
    std::uint64_t node_id{0};
    std::uint64_t runtime_id{0};
    std::uint32_t endpoint_id{0};
    std::uint64_t control_seq{0};
    std::uint64_t control_epoch{0};
    std::uint8_t availability{0};
    std::uint8_t health{0};
    std::uint8_t load_pct{0};
    std::uint8_t reserved{0};
    std::uint32_t queue_depth{0};
    std::uint32_t capability_revision{0};
    std::uint64_t capability_digest{0};
    std::uint16_t tcp_port{0};
    std::uint16_t reserved2{0};
    std::uint64_t timestamp_us{0};
    std::uint32_t crc32{0};

    bool is_trunk_ready() const noexcept { return (flags & 0x01) != 0; }
    void set_trunk_ready(bool ready) noexcept {
        if (ready) flags |= 0x01;
        else flags &= ~0x01;
    }
};
#pragma pack(pop)

static_assert(sizeof(udp_control_datagram) == LINEP_V02_UDP_DATAGRAM_SIZE, "udp_control_datagram must be exactly 80 bytes");

struct node_endpoint_identity {
    std::uint64_t node_id{0};
    std::uint64_t runtime_id{0};
    std::uint32_t endpoint_id{0};

    bool operator==(const node_endpoint_identity& other) const noexcept {
        return node_id == other.node_id &&
               runtime_id == other.runtime_id &&
               endpoint_id == other.endpoint_id;
    }
    bool operator!=(const node_endpoint_identity& other) const noexcept {
        return !(*this == other);
    }
};

struct node_endpoint_hash {
    std::size_t operator()(const node_endpoint_identity& id) const noexcept {
        std::size_t h1 = std::hash<std::uint64_t>{}(id.node_id);
        std::size_t h2 = std::hash<std::uint64_t>{}(id.runtime_id);
        std::size_t h3 = std::hash<std::uint32_t>{}(id.endpoint_id);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

struct control_plane_node_state {
    node_endpoint_identity identity;
    control_node_lifecycle state{control_node_lifecycle::unknown};
    std::uint64_t last_control_epoch{0};
    std::uint64_t last_control_seq{0};
    node_availability availability{node_availability::unknown};
    node_health health{node_health::unknown};
    std::uint8_t load_pct{0};
    std::uint32_t queue_depth{0};
    std::uint32_t capability_revision{0};
    std::uint64_t capability_digest{0};
    std::uint16_t tcp_port{0};
    bool tcp_trunk_ready{false};
    std::uint64_t last_seen_us{0};

    bool is_routable() const noexcept {
        return (state == control_node_lifecycle::active || state == control_node_lifecycle::degraded) &&
               (availability == node_availability::available || availability == node_availability::degraded) &&
               (health == node_health::healthy || health == node_health::degraded) &&
               tcp_trunk_ready && tcp_port > 0;
    }
};

// Serialization and validation functions
void encode_control_datagram(const udp_control_datagram& dgram, std::vector<std::uint8_t>& out_buf);
bool decode_control_datagram(const std::uint8_t* data, std::size_t size, udp_control_datagram& out_dgram);

class control_plane_router {
public:
    control_plane_router() = default;

    // Ingest incoming UDP control datagram with epoch/seq monotonicity & idempotence
    bool ingest_datagram(const udp_control_datagram& dgram, std::uint64_t current_time_us);

    // Select the best routable node candidate for new task placement based on load, queue & health
    bool select_best_candidate(node_endpoint_identity& out_node, std::uint16_t& out_tcp_port) const;

    // Sweep nodes for stale heartbeat expiration (active -> cooling -> offline)
    std::size_t sweep_stale_nodes(std::uint64_t current_time_us, std::uint64_t stale_timeout_us, std::uint64_t offline_timeout_us);

    // Invalidate/query capability cache
    bool is_capability_cache_valid(const node_endpoint_identity& id) const;
    void set_cached_capability_valid(const node_endpoint_identity& id, std::uint32_t rev, std::uint64_t digest);

    std::size_t get_node_count() const;
    std::size_t get_routable_node_count() const;
    bool get_node_state(const node_endpoint_identity& id, control_plane_node_state& out_state) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<node_endpoint_identity, control_plane_node_state, node_endpoint_hash> nodes_;
    std::unordered_map<node_endpoint_identity, std::pair<std::uint32_t, std::uint64_t>, node_endpoint_hash> capability_cache_;
};

} // namespace linep::v0_2
