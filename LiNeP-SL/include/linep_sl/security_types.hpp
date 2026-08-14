#ifndef LINEP_SL_SECURITY_TYPES_HPP
#define LINEP_SL_SECURITY_TYPES_HPP

#include <cstdint>

namespace linep::sl {

// ── Capability Flags (SL2 Role-Based Capabilities) ───────────────────────────
enum class CapFlags : uint64_t {
    CAP_NONE            = 0u,
    CAP_INFERENCE_READ  = 1u << 0, // 0x0001: Execute inferential read/evaluate tasks
    CAP_INFERENCE_WRITE = 1u << 1, // 0x0002: Execute state-modifying / code tasks
    CAP_ADMIN           = 1u << 2, // 0x0004: Administrative control actions
    CAP_SLOT_MANAGE     = 1u << 3, // 0x0008: Reserve/invite/configure worker slots
    CAP_METRICS_READ    = 1u << 4, // 0x0010: Query worker telemetry & score details
    CAP_HEARTBEAT_EMIT  = 1u << 5  // 0x0020: Emit authenticated LiNeP UDP heartbeat datagrams
};

inline constexpr CapFlags operator|(CapFlags a, CapFlags b) noexcept {
    return static_cast<CapFlags>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline constexpr CapFlags operator&(CapFlags a, CapFlags b) noexcept {
    return static_cast<CapFlags>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}

inline constexpr bool has_capability(uint64_t granted_mask, CapFlags required_cap) noexcept {
    return (granted_mask & static_cast<uint64_t>(required_cap)) == static_cast<uint64_t>(required_cap);
}

// ── Header Extensions ────────────────────────────────────────────────────────

#pragma pack(push, 1)

// HeaderAuthExt (26 bytes) - Attached when FLAG_AUTHENTICATED (0x0008) is set
struct HeaderAuthExt {
    uint32_t session_id; // Unique trust-domain session ID
    uint16_t key_id;     // Active key ID index
    uint32_t auth_seq;   // Monotonic sequence number for replay protection
    uint8_t  mac[16];    // Truncated HMAC-SHA256 signature
};

// HeaderCapExt (36 bytes) - Attached when SL2 capability authorization is active
struct HeaderCapExt {
    uint32_t session_id;     // Trust-domain session ID
    uint64_t granted_caps;   // Bitmask of granted CapFlags
    uint64_t expires_at_sec; // Unix timestamp expiration (seconds)
    uint8_t  cap_mac[16];    // Truncated HMAC-SHA256 signature over capability token
};

#pragma pack(pop)

static_assert(sizeof(HeaderAuthExt) == 26, "HeaderAuthExt must be exactly 26 bytes");
static_assert(sizeof(HeaderCapExt) == 36, "HeaderCapExt must be exactly 36 bytes");

} // namespace linep::sl

#endif // LINEP_SL_SECURITY_TYPES_HPP
