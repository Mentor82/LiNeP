#pragma once

#include <functional>
#include "linep/v0_2/session.hpp"

namespace linep::v0_2 {

class envelope_connection;

// Connection-level, versioned TLV payload; TCP roles never change SL1 labels.
enum class registration_operation : std::uint8_t {
    register_runtime = 1, result = 2, draining = 3, deregister = 4,
    capacity_update = 5, capabilities_query = 6,
};
struct registration_extension {
    std::uint16_t tag{0}; // >= 0x8000: optional, preserved; unknown mandatory tags fail
    std::vector<std::uint8_t> value;
};
struct runtime_registration_envelope {
    registration_operation operation{registration_operation::register_runtime};
    std::uint32_t concurrent_slots{0};
    std::uint32_t status_code{0}; // result: 200 accepted or 4xx/5xx rejected
    std::string reason;
    capabilities_envelope capabilities;
    std::vector<registration_extension> extensions;
};
bool encode_runtime_registration(const runtime_registration_envelope&, std::vector<std::uint8_t>&);
// Structural decode only. Verify SL1 before consuming authenticated contents.
bool decode_runtime_registration(const std::uint8_t*, std::size_t, runtime_registration_envelope&);

// Router-side reference connection state. Serial dispatch on one connection.
// Authorization is deny-by-default and sees the authenticated binding and all models.
class runtime_registration_session {
public:
    using authorizer = std::function<bool(const session_bind_envelope&,
                                         const runtime_capabilities_descriptor&)>;
    explicit runtime_registration_session(session_manager& session, authorizer authorize = {})
        : session_(session), authorize_(std::move(authorize)) {}
    // Worker frames are authenticated here, then decoded and dispatched.
    // Protocol errors permanently close this state and terminate in-flight streams.
    bool receive_worker_frame(const std::uint8_t*, std::size_t,
                              runtime_registration_envelope& reply, runtime_error&);
    // Validate/dispatch a router frame before transmission. Signing remains transport-owned.
    bool send_router_frame(const std::uint8_t*, std::size_t, runtime_error&);
    // Reads and dispatches one worker frame; closes the socket on protocol failure.
    bool receive_worker(envelope_connection&, runtime_registration_envelope& reply, runtime_error&);
    bool registered();
    bool draining() const noexcept { return draining_; }
    bool closed() const noexcept { return closed_; }
    std::uint32_t concurrent_slots() const noexcept { return slots_; }
private:
    bool synchronize_binding();
    bool reject(runtime_error&, std::uint32_t, error_category, const char*, bool close);
    session_manager& session_;
    authorizer authorize_;
    session_bind_envelope binding_{};
    std::uint64_t binding_generation_{0};
    bool registered_{false}, draining_{false}, closed_{false};
    std::uint32_t slots_{0};
    runtime_capabilities_descriptor capabilities_;
};
} // namespace linep::v0_2
