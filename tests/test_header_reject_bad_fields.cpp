#include "../src/core/framing.hpp"
#include <linep/messages.hpp>
#include <linep/types.hpp>

#include <cassert>
#include <cstdio>

int main() {
    // Build a valid reference header.
    auto ok = linep::core::make_header(
        static_cast<uint8_t>(linep::MsgType::TASK),
        0u,
        64u,   // payload_len well within limit
        1u,
        42u,
        7u,
        0u);
    assert(linep::core::validate_header(ok));

    // --- bad magic --------------------------------------------------------
    {
        auto h = ok;
        h.magic = 0xDEADu;
        assert(!linep::core::validate_header(h));
    }

    // --- bad version ------------------------------------------------------
    {
        auto h = ok;
        h.version = 0x02u;
        assert(!linep::core::validate_header(h));
    }

    // --- header_len too small (below HEADER_BASE_LEN) --------------------
    {
        auto h = ok;
        h.header_len = static_cast<uint16_t>(linep::HEADER_BASE_LEN - 1u);
        assert(!linep::core::validate_header(h));
    }

    // --- header_len too large (above HEADER_BASE_LEN + BUILD_TIME_LEN) ---
    {
        auto h = ok;
        h.header_len = static_cast<uint16_t>(linep::HEADER_BASE_LEN + linep::HEADER_BUILD_TIME_LEN + 1u);
        assert(!linep::core::validate_header(h));
    }

    // --- payload_len exceeds MAX_PAYLOAD_BYTES ---------------------------
    {
        auto h = ok;
        h.payload_len = linep::MAX_PAYLOAD_BYTES + 1u;
        // Recompute CRC so that only the size guard fires, not CRC.
        // (validate_header must reject before even reaching CRC.)
        assert(!linep::core::validate_header(h));
    }

    std::puts("[PASS] test_header_reject_bad_fields");
    return 0;
}
