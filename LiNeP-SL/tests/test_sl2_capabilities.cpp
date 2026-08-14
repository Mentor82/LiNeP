#include <linep_sl/sl2.hpp>
#include <linep_sl/security_types.hpp>
#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    std::cout << "[test_sl2_capabilities] Starting LiNeP-SL SL2 unit tests..." << std::endl;

    const uint8_t secret[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    const uint32_t session_id = 0xCAFE0001;
    const uint64_t granted_caps = static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ | linep::sl::CapFlags::CAP_METRICS_READ);
    const uint64_t expires_at = 2000000000ULL; // Year 2033

    linep::sl::HeaderCapExt tok{};
    tok.session_id = session_id;
    tok.granted_caps = granted_caps;
    tok.expires_at_sec = expires_at;
    linep::sl::compute_cap_token_mac(secret, sizeof(secret), session_id, granted_caps, expires_at, tok.cap_mac);

    // 1. Valid token verification for granted capability
    const uint64_t current_time = 1700000000ULL; // Current time before expiration
    bool read_ok = linep::sl::verify_cap_token(secret, sizeof(secret), tok, session_id, current_time, linep::sl::CapFlags::CAP_INFERENCE_READ);
    assert(read_ok == true);
    std::cout << "[test_sl2_capabilities] Valid token with CAP_INFERENCE_READ PASSED" << std::endl;

    // 2. Reject missing capability (CAP_ADMIN is NOT granted)
    bool admin_ok = linep::sl::verify_cap_token(secret, sizeof(secret), tok, session_id, current_time, linep::sl::CapFlags::CAP_ADMIN);
    assert(admin_ok == false);
    std::cout << "[test_sl2_capabilities] Reject missing capability (CAP_ADMIN) PASSED" << std::endl;

    // 3. Reject expired capability token
    const uint64_t expired_time = 2000000001ULL; // 1 second past expiration
    bool expired_ok = linep::sl::verify_cap_token(secret, sizeof(secret), tok, session_id, expired_time, linep::sl::CapFlags::CAP_INFERENCE_READ);
    assert(expired_ok == false);
    std::cout << "[test_sl2_capabilities] Reject expired token PASSED" << std::endl;

    // 4. Reject tampered capability mask
    linep::sl::HeaderCapExt tampered_tok = tok;
    tampered_tok.granted_caps |= static_cast<uint64_t>(linep::sl::CapFlags::CAP_ADMIN); // Attempt privilege escalation
    bool tampered_ok = linep::sl::verify_cap_token(secret, sizeof(secret), tampered_tok, session_id, current_time, linep::sl::CapFlags::CAP_ADMIN);
    assert(tampered_ok == false);
    std::cout << "[test_sl2_capabilities] Reject tampered capability bitmask PASSED" << std::endl;

    std::cout << "[test_sl2_capabilities] ALL SL2 TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
