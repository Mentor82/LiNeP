#include <linep_sl/sl1.hpp>
#include <linep_sl/security_types.hpp>
#include <linep/messages.hpp>
#include <linep/types.hpp>
#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    std::cout << "[test_sl1_auth] Starting LiNeP-SL SL1 unit tests..." << std::endl;

    const uint8_t secret[16] = {'S', 'E', 'C', 'R', 'E', 'T', '_', 'K', 'E', 'Y', '_', '1', '2', '3', '4', '5'};
    linep::Header hdr{};
    hdr.magic = linep::MAGIC;
    hdr.version = linep::VERSION;
    hdr.msg_type = static_cast<uint8_t>(linep::MsgType::TASK);
    hdr.header_len = 56;
    hdr.flags = static_cast<uint16_t>(linep::FLAG_AUTHENTICATED);
    hdr.payload_len = 8;
    hdr.sequence = 100;
    hdr.correlation_id = 42;
    hdr.worker_id = 1;
    hdr.slot_id = 0;
    hdr.header_crc = 0xAB;

    const uint8_t payload[8] = {'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A'};
    uint8_t mac1[16];
    uint8_t mac2[16];

    linep::sl::compute_sl1_mac(secret, sizeof(secret), hdr, 0x12345678, 1, 100, payload, 8, mac1);
    linep::sl::compute_sl1_mac(secret, sizeof(secret), hdr, 0x12345678, 1, 100, payload, 8, mac2);

    assert(linep::sl::constant_time_memcmp16(mac1, mac2) == true);

    linep::sl::HeaderAuthExt auth_ext{};
    auth_ext.session_id = 0x12345678;
    auth_ext.key_id = 1;
    auth_ext.auth_seq = 100;
    std::memcpy(auth_ext.mac, mac1, 16);

    bool ok = linep::sl::verify_sl1_mac(secret, sizeof(secret), hdr, auth_ext, payload, 8);
    assert(ok == true);
    std::cout << "[test_sl1_auth] Valid SL1 MAC verification PASSED" << std::endl;

    // Tampered payload rejection
    const uint8_t tampered_payload[8] = {'X', 'E', 'S', 'T', 'D', 'A', 'T', 'A'};
    bool tampered_ok = linep::sl::verify_sl1_mac(secret, sizeof(secret), hdr, auth_ext, tampered_payload, 8);
    assert(tampered_ok == false);
    std::cout << "[test_sl1_auth] Tampered payload MAC rejection PASSED" << std::endl;

    // Bad key rejection
    const uint8_t wrong_secret[16] = {0xFF};
    bool wrong_key_ok = linep::sl::verify_sl1_mac(wrong_secret, sizeof(wrong_secret), hdr, auth_ext, payload, 8);
    assert(wrong_key_ok == false);
    std::cout << "[test_sl1_auth] Wrong secret key MAC rejection PASSED" << std::endl;

    std::cout << "[test_sl1_auth] ALL SL1 TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
