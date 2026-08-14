#include <linep/tcp.hpp>
#include "../src/pal/socket.hpp"
#include "../src/core/security.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>

static uint8_t test_task_cb(uint8_t task_type,
                            uint32_t correlation_id,
                            uint16_t worker_id,
                            uint8_t slot_id,
                            const uint8_t* payload,
                            uint32_t payload_len,
                            uint8_t* result_buf,
                            uint32_t result_cap,
                            uint32_t* result_len,
                            void* user_data)
{
    (void)task_type; (void)correlation_id; (void)worker_id; (void)slot_id; (void)user_data;
    const char* resp = "SL1_OK_RESPONSE";
    uint32_t len = static_cast<uint32_t>(std::strlen(resp));
    if (result_buf && result_cap >= len) {
        std::memcpy(result_buf, resp, len);
        *result_len = len;
    }
    return linep::RESULT_OK;
}

int main() {
    linep::pal::net_init();
    std::cout << "[test_sl1_auth] Starting SL1 unit tests..." << std::endl;

    // 1. Test SHA-256 and HMAC MAC calculation consistency
    const uint8_t secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    linep::Header hdr{};
    hdr.magic = linep::MAGIC;
    hdr.version = linep::VERSION;
    hdr.header_len = 50;
    hdr.flags = linep::FLAG_AUTHENTICATED;
    hdr.msg_type = static_cast<uint8_t>(linep::MsgType::TASK);
    hdr.payload_len = 8;
    hdr.sequence = 1;
    hdr.correlation_id = 1001;
    hdr.worker_id = 42;
    hdr.slot_id = 0;

    const uint8_t payload[8] = {'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A'};
    uint8_t mac1[16];
    uint8_t mac2[16];

    linep::core::compute_sl1_mac(secret, sizeof(secret), hdr, 0x12345678, 1, 100, payload, 8, mac1);
    linep::core::compute_sl1_mac(secret, sizeof(secret), hdr, 0x12345678, 1, 100, payload, 8, mac2);

    assert(linep::core::constant_time_memcmp16(mac1, mac2) == true);

    // Tamper with payload -> MAC must change
    const uint8_t tampered_payload[8] = {'X', 'E', 'S', 'T', 'D', 'A', 'T', 'A'};
    uint8_t mac_tampered[16];
    linep::core::compute_sl1_mac(secret, sizeof(secret), hdr, 0x12345678, 1, 100, tampered_payload, 8, mac_tampered);
    assert(linep::core::constant_time_memcmp16(mac1, mac_tampered) == false);

    std::cout << "[test_sl1_auth] MAC calculation & constant time comparison PASSED" << std::endl;

    // 2. Integration test: Sender & Receiver with SL1
    auto receiver = linep::tcp::create_task_receiver();
    const uint16_t test_port = 19876;

    receiver->set_sl1_session(0xCAFE1234, 1, secret, sizeof(secret), true);
    bool started = receiver->start(test_port, test_task_cb, nullptr);
    assert(started == true);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto sender = linep::tcp::create_task_sender();

    // A) Send with valid SL1 session
    sender->set_sl1_session(0xCAFE1234, 1, secret, sizeof(secret));

    uint8_t res_buf[64];
    uint32_t res_len = sizeof(res_buf);
    const uint8_t req_data[] = "hello_sl1";
    uint8_t status = sender->send_task("127.0.0.1", test_port, 1, 999, 42, 0, req_data, sizeof(req_data), res_buf, &res_len);

    std::cout << "[test_sl1_auth] Received status: " << static_cast<int>(status) << std::endl;
    if (status != linep::RESULT_OK) {
        std::cerr << "[test_sl1_auth FAIL] send_task returned status " << static_cast<int>(status) << "\n" << std::flush;
        return 1;
    }
    assert(res_len == 15);
    assert(std::memcmp(res_buf, "SL1_OK_RESPONSE", 15) == 0);
    std::cout << "[test_sl1_auth] Valid SL1 task execution PASSED" << std::endl;

    // B) Send with invalid secret key -> Receiver must reject (fail closed)
    const uint8_t wrong_secret[16] = {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    sender->set_sl1_session(0xCAFE1234, 1, wrong_secret, sizeof(wrong_secret));

    status = sender->send_task("127.0.0.1", test_port, 1, 1000, 42, 0, req_data, sizeof(req_data), res_buf, &res_len);
    assert(status != linep::RESULT_OK);
    std::cout << "[test_sl1_auth] Bad key rejection (reject-before-execution) PASSED" << std::endl;

    // D) Send with wrong session ID -> Receiver must reject
    sender->set_sl1_session(0x99999999, 1, secret, sizeof(secret));
    status = sender->send_task("127.0.0.1", test_port, 1, 1002, 42, 0, req_data, sizeof(req_data), res_buf, &res_len);
    assert(status != linep::RESULT_OK);
    std::cout << "[test_sl1_auth] Wrong session ID rejection PASSED" << std::endl;

    receiver->stop();
    linep::tcp::destroy_task_receiver(receiver);
    linep::tcp::destroy_task_sender(sender);

    std::cout << "[test_sl1_auth] ALL SL1 TESTS PASSED SUCCESSFULLY!" << std::endl;
    return 0;
}
