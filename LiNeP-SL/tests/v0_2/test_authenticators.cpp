#include <linep_sl/v0_2/authenticator.hpp>

#include <cstdlib>
#include <iostream>
#include <vector>

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            std::cerr << "CHECK failed: " #condition " at " __FILE__ ":" << __LINE__ << std::endl; \
            std::exit(EXIT_FAILURE); \
        } \
    } while (0)

using namespace linep::sl::v0_2;

void test_constant_time_equals() {
    std::cout << "[Test 1] Constant-Time Memory Comparison..." << std::endl;
    std::uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    std::uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    std::uint8_t c[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99};

    CHECK(constant_time_equals(a, b, 16));
    CHECK(!constant_time_equals(a, c, 16));
    CHECK(!constant_time_equals(nullptr, b, 16));
    CHECK(!constant_time_equals(a, nullptr, 16));

    std::cout << "  -> Constant-Time Memory Comparison PASSED" << std::endl;
}

void test_content_digest_calculation() {
    std::cout << "[Test 2] Content Digest Calculation..." << std::endl;
    std::vector<std::uint8_t> data = {'L', 'i', 'N', 'e', 'P', '-', 'S', 'L', '2'};
    std::vector<std::uint8_t> digest1;
    std::vector<std::uint8_t> digest2;

    CHECK(compute_sha256_digest(data.data(), data.size(), digest1));
    CHECK(digest1.size() == 32);

    CHECK(compute_sha256_digest(data.data(), data.size(), digest2));
    CHECK(digest1 == digest2);

    // Tampered data produces different digest
    data[0] = 'X';
    std::vector<std::uint8_t> digest_tampered;
    CHECK(compute_sha256_digest(data.data(), data.size(), digest_tampered));
    CHECK(digest1 != digest_tampered);

    std::cout << "  -> Content Digest Calculation PASSED" << std::endl;
}

void test_hmac_sha256_signing_and_verification() {
    std::cout << "[Test 3] HMAC-SHA256 Authenticator Signing & Verification..." << std::endl;
    auto auth = create_authenticator(crypto_suite::hmac_sha256_128);
    CHECK(auth != nullptr);
    CHECK(auth->suite() == crypto_suite::hmac_sha256_128);
    CHECK(auth->tag_size() == 16);

    std::vector<std::uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                     0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    std::vector<std::uint8_t> input = {'L', 'N', 'S', '2', 0x00, 0x02, 0x01, 0x01, 0x02, 0x03};

    std::vector<std::uint8_t> tag;
    CHECK(auth->sign(input, key, tag));
    CHECK(tag.size() == 16);

    // Verification succeeds with valid tag
    CHECK(auth->verify(input, key, tag));

    // Tampered input fails verification
    std::vector<std::uint8_t> bad_input = input;
    bad_input[0] = 'X';
    CHECK(!auth->verify(bad_input, key, tag));

    // Tampered key fails verification
    std::vector<std::uint8_t> bad_key = key;
    bad_key[0] ^= 0xFF;
    CHECK(!auth->verify(input, bad_key, tag));

    // Tampered tag fails verification
    std::vector<std::uint8_t> bad_tag = tag;
    bad_tag[0] ^= 0x01;
    CHECK(!auth->verify(input, key, bad_tag));

    // Truncated tag fails verification
    std::vector<std::uint8_t> short_tag = tag;
    short_tag.pop_back();
    CHECK(!auth->verify(input, key, short_tag));

    std::cout << "  -> HMAC-SHA256 Authenticator Tests PASSED" << std::endl;
}

int main() {
    std::cout << "=== LiNeP-SL V0.2 Authenticator Test Suite ===" << std::endl;
    test_constant_time_equals();
    test_content_digest_calculation();
    test_hmac_sha256_signing_and_verification();
    std::cout << "ALL AUTHENTICATOR TESTS PASSED 100%!" << std::endl;
    return 0;
}
