#include "sha256.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

static void hash_string(const std::string& input, uint8_t hash[32]) {
    linep::core::SHA256_CTX ctx;
    linep::core::sha256_init(&ctx);
    linep::core::sha256_update(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    linep::core::sha256_final(&ctx, hash);
}

static void test_fips_180_4() {
    std::cout << "[FIPS 180-4] Testing SHA-256 standard vectors..." << std::endl;
    uint8_t hash[32];

    // Vector 1: Empty string
    hash_string("", hash);
    std::string h_empty = to_hex(hash, 32);
    std::cout << "  Empty string: " << h_empty << std::endl;
    assert(h_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Vector 2: "abc"
    hash_string("abc", hash);
    std::string h_abc = to_hex(hash, 32);
    std::cout << "  'abc':        " << h_abc << std::endl;
    assert(h_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Vector 3: 56-byte message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    std::string msg56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hash_string(msg56, hash);
    std::string h_56 = to_hex(hash, 32);
    std::cout << "  56 bytes:     " << h_56 << std::endl;
    assert(h_56 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Vector 4: 112 bytes (two 56-byte blocks)
    std::string msg112 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    hash_string(msg112, hash);
    std::string h_112 = to_hex(hash, 32);
    std::cout << "  112 bytes:    " << h_112 << std::endl;
    assert(h_112 == "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

    // Vector 5: 1,000,000 repetitions of 'a'
    {
        linep::core::SHA256_CTX ctx;
        linep::core::sha256_init(&ctx);
        std::vector<uint8_t> chunk(1000, 'a');
        for (int i = 0; i < 1000; ++i) {
            linep::core::sha256_update(&ctx, chunk.data(), chunk.size());
        }
        linep::core::sha256_final(&ctx, hash);
        std::string h_million = to_hex(hash, 32);
        std::cout << "  1M 'a':       " << h_million << std::endl;
        assert(h_million == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    std::cout << "[FIPS 180-4] ALL SHA-256 VECTORS PASSED!" << std::endl;
}

static void test_rfc_4231() {
    std::cout << "[RFC 4231] Testing HMAC-SHA-256 standard vectors..." << std::endl;
    uint8_t mac[32];

    // RFC 4231 Case 1:
    // Key  = 20 bytes 0x0b
    // Data = "Hi There" (8 bytes)
    {
        std::vector<uint8_t> key(20, 0x0b);
        std::string data = "Hi There";
        linep::core::hmac_sha256(key.data(), key.size(),
                                 reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                 mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 1: " << h_mac << std::endl;
        assert(h_mac == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    // RFC 4231 Case 2:
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    {
        std::string key = "Jefe";
        std::string data = "what do ya want for nothing?";
        linep::core::hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                                 reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                 mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 2: " << h_mac << std::endl;
        assert(h_mac == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    // RFC 4231 Case 3 (20-byte key):
    // Key  = 20 bytes 0xaa
    // Data = 50 bytes 0xdd
    {
        std::vector<uint8_t> key(20, 0xaa);
        std::vector<uint8_t> data(50, 0xdd);
        linep::core::hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 3 (20B key): " << h_mac << std::endl;
        assert(h_mac == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    // RFC 4231 Case 3 variation (16-byte key):
    {
        std::vector<uint8_t> key(16, 0xaa);
        std::vector<uint8_t> data(50, 0xdd);
        linep::core::hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 3 (16B key): " << h_mac << std::endl;
        assert(h_mac == "7dda3cc169743a6484649f94f0eda0f9f2ff496a9733fb796ed5adb40a44c3c1");
    }

    // RFC 4231 Case 4:
    // Key  = 25 bytes 0x01..0x19
    // Data = 50 bytes 0xcd
    {
        std::vector<uint8_t> key;
        for (uint8_t b = 1; b <= 25; ++b) key.push_back(b);
        std::vector<uint8_t> data(50, 0xcd);
        linep::core::hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 4: " << h_mac << std::endl;
        assert(h_mac == "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
    }

    // RFC 4231 Case 6 (key > 64 bytes):
    // Key  = 131 bytes 0xaa
    // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    {
        std::vector<uint8_t> key(131, 0xaa);
        std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
        linep::core::hmac_sha256(key.data(), key.size(),
                                 reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                 mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 6: " << h_mac << std::endl;
        assert(h_mac == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    // RFC 4231 Case 7 (key > 64 bytes and long data):
    // Key  = 131 bytes 0xaa
    // Data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    {
        std::vector<uint8_t> key(131, 0xaa);
        std::string data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        linep::core::hmac_sha256(key.data(), key.size(),
                                 reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                                 mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Case 7: " << h_mac << std::endl;
        assert(h_mac == "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    }

    // Evidence from Issue #23:
    // Key = 32 bytes 0x01..0x20
    // Data = "" (empty message)
    {
        std::vector<uint8_t> key;
        for (uint8_t b = 1; b <= 32; ++b) key.push_back(b);
        linep::core::hmac_sha256(key.data(), key.size(), nullptr, 0, mac);
        std::string h_mac = to_hex(mac, 32);
        std::cout << "  Issue #23 Case (Key 01..20, empty data): " << h_mac << std::endl;
        assert(h_mac == "462476a897ddfdbd40d1420e08a5bcfeeb25c3e2ade6a0a9083b327b9ef9fca1");
    }

    std::cout << "[RFC 4231] ALL HMAC-SHA-256 VECTORS PASSED!" << std::endl;
}

int main() {
    std::cout << "=== LiNeP Core SHA-256 and HMAC-SHA-256 Conformance Test ===" << std::endl;
    test_fips_180_4();
    test_rfc_4231();
    std::cout << "ALL CRYPTO TESTS PASSED 100%!" << std::endl;
    return 0;
}
