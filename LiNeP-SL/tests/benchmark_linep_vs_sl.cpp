#include <linep_sl/sl1.hpp>
#include <linep_sl/sl2.hpp>
#include <linep_sl/sl3.hpp>
#include <linep_sl/sl4.hpp>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

int main() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "           LiNeP vs LiNeP-SL Security Layer Performance Benchmark              " << std::endl;
    std::cout << "================================================================================" << std::endl;

    const size_t NUM_ITERATIONS = 100'000;
    const uint32_t domain_a = 0x4C4E5031;
    const uint8_t master_secret[32] = {0xAA};
    const uint8_t pubkey_node[32] = {0xBB};
    const uint32_t session_id = 0x1001;
    const uint16_t key_id = 1;
    const uint16_t node_id = 10;
    const uint64_t now_sec = 1700000000ULL;

    uint8_t payload[256];
    std::memset(payload, 0x42, sizeof(payload));

    linep::Header hdr{};
    hdr.magic = linep::MAGIC;
    hdr.version = linep::VERSION;
    hdr.msg_type = 0x01; // TASK
    hdr.flags = 0x0008;

    // --- 1. SL0 Baseline (Raw Wire Header & Payload Copy) ---
    auto start_sl0 = std::chrono::high_resolution_clock::now();
    uint8_t buffer[512];
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        std::memcpy(buffer, &hdr, sizeof(hdr));
        std::memcpy(buffer + sizeof(hdr), payload, sizeof(payload));
        // Volatile barrier to prevent compiler elision
        asm volatile("" : : "g"(buffer) : "memory");
    }
    auto end_sl0 = std::chrono::high_resolution_clock::now();
    double time_sl0_ms = std::chrono::duration<double, std::milli>(end_sl0 - start_sl0).count();
    double ops_sl0 = (NUM_ITERATIONS / time_sl0_ms) * 1000.0;
    double lat_sl0_ns = (time_sl0_ms * 1'000'000.0) / NUM_ITERATIONS;

    // Setup SL2 Session Key
    linep::sl::SessionKey sk{};
    linep::sl::derive_session_key(master_secret, 32, session_id, key_id, node_id, 3600, now_sec, sk);

    // --- 2. SL1 Only (HMAC-SHA256 Computation & Verification) ---
    linep::sl::HeaderAuthExt auth_ext{};
    auth_ext.session_id = session_id;
    auth_ext.key_id = key_id;
    auth_ext.auth_seq = 1;
    linep::sl::compute_sl1_mac(sk.secret_key, 32, hdr, session_id, key_id, 1, payload, sizeof(payload), auth_ext.mac);

    auto start_sl1 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        bool ok = linep::sl::verify_sl1_mac(sk.secret_key, 32, hdr, auth_ext, payload, sizeof(payload));
        asm volatile("" : : "g"(ok) : "memory");
    }
    auto end_sl1 = std::chrono::high_resolution_clock::now();
    double time_sl1_ms = std::chrono::duration<double, std::milli>(end_sl1 - start_sl1).count();
    double ops_sl1 = (NUM_ITERATIONS / time_sl1_ms) * 1000.0;
    double lat_sl1_ns = (time_sl1_ms * 1'000'000.0) / NUM_ITERATIONS;

    // --- 3. SL2 Only (Session Key Derivation & Freshness Check) ---
    auto start_sl2 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        linep::sl::SessionKey tmp_sk{};
        linep::sl::derive_session_key(master_secret, 32, session_id, key_id, node_id, 3600, now_sec, tmp_sk);
        bool fresh = linep::sl::verify_session_key_freshness(tmp_sk, now_sec);
        asm volatile("" : : "g"(fresh) : "memory");
    }
    auto end_sl2 = std::chrono::high_resolution_clock::now();
    double time_sl2_ms = std::chrono::duration<double, std::milli>(end_sl2 - start_sl2).count();
    double ops_sl2 = (NUM_ITERATIONS / time_sl2_ms) * 1000.0;
    double lat_sl2_ns = (time_sl2_ms * 1'000'000.0) / NUM_ITERATIONS;

    // --- 4. SL3 Only (Capability Token Creation & MAC Verification) ---
    linep::sl::HeaderCapExt cap_token{};
    cap_token.session_id = session_id;
    cap_token.granted_caps = static_cast<uint64_t>(linep::sl::CapFlags::CAP_INFERENCE_READ);
    cap_token.expires_at_sec = now_sec + 3600;
    linep::sl::compute_cap_token_mac(sk.secret_key, 32, session_id, cap_token.granted_caps, cap_token.expires_at_sec, cap_token.cap_mac);

    auto start_sl3 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        bool cap_ok = linep::sl::verify_cap_token(sk.secret_key, 32, cap_token, session_id, now_sec, linep::sl::CapFlags::CAP_INFERENCE_READ);
        asm volatile("" : : "g"(cap_ok) : "memory");
    }
    auto end_sl3 = std::chrono::high_resolution_clock::now();
    double time_sl3_ms = std::chrono::duration<double, std::milli>(end_sl3 - start_sl3).count();
    double ops_sl3 = (NUM_ITERATIONS / time_sl3_ms) * 1000.0;
    double lat_sl3_ns = (time_sl3_ms * 1'000'000.0) / NUM_ITERATIONS;

    // --- 5. SL4 Only (Governance Engine Decision & Secret-Free Audit Provenance) ---
    auto pol_provider = std::make_shared<linep::sl::MemoryGovernancePolicyProvider>();
    auto id_provider = std::make_shared<linep::sl::MemoryIdentityProvider>(domain_a);
    id_provider->register_peer(node_id, pubkey_node);
    auto fed_provider = std::make_shared<linep::sl::MemoryFederationTrustProvider>();
    auto audit_sink = std::make_shared<linep::sl::MemoryAuditSink>();
    linep::sl::SecurityDecisionEngine engine(pol_provider, id_provider, fed_provider, audit_sink);

    linep::sl::DecisionContext dctx{};
    dctx.trust_domain_id = domain_a;
    dctx.session_id = session_id;
    dctx.key_id = key_id;
    dctx.local_peer.node_id = 1;
    dctx.local_peer.trust_domain_id = domain_a;
    dctx.remote_peer.node_id = node_id;
    dctx.remote_peer.trust_domain_id = domain_a;
    std::memcpy(dctx.remote_peer.pubkey, pubkey_node, 32);
    dctx.negotiated_sl = linep::sl::SecurityLevel::SL2_IDENTITY;
    dctx.requested_cap = linep::sl::CapFlags::CAP_INFERENCE_READ;
    dctx.msg_type = 0x01;
    dctx.policy_id = "default-policy";
    dctx.established_policy_revision = 1;
    dctx.timestamp_sec = now_sec;

    auto start_sl4 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        auto res = engine.evaluate(dctx);
        asm volatile("" : : "g"(res.decision) : "memory");
    }
    auto end_sl4 = std::chrono::high_resolution_clock::now();
    double time_sl4_ms = std::chrono::duration<double, std::milli>(end_sl4 - start_sl4).count();
    double ops_sl4 = (NUM_ITERATIONS / time_sl4_ms) * 1000.0;
    double lat_sl4_ns = (time_sl4_ms * 1'000'000.0) / NUM_ITERATIONS;

    // --- 6. Full Stack (SL0 + SL1 + SL2 + SL3 + SL4 All Active) ---
    auto start_full = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        // SL0: Wire Header
        std::memcpy(buffer, &hdr, sizeof(hdr));
        std::memcpy(buffer + sizeof(hdr), payload, sizeof(payload));

        // SL1: MAC Verification
        bool mac_ok = linep::sl::verify_sl1_mac(sk.secret_key, 32, hdr, auth_ext, payload, sizeof(payload));

        // SL2: Session Key Freshness
        bool fresh = linep::sl::verify_session_key_freshness(sk, now_sec);

        // SL3: Capability Verification
        bool cap_ok = linep::sl::verify_cap_token(sk.secret_key, 32, cap_token, session_id, now_sec, linep::sl::CapFlags::CAP_INFERENCE_READ);

        // SL4: Governance Engine Decision
        auto res = engine.evaluate(dctx);

        asm volatile("" : : "g"(mac_ok && fresh && cap_ok && (res.decision == linep::sl::Decision::ALLOW)) : "memory");
    }
    auto end_full = std::chrono::high_resolution_clock::now();
    double time_full_ms = std::chrono::duration<double, std::milli>(end_full - start_full).count();
    double ops_full = (NUM_ITERATIONS / time_full_ms) * 1000.0;
    double lat_full_ns = (time_full_ms * 1'000'000.0) / NUM_ITERATIONS;

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Iterations per Benchmark: " << NUM_ITERATIONS << " messages\n" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << " Layer / Component                |  Ops / sec (msg/s)  | Latency per Msg (ns)  " << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << " SL0: LiNeP Baseline Wire Format | " << std::setw(17) << ops_sl0  << " | " << std::setw(19) << lat_sl0_ns  << " ns" << std::endl;
    std::cout << " SL1: HMAC-SHA256 MAC Verification| " << std::setw(17) << ops_sl1  << " | " << std::setw(19) << lat_sl1_ns  << " ns" << std::endl;
    std::cout << " SL2: Key Derivation & Freshness  | " << std::setw(17) << ops_sl2  << " | " << std::setw(19) << lat_sl2_ns  << " ns" << std::endl;
    std::cout << " SL3: Capability Token Verification| " << std::setw(17) << ops_sl3  << " | " << std::setw(19) << lat_sl3_ns  << " ns" << std::endl;
    std::cout << " SL4: Zero-Trust Governance & Audit| " << std::setw(17) << ops_sl4  << " | " << std::setw(19) << lat_sl4_ns  << " ns" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << " Full Stack (SL0 + SL1-SL4 Active) | " << std::setw(17) << ops_full << " | " << std::setw(19) << lat_full_ns << " ns" << std::endl;
    std::cout << "--------------------------------------------------------------------------------\n" << std::endl;

    double overhead_us = (lat_full_ns - lat_sl0_ns) / 1000.0;
    std::cout << "==> Security Overhead (SL1-SL4 over SL0): " << overhead_us << " microseconds (us) per message" << std::endl;
    std::cout << "==> Peak Throughput with Full SL1-SL4 Gating: " << static_cast<size_t>(ops_full) << " msg/sec" << std::endl;
    std::cout << "================================================================================" << std::endl;

    return 0;
}
