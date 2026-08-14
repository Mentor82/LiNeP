# LiNeP vs LiNeP-SL Micro-Benchmark & Security Layer Overhead Audit Report

**Date**: 2026-08-14  
**Scope**: In-Memory Component Micro-Benchmark & Security Overhead Audit for Baseline LiNeP Frame Construction vs Protected Security Layer (LiNeP-SL SL1–SL4)  
**Repository**: [`Mentor82/LiNeP`](https://github.com/Mentor82/LiNeP.git)  

---

## 1. Executive Summary & Methodological Clarification

This audit report documents micro-benchmark evaluations comparing in-memory **LiNeP baseline frame packing** against individual and combined components of the **LiNeP-SL security stack (SL1–SL4)**.

> [!NOTE]
> **Methodology Clarification**: The SL0 baseline in these micro-benchmarks measures in-memory wire format header packing and payload buffer operations. It serves as an in-memory component micro-benchmark to evaluate the exact CPU cycle and latency overhead introduced by cryptographic signatures (SL1), key derivations (SL2), capability token checks (SL3), and zero-trust governance decision engine evaluations (SL4). End-to-end network socket throughput across TCP/UDP is evaluated separately via the real-socket interoperability harness (`interop_peer_daemon.py`).

### Key Audit Highlights:
- **Baseline LiNeP SL0 Frame Construction**: **143.59 Million ops/sec** (6.96 ns/msg).
- **SL4 Zero-Trust Governance Engine Overhead**: **< 1.34 microseconds (µs)** per evaluation (**748,783 ops/sec**).
- **Full Security Stack (SL1–SL4) Native C++ Overhead**: **15.10 microseconds (µs)** per message (0.015 ms).
- **Peak In-Memory Throughput (C++)**: **66,187 ops/sec** with 100% SL1 MAC, SL2 Identity, SL3 Capability Gating, and SL4 3-Gate Zero-Trust Governance active simultaneously on a single thread.
- **Python CFFI Full Stack (SL1–SL4 with SL2 included)**: **43,693 ops/sec** (22.89 µs) on Windows Host, **16,141 ops/sec** (61.95 µs) on Debian 13 WSL.

---

## 2. Test Environments

| Attribute | Environment 1 (Host) | Environment 2 (Subsystem) |
|---|---|---|
| **OS** | Windows 10/11 x64 Native Host | Debian 13 (Trixie) WSL2 |
| **Compiler Toolchain** | MinGW-w64 GCC 14.2 (gnu++20) | GCC 14.2 (gnu++20) / Ninja |
| **Python Runtime** | CPython 3.12.7 x64 | CPython 3.13.5 x64 |
| **CFFI Binding** | CFFI v1.17 | CFFI v1.17 |
| **Micro-Benchmark Tooling** | `benchmark_linep_vs_sl.cpp` | `benchmark_linep_vs_sl.cpp` |

---

## 3. Native C++ Micro-Benchmark Audit Results (100,000 Iterations)

### Windows Host (MinGW GCC 14 x64)

```text
================================================================================
           LiNeP vs LiNeP-SL Security Layer Performance Benchmark              
================================================================================
Iterations per Benchmark: 100,000 messages

--------------------------------------------------------------------------------
 Layer / Component                |  Ops / sec (msg/s)  | Latency per Msg (ns)  
--------------------------------------------------------------------------------
 SL0: LiNeP Baseline Wire Format |      143,595,634.69 |                6.96 ns
 SL1: HMAC-SHA256 MAC Verification|         112,304.29 |             8,904.38 ns
 SL2: Key Derivation & Freshness  |         239,195.08 |             4,180.69 ns
 SL3: Capability Token Verification|         245,456.24 |             4,074.05 ns
 SL4: Zero-Trust Governance & Audit|         748,783.79 |             1,335.50 ns
--------------------------------------------------------------------------------
 Full Stack (SL0 + SL1-SL4 Active) |          66,187.18 |            15,108.67 ns
--------------------------------------------------------------------------------

==> Security Overhead (SL1-SL4 over SL0): 15.10 microseconds (us) per message
==> Peak Throughput with Full SL1-SL4 Gating: 66,187 msg/sec
================================================================================
```

### Debian 13 WSL (GCC 14.2 x64)

```text
================================================================================
           LiNeP vs LiNeP-SL Security Layer Performance Benchmark              
================================================================================
Iterations per Benchmark: 100,000 messages

--------------------------------------------------------------------------------
 Layer / Component                |  Ops / sec (msg/s)  | Latency per Msg (ns)  
--------------------------------------------------------------------------------
 SL0: LiNeP Baseline Wire Format |      123,107,226.39 |                8.12 ns
 SL1: HMAC-SHA256 MAC Verification|          58,217.69 |            17,176.91 ns
 SL2: Key Derivation & Freshness  |         101,428.76 |             9,859.14 ns
 SL3: Capability Token Verification|         103,262.90 |             9,684.02 ns
 SL4: Zero-Trust Governance & Audit|         283,607.50 |             3,526.00 ns
--------------------------------------------------------------------------------
 Full Stack (SL0 + SL1-SL4 Active) |          27,644.56 |            36,173.49 ns
--------------------------------------------------------------------------------

==> Security Overhead (SL1-SL4 over SL0): 36.17 microseconds (us) per message
==> Peak Throughput with Full SL1-SL4 Gating: 27,644 msg/sec
================================================================================
```

---

## 4. Python CFFI Binding Audit Results (20,000 Iterations, SL2 Included)

| Layer / Component | Windows Host (Ops/sec) | Windows Latency | Debian 13 WSL (Ops/sec) | Debian 13 WSL Latency |
|---|---|---|---|---|
| **SL1 HMAC-SHA256 MAC** | 85,920 msg/s | 11.64 µs | 34,399 msg/s | 29.07 µs |
| **SL2 Session Key Derivation** | 145,753 msg/s | 6.86 µs | 60,584 msg/s | 16.51 µs |
| **SL3 Capability Verification** | 163,066 msg/s | 6.13 µs | 61,413 msg/s | 16.28 µs |
| **SL4 Governance & Audit Engine** | 210,689 msg/s | 4.75 µs | 54,600 msg/s | 18.31 µs |
| **FULL STACK (SL1–SL4 with SL2)** | **43,693 msg/s** | **22.89 µs** | **16,141 msg/s** | **61.95 µs** |

---

## 5. Security Invariant & Enforcement Verification Checklist

- [x] **No Gate Bypass for Message Types**: `TASK`, `STREAM_CHUNK`, `TASK_CANCEL`, and `UDP_HEARTBEAT` all undergo mandatory SL1 MAC, SL3 Capability Authorization, and SL4 Zero-Trust Governance checks.
- [x] **Identity Provider Anchor**: Server engine uses pre-provisioned trusted peer identity anchors. Incoming packets cannot dynamically register untrusted public keys.
- [x] **Transport Isolation**: Replay state is scoped per `(session_id, correlation_id, transport_type)` avoiding sequence collisions between TCP and UDP.
- [x] **Zero Secrets in Audit Logs**: Audit records track policy revisions, capabilities, and decision codes without exposing private keys or raw secrets.

---

## 6. Audit Conclusion & Status

The **LiNeP-SL Security Layer** demonstrates exceptional in-memory performance, adding **only ~15.1 microseconds** of CPU processing overhead per message while enforcing full Zero-Trust security guarantees.

- **Status**: **EMPIRICAL MICRO-BENCHMARK AUDITED & VERIFIED**
- **Git Verification**: Commit `c1d23cc` on branch `main`.
