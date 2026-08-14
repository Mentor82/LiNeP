# Interoperability & Integration Report: Windows ↔ Debian 13 (Trixie)

This document records the cross-platform build, binary parity, socket communication, security level negotiation, session key lifecycle, fail-closed security gates, streaming fragments, authenticated cancellation, and complete 25-test UDP heartbeat security invariants between **Windows Host** and **Debian 13 WSL (LIARA Workstation)** over an explicit, un-derived `PortPair(tcp_port, udp_port)`.

---

## 1. System & Environment Metadata

| Parameter | Peer A (Windows Control Host) | Peer B (Debian 13 LIARA Workstation) |
|---|---|---|
| **OS / Environment** | Windows 10/11 x64 (Native Host) | Debian GNU/Linux 13 (trixie) WSL2 |
| **Compiler / Toolchain** | MinGW-w64 GCC 14.0 / MSVC | GNU GCC 14.2.0-19 / Ninja 1.12.1 |
| **Python Runtime** | Python 3.12.7 (win32) | Python 3.13.5 (linux) |
| **Binary Artifacts** | `build/src/liblinep_sl.dll` | `build_linux/src/liblinep_sl.so` |
| **PortPair Configuration** | `--tcp-port <port> --udp-port <port>` (Strictly un-derived) | `--tcp-port <port> --udp-port <port>` (Strictly un-derived) |

---

## 2. Fail-Closed Security Gates & Protocol Verification

### Security Gate 1: Fail-Closed MAC Verification (SL1)
- **Rule**: If `verify_sl1_mac()` returns `False` (tampered header, modified payload, wrong key), the server MUST immediately abort dispatch and return `status: REJECTED`.
- **Test Outcome**: Verified across Windows Host and Debian 13 WSL. Tampered MACs were rejected with `"status": "REJECTED"`, `"reason": "Authentication failed (Invalid MAC)"`.

### Security Gate 2: Fail-Closed Capability Authorization (SL3)
- **Rule**: If `verify_capability_token()` fails (unauthorized action e.g. requesting `ADMIN` when only `INFERENCE_READ` is granted), the server MUST immediately reject with `status: REJECTED`.
- **Test Outcome**: Verified across OS boundaries. Requesting unauthorized `ADMIN` returned `"status": "REJECTED"`, `"reason": "Capability authorization failed"`.

### Security Gate 3: Zero-Trust Governance & Cross-Domain Identity Anchor (SL4)
- **Rule**: Cross-domain communications require active Federation Trust, explicit Governance Policy approval (`allow_cross_domain = True`), AND domain-scoped identity verification (`(trust_domain_id, node_id) -> pubkey`). Untrusted federated peers or revoked federations are rejected fail-closed.
- **Test Outcome**: Verified across Windows Host and Debian 13 WSL. Requests without federation returned `"CROSS_DOMAIN_FEDERATION_DENIED"`, policy denial returned `"GOVERNANCE_POLICY_CROSS_DOMAIN_DENIED"`, and untrusted federated peer keys returned `"CROSS_DOMAIN_IDENTITY_UNTRUSTED"`.

### V0.2 Transport: Stream Fragments & Duplicate Rejection
- **Rule**: Stream chunks must maintain strictly monotonic sequence numbers (`chunk_seq = 1, 2, 3...`). Out-of-order or duplicate fragments MUST be rejected.
- **Test Outcome**:
  - Valid Chunks 1 & 2 $\rightarrow$ `status: STREAM_ACCEPTED`.
  - Retransmitted / Duplicate Chunk 2 $\rightarrow$ `status: REJECTED`.

### V0.2 Transport: Authenticated TASK_CANCEL
- **Rule**: `TASK_CANCEL` must pass SL1 HMAC authentication, SL3 Capability Authorization, AND SL4 Governance decision before cancellation execution.
- **Test Outcome**:
  - Valid SL1/SL3/SL4 Authenticated `TASK_CANCEL` $\rightarrow$ `status: CANCEL_ACCEPTED`.
  - Unauthorized / Tampered `TASK_CANCEL` $\rightarrow$ `status: REJECTED`.

### UDP Heartbeat Security Invariants & Edge Cases (Issue #7)
- **Rule**: UDP heartbeats sent over `PortPair(tcp_port, udp_port)` must require `CAP_HEARTBEAT_EMIT` (`0x0020`), SL1 MAC authentication, SL4 Governance decision, sequence tracking isolated per `(session_id, correlation_id, transport_type)`, source address/port checks, sender restart handling, policy revision invalidation, and concurrent multi-peer support.
- **Test Outcome**:
  - Valid Protected UDP Heartbeat $\rightarrow$ `status: HEARTBEAT_ACCEPTED`.
  - Replayed / Tampered / Truncated / Oversized / Unexpected Source / Stale Session / Revoked Federation UDP Datagram $\rightarrow$ `status: REJECTED`.

---

## 3. Full 25-Test Multi-Platform Interop Matrix

| Test Case | Direction 1: Win Server $\leftarrow$ Debian Client | Direction 2: Debian Server $\leftarrow$ Win Client | Status |
|---|---|---|---|
| **1. Valid TASK Request** | PASSED | PASSED | **OK** |
| **2. Tampered MAC (Gate 1)** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **3. Unauthorized Capability (Gate 2)** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **4. Stream Fragments (Chunk 1 & 2)** | PASSED (ACCEPTED) | PASSED (ACCEPTED) | **OK** |
| **5. STREAM_CHUNK Unauthorized Cap** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **6. Duplicate Stream Chunk** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **7. Authenticated TASK_CANCEL** | PASSED (CANCEL_ACCEPTED) | PASSED (CANCEL_ACCEPTED) | **OK** |
| **8. TASK_CANCEL Unauthorized Cap** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **9. Tampered TASK_CANCEL MAC** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **10A. Cross-Domain without Federation** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **10B. Cross-Domain with Policy Deny** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **11. Stale / Expired Session Key** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **12. Authenticated Key Rotation** | PASSED (KEY_ROTATED) | PASSED (KEY_ROTATED) | **OK** |
| **13. Protected UDP Heartbeat** | PASSED (HEARTBEAT_ACCEPTED) | PASSED (HEARTBEAT_ACCEPTED) | **OK** |
| **14. Tampered UDP Heartbeat MAC** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **15. Duplicate UDP Heartbeat Replay** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **16. Cross-Domain UDP without Federation** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **17. Truncated UDP Datagram (< 24 B)** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **18. Oversized UDP Datagram (> 4096 B)** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **19. UDP Expired / Stale Session Key** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **20. UDP Unauthorized Capability** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **21. UDP Policy Revision Impact** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **22. UDP Federation Revocation** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **23. Sender Restart Stale Session** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **24. Unexpected Source Address / Port** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **25. Concurrent Multiple UDP Peers** | PASSED (ACCEPTED) | PASSED (ACCEPTED) | **OK** |

---

## 4. Normative References & Issue Tracking

- **GitHub Issue #6**: [`feat(linep-sl/sl4): implement governance, audit, zero-trust and federation semantics`](https://github.com/Mentor82/LiNeP/issues/6)
- **GitHub Issue #7**: [`test(linep-sl): validate SL security invariants over LiNeP UDP heartbeat transport`](https://github.com/Mentor82/LiNeP/issues/7)
