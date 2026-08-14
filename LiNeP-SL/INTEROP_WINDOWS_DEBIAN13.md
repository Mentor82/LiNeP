# Interoperability & Integration Report: Windows ↔ Debian 13 (Trixie)

This document records the cross-platform build, binary parity, socket communication, security level negotiation, session key lifecycle, fail-closed security gates, streaming fragments, and authenticated cancellation between **Windows Host** and **Debian 13 WSL (LIARA Workstation)**.

---

## 1. System & Environment Metadata

| Parameter | Peer A (Windows Control Host) | Peer B (Debian 13 LIARA Workstation) |
|---|---|---|
| **OS / Environment** | Windows 10/11 x64 (Native Host) | Debian GNU/Linux 13 (trixie) WSL2 |
| **Compiler / Toolchain** | MinGW-w64 GCC 14.0 / MSVC | GNU GCC 14.2.0-19 / Ninja 1.12.1 |
| **Python Runtime** | Python 3.12.7 (win32) | Python 3.13.5 (linux) |
| **Binary Artifacts** | `build/src/liblinep_sl.dll` | `build_linux/src/liblinep_sl.so` |
| **Position Independent Code** | Windows DLL standard | `-fPIC` (`POSITION_INDEPENDENT_CODE ON`) |

---

## 2. Fail-Closed Security Gates & DoD Protocol Verification

### Security Gate 1: Fail-Closed MAC Verification
- **Rule**: If `verify_sl1_mac()` returns `False` (tampered header, modified payload, wrong key), the server MUST immediately abort dispatch and return `status: REJECTED`.
- **Test Outcome**: Verified across Windows Host and Debian 13 WSL. Tampered MACs were rejected with `"status": "REJECTED"`, `"reason": "Authentication failed (Invalid MAC)"`.

### Security Gate 2: Fail-Closed Capability Authorization
- **Rule**: If `verify_capability_token()` fails (unauthorized action e.g. requesting `ADMIN` when only `INFERENCE_READ` is granted), the server MUST immediately reject with `status: REJECTED`.
- **Test Outcome**: Verified across OS boundaries. Requesting unauthorized `ADMIN` returned `"status": "REJECTED"`, `"reason": "Capability authorization failed"`.

### V0.2 Transport: Stream Fragments & Duplicate Rejection
- **Rule**: Stream chunks must maintain strictly monotonic sequence numbers (`chunk_seq = 1, 2, 3...`). Out-of-order or duplicate fragments MUST be rejected.
- **Test Outcome**:
  - Valid Chunks 1 & 2 $\rightarrow$ `status: ACCEPTED`.
  - Retransmitted / Duplicate Chunk 2 $\rightarrow$ `status: REJECTED`, `"reason": "Stream sequence error (duplicate/reordered chunk 2)"`.

### V0.2 Transport: Authenticated TASK_CANCEL
- **Rule**: `TASK_CANCEL` must contain valid SL1 HMAC authentication. Unauthenticated or tampered cancels MUST be rejected.
- **Test Outcome**:
  - Valid SL1 Authenticated `TASK_CANCEL` $\rightarrow$ `status: CANCEL_ACCEPTED`.
  - Tampered / Bad MAC `TASK_CANCEL` $\rightarrow$ `status: REJECTED`.

---

## 3. Security & Observability Compliance (No Secret Leakage)

- **Sanitized Audit Log**: No raw 256-bit symmetric session keys or master secret material appear in logs, responses, or documentation.
- **Fingerprinting**: Session key identification uses SHA-256 key fingerprints (`Key Fingerprint: 4f89d3a7e21b... [Redacted 256-bit Secret]`).
- **Fail-Closed Reason Codes**: Error responses expose structured reason strings without disclosing internal key bytes or cryptographic states.

---

## 4. Multi-Platform Interop Matrix

| Test Case | Direction 1: Win Server $\leftarrow$ Debian Client | Direction 2: Debian Server $\leftarrow$ Win Client | Status |
|---|---|---|---|
| **Mutual Identity Authentication** | PASSED | PASSED | **OK** |
| **SL2 Security Level Negotiation** | PASSED | PASSED | **OK** |
| **SL1 MAC Verification (Gate 1)** | PASSED | PASSED | **OK** |
| **SL3 Capability Check (Gate 2)** | PASSED | PASSED | **OK** |
| **Tampered MAC Rejection** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **Unauthorized Capability Rejection** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **Stream Chunk Monotonic Sequence** | PASSED (ACCEPTED) | PASSED (ACCEPTED) | **OK** |
| **Duplicate Stream Chunk Rejection** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
| **Authenticated TASK_CANCEL** | PASSED (CANCEL_ACCEPTED) | PASSED (CANCEL_ACCEPTED) | **OK** |
| **Tampered TASK_CANCEL Rejection** | PASSED (REJECTED) | PASSED (REJECTED) | **OK** |
