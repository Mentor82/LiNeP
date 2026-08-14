# Interoperability & Integration Report: Windows ↔ Debian 13 (Trixie)

This document records the cross-platform build, binary parity, socket communication, security level negotiation, session key lifecycle, and fail-closed validation between **Windows Host** and **Debian 13 WSL (LIARA Workstation)**.

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

## 2. Phase 1–6 Validation Summary

### Phase 1 — Build & Parity
- **C++ Native Builds**: Built `linep_sl_core` static libraries and shared objects (`.dll` and `.so`) cleanly on both platforms.
- **SL1 MAC Golden Vectors**: 34-byte Little-Endian wire format prefix produced 100% identical 16-byte HMAC-SHA256 signatures across Windows and Debian 13.
- **Python Bindings**: CFFI bindings loaded seamlessly on both platforms.

### Phase 2 — Peer Identity & Trust Domain
- **Identity Allocation**:
  - Peer A (Windows): Node ID `10`, Pubkey `0xAA...`
  - Peer B (Debian): Node ID `20`, Pubkey `0xBB...`
- **Verification**: Mutual identity acceptance succeeded (`is_peer_trusted == True`). Unknown node IDs, revoked nodes, and trust-domain ID mismatches failed closed.

### Phase 3 — SL2 Session Establishment & Anti-Downgrade
- **Security Negotiation**: Negotiated `SL2_IDENTITY` when offered `SL2` and `SL3`.
- **Downgrade Rejection**: When offered `SL1` against a policy requiring `SL2`, negotiation failed closed (`success == False`).
- **Session Key Derivation**: Both platforms derived identical 256-bit symmetric session key:
  `d4b803b37703fe5f19b04106fd039273b0f96a621be3d3b737f41af17f5b8671`

### Phase 4 — Key Rotation & Boundary Behavior
- **Key Rotation**: Successfully rotated session keys over active TCP sockets (`key_id` 1 $\rightarrow$ 2).
- **Rotation Boundary**: Old key from 2+ generations prior was rejected (`is_key_valid == False`).

### Phase 5 — Protected LiNeP Transport Over TCP
- **Real Socket Transfer**: Tested live TCP socket communication in both directions:
  1. Windows Server (`0.0.0.0:19878`) $\leftarrow$ Debian Client (`172.24.224.1:19878`) — **PASSED**
  2. Debian Server (`0.0.0.0:19879`) $\leftarrow$ Windows Client (`127.0.0.1:19879`) — **PASSED**
- **Payload Verification**: Authenticated SL1 header & SL3 capability token frames were processed cleanly with response `b"OK_SL2_ACK"`.

### Phase 6 — SL3 Capability Enforcement
- **`INFERENCE_READ`**: Verified allowed (`cap_read_ok == True`).
- **`ADMIN`**: Verified denied-by-default (`cap_admin_ok == False`).

---

## 3. Observability & Security Compliance
- **Zero Key Leaks**: Private key material and master secrets are strictly unlogged and hidden from error payloads.
- **Fail-Closed Guarantee**: All invalid headers, tampered MACs, expired tokens, and downgrade attempts are rejected before task callback execution.
