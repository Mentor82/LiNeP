# LiNeP - Liara Neural Protocol (Lightweight Network Protocol for Inter-AI Engine)

Welcome to the **LiNeP** repository.

This repository contains two related but deliberately separated architecture branches:

- [`LiNeP/`](./LiNeP) — core protocol, C++ engine, Python bindings, scheduling, streaming, telemetry, consensus, documentation, and tests.
- [`LiNeP-SL/`](./LiNeP-SL) — Security Layers for LiNeP: authentication, cryptographic identity, authorization, replay protection, policy, audit, and federation.

## Architecture boundary

```text
LiNeP    = communication / transport / scheduling / streaming / consensus
LiNeP-SL = trust + security for that communication
```

LiNeP-SL is not a second transport. It adds progressively stronger security while preserving the low-latency, deterministic LiNeP core.

## Quick Links — LiNeP Core

* 📂 **[LiNeP Core Directory](./LiNeP)**
* 📜 **[Protocol Specification V0.1.0](./LiNeP/PROTOCOL_V0_1_0.md)**
* 🚀 **[System Architecture & Quickstart](./LiNeP/README.md)**
* 📋 **[V0.2.0 Roadmap & Rollout Status](./LiNeP/TODO_V0_2_0.md)**

## Quick Links — LiNeP-SL (Security Layers)

* 📚 **[Library Reference & API Guide](./LiNeP-SL/LIBRARY_REFERENCE.md)**
* 🔐 **[LiNeP-SL Architecture Overview](./LiNeP-SL/README.md)**
* 📜 **[Reconstructed Security Specification V0.1](./LiNeP-SL/SPEC_V0_1_RECONSTRUCTED.md)**
* 📊 **[Micro-Benchmark & Security Overhead Audit Report](./LiNeP-SL/AUDIT_PERFORMANCE_SL0_VS_SL4.md)**
* 🌐 **[Windows ↔ Debian 13 Interoperability Report](./LiNeP-SL/INTEROP_WINDOWS_DEBIAN13.md)**
* 📋 **[LiNeP-SL V0.1 Implementation Roadmap](./LiNeP-SL/TODO_V0_1.md)**
* 🚧 **[LiNeP-SL V0.2 Bootstrap](./LiNeP-SL/V0_2_BOOTSTRAP.md)**
* 📋 **[LiNeP-SL V0.2 Roadmap](./LiNeP-SL/TODO_V0_2.md)**

## License, third-party software, and project name

The frozen LiNeP V0.1 baseline, the separate current LiNeP V0.2 baseline, and
the separately versioned LiNeP-SL V0.1 security baseline are licensed under
Apache-2.0 unless a file states otherwise. Their common license does not merge
the three version lines or their semantics.
Independent compatible implementations are explicitly encouraged; third-party
components retain their own licenses, and use of the LiNeP name or logo is
separate from implementation rights.

See the [`docs/legal/`](./docs/legal) index for the licensing policy,
third-party notices, dependency review, release requirements, and name-use
policy.

### Implementation Issues & Verification:
- **Issue #1**: [`fix(linep-sl): restore normative SL0–SL4 layer boundaries`](https://github.com/Mentor82/LiNeP/issues/1)
- **Issue #2**: [`hardening(linep-sl/sl1): canonicalize MAC input`](https://github.com/Mentor82/LiNeP/issues/2)
- **Issue #3**: [`feat(linep-sl/sl2): implement cryptographic identity & session key management`](https://github.com/Mentor82/LiNeP/issues/3)
- **Issue #4**: [`test(linep-sl): validate SL2 interoperability on real Windows ↔ Debian 13 peers`](https://github.com/Mentor82/LiNeP/issues/4)
- **Issue #6**: [`feat(linep-sl/sl4): implement governance, audit, zero-trust and federation semantics`](https://github.com/Mentor82/LiNeP/issues/6)
- **Issue #7**: [`test(linep-sl): validate SL security invariants over LiNeP UDP heartbeat transport`](https://github.com/Mentor82/LiNeP/issues/7)
