# LiNeP (Lightweight Network Protocol for Inter-AI Engine)

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

## Quick Links — LiNeP-SL

* 🔐 **[LiNeP-SL Architecture Overview](./LiNeP-SL/README.md)**
* 📜 **[Reconstructed Security Specification V0.1](./LiNeP-SL/SPEC_V0_1_RECONSTRUCTED.md)**
* 📋 **[LiNeP-SL V0.1 Implementation Roadmap](./LiNeP-SL/TODO_V0_1.md)**

### For implementation agents

Read the three LiNeP-SL documents above before changing security-related code. Treat SL0–SL4 and the LiNeP/LiNeP-SL boundary as the architecture baseline. First inspect compatibility with current LiNeP V0.2 and propose the smallest safe SL1 integration seam; do not silently redesign the layer model or create a parallel transport.