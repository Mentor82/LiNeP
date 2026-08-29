# LiNeP Wiki Source

This directory is the repository-maintained source for the LiNeP Wiki. Wiki content is explanatory; normative protocol truth lives in `docs/reference/`.

## Suggested Wiki tree

```text
Home
├── What is LiNeP?
├── Architecture at a Glance
├── Protocol Versions
│   ├── LiNeP V0.1 — Frozen
│   ├── LiNeP V0.2 — Current
│   └── Migrating V0.1 → V0.2
├── Why Dual Plane?
├── Getting Started
├── Concepts
│   ├── Nodes, Runtimes and Endpoints
│   ├── Streams and Executions
│   ├── Runtime Profiles
│   ├── Capabilities
│   └── LiNeP-SL
├── Implementing LiNeP
│   ├── Build your first runtime adapter
│   ├── TCP Data Plane
│   ├── UDP Control Plane
│   ├── Streaming correctly
│   ├── Cancellation correctly
│   ├── Embeddings correctly
│   └── Implementer's Checklist
├── Integrations
│   ├── Ollama
│   ├── llama.cpp
│   ├── vLLM
│   └── TensorRT-LLM
├── Testing
│   ├── Conformance Harness
│   ├── Golden Frames
│   ├── Cross-language Testing
│   └── Debugging
├── Design
│   ├── Design Principles
│   ├── Why UDP + TCP?
│   ├── Why transport-neutral semantics?
│   ├── Failure Model
│   └── Versioning
├── Common Implementation Mistakes
├── FAQ
├── Glossary
└── Roadmap
```

## Wiki version labels

Every protocol-specific Wiki page SHOULD begin with one of:

```text
Applies to: LiNeP V0.1 — Frozen
```

or

```text
Applies to: LiNeP V0.2 — Current normative baseline
```

Never publish version-ambiguous protocol rules.

## Source-of-truth order

```text
Reference Manual      → normative truth
Conformance Tests     → executable verification
Reference Implementation → implementation example
Wiki                  → explanatory documentation
Adapters              → consumers
```

The Wiki may explain the protocol, but it must not create new semantics.
