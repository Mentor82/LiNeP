# LiNeP Reference Manual

This directory contains the normative LiNeP protocol documentation.

> **The LiNeP Reference Manual defines the protocol. Implementations conform to this specification; implementations do not define or modify LiNeP semantics.**

Normative terms such as **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as protocol requirements unless explicitly marked informative.

## Protocol baselines

| Version | Status | Role |
|---|---|---|
| [V0.1](./v0_1/README.md) | **Frozen** | Historical normative worker-protocol baseline |
| [V0.2](./v0_2/README.md) | **Current normative baseline** | Engine-neutral runtime interoperability protocol |

LiNeP V0.1 and V0.2 are distinct protocol baselines. Requirements from one version **MUST NOT** be implicitly applied to the other.

## Version rule

Documentation, tests, adapters, issues, and conformance claims SHOULD always name the protocol version they apply to. Avoid ambiguous statements such as `LiNeP heartbeat does ...`; prefer `LiNeP V0.1 heartbeat ...` or `LiNeP V0.2 HEARTBEAT ...`.

## Architectural continuity

V0.2 preserves and generalizes the dual-plane idea proven by V0.1, but V0.2 is not merely "V0.1 plus features".

```text
V0.1
worker-oriented dual-plane protocol
        ↓ architectural evolution
V0.2
engine-neutral runtime interoperability protocol
```

For migration guidance see [`../migration/V0_1_TO_V0_2.md`](../migration/V0_1_TO_V0_2.md) and the [`compatibility matrix`](../migration/COMPATIBILITY_MATRIX.md).
