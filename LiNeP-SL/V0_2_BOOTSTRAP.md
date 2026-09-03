# LiNeP-SL V0.2 Bootstrap Workspace

Tracking: [Issue #12](https://github.com/Mentor82/LiNeP/issues/12)

LiNeP-SL V0.2 is the security contract for the engine-neutral LiNeP V0.2
runtime protocol. It protects the existing dual-plane communication model; it
does not create another transport or standardize an inference engine.

Its primary deployment boundary is communication that leaves the trusted
LiNeP intranet or crosses an Internet/federation trust boundary. It can still
protect internal profiles when policy requires it, but it does not turn LiNeP
core into an Internet transport.

## Hard compatibility rule

```text
LiNeP-SL V0.2 may depend on public LiNeP V0.2 contract types.
LiNeP V0.2 must not depend on LiNeP-SL V0.2.
LiNeP-SL V0.1 must not depend on, or be changed for, V0.2.
```

The existing `linep::sl` API, C ABI, wire extensions, and tests are the frozen
LiNeP-SL V0.1 baseline. New V0.2 work lives under `linep::sl::v0_2` and is
enabled only with `LINEP_SL_BUILD_V02=ON`.

## Version boundaries

| Component | Current contract | Role |
| --- | --- | --- |
| LiNeP | V0.1 | Frozen historical worker/core protocol |
| LiNeP | V0.2 | Engine-neutral runtime protocol |
| LiNeP-SL | V0.1 | Frozen SL0-SL4 security baseline |
| LiNeP-SL | V0.2 | New dual-plane, engine-neutral security contract |

Package and CMake metadata for the frozen SL implementation use `0.1.x` until
a LiNeP-SL V0.2 release is deliberately produced.

## Initial layout

```text
LiNeP-SL/
├─ include/linep_sl/v0_2/   # V0.2-only public security contract
├─ src/v0_2/                # canonical binding implementation
├─ tests/v0_2/              # isolated contract tests
└─ docs/v0_2/               # normative draft documentation
```

## Phase A — security binding contract

The first checkpoint defines only what must be authenticated and authorized:

- a security-session identity distinct from transport/runtime identities;
- explicit Control Plane versus Data Plane binding;
- sender-to-receiver direction binding to prevent reflection;
- node/runtime/endpoint, control epoch, lease and control sequence binding;
- request/execution/output, event and fragment sequence binding;
- engine-neutral actions and content-digest binding;
- fail-closed security-level validation.

It deliberately does not select a production crypto suite, establish network
sessions, or modify LiNeP framing.

## Later phases

1. Negotiation, algorithm suites and security-session lifecycle.
2. Authenticators and independent replay windows for both planes.
3. Engine-neutral authorization and capability-to-policy mapping.
4. Key rotation, governance, audit and federation.
5. Cross-language conformance, fuzzing and equivalent performance benchmarks.

The maintained phase checklist is [`TODO_V0_2.md`](TODO_V0_2.md).

## Guardrails

- Capability is not availability, and neither is authorization.
- Control, runtime, stream, conversation, backend-task and security-session
  identities are never interchangeable.
- `event_seq` and `fragment_seq` remain different ordering domains.
- No silent downgrade and no unauthenticated fallback for protected profiles.
- No engine-specific names in the normative contract.
- No performance or conformance claim before the corresponding tests exist.
