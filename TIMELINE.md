# LiNeP — Timeline

> From a lightweight internal transport idea to a cross-platform, security-layered protocol for LIARA.

LiNeP did not begin as a fully specified protocol. It evolved incrementally from a practical need inside LIARA: components and workers needed a small, fast and deterministic way to communicate without coupling the system to HTTP or one specific runtime.

This timeline records that evolution, including the reasoning behind important design changes rather than only the commits that implemented them.

---

## May 2026 — The original idea

### 2026-05-01 — LiNeP emerges as the "Liara Neural Protocol"

The first concept was deliberately small:

- compact binary framing
- deterministic request/result transport
- heartbeat / liveness
- worker registration
- task dispatch
- timeout and error handling
- minimal runtime state

The goal was not to invent another general-purpose network stack. LiNeP was intended as LIARA's internal neural/service communication protocol: small enough to embed close to inference workers, but structured enough to become independent from individual model runtimes.

Very early builds already targeted Windows x64, Debian/Linux x64 and ARM64 environments. That portability later became one of LiNeP's defining properties.

### 2026-05-01 → 2026-05-02 — From transport to worker coordination

Once basic request/result communication worked, the question changed from "can two components exchange frames?" to "can LIARA coordinate several workers through this protocol?"

The design therefore expanded toward heartbeat-driven worker state, slot registration, task queues, worker availability, scheduler ↔ worker communication and score-based dispatch decisions.

An important architectural separation emerged: HTTP could remain the external/service-facing API, while LiNeP would serve the internal scheduler ↔ worker relationship. This prevented LiNeP from becoming an "HTTP replacement for everything."

---

## 2026-05-02 — LiNeP-SL is conceived

Security was initially intentionally kept outside the minimal transport core. That changed once LiNeP began looking less like an experiment and more like infrastructure.

The idea of **LiNeP-SL — LiNeP Security Layers** emerged.

The key design choice was that LiNeP-SL would **not create another transport protocol**. Security would be layered over LiNeP.

Early conceptual layering:

- **SL0** — LiNeP transport baseline
- **SL1** — lightweight authentication
- **SL2** — cryptographic identity / session security
- **SL3** — authorization / capabilities
- **SL4** — governance / audit / zero-trust / federation

This separation later became one of the strongest architectural invariants of LiNeP-SL.

---

## 2026-05-04 — Important correction: SL0 is not "insecure mode"

SL0 must not mean "plain / insecure LiNeP". LiNeP already owns its transport boundary and can operate with transport security such as TLS.

LiNeP-SL therefore adds protocol-level security semantics on top:

- authenticated message identity
- peer identity
- session/key lifecycle
- authorization
- governance

SL0 is the transport/integrity baseline, not an opt-out from security.

---

# LiNeP V0.2 — Transport becomes stateful

As LiNeP matured, request/result exchange was no longer sufficient. Large model responses and long-running tasks required streaming and explicit lifecycle control.

## Streaming transport

LiNeP gained fragmented message transport with:

- `FLAG_FRAGMENTED`
- ordered fragments
- monotonic sequence numbers
- correlation preservation
- reassembly semantics

The protocol could now transport data incrementally instead of requiring every result to fit into one frame.

## TASK_CANCEL

Streaming introduced another requirement: once a task can remain active over time, cancellation becomes a protocol operation rather than merely a local API concern.

`TASK_CANCEL` was added so cancellation could propagate through the same relationship that owns the task. Later LiNeP-SL hardening made authenticated cancellation an explicit security requirement.

## Telemetry and scoring

The next layer was not transport at all. LiNeP began carrying enough runtime information for LIARA to evaluate workers. Telemetry/scoring support allowed scheduling to consider worker state, availability, observed behavior and execution suitability.

## Consensus

Consensus support followed, extending LiNeP beyond one scheduler assigning one task to one worker and toward relationships in which several nodes can contribute to a decision or execution state.

At this stage the original "tiny internal transport" had clearly evolved into infrastructure, while preserving boundaries between transport, scheduling semantics and security.

---

# August 2026 — LiNeP-SL reconstruction and hardening

## 2026-08-14 — The security architecture is reconstructed

The original LiNeP-SL idea was turned into an explicit architecture and specification.

The repository gained:

- LiNeP-SL architecture documentation
- reconstructed V0.1 security specification
- phased implementation roadmap

The normative layering was formalized as:

### SL0 — LiNeP baseline
Transport, framing and transport integrity.

### SL1 — Lightweight internal authentication
Fast authenticated message integrity for trusted/internal environments.

### SL2 — Cryptographic identity & session key management
Peer identities, trust domains, key lifecycle and security negotiation.

### SL3 — Authorization / capabilities
What an authenticated peer is allowed to do.

### SL4 — Governance / audit / zero-trust / federation
Higher-level organizational and policy semantics. **Architecture defined; operational implementation still pending.**

A major design invariant was reaffirmed:

> Security layers extend LiNeP. They do not create a second transport.

---

## SL1 implementation and hardening

The first implementation used HMAC-SHA256-based message authentication.

Review uncovered several subtle issues that became architectural improvements:

- native-memory serialization must not define a network transcript
- MAC input must use a canonical wire representation
- sequence numbers must be enforced, not merely signed
- subject/session binding must be explicit
- replay handling must fail closed

This led to canonical little-endian MAC serialization and replay hardening.

---

## Layer-boundary correction

An early capability implementation had been placed under SL2.

Review showed that this violated the architecture:

> Identity answers: "Who is this peer?"
>
> Authorization answers: "What may this peer do?"

Capabilities therefore belong to **SL3**, not SL2.

The implementation was moved accordingly and the public interfaces were renamed to reflect the correct layer ownership.

---

## SL2 — Identity and session security

SL2 added:

- `PeerIdentity`
- trust-domain handling
- trusted / unknown / revoked peer state
- `SessionKey`
- session key derivation
- freshness / expiry
- key rotation
- security-level negotiation
- `IdentityProvider`
- session state abstractions

A second review cycle expanded the work beyond "derive a key" into an actual security-policy boundary. Silent security downgrade became explicitly forbidden.

---

# Real interoperability

## Windows ↔ Debian 13

Unit tests were no longer considered sufficient. A dedicated interoperability milestone was created to validate LiNeP-SL between a Windows control/development side and Debian 13 on the LIARA workstation.

The first implementation proved build parity and local TCP behavior, but review identified an important distinction:

> localhost TCP is real TCP, but it is not yet real peer interoperability.

This led to separate client/server roles and actual Windows ↔ Debian execution.

## Fail-closed network behavior

The interop implementation was hardened so security checks became real gates rather than diagnostic booleans.

A message with invalid MAC, invalid capability, untrusted identity or insufficient security level must be rejected **before acceptance or dispatch**.

## Secret handling

Interop review also detected that a derived session key had been written into the test report. That violated LiNeP-SL's own observability requirements.

The raw key was removed and replaced with a non-secret fingerprint.

> Security diagnostics may identify a key. They must never expose the key.

---

# V0.2 + LiNeP-SL meet

The final interoperability work brought the transport and security paths together.

Protected validation covered:

- normal task traffic
- authenticated MAC verification
- SL3 capability authorization
- stream fragments
- monotonic fragment sequencing
- duplicate / reordered fragment rejection
- authenticated `TASK_CANCEL`
- tampered cancellation rejection

LiNeP-SL was no longer an isolated cryptographic library sitting beside LiNeP. Security semantics now governed actual LiNeP V0.2 behavior.

## Per-stream sequence state

The first integration daemon kept one global `last_stream_seq`. That worked for a single test stream but would incorrectly couple independent concurrent streams.

The sequence state was therefore changed to:

```text
(session_id, correlation_id) -> last_sequence
```

Each task/stream relationship now owns its own fragment sequence state.

Commit: `bbbca74` — *Hardening: Scope stream sequence state per (session_id, correlation_id) stream*.

---

# Current state — 2026-08-14

LiNeP has evolved from a compact internal worker protocol into a cross-platform coordination transport with:

- deterministic framing
- request/result semantics
- heartbeats and worker relationships
- streaming / fragmentation
- task cancellation
- telemetry and scoring
- consensus support
- canonical authenticated wire transcripts
- replay protection
- cryptographic peer identity
- session/key lifecycle
- security-level negotiation
- capabilities
- fail-closed protected traffic
- Windows ↔ Debian interoperability

LiNeP-SL currently stands at:

```text
SL4  Governance / Audit / Zero-Trust / Federation   [PLANNED / NOT YET COMPLETE]
 ↑
SL3  Authorization / Capabilities                   [IMPLEMENTED / VALIDATED]
 ↑
SL2  Cryptographic Identity / Session Security       [IMPLEMENTED / VALIDATED]
 ↑
SL1  Lightweight Message Authentication              [IMPLEMENTED / HARDENED]
 ↑
SL0  LiNeP Transport Baseline                        [IMPLEMENTED]
```

The next major security-layer milestone is therefore **SL4**.

---

# Design philosophy that emerged

Several principles were not part of the original tiny protocol idea. They emerged through implementation and review.

### Keep transport small
Higher-level functions may use LiNeP, but they should not silently become part of its framing core.

### Do not collapse architectural layers
Authentication, identity and authorization solve different problems.

### Canonical bytes define protocol truth
Host memory representation must never accidentally become wire format.

### Security decisions are gates
`verified = false` is not merely telemetry. It must prevent execution.

### Fail closed
Unknown, malformed, expired, downgraded or unauthenticated states must not silently become accepted states.

### Real interoperability matters
A protocol is not truly portable merely because the same source compiles twice. Both ends must exchange real traffic and independently reach the same security conclusions.

---

# From idea to protocol

```text
Need for fast internal communication
        ↓
LiNeP V0.1
        ↓
Worker coordination
        ↓
Streaming / Cancellation
        ↓
Telemetry / Scoring
        ↓
Consensus
        ↓
Need for protocol-level trust
        ↓
LiNeP-SL
        ↓
SL0–SL4 architecture
        ↓
Canonical authentication
        ↓
Identity / Sessions / Capabilities
        ↓
Real Windows ↔ Debian interoperability
        ↓
Fail-closed protected LiNeP V0.2 traffic
        ↓
Next: SL4 Governance / Audit / Zero-Trust / Federation
```

What started as a small internal protocol has become a reusable, platform-independent communication and security foundation for LIARA — while still preserving the original goal:

**keep the transport deterministic, explicit and understandable.**
