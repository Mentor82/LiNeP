# LiNeP V0.2 Bootstrap Workspace

Tracking: [Issue #10](https://github.com/Mentor82/LiNeP/issues/10)

This directory layout is the implementation sandbox for the **testable V0.2 runtime baseline**.

## Hard compatibility rule

```text
V0.2 may depend on reusable V0.1/core transport primitives.
V0.1 must not depend on V0.2.
```

The existing V0.1 wire contract, public headers, tests, and build behavior are frozen. Do not modify V0.1 merely to make V0.2 easier to implement.

If a V0.2 task appears to require changing an existing V0.1 wire field, message ID, framing rule, or test expectation, stop and document the incompatibility first.

## Initial layout

```text
LiNeP/
├─ include/linep/v0_2/       # V0.2-only public/runtime contract types
├─ src/v0_2/                 # V0.2 implementation
├─ tests/v0_2/               # V0.2 unit/integration tests
├─ tools/v0_2/
│  ├─ mock_runtime/          # deterministic test endpoint
│  └─ linep_conformance/     # reusable conformance runner
└─ docs/v0_2/                # draft normative/test documentation
```

## Build isolation

The root `LiNeP/CMakeLists.txt` is intentionally **not changed by this scaffold**. Existing builds therefore keep compiling only the current implementation.

When implementation begins, add V0.2 through an opt-in build flag, for example:

```cmake
option(LINEP_BUILD_V02 "Build experimental LiNeP V0.2 runtime baseline" OFF)
```

Only when the option is enabled should CMake enter `src/v0_2`, `tests/v0_2`, or `tools/v0_2`.

Suggested targets:

```text
linep_v02
linep_v02_mock_runtime
linep_v02_conformance
```

Do not rename or repurpose the existing `linep` target as part of Issue #10.

## Suggested Codex implementation order

### Phase A — contract types and envelopes

1. Complete `runtime_types.hpp`.
2. Define the four envelope families in `envelopes.hpp`.
3. Add encode/decode with strict validation.
4. Add unit tests before network code.

### Phase B — persistent session and multiplexing

1. Implement a V0.2 session abstraction under `src/v0_2`.
2. Allow multiple concurrent logical executions on one persistent connection.
3. Keep semantic `event_seq` separate from transport `fragment_seq`.
4. Prove stream isolation with deterministic tests.

### Phase C — lifecycle, cancel, terminal state, backpressure

1. Target cancellation by owned execution identity.
2. Treat cancel-requested as non-terminal.
3. Enforce exactly one authoritative logical terminal outcome per execution attempt.
4. Use bounded buffering with explicit overload behavior.

### Phase D — embedding + deterministic conformance tools

1. Implement `PROFILE_EMBED` semantics and vector-space identity validation.
2. Build the deterministic mock runtime.
3. Build the conformance runner.
4. Mark only executed profiles as conformant.

## Guardrails

- No real Ollama/llama.cpp/vLLM adapter code in Issue #10.
- No performance claims before equivalent benchmarks exist.
- No silent capability downgrade.
- No assumption that one callback equals one token.
- No conflation of conversation, execution, backend-task, security-session, or trace identity.
- No conflation of semantic event ordering with frame fragmentation.
- Equal embedding dimension is not evidence of equal embedding space.
- Existing V0.1 tests must remain green without modification.

## Definition of a useful first checkpoint

A good first implementation checkpoint is intentionally small:

```text
V0.2 Request envelope encode/decode ........ PASS
V0.2 Event envelope encode/decode .......... PASS
V0.2 Control envelope encode/decode ........ PASS
V0.2 Capabilities encode/decode ............ PASS
identity validation ........................ PASS
event_seq validation ....................... PASS
embedding metadata validation .............. PASS
V0.1 regression suite ...................... PASS
```

Only after that checkpoint should persistent socket/session work start.
