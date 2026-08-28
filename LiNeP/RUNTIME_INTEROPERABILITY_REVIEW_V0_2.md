# V0.2 Runtime Interoperability: Contract Review

Date: 2026-08-28

Tracking: [Issue #9 — engine-neutral runtime interoperability layer](https://github.com/Mentor82/LiNeP/issues/9)

## Status and scope

This document records a source-based architecture investigation, not an approved
wire specification, implemented adapter, or successful interoperability test.
Observations describe the pinned sources below; proposed requirements and tests
remain subject to architecture review. No runtime integration tests or benchmarks
were executed for this review.

The V0.1 baseline remains unchanged. No message IDs, payload encoding, new public
API, or LiNeP-SL redesign is decided here. Existing V0.2 rollout checkmarks are not
evidence that the broader contract in issue #9 is complete.

The principle under review is:

> LiNeP standardizes communication between heterogeneous AI runtimes,
> orchestrators, and nodes, not the implementation of those runtimes.

LIARA is an originating use case, not an exclusive consumer. Ollama, llama.cpp,
vLLM, TensorRT-LLM, SGLang, MLX-LM, VINOX, and LM Studio are contrasting examples,
not an exhaustive product list or a list of supported adapters. Audio, image,
video, and other inference systems still need their own concrete mappings before
support can be claimed.

The intended deployment distinction remains LiNeP for intranet communication and
LiNeP-SL for secured internet communication. LiNeP-SL secures LiNeP communication;
it does not replace the runtime's execution permissions or local resource policy.

## 1. Reuse existing boundaries

| Example | Inspected integration seam | Boundary to preserve |
| --- | --- | --- |
| Ollama | `llm.LlamaServer`; application logic currently reached through server handlers | External ingress and internal runner transport replacement are separate projects. Preserve scheduling, model management, templates, and parsers. |
| llama.cpp | `server_context.get_response_reader()` and task/result queues | Existing task ownership and cancellation, preprocessing, and chat handling. This internal C++ seam is not a guaranteed stable plugin ABI. |
| vLLM | `AsyncLLM.generate()`, output collection, and `abort()` | EngineCore scheduling and internal communication. Initial native integration need not replace ZMQ. Chat rendering/parsing is not identical to raw generation. |
| TensorRT-LLM | `LLM.generate_async()` and its generation executor/result objects | Existing preprocessing, scheduling, and per-output completion semantics. Older C++ Executor references require a version-specific review. |
| SGLang | `Engine.async_generate()` and TokenizerManager request management | Internal scheduler, multimodal handling, sessions, and cleanup. |
| MLX-LM | `stream_generate()` or the existing `ResponseGenerator` layer | Model/cache lifecycle and the actual cancellation guarantees of the selected path. A library call does not require an HTTP server. |
| VINOX | Generation/cancellation functions and the planned optional transport adapter | Core independence, model-handle ownership, admission control, permissions, and typed execution outcomes. Readiness documentation is not a finished adapter. |
| LM Studio | Documented SDK generation, streaming, and cancellation | An SDK integration is evidenced; an accessible native backend transport replacement is not established by those docs. |

Sources: [Ollama interface][ollama-interface], [Ollama handlers][ollama-routes],
[llama.cpp context][llama-context], [vLLM generation][vllm-async],
[vLLM chat processing][vllm-chat], [TensorRT-LLM LLM API][trt-llm],
[SGLang Engine][sglang-engine], [MLX-LM generator][mlx-generate],
[MLX-LM server][mlx-server], [VINOX readiness][vinox-readiness],
[LM Studio SDK][lmstudio-sdk], and [LM Studio cancellation][lmstudio-cancel].

For Ollama, keep the two existing investigations distinct:
[external native ingress](https://github.com/Mentor82/LiNeP-Ollama/issues/1) and
[internal runner transport](https://github.com/Mentor82/LiNeP-Ollama/issues/2).
An HTTP bridge can demonstrate an application mapping but does not demonstrate
the native transport replacement sought by those investigations.

NVIDIA's current [migration guide][trt-migration] documents removal of the legacy
TensorRT engine backend. An old diagram saying only "Executor" is therefore not
a sufficient version-independent adapter design.

## 2. Candidate common contract

These are proposed semantic requirements, not new message names or wire layouts.

| Concern | Candidate common guarantee | Do not infer |
| --- | --- | --- |
| Request | Scoped identity, validated requirements, explicit acceptance or rejection | Acceptance means GPU execution has begun |
| Results | Ownership by request and, where relevant, output/child operation | Every request returns one text string |
| Streaming | Defined ordering and delta versus snapshot semantics | One callback or frame equals one token |
| Cancellation | Explicit target, support level, and observable outcome | Requesting cancellation immediately stops all computation |
| Completion | One authoritative logical terminal outcome per execution attempt | Exactly-once network delivery through disconnects |
| Capabilities | Supported operations, constraints, and relevant combinations | Product name or independent booleans prove support |
| Errors | Common classification with preserved backend diagnostics | Every error is safe to retry |

Acceptance must identify its authority: receipt by an adapter, acceptance by local
admission control, or submission to a backend are different observations. Queue
entry and execution-start notifications should only be exposed when the selected
boundary can actually observe them. Unknown timings must not be fabricated.

### 2.1 Identity and ownership

Keep client invocation identity, execution-attempt identity, backend task IDs,
output indices, conversation identity, security-session identity, and tracing
identity conceptually distinct. Their wire representation is still undecided.

Observed reasons:

- vLLM can map one external request ID to multiple internal requests. Aborting
  that external ID aborts all associated requests; parallel sampling also has
  parent/child ownership. See [output processing][vllm-output].
- SGLang's scheduler uses `startswith` matching for cancellation targets. Passing
  arbitrary client IDs through unchanged can accidentally broaden cancellation.
  See [scheduler cancellation][sglang-scheduler].
- VINOX's readiness contract uses `session_id` for a conversation; LiNeP's
  `set_sl1_session()` configures a security context. Equal field names do not
  establish equal semantics. The readiness document also names `correlation_id`,
  while the inspected public `vinox_correlation_context` has no such member;
  that documentation/API alignment remains open. See [VINOX logging][vinox-logging]
  and [LiNeP TCP API][linep-tcp-api].

Proposed rule: adapters maintain controlled, collision-resistant ownership
mappings and validate cancellation authority. A request may own several backend
tasks, but never unrelated tasks belonging to another client or attempt.

### 2.2 Cancellation and terminal outcomes

Separate cancellation requested, cancellation observed by the runtime, and
execution completed. SGLang explicitly allows a running request to execute one
more decode forward pass after being marked for abort. TensorRT-LLM separates its
aborted flag from the result's finished state. See [SGLang][sglang-scheduler] and
[TensorRT-LLM results][trt-result].

The contract should describe cancellation during preprocessing, queueing, and
generation, repeated cancellation, unknown targets, and the completion/cancel
race. Unsupported cancellation must be explicit. A proposed interactive profile
may require targeted cancellation; a non-interruptible library must not advertise
that profile merely because its adapter can close a socket.

One logical terminal outcome does not imply that the peer received it. After a
disconnect or process crash, the observer may not know the execution outcome.
Result lookup, replay, reattachment, and re-execution are separate capabilities.
An observer-side timeout must not be presented as proof that remote work stopped.

VINOX additionally distinguishes permission denial, blocked execution, and an
indeterminate outcome for mutating operations. Preserve these distinctions when
mapping errors. Its readiness document treats `BLOCKED` as terminal; a resumable
approval workflow must explicitly distinguish a closed attempt from a waiting
operation instead of silently reinterpreting that state. See [readiness][vinox-readiness].

### 2.3 Stream representation and backpressure

TensorRT-LLM's result iterator returns the same updated object on successive
iterations. vLLM supports different output kinds, and SGLang coalesces incremental
text/token chunks. Blindly appending every callback is not a valid common mapping.
See [TensorRT-LLM results][trt-result], [vLLM output][vllm-output], and
[SGLang TokenizerManager][sglang-tokenizer].

An adapter must explicitly preserve or translate:

- deltas versus complete snapshots, including whether previous output can change;
- request completion versus completion of one output/sequence;
- content, tool arguments, reasoning output, status, and metrics;
- backend chunking versus LiNeP frame fragmentation and stream ordering.

Define bounded buffering and the behavior when the consumer is slower than the
producer. Coalescing may preserve semantics; silently dropping required deltas
does not. Do not infer generation pause merely from socket backpressure. Per-stream
ordering does not establish a total order between independent requests.

### 2.4 Capabilities and optional profiles

Candidate profiles include generation, chat, tool-call representation, separately
exposed reasoning, embeddings/ranking, multimodal input/output, multiple outputs,
streaming input, and resumable/background operations. None makes every engine
implement every feature. These groupings are review candidates, not protocol IDs.

Capability descriptions should account for the loaded model, backend/configuration,
supported parameter combinations, and effective limits. `vision=true` and
`tools=true` separately do not prove that their combination is supported.
Unsupported required features should cause explicit rejection, not silent fallback.

Preserve existing templates, tokenizers, parsers, and typed results where useful.
Transporting token IDs requires compatible tokenizer identity; exchanging vectors
requires sufficient representation identity, not just equal dimension. This review
does not define a universal tokenizer, embedding space, or model format.

Distinguish capability from current availability and local authorization. A tool
call proposed by a model is not permission to execute it. Transport authentication
does not grant that permission either. Reassembly must not bypass runtime payload
limits; VINOX's documented 262,144-byte tool argument/output limit is independent
of an individual LiNeP frame's capacity. See [VINOX readiness][vinox-readiness].

### 2.5 Retry and measurement semantics

Routing, retries, and speculative execution are policy decisions above basic
request transport. Do not automatically repeat a mutating operation whose outcome
is unknown. Idempotency, deduplication, and result replay require explicit support;
a reused correlation ID alone supplies none of them.

Metrics need units and scope: request versus sequence, cumulative versus incremental,
adapter versus backend timing, cached versus evaluated tokens where available.
Unknown is not zero. Compare durations measured within their clock domain; do not
derive latency from unsynchronized timestamps on different hosts.

## 3. Existing LiNeP implementation gaps relevant to issue #9

These are static findings at `fcb28c665278a9e9e83f45efd8dd9316a02736d6`, not newly
executed regression tests. This documentation commit does not fix them.

1. **Scheduler/receiver framing disagreement.** `submit()` stores the body separately
   from its task type, but `dispatch_transport()` sends only that body. The TCP
   receiver consumes its first byte as the task type. The scheduler also reads
   result payload immediately after the base header, whereas the receiver emits
   a build-time header extension first. These paths disagree on request and
   response layout. See [scheduler][linep-scheduler] and [TCP implementation][linep-tcp].
2. **Targeted cancellation is not end-to-end in the inspected TCP path.** The
   receiver initially accepts only `TASK`, then invokes the streaming callback
   synchronously. Its cancellation flag is set on write failure; this is not a
   request-targeted `TASK_CANCEL` control path, especially before the first output.
3. **Streaming terminal/error handling is incomplete.** The callback return status
   is ignored, the first streamed result gets `RESULT_OK`, and the writer does not
   guard against writes after a final fragment. See [TCP implementation][linep-tcp].
4. **Connection reuse is not an existing benefit of this sender.** Both single
   and streaming sends open a fresh TCP connection per call. Persistent sessions
   or multiplexing would need implementation and measurement, not just a claim
   that binary framing is faster.

The existing [streaming test](tests/test_task_streaming.cpp) demonstrates a happy
path, not the complete identity/cancel/terminal contract proposed here. Separate
security or interoperability harness results must not be transferred to a runtime
path without demonstrating that the tested implementation is the same path.

## 4. Proposed acceptance tests — not yet executed

| ID | Scenario | Required evidence |
| --- | --- | --- |
| C01 | Two clients choose the same local request ID | No result or cancellation crosses ownership boundaries |
| C02 | Backend IDs collide by prefix; one request has child tasks | Only the intended request and its owned children are cancelled |
| C03 | Cancel during preprocessing, queueing, and generation | Explicit supported behavior, cleanup, and observed completion; no socket-close shortcut |
| C04 | Repeat cancel; cancel unknown/completed request; race cancel against completion | Idempotent control behavior and one authoritative terminal outcome per attempt |
| C05 | Delta source and snapshot source produce equivalent content | Correct reconstruction without duplication, loss, or cross-output contamination |
| C06 | Multiple outputs finish differently or errors occur before/after first content | Per-output status retained and whole-request completion unambiguous |
| C07 | Consumer stalls or stops reading | Bounded memory and documented overload behavior; no silent semantic data loss |
| C08 | Disconnect immediately before terminal delivery or crash during a mutation | Unknown outcome remains explicit; no false success or unauthorized retry |
| C09 | Missing capability or unsupported combination of otherwise supported features | Explicit rejection rather than silent downgrade |
| C10 | Capability exists but local policy denies use; payload exceeds reassembled limit | Refusal before execution; LiNeP-SL does not bypass runtime governance |
| C11 | Metrics omitted, cumulative, multi-output, or from different hosts | Correct units/scope; no unknown-to-zero conversion or clock mixing |
| C12 | Existing Scheduler sends to the existing TCP Receiver | Exact task type/body and response extension/payload round trip |

Use contrasting implementations to test the abstraction: a task-queue engine,
an async scheduled engine, a library-style generator, and a policy-aware runtime.
This is a selection method, not a permanent four-product restriction.

Performance validation is separate: compare the same model, hardware, workload,
concurrency, output correctness, and enabled security properties. Measure first
token latency, throughput, CPU/copy overhead, tail latency under slow consumers,
and cancellation completion. For a library baseline, include direct in-process
execution; adding a transport may add overhead. Do not infer faster model compute
from reduced serialization work, or replace GPU collectives as part of this scope.

## 5. Decisions still open for issue #9

- Approve or revise the minimum contract and profile-specific guarantees.
- Define identity scopes, admission authority, and terminal/cancel race rules.
- Choose stream representations, bounded-buffer behavior, and compatibility rules.
- Specify capability negotiation and unsupported-feature behavior.
- Decide how to represent the contract using existing frames or explicit extensions,
  without retroactively changing the frozen V0.1 baseline.
- Separate implementation gap fixes from adapter work and the architecture decision.
- Prove mappings with the acceptance tests before calling an adapter conformant.

The evidence supports continued engine-neutral design work. It does not establish
that all runtimes are already interoperable, that every seam is stable, or that a
performance gain has been achieved.

## Source snapshots

GitHub source links are pinned to the revisions inspected during the review.
Vendor documentation links were consulted on 2026-08-28 and may change afterwards.

[ollama-interface]: https://github.com/ollama/ollama/blob/f96e7aa0513b9973a0ccc71be414c2ecb9d65b1a/llm/server.go
[ollama-routes]: https://github.com/ollama/ollama/blob/f96e7aa0513b9973a0ccc71be414c2ecb9d65b1a/server/routes.go
[llama-context]: https://github.com/ggml-org/llama.cpp/blob/50f068ffffc3e0e4c9c2e4139281c6075224f429/tools/server/server-context.h
[vllm-async]: https://github.com/vllm-project/vllm/blob/06cccf8730a199817be58e2de576918fe7a46e1e/vllm/v1/engine/async_llm.py
[vllm-output]: https://github.com/vllm-project/vllm/blob/06cccf8730a199817be58e2de576918fe7a46e1e/vllm/v1/engine/output_processor.py
[vllm-chat]: https://github.com/vllm-project/vllm/blob/06cccf8730a199817be58e2de576918fe7a46e1e/vllm/entrypoints/openai/chat_completion/serving.py
[trt-llm]: https://github.com/NVIDIA/TensorRT-LLM/blob/61083f4af353fc95d76b2fa1bf6d23b75d0e21d8/tensorrt_llm/llmapi/llm.py
[trt-result]: https://github.com/NVIDIA/TensorRT-LLM/blob/61083f4af353fc95d76b2fa1bf6d23b75d0e21d8/tensorrt_llm/executor/result.py
[trt-migration]: https://nvidia.github.io/TensorRT-LLM/legacy/tensorrt-backend-removal.html
[sglang-engine]: https://github.com/sgl-project/sglang/blob/70088aa5dbb77a7e70a16a4fb1a106fc7e8b2764/python/sglang/srt/entrypoints/engine.py
[sglang-tokenizer]: https://github.com/sgl-project/sglang/blob/70088aa5dbb77a7e70a16a4fb1a106fc7e8b2764/python/sglang/srt/managers/tokenizer_manager.py
[sglang-scheduler]: https://github.com/sgl-project/sglang/blob/70088aa5dbb77a7e70a16a4fb1a106fc7e8b2764/python/sglang/srt/managers/scheduler.py
[mlx-generate]: https://github.com/ml-explore/mlx-lm/blob/1f9883c91ab726c6a44fc0249adbfea283ca0b33/mlx_lm/generate.py
[mlx-server]: https://github.com/ml-explore/mlx-lm/blob/1f9883c91ab726c6a44fc0249adbfea283ca0b33/mlx_lm/server.py
[vinox-readiness]: https://github.com/Mentor82/VINOX/blob/0f89923b9fe7e2c065a8b50ac00a83ed70fb427e/docs/architecture/linep-readiness.md
[vinox-logging]: https://github.com/Mentor82/VINOX/blob/0f89923b9fe7e2c065a8b50ac00a83ed70fb427e/include/vinox/logging.h
[lmstudio-sdk]: https://lmstudio.ai/docs/typescript
[lmstudio-cancel]: https://lmstudio.ai/docs/typescript/llm-prediction/cancelling-predictions
[linep-tcp-api]: https://github.com/Mentor82/LiNeP/blob/fcb28c665278a9e9e83f45efd8dd9316a02736d6/LiNeP/include/linep/tcp.hpp
[linep-tcp]: https://github.com/Mentor82/LiNeP/blob/fcb28c665278a9e9e83f45efd8dd9316a02736d6/LiNeP/src/tcp/tcp.cpp
[linep-scheduler]: https://github.com/Mentor82/LiNeP/blob/fcb28c665278a9e9e83f45efd8dd9316a02736d6/LiNeP/src/scheduler/scheduler.cpp
