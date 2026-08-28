# LiNeP V0.2.0 Rollout Roadmap & Checklist

Use this checklist to track Phase 1, Phase 2, and Phase 3 rollout end-to-end.

The checked implementation milestones below do not establish completion of the
engine-neutral architecture in [issue #9](https://github.com/Mentor82/LiNeP/issues/9).
See the [runtime interoperability review](RUNTIME_INTEROPERABILITY_REVIEW_V0_2.md)
for the source-based contract comparison, implementation gaps, and proposed
acceptance tests. That review is non-normative and does not change the V0.1 baseline.

## Phase 1: Streaming Transport Layer

- [x] Create git backup & tag `v0.1.0-baseline`
- [x] Define `MsgType::TASK_CANCEL` (`0x14`) and `FLAG_FRAGMENTED` / `FLAG_FINAL_FRAGMENT` in C++ & C-ABI
- [x] Implement C++ `send_task_stream()` with monotone `sequence` checks, duplicate rejection, and final fragment termination
- [x] Implement C++ `start_stream()` with `StreamWriterContext` and `is_cancelled` cancellation flag in `ITcpTaskReceiver`
- [x] Add C++ unit test `test_task_streaming.cpp` (26/26 C++ tests passed)
- [x] Expose `TASK_CANCEL` and stream flags in Python bindings (`linep.constants` & `linep.framing`)
- [x] Add Python streaming test `test_streaming.py` (13/13 Python tests passed)

## Phase 2: Enhanced Telemetry & Normalized Scoring

- [x] Add `vram_free_mb` and `prefix_affinity` / `kv_prefix_match_pct` metrics
- [x] Implement weighted normalized score formula $S_{\text{final}}$ in `src/scheduler/score_engine.cpp`
- [x] Add unit tests for normalized VRAM & KV-Cache affinity scoring (27/27 C++ tests passed)

## Phase 3: Consensus Engine

- [x] Implement Post-Completion Consensus evaluator for free-form responses
- [x] Implement Bounded Streaming Consensus at semantic checkpoints
- [x] Implement model-calibrated Cosine Similarity threshold evaluator (Vector-Space Contract #5)
- [x] Add unit tests for multi-worker Schwarm-Konsens voting (28/28 C++ tests passed)
