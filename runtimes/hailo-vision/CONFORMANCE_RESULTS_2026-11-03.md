# VISION point 6 — verification on 2026-11-03

Status: partial; signed client-to-Rust-trunk E2E is still pending. This report
does not close planner point 6 or authorize client deployment (point 7).

Tests use LiNeP main `27fd5e0a822baa35808b88cbb99a8c92d7c3e432` plus the
`codex/vision-conformance` changes. VM108 commands ran exclusively as `codex`
through `vm108-codex`. Production services, registry, keys and HA were unchanged.

| Layer | Result | Scope |
| --- | --- | --- |
| Windows native CTest | 42/42 passed | MinGW 13.2, V0.2 enabled |
| VM108 native CTest | 42/42 passed | GCC 16.2, codex-owned build |
| Windows Python SDK + adapter | 138 passed, 1 skipped | Native golden generator enabled; OpenCV module skipped locally |
| Pi adapter tests | 60/60 passed | Includes real OpenCV and injected SDK-boundary failures |
| Pi direct real worker | 14/14 passed | Python conformance, real YOLOv8s/Hailo-8L |
| VM108 reverse-tunnel real worker | 15/15 passed | Includes valid 4100x4100 PNG rejected by decoded pixel budget |
| Native C++ and Go clients | Both passed | VM108 loopback tunnel to real worker; bus/person, original dimensions, model revision, lifecycle |
| C++, Go, Rust, Python codecs | All passed | Four captured frames roundtrip byte-identically; each rejects all 12 negative vectors |
| Production trunk auth negatives | Both passed | Unsigned inference and unregistered synthetic key rejected with 401 |
| Signed positive trunk E2E | **Pending** | Needs coordinated client credentials accessible to codex or an agreed isolated trunk |

Counts overlap and must not be added into a single independent-test total.
The final startup-device test was added after the Windows run; its module is
skipped there, and all six OpenCV/backend cases passed on the Pi.

## Real hardware identity

- Worker: Pi `192.168.178.15`, Hailo-8L, HailoRT 4.23.0, `yolov8s-detect`.
- HEF SHA-256: `597d4492bd7ed7d922595f8b445887773666639fc9940f23b24ea42390dfb00d`.
- Original fixture: host-provided `bus.jpg`, 810x1080;
  SHA-256 `33b198a1d2839bb9ac4c65d61f9e852196793cae9a0781360859425f6022b69c`.
- VM108 endpoint `127.0.0.1:19653` forwards to the worker. These positive tests
  bypass the Rust trunk; Rust codec roundtrips are a separate verification layer.

## Error coverage

Live checks cover empty/corrupt/unsupported images, absent or unsupported task,
unknown option, NaN confidence, invalid IoU/detection limit, content-type mismatch,
and decoded pixel budget. Each invalid input is followed by healthy inference
on the same session. Success also checks zero detections, a detection limit,
session reuse, contiguous sequence, exactly one terminal and advertised HEF revision.

Isolated socket tests cover malformed headers, partial-frame timeout, connection
limit, duplicate active identity, malformed backend results, sequence gaps and
cross-stream/duplicate-terminal rejection. Existing adapter tests cover BUSY,
cancellation and disconnect cleanup. Hailo startup absence, infer exception,
timeout and invalid output are injected at the SDK boundary, with real image
decode/preprocessing. No physical device removal, shared service stop or driver
reset was performed. The backend must latch unavailable without retry after
an inference fault; bad client images must not poison it.

The 12 negative wire vectors preserve outer framing and test confidence,
coordinates, dimensions, detection count, task, label registry and truncated
inner payload. They are generated from a real captured result.

## Cross-repository provenance and remaining work

Reference snapshots were exported from committed files without changing either
source repository:

- Go LiNeP-Ollama candidate commit `9e8ecbb8658f523ea29b0505193fd0805780481e`.
- Rust L.I.A.R.A. OS candidate commit `3d635a03519b9b60ca07c1e700346742f97b2cb4`.
- `prepare_codecs.py` records every source file SHA-256 in `CODEC_SOURCES.json`.

These candidate snapshots have not yet been confirmed by Claude as the intended
deployed source revisions. Coordination requests were sent through Whisper;
no new reply was present at the verification cutoff. The codex account cannot
read the production cluster key; no privileged fallback or key copy was attempted.

Before closing point 6: confirm codec revisions with Claude, run C++/Go/Python
through lease + SL1 + the Rust trunk to the real worker (including task:vision),
and execute the conformance suite through that path. Any routing-layer failure
matrix must use an agreed isolated instance, not production outage injection.

Operator artifacts remain under `/srv/dev/codex/vision-point6-FNAgdaAx` on VM108
and `/tmp/vision-point6-4mKdDayW` on the Pi. Captures contain canonical unsigned
application frames, not authentication envelopes. Images and keys are not
included in this repository. Reproduction commands are in `CONFORMANCE.md`.
