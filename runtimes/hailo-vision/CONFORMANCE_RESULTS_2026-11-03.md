# VISION point 6 — verification on 2026-11-03

Status: point-6 verification complete, including signed client-to-Rust-trunk E2E.
The changes remain subject to PR review; client deployment (point 7) is separate.

Tests use LiNeP main `27fd5e0a822baa35808b88cbb99a8c92d7c3e432` plus the
`codex/vision-conformance` changes. VM108 commands ran exclusively as `codex`
through `vm108-codex`. Production services, registry and HA were unchanged.
Claude provisioned a temporary Vision-only client key with Mirko's approval;
the test clients read it in place and did not copy or print it.

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
| Signed positive trunk E2E | All passed | C++/Go/Python lease + SL1 through production Rust trunk, task:vision to real Hailo |
| Signed Python conformance | 15/15 passed | All cases through production Rust trunk, including decoded pixel budget and session recovery |
| Signed capture interop | All passed | Both native captures: four frames byte-identical and 12 negative vectors rejected by each of four codecs |
| Vision-only client allowlist | Passed | task:fast and direct yolov8s-detect denied with 403; subsequent task:vision detection works on the same session |
| GitHub CI (initial commit) | All required jobs passed | Run 41622118777: Python 98 passed, adapter 60 passed; no skips in either job |

Counts overlap and must not be added into a single independent-test total.
The final startup-device test was added after the Windows run; its module is
skipped there, and all six OpenCV/backend cases passed on the Pi.

## Real hardware identity

- Worker: Pi `192.168.178.15`, Hailo-8L, HailoRT 4.23.0, `yolov8s-detect`.
- HEF SHA-256: `597d4492bd7ed7d922595f8b445887773666639fc9940f23b24ea42390dfb00d`.
- Original fixture: host-provided `bus.jpg`, 810x1080;
  SHA-256 `33b198a1d2839bb9ac4c65d61f9e852196793cae9a0781360859425f6022b69c`.
- VM108 endpoint `127.0.0.1:19653` forwards to the worker. Direct tunnel tests
  bypass the Rust trunk; the additional SL1 runs use `192.168.178.161:9000`
  with leases from UDP `:9001`, routing `task:vision` through Rust to the worker.
- Installed `/usr/bin/linepd` SHA-256 remained
  `e44313342e8574961fdad5ab91e0f96ce5ed94cbb761d4f387baa0ce6338f66b`.

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

## Cross-repository provenance and coordination

Reference snapshots were exported from committed files without changing either
source repository:

- Go LiNeP-Ollama test-client commit `9e8ecbb8658f523ea29b0505193fd0805780481e`.
  Claude confirmed the source branch identity; this is not a claim about the
  deployed Ollama adapter revision, which this VISION path does not use.
- Rust L.I.A.R.A. OS commit `6ab7e9b9eb9a9f2e55c9d2cc441b6bedbc58057e`,
  confirmed by Claude as the source of VM108 linepd 1.18.0. The earlier base
  `3d635a0` was replaced for the final checks. Rust codec SHA-256:
  `fc7fb85a805e137d0ae82c1bddd63339135aa00d61de3c0dcdeec6bd45f479e2`.
- `prepare_codecs.py` records every source file SHA-256 in `CODEC_SOURCES.json`.

Claude's Whisper messages `whisp-cc890986` and `whisp-4290afd7` supplied the
source correction and approved key 2004 (`codex-vision`, allowlist `task:vision`,
codex-owned mode 0600). C++ and Go verify the responder MAC, key identity and
increasing auth sequence; Python uses TrunkSession's verification. Their
successful outputs explicitly report SL1 enabled. The key authorizes the task,
not the direct model name; both denied-request checks return exactly one FAILED
and permit a healthy task request afterwards on the same signed connection.

Completion and the agreed revoke request were sent to Claude in
`whisp-745e5732`; revocation confirmation is pending at this report's cutoff.
No cluster key was read, no privileged fallback was used, and the client key
was not transferred. Production failure injection was not performed.

Operator artifacts remain under `/srv/dev/codex/vision-point6-FNAgdaAx` on VM108
and `/tmp/vision-point6-4mKdDayW` on the Pi. Captures contain canonical unsigned
application frames, not authentication envelopes. Images and keys are not
included in this repository. Reproduction commands are in `CONFORMANCE.md`.
Signed reports/captures are `trunk-conformance.json`, `captures/cpp-sl1`,
`captures/go-sl1`; the corrected Rust snapshot and file hashes are under
`interop-sl1` and `interop-sl1/CODEC_SOURCES.json`.
