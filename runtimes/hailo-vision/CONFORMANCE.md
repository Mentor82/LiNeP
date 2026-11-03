# Vision conformance and failure matrix (planner point 6)

The generic SDK conformance runner requests CHAT/EMBED and is not a detector
acceptance test. `linep_vision.conformance.VisionConformance` tests the VISION
contract, independently of how the worker implements inference.

## Evidence levels

| Layer | What a pass establishes |
| --- | --- |
| SDK/unit | Codecs, request validation, label/box geometry, framing bounds |
| Isolated runtime sockets | Busy, correct/wrong-stream Cancel, disconnect slot retention, incomplete-frame timeouts, connection cap, invalid outputs, single terminal and contiguous sequencing |
| Backend boundary | Real OpenCV decode/preprocess with injected inference errors/timeouts; failure latch and no automatic retry; invalid client images do not poison backend |
| Real worker | Real JPEG detection, original dimensions/COCO labels, HEF revision, empty detections, max_detections, bad inputs/options and subsequent healthy requests |
| Codec interop | Exact request image bytes and canonical capability/result/terminal frames across pinned C++/Go/Rust/Python codecs; semantic negative vectors rejected in all four |
| Trunk E2E | Actual UDP lease, signed SESSION_BIND, per-frame SL1 verification and successful routing through Rust linepd to the real Python/Hailo worker |

The levels are reported separately. A direct/tunnel worker test is not a signed
trunk test. A substituted SDK inference function is not a physical unplug test.
The shared `hailort.service` must never be stopped by the suite.

## Python acceptance suite

Use the current SDK and adapter on PYTHONPATH, then:

```sh
python3 runtimes/hailo-vision/tools/conformance.py \
  --image /path/to/bus.jpg --host 127.0.0.1 --port 11436 --output direct.json

# For an explicitly provisioned, model-scoped client key, read in place:
python3 runtimes/hailo-vision/tools/conformance.py \
  --image /path/to/bus.jpg --host 192.168.178.161 --port 9000 \
  --control-port 9001 --key-file /path/to/vision-test-client.key \
  --model task:vision --output trunk.json
```

The fixture is the existing bus.jpg (810x1080) with bus/person objects. The suite
checks actual inference, never exact scores or timing. It checks the next
capability reply after a terminal too, so SDK iteration cannot conceal a queued
duplicate terminal. No request is automatically retried on uncertain delivery.

`--oversized-decoded-image /path/to/over-budget.png` adds a valid PNG image whose
IHDR dimensions exceed 16 million pixels (e.g. 4100x4100). It must yield FAILED
without VISION_RESULT, and the next normal image must work. Envelope claims over
16 MiB are tested separately: close before reading/allocating the body, rather
than promising a structured error for a frame that violates framing limits.

The helper `tools/negative_auth.py` submits unsigned inference and a bind using
an unregistered **synthetic** key ID 65000. Both must be denied. It reads no real
cluster key and does not enroll a key or edit policy.
With `--key-file` it additionally verifies a `task:vision`-only client's scope:
`task:fast` and the direct model name must receive 403, followed by healthy
`task:vision` detection on the same signed session. This optional check needs
the adapter source on PYTHONPATH as well as the SDK.

## Native clients and pinned codec snapshots

Build `linep-v02-vision-check` through the normal `LINEP_BUILD_V02=ON` CMake build.
The native C++ client uses reference transport/codec/UDP/SL1 functions. It verifies
the server's MAC, key identity and increasing auth_seq, checks the binding and
the VISION lifecycle, and captures only canonical unsigned data frames:

```sh
linep-v02-vision-check --host 127.0.0.1 --port 19653 \
  --image bus.jpg --out-dir captures/cpp-direct
# Add --key-file ... --control-port ... for a leased SL1 trunk.
```

`tools/interop/prepare_codecs.py --go-repo ... --rust-repo ... --output ...` copies
only **committed** codec files into an isolated build directory, with source
commits and per-file SHA-256 in CODEC_SOURCES.json. It does not edit those projects
or vendor them into this repository. Use the OS owner's agreed snapshots; record
their identities separately from the identity of the running daemon binary.
Use `--go-ref <commit>` and `--rust-ref <commit>` to export an explicit committed
revision without checking it out or disturbing another owner's worktree.

The Go client imports the real LiNeP-Ollama codec (including opaque binary strings)
and uses standard-library networking. In the generated module:

```sh
GOWORK=off GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 go build -o vision-go .
./vision-go --host 127.0.0.1 --port 19653 --image bus.jpg --out-dir captures/go
```

Compile the Rust inspector next to the copied LIARA OS modules with
`rustc --edition=2021 -Awarnings main.rs -o vision-rust`. It uses the actual Rust
codec; it is not a new hand-written interpretation of the frame format.

For a capture directory from either native client:

```sh
python3 tools/interop/make_negative_frames.py captures/cpp-direct
linep-v02-vision-check --verify-dir captures/cpp-direct
vision-go --verify-dir captures/cpp-direct
vision-rust captures/cpp-direct
python3 tools/interop/verify_capture.py captures/cpp-direct --image bus.jpg
```

Run Python helper paths relative to `runtimes/hailo-vision`. All four check exact
positive roundtrips. Negative vectors mutate a real result while preserving valid
outer framing: NaN/Inf/out-of-range confidence, out-of-bounds or zero-area boxes,
zero/oversized dimensions, excessive detection count, unsupported task, mismatched
label/registry and truncated inner payload. No image bytes or keys belong in the
published report; retain captures in the operator's test directory and publish
only identities, counts and outcomes.

## Test isolation

VM108 tests run under the `codex` account. Root/HA/registry changes or temporary
client enrollment are coordinated with the L.I.A.R.A. OS owner. No fallback to a
root SSH account or cluster-key copy is part of these commands. Fault injection
is restricted to isolated test instances and the injected backend boundary.

Run `pytest runtimes/hailo-vision/tests` on the Pi for the host OpenCV cases; CI
installs NumPy/OpenCV only in its disposable test runner. For SDK golden tests in
isolated worktrees, set `LINEP_CPP_GOLDEN_TOOL` to the freshly built reference
generator. An explicitly configured but missing generator fails instead of
silently skipping.
