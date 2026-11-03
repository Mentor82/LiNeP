# Point 4 validation — 2026-11-03

Scope: standalone real Hailo runtime and service template. No systemd service
installed, no packages installed on the Pi, no linepd or tunnel configuration
changed, no existing service restarted. Test source was copied to a fresh
`/tmp/linep-vision-review-*` directory on the explicitly selected rpi5 (.15).
The temporary process bound an ephemeral IPv4 loopback port and exited after each
test. Existing hailort, linep-ollama and linep-tunnel services remained active.

## Automated checks

- Windows Python 3.12: 39 adapter unit/socket tests pass. Cases include canonical
  capabilities, repeated requests, original stream IDs, exactly one terminal,
  hardware exception -> FAILED, global busy rejection, correct/wrong-stream
  cancellation, disconnect slot retention, bad images/options, frame-size bounds,
  COCO labels and inverse letterbox geometry.
- Combined adapter + SDK V0.2 run: 106 passed, 2 skipped. The two skips require a
  C++ golden-frame tool that is not built in the isolated worktree.
- rpi5 Python 3.13.5: the same 39 adapter tests pass.
- Adapter wheel builds offline (`pip wheel --no-deps --no-build-isolation`);
  LICENSE and NOTICE are present in the wheel. This is a Python packaging check,
  not an arm64 release bundle or signed lpkg release.
- `systemd-analyze verify --man=no deploy/linep-vision.service` succeeds on the Pi.
  The template has not been installed or started as a systemd service.
- Follow-up review: transient systemd socket-visibility checks reproduce that
  `PrivateTmp=yes` hides `/tmp/hailort_uds.sock` while `PrivateTmp=no` exposes it.
  The service template now explicitly shares the host tmp namespace.
  `HOME` points to the writable StateDirectory for HailoRT's `.hailo` state,
  preserving `ProtectHome=true`. The hardware smoke also passes under a transient
  systemd unit with the template's hardening and state-directory settings.

## Real Hailo inference over the runtime socket

Device: Hailo-8L, HailoRT/firmware 4.23.0; Python 3.13.5, OpenCV 4.10.
HEF: `/usr/local/hailo/resources/models/hailo8l/yolov8s.hef`.
Model revision (SHA-256):
`597d4492bd7ed7d922595f8b445887773666639fc9940f23b24ea42390dfb00d`.

Command (from the temporary source root with SDK/adapter on PYTHONPATH):

```sh
python3 runtimes/hailo-vision/tools/smoke_hailo.py \
  --hef /usr/local/hailo/resources/models/hailo8l/yolov8s.hef
```

The tool checks advertised capabilities, image payload bytes, result validity,
event order/sequence/identity, and expected labels. One measured run:

| Image | Dimensions | Recognized labels | Socket request to terminal |
| --- | --- | --- | --- |
| bus.jpg | 810 x 1080 | bus, person | 66.69 ms |
| dog_bicycle.jpg | 640 x 640 | dog, bicycle, truck | 50.23 ms |
| zidane.jpg | 1280 x 720 | person, tie | 44.33 ms |

These are three single measurements, not a throughput or tail-latency benchmark;
they include local decode, preprocessing, inference, postprocessing and TCP
events, but exclude network/tunnel/linepd and model startup. The installed
`dog_bicycle.jpg` is actually BMP data; it is converted to PNG **in memory** by
the test tool. Production accepts JPEG/PNG/WebP only and correctly rejects BMP.

Corrupt JPEG: FAILED with `VISION_INVALID_PAYLOAD`, no VISION_RESULT. The next
request on the same runtime succeeds. Confidence 1.0 yields a valid empty result,
distinguishing zero detections from a hardware failure.

Separate real-backend check: initialized yolov8s and yolov11n in one Hailo
VDevice, ran bus.jpg through both, obtained valid bus/person detections for each.
No test physically unplugged the Hailo or stopped the shared HailoRT service;
backend exceptions are injected only in the unit/socket suite.

## Remaining gates

Point 5: reverse tunnel, SSH permitlisten, runtime registration/configuration,
HA rollout and actual installed-service health. Point 6: full linepd conformance,
cross-language E2E and wider hardware failure/overload matrix. Distribution:
arm64 bundle + SHA256SUMS and signed lpkg recipe. Personal integration remains
point 7. Nothing here establishes these later gates as passed.
