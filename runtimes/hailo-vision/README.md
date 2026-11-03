# Hailo vision runtime (point 4)

Independent Python adapter project using the LiNeP SDK codecs. It executes real
HailoRT inference; it does not inherit from `LiNePMockServer` and has no synthetic
fallback. The common wire protocol remains hardware-neutral.

## Contract and execution

- Private TCP runtime endpoint on **127.0.0.1:11436**, V0.2, VISION only.
- Explicit model allowlist via repeatable `--model ID=/path/to/model.hef`.
  Capabilities advertise a `VisionModelDescriptor` per initialized model, task
  `detect`, label set `coco80:v1`, max 1000 detections. Model revision is the HEF's
  SHA-256. Startup fails if a model cannot initialize.
- Supported HEFs: one RGB NHWC input, one COCO80 Hailo NMS-by-class output, e.g.
  the Pi's `yolov8s.hef` and `yolov11n.hef`. Other layouts are rejected.
- Raw JPEG, PNG or WebP bytes; `vision.task=detect` is required. Confidence and
  IoU defaults are 0.25 and 0.45, explicitly set in HailoRT for each request.
  `vision.max_detections` defaults to 100 (1..1000), sorted by descending score.
  Unknown options and tasks fail rather than being silently ignored.
- Decode to RGB, centered letterbox with padding 114, hardware NMS, then inverse
  geometry using actual rounded resize dimensions. Boxes refer to the original
  unpadded image. Padding-only boxes are discarded; malformed outputs fail.
- One device-wide inference at a time, **no waiting queue**. Contending requests
  receive `FAILED / RESOURCE_EXHAUSTED / 429 / VISION_BUSY`. Maximum eight TCP
  connections; excess connections are closed. The slot remains occupied until
  the hardware call returns even if its client disconnects.
- Success: `ACCEPTED -> VISION_RESULT -> COMPLETED`, monotonically numbered events
  with the original stream identity. Invalid requests fail before acceptance.
  Backend errors after acceptance emit `FAILED`, never an empty detection result.
  A legitimate zero-detection image is a successful empty result.
- Cancellation is cooperative: Hailo inference itself is not interrupted. A
  matching CANCEL received before result delivery suppresses the result and
  emits one CANCELLED after the bounded hardware call returns. Once terminal
  delivery starts, cancellation is too late. Disconnects suppress further output.
- Backend/model-output faults latch the Hailo backend unavailable until process
  restart. Bad client images do not poison the device. VStream timeout is 5 s.
- Unsigned frames only on this private runtime leg. No UDP lease authority or
  SL1 key provisioning here: linepd enforces client lease/auth/policy, and the
  separately configured SSH tunnel protects the worker leg. SESSION_BIND is
  accepted syntactically for runtime interoperability, not treated as proof of
  authorization. This endpoint must remain loopback-only.

Input is limited by the SDK's 16 MiB envelope limit and image cap. Consequently
the maximum image is slightly smaller than 16 MiB because the envelope also
contains metadata. Decompressed images are bounded to 16 million pixels and
dimensions 1..65535. EXIF orientation is ignored, so coordinates reference the
encoded image dimensions. Animated images and image batches are not supported.

## Development and startup

Use the SDK from LiNeP main **10a4854 or later** (requires the binary payload fix).
The generic `linep==0.2.0` version alone does not establish that source revision.
HailoRT, its driver, HEFs, NumPy and OpenCV must be supplied by the host; this
project does not vendor or install them. Verified host API target: HailoRT 4.23.

From the repository root, without installing packages (Linux):

```sh
export PYTHONPATH="$PWD/LiNeP/python:$PWD/runtimes/hailo-vision/src"
python3 -m linep_vision --model yolov8s-detect=/usr/local/hailo/resources/models/hailo8l/yolov8s.hef
```

Optional second model: append
`--model yolov11n-detect=/usr/local/hailo/resources/models/hailo8l/yolov11n.hef`.
The device scheduler uses `hailort.service` with multi-process support, so another
Hailo client may share the hardware. The one-slot limit is local to this process;
other processes can affect latency.

`deploy/linep-vision.service` is a **template**, not an installed service. Its
`/opt/linep/linep-vision` directory must contain importable `linep_vision` and
`linep` packages. The example uses the Pi's existing `mirko` account and model
path; review the service user and package layout for each target host. A writable
`StateDirectory` holds HailoRT logs while application code remains read-only.
`HOME` also points there because HailoRT writes `.hailo` state and the user's
actual home is hidden by `ProtectHome=true`.
The service must share the host's `/tmp`: HailoRT's multiprocess socket is
`/tmp/hailort_uds.sock`, so `PrivateTmp=true` would prevent device access.

## Validation

```sh
python3 -m pytest runtimes/hailo-vision/tests
python3 runtimes/hailo-vision/tools/smoke_hailo.py \
  --hef /usr/local/hailo/resources/models/hailo8l/yolov8s.hef
```

The unit/socket suite uses an explicitly injected **test-only** backend; production
CLI always constructs `HailoBackend`. The smoke test uses the real Hailo device,
a temporary loopback listener and local bus/dog/bicycle/person images, plus a
corrupt JPEG. It does not install anything or contact linepd.

Point 5 deployment artifacts and the controlled procedure are documented in
[`deploy/README.md`](deploy/README.md); the first rollout is recorded in
[`deploy/ROLLOUT_2026-11-03.md`](deploy/ROLLOUT_2026-11-03.md).
Point 6 still needs full linepd conformance/E2E and the wider failure matrix.
Distribution remains one source tree with an arm64 bundle + SHA256SUMS and a
signed lpkg recipe; packaging and deployment are not performed by this change.
