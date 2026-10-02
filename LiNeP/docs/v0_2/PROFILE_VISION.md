# LiNeP V0.2 Runtime Profile: PROFILE_VISION (Phase 1: Object Detection)

Status: **Phase 1 Specification Baseline** (Issue #32).  
Governing Standard: `equorus-value-v1`, LiNeP V0.2 Protocol Specifications.

---

## 1. Overview & Architectural Role

`PROFILE_VISION` standardizes computer vision inference on edge accelerators (such as Hailo-8L on Raspberry Pi 5, or other dedicated NPU/TPU edge runtimes) within the LiNeP V0.2 protocol family.

### Architectural Invariants:
1. **Hardware-Neutral Protocol:** The wire format is independent of specific accelerators, SDKs (e.g. HailoRT, OpenVINO, TensorRT), or sensor types.
2. **Clear Separation of Concerns:**
   - **Text & Embedding Runtimes (e.g. VINOX):** Serve `PROFILE_CHAT`, `PROFILE_GENERATE`, and `PROFILE_EMBED`.
   - **Dedicated Vision Accelerators:** Serve `PROFILE_VISION` (object detection, keypoints, segmentation).
   - **CLIP Image Encoders:** Multimodal image embeddings output vector representations, not detections. They belong strictly to `PROFILE_EMBED` under compatible vector space contracts and are explicitly out of scope for `PROFILE_VISION`.
3. **Phased Implementation:**
   - **Phase 1 (This Specification):** Establishes the common vision envelope framing, request options, and the fully specified `detect` task (bounding boxes, class IDs, confidence scores, versioned label sets).
   - **Subsequent Phases:** Will specify complex binary tasks (`segment`, `pose`, `ocr_detect`, `depth`) with dedicated artifact correlation IDs and stream chunking / flow control to prevent Head-of-Line (HoL) blocking.

---

## 2. Wire Allocation & Envelope Values

| Identifier | Type | Wire Value | Meaning |
| :--- | :--- | :--- | :--- |
| `runtime_profile::vision` | `uint8_t` | `4` | Profile identifier for computer vision runtimes |
| `runtime_event_type::vision_result` | `uint8_t` | `13` | Event containing structured vision results |
| `vision_task::unspecified` | `uint8_t` | `0` | Unspecified / invalid task |
| `vision_task::detect` | `uint8_t` | `1` | 2D Object detection (bounding boxes + scores + classes) |

---

## 3. Input Contract (REQUEST)

A client invokes a vision model using a standard `request_envelope`:
- `profile`: `runtime_profile::vision` (`4`)
- `model_id`: Identifier of the advertised vision model (e.g. `"yolov8n-detect"`, `"scrfd-2.5g"`)
- `payload`: Raw encoded image binary bytes (JPEG, PNG, WebP)
- `max_payload_bytes`: Upper limit defined by `LINEP_V02_MAX_VISION_IMAGE_BYTES` (16 MiB). Requests exceeding this limit are rejected fail-closed.
- `options` (`generation_options.extra_options` key-value pairs):
  - `"vision.task"`: Required task name, e.g. `"detect"`.
  - `"vision.confidence_threshold"`: Optional confidence threshold float string, e.g. `"0.25"` (must be in `[0.0, 1.0]`).
  - `"vision.max_detections"`: Optional maximum detections count uint32 string, e.g. `"100"` (bounded $\le 1000$).
  - `"vision.iou_threshold"`: Optional NMS IoU threshold float string, e.g. `"0.45"`.
  - `"vision.content_type"`: Optional MIME type (`"image/jpeg"`, `"image/png"`, `"image/webp"`).

### Correlation Semantics:
Each vision request is uniquely tracked via `stream_identity` (`request_id`, `execution_id`, `output_id`).
In single-image inference, `output_id = 0`.
In batched requests, `output_id` maps strictly to the zero-based image index in the batch.

---

## 4. Detection Result Schema (detect)

When `event_type == runtime_event_type::vision_result` and `task == vision_task::detect`:

### A. Coordinate Normalization & Box Invariants
1. **Reference Frame:** Coordinates relate strictly to the **original unpadded input image** dimensions ($W, H$), **prior** to any model-internal resizing, letterboxing, or aspect-ratio padding performed by the runtime.
2. **Coordinate Space:** Normalized unit space $[0.0, 1.0] \times [0.0, 1.0]$.
3. **Origin:** Top-left corner $(0.0, 0.0)$, bottom-right corner $(1.0, 1.0)$.
4. **Format:** `(x_min, y_min, x_max, y_max)` as `vision_box_2d`.
5. **Strict Validity Rules (Fail-Closed):**
   - No zero-area or collapsed boxes: $x_{\min} < x_{\max}$ and $y_{\min} < y_{\max}$.
   - Boundary adherence: $0.0 \le x_{\min} < x_{\max} \le 1.0$ and $0.0 \le y_{\min} < y_{\max} \le 1.0$.
   - Confidence score: $0.0 \le \text{score} \le 1.0$.
   - Rejection of `NaN` or `Infinity` for any coordinate or score.
   - Original dimensions: $W > 0$ and $H > 0$ (bounded $\le 65535$).

### B. Detection Structure
```cpp
struct vision_detection {
    std::uint32_t class_id{0};
    std::string label;       // Optional label string. If present, MUST match label_set_id.
    float score{0.0f};       // Confidence score in [0.0, 1.0]
    vision_box_2d box{};     // Normalized bounding box [0.0, 1.0]
};
```

### C. Empty Detections
An empty detection list (`detections.empty()`) is completely valid and signifies that no objects matching the confidence threshold were detected in the image.

---

## 5. Label Registries & Canonical Ordering

To prevent ambiguity and transmission overhead:
1. `class_id` is the primary, authoritative integer index within the versioned `label_set_id`.
2. The `label` string in each detection is optional. If present, it **must** match the canonical label at `class_id` in the specified registry.
3. Standard Registries:
   - **`"coco80:v1"`**: Standard 80 Microsoft COCO classes ($0 \dots 79$: 0=person, 1=bicycle, 2=car, ..., 79=toothbrush).
   - **`"widerface:v1"`**: 1 class (0=face).
   - **`"voc20:v1"`**: 20 Pascal VOC classes ($0 \dots 19$: 0=aeroplane, 1=bicycle, ..., 19=tvmonitor).
4. Custom Labelsets:
   - Format: `"custom:<id>"` or `"custom:<sha256>"`.
   - Runtimes advertising a custom label set declare the immutable list of class names in `vision_model_descriptor::custom_labels`.

---

## 6. Binary Wire Layout for `vision_result`

When serialized inside an `event_envelope`, the vision result payload is appended using little-endian canonical framing:

```
[task: uint8]                   = 1 (detect)
[model_id_len: uint16_le]       = length of model_id string
[model_id: bytes]               = UTF-8 string (<= 256 bytes)
[model_rev_len: uint16_le]      = length of model_revision string
[model_rev: bytes]              = UTF-8 string (<= 256 bytes)

--- detect task fields ---
[label_set_id_len: uint16_le]   = length of label_set_id string
[label_set_id: bytes]           = UTF-8 string (<= 256 bytes)
[original_width: uint32_le]     = Original image width in px (> 0, <= 65535)
[original_height: uint32_le]    = Original image height in px (> 0, <= 65535)
[detection_count: uint32_le]    = N (0 <= N <= 1000)

--- N repetitions of vision_detection ---
  [class_id: uint32_le]         = Class index in label set
  [score: float32_le]           = Confidence score (0.0 .. 1.0)
  [x_min: float32_le]           = Normalized x_min (0.0 <= x_min < x_max <= 1.0)
  [y_min: float32_le]           = Normalized y_min (0.0 <= y_min < y_max <= 1.0)
  [x_max: float32_le]           = Normalized x_max
  [y_max: float32_le]           = Normalized y_max
  [label_len: uint16_le]        = length of label string (0 if omitted)
  [label: bytes]                = UTF-8 string
```

---

## 7. Model Capabilities Declaration

In `capabilities_envelope`, a runtime announces support for vision models in `supported_vision_models`:
```cpp
struct vision_model_descriptor {
    std::string model_id;
    std::string model_revision;
    std::string label_set_id;
    vision_task task{vision_task::detect};
    std::uint32_t max_detections{100};
    std::vector<std::string> custom_labels;
};
```
Backward compatibility invariant: If `supported_vision_models` is empty, no extra bytes are encoded at the end of the capabilities payload, preserving full byte-for-byte compatibility with legacy V0.2 frames.

---

## 8. Error Codes & Failure Modes

| Error Category | Code / Reason | Condition |
| :--- | :--- | :--- |
| `error_category::unsupported` | `"VISION_UNSUPPORTED_TASK"` | Request asks for task other than `detect` or not advertised by model |
| `error_category::bad_request` | `"VISION_INVALID_PAYLOAD"` | Image bytes empty, corrupted, or exceeding 16 MiB |
| `error_category::bad_request` | `"VISION_INVALID_COORDINATES"` | Box coordinates with $x_{\min} \ge x_{\max}$, $y_{\min} \ge y_{\max}$, out-of-bounds, NaN/Inf |
| `error_category::bad_request` | `"VISION_LABEL_MISMATCH"` | Explicit `label` does not match the canonical class name in `label_set_id` |
| `error_category::bad_request` | `"VISION_UNKNOWN_LABEL_SET"` | Specified `label_set_id` is unknown and not defined |
| `error_category::resource_exhausted` | `"VISION_TOO_MANY_DETECTIONS"` | Detection count exceeds 1000 limit |
