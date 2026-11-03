"""Request validation and letterbox geometry, independent of HailoRT."""

import math
from dataclasses import dataclass

from linep.v0_2.constants import ErrorCategory, RuntimeProfile, LINEP_V02_MAX_VISION_IMAGE_BYTES
from linep.v0_2.vision import (
    COCO80_V1_LABELS, LABEL_SET_COCO80_V1, VisionBox2D, VisionDetectResult, VisionDetection,
)


class VisionError(Exception):
    def __init__(self, reason, category=ErrorCategory.BAD_REQUEST, code=400):
        super().__init__(reason)
        self.category = category
        self.code = code


@dataclass(frozen=True)
class DetectOptions:
    confidence: float = 0.25
    iou: float = 0.45
    max_detections: int = 100


def validate_request(req, models):
    if req.profile != RuntimeProfile.VISION:
        raise VisionError("VISION_UNSUPPORTED_PROFILE", ErrorCategory.UNSUPPORTED, 501)
    if req.model_id not in models:
        raise VisionError("VISION_UNKNOWN_MODEL", ErrorCategory.UNSUPPORTED, 404)
    if req.stream.output_id != 0:
        raise VisionError("VISION_SINGLE_IMAGE_ONLY", ErrorCategory.UNSUPPORTED, 501)
    if not isinstance(req.payload, bytes) or not 0 < len(req.payload) <= LINEP_V02_MAX_VISION_IMAGE_BYTES:
        raise VisionError("VISION_INVALID_PAYLOAD")
    extras = dict(req.options.extra_options) if req.has_options else {}
    if extras.get("vision.task") != "detect":
        raise VisionError("VISION_UNSUPPORTED_TASK", ErrorCategory.UNSUPPORTED, 501)
    allowed = {"vision.task", "vision.confidence_threshold", "vision.iou_threshold",
               "vision.max_detections", "vision.content_type"}
    if any(k not in allowed for k in extras):
        raise VisionError("VISION_UNSUPPORTED_OPTION", ErrorCategory.UNSUPPORTED, 501)
    raw = req.payload
    if raw.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif raw.startswith(b"RIFF") and raw[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        raise VisionError("VISION_INVALID_PAYLOAD")
    if extras.get("vision.content_type", mime) != mime:
        raise VisionError("VISION_INVALID_CONTENT_TYPE")
    try:
        confidence = float(extras.get("vision.confidence_threshold", "0.25"))
        iou = float(extras.get("vision.iou_threshold", "0.45"))
        limit_text = extras.get("vision.max_detections", "100")
        if not limit_text.isascii() or not limit_text.isdecimal():
            raise ValueError()
        limit = int(limit_text)
        if not all(math.isfinite(v) and 0 <= v <= 1 for v in (confidence, iou)) or not 1 <= limit <= 1000:
            raise ValueError()
    except (ValueError, OverflowError):
        raise VisionError("VISION_INVALID_OPTIONS") from None
    return DetectOptions(confidence, iou, limit)


@dataclass(frozen=True)
class Letterbox:
    width: int
    height: int
    target_width: int
    target_height: int
    resized_width: int
    resized_height: int
    left: int
    top: int

    @classmethod
    def create(cls, width, height, target_width, target_height):
        if min(width, height, target_width, target_height) <= 0:
            raise VisionError("VISION_INVALID_PAYLOAD")
        scale = min(target_width / width, target_height / height)
        rw = max(1, min(target_width, round(width * scale)))
        rh = max(1, min(target_height, round(height * scale)))
        return cls(width, height, target_width, target_height, rw, rh,
                   (target_width - rw) // 2, (target_height - rh) // 2)

    def box(self, ymin, xmin, ymax, xmax):
        # Hailo NMS coordinates are normalized to the padded network input.
        # Divide by the actual rounded resize dimensions, not an ideal scale.
        x1 = (xmin * self.target_width - self.left) / self.resized_width
        x2 = (xmax * self.target_width - self.left) / self.resized_width
        y1 = (ymin * self.target_height - self.top) / self.resized_height
        y2 = (ymax * self.target_height - self.top) / self.resized_height
        box = VisionBox2D(*(max(0.0, min(1.0, v)) for v in (x1, y1, x2, y2)))
        return box if box.is_valid() else None  # padding-only boxes have no original-image area


def decode_detections(classes, geometry, options):
    if len(classes) != 80:
        raise VisionError("VISION_INVALID_MODEL_OUTPUT", ErrorCategory.MODEL_ERROR, 502)
    detections = []
    for class_id, rows in enumerate(classes):
        for row in rows:
            if len(row) != 5:
                raise VisionError("VISION_INVALID_MODEL_OUTPUT", ErrorCategory.MODEL_ERROR, 502)
            ymin, xmin, ymax, xmax, score = (float(v) for v in row)
            if not all(math.isfinite(v) and 0 <= v <= 1 for v in (ymin, xmin, ymax, xmax, score)):
                raise VisionError("VISION_INVALID_COORDINATES", ErrorCategory.MODEL_ERROR, 502)
            if ymin >= ymax or xmin >= xmax:
                raise VisionError("VISION_INVALID_COORDINATES", ErrorCategory.MODEL_ERROR, 502)
            if score < options.confidence:
                continue
            box = geometry.box(ymin, xmin, ymax, xmax)
            if box is not None:
                detections.append(VisionDetection(class_id, COCO80_V1_LABELS[class_id], score, box))
    detections.sort(key=lambda d: (-d.score, d.class_id, d.box.x_min, d.box.y_min))
    result = VisionDetectResult(LABEL_SET_COCO80_V1, geometry.width, geometry.height,
                                detections[:options.max_detections])
    if not result.is_valid():
        raise VisionError("VISION_INVALID_MODEL_OUTPUT", ErrorCategory.MODEL_ERROR, 502)
    return result
