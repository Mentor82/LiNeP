"""LiNeP V0.2 PROFILE_VISION (Phase 1: Object Detection) Dataclasses and Validation."""

import math
from dataclasses import dataclass, field
from typing import List, Optional

from linep.v0_2.constants import (
    LINEP_V02_MAX_VISION_DETECTIONS,
    LINEP_V02_MAX_VISION_IMAGE_BYTES,
    VisionTask,
)

LABEL_SET_COCO80_V1: str = "coco80:v1"
LABEL_SET_WIDERFACE_V1: str = "widerface:v1"
LABEL_SET_VOC20_V1: str = "voc20:v1"

# Standard COCO-80 v1 classes (80 classes, indices 0..79)
COCO80_V1_LABELS: tuple[str, ...] = (
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat",
    "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat",
    "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack",
    "umbrella", "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball",
    "kite", "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket",
    "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
    "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake",
    "chair", "couch", "potted plant", "bed", "dining table", "toilet", "tv", "laptop",
    "mouse", "remote", "keyboard", "cell phone", "microwave", "oven", "toaster", "sink",
    "refrigerator", "book", "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush",
)

# Standard WIDER FACE v1 class (1 class, index 0)
WIDERFACE_V1_LABELS: tuple[str, ...] = (
    "face",
)

# Standard Pascal VOC 20 v1 classes (20 classes, indices 0..19)
VOC20_V1_LABELS: tuple[str, ...] = (
    "aeroplane", "bicycle", "bird", "boat", "bottle", "bus", "car", "cat", "chair", "cow",
    "diningtable", "dog", "horse", "motorbike", "person", "pottedplant", "sheep", "sofa",
    "train", "tvmonitor",
)


def resolve_standard_label(label_set_id: str, class_id: int) -> Optional[str]:
    """Look up canonical class label from standard versioned registries."""
    if label_set_id == LABEL_SET_COCO80_V1:
        if 0 <= class_id < len(COCO80_V1_LABELS):
            return COCO80_V1_LABELS[class_id]
    elif label_set_id == LABEL_SET_WIDERFACE_V1:
        if 0 <= class_id < len(WIDERFACE_V1_LABELS):
            return WIDERFACE_V1_LABELS[class_id]
    elif label_set_id == LABEL_SET_VOC20_V1:
        if 0 <= class_id < len(VOC20_V1_LABELS):
            return VOC20_V1_LABELS[class_id]
    return None


def is_valid_label_for_class(label_set_id: str, class_id: int, label: str) -> bool:
    """Verify that an explicit non-empty label matches the registry."""
    if not label:
        return True  # Omitted/empty label is valid
    canonical = resolve_standard_label(label_set_id, class_id)
    if canonical is not None:
        return label == canonical
    if label_set_id.startswith("custom:"):
        return len(label) <= 256
    return False


@dataclass(frozen=True)
class VisionBox2D:
    x_min: float = 0.0
    y_min: float = 0.0
    x_max: float = 0.0
    y_max: float = 0.0

    @property
    def width(self) -> float:
        return self.x_max - self.x_min

    @property
    def height(self) -> float:
        return self.y_max - self.y_min

    def is_valid(self) -> bool:
        if any(math.isnan(v) or math.isinf(v) for v in (self.x_min, self.y_min, self.x_max, self.y_max)):
            return False
        # Strict boundary and non-zero area: x_min < x_max and y_min < y_max
        return (
            0.0 <= self.x_min < self.x_max <= 1.0
            and 0.0 <= self.y_min < self.y_max <= 1.0
        )


@dataclass
class VisionDetection:
    class_id: int = 0
    label: str = ""
    score: float = 0.0
    box: VisionBox2D = field(default_factory=VisionBox2D)

    def is_valid(self) -> bool:
        if math.isnan(self.score) or math.isinf(self.score):
            return False
        if not (0.0 <= self.score <= 1.0):
            return False
        if len(self.label) > 256:
            return False
        return self.box.is_valid()


@dataclass
class VisionDetectResult:
    label_set_id: str = ""
    original_width: int = 0
    original_height: int = 0
    detections: List[VisionDetection] = field(default_factory=list)

    def is_valid(self) -> bool:
        if self.original_width <= 0 or self.original_width > 65535:
            return False
        if self.original_height <= 0 or self.original_height > 65535:
            return False
        if not self.label_set_id or len(self.label_set_id) > 256:
            return False
        if len(self.detections) > LINEP_V02_MAX_VISION_DETECTIONS:
            return False
        for d in self.detections:
            if not d.is_valid():
                return False
            if d.label and not is_valid_label_for_class(self.label_set_id, d.class_id, d.label):
                return False
        return True


@dataclass
class VisionResultPayload:
    task: VisionTask = VisionTask.UNSPECIFIED
    model_id: str = ""
    model_revision: str = ""
    detect: VisionDetectResult = field(default_factory=VisionDetectResult)

    def is_valid(self) -> bool:
        if self.task != VisionTask.DETECT:
            return False
        if not self.model_id or len(self.model_id) > 256 or len(self.model_revision) > 256:
            return False
        return self.detect.is_valid()


@dataclass
class VisionModelDescriptor:
    model_id: str = ""
    model_revision: str = ""
    label_set_id: str = ""
    task: VisionTask = VisionTask.DETECT
    max_detections: int = 100
    custom_labels: List[str] = field(default_factory=list)
