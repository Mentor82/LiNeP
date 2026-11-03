"""HailoRT 4.23 VStreams backend for COCO80 HEFs with on-device NMS."""

import hashlib
import os
from contextlib import ExitStack
from pathlib import Path

from linep.v0_2.constants import ErrorCategory, VisionTask
from linep.v0_2.vision import LABEL_SET_COCO80_V1, VisionModelDescriptor
from .detection import Letterbox, VisionError, decode_detections


class HailoBackend:
    """Owned by one runtime; callers serialize all detect/close operations."""

    def __init__(self, models, timeout_ms=5000, max_pixels=16_000_000):
        # Set before importing OpenCV to bound decompression before allocation.
        os.environ["OPENCV_IO_MAX_IMAGE_PIXELS"] = str(max_pixels)
        import cv2
        import numpy as np
        import hailo_platform as h
        self.cv2, self.np = cv2, np
        self.max_pixels = max_pixels
        self._stack = ExitStack()
        self._models = {}
        self._faulted = False
        self.descriptors = []
        try:
            params = h.VDevice.create_params()
            params.multi_process_service = True
            params.scheduling_algorithm = h.HailoSchedulingAlgorithm.ROUND_ROBIN
            device = self._stack.enter_context(h.VDevice(params))
            for model_id, path in models.items():
                path = Path(path).resolve(strict=True)
                revision = hashlib.sha256(path.read_bytes()).hexdigest()
                hef = h.HEF(str(path))
                inputs, outputs = hef.get_input_vstream_infos(), hef.get_output_vstream_infos()
                if (len(inputs) != 1 or len(outputs) != 1 or len(inputs[0].shape) != 3
                        or inputs[0].shape[2] != 3
                        or outputs[0].format.order != h.FormatOrder.HAILO_NMS_BY_CLASS
                        or outputs[0].nms_shape.number_of_classes != 80):
                    raise ValueError("only single-input RGB COCO80 NMS-by-class HEFs are supported")
                group, = device.configure(hef, h.ConfigureParams.create_from_hef(hef, h.HailoStreamInterface.PCIe))
                inp = h.InputVStreamParams.make_from_network_group(
                    group, quantized=True, format_type=h.FormatType.UINT8, timeout_ms=timeout_ms)
                out = h.OutputVStreamParams.make_from_network_group(
                    group, quantized=False, format_type=h.FormatType.FLOAT32, timeout_ms=timeout_ms)
                pipeline = self._stack.enter_context(h.InferVStreams(group, inp, out))
                self._models[model_id] = (inputs[0], outputs[0], pipeline)
                self.descriptors.append(VisionModelDescriptor(
                    model_id=model_id, model_revision=revision, label_set_id=LABEL_SET_COCO80_V1,
                    task=VisionTask.DETECT, max_detections=1000))
        except BaseException:
            self._stack.close()
            raise

    def detect(self, model_id, payload, options):
        if self._faulted:
            raise VisionError("VISION_BACKEND_UNAVAILABLE", ErrorCategory.TRANSIENT, 503)
        cv2, np = self.cv2, self.np
        try:
            image = cv2.imdecode(np.frombuffer(payload, dtype=np.uint8),
                                 cv2.IMREAD_COLOR | cv2.IMREAD_IGNORE_ORIENTATION)
        except cv2.error:
            raise VisionError("VISION_INVALID_PAYLOAD") from None
        if image is None:
            raise VisionError("VISION_INVALID_PAYLOAD")
        height, width = image.shape[:2]
        if not (0 < width <= 65535 and 0 < height <= 65535) or width * height > self.max_pixels:
            raise VisionError("VISION_INVALID_PAYLOAD")
        info, output, pipeline = self._models[model_id]
        th, tw, _ = info.shape
        geometry = Letterbox.create(width, height, tw, th)
        resized = cv2.resize(image, (geometry.resized_width, geometry.resized_height))
        padded = np.full((th, tw, 3), 114, dtype=np.uint8)
        padded[geometry.top:geometry.top + geometry.resized_height,
               geometry.left:geometry.left + geometry.resized_width] = resized
        tensor = cv2.cvtColor(padded, cv2.COLOR_BGR2RGB)[None, ...]
        try:
            pipeline.set_nms_score_threshold(options.confidence)
            pipeline.set_nms_iou_threshold(options.iou)
            values = pipeline.infer({info.name: tensor})[output.name]
            if len(values) != 1:
                raise ValueError("unexpected batch size")
            return decode_detections(values[0], geometry, options)
        except Exception as exc:
            # A hardware or model-output failure must never look like zero detections.
            # Latch unhealthy until an operator restarts the process.
            self._faulted = True
            if isinstance(exc, VisionError):
                raise
            raise VisionError("VISION_BACKEND_FAILED", ErrorCategory.MODEL_ERROR, 502) from exc

    def close(self):
        self._stack.close()
