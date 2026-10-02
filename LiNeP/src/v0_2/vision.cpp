#include "linep/v0_2/vision.hpp"

#include <array>
#include <cstring>

namespace linep::v0_2 {

namespace {

// COCO-80 v1 standard canonical class list (80 classes, indices 0..79)
constexpr std::array<const char*, 80> COCO80_V1_LABELS = {
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat",
    "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat",
    "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack",
    "umbrella", "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball",
    "kite", "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket",
    "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
    "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake",
    "chair", "couch", "potted plant", "bed", "dining table", "toilet", "tv", "laptop",
    "mouse", "remote", "keyboard", "cell phone", "microwave", "oven", "toaster", "sink",
    "refrigerator", "book", "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush"
};

// WIDER FACE v1 standard class list (1 class, index 0)
constexpr std::array<const char*, 1> WIDERFACE_V1_LABELS = {
    "face"
};

// Pascal VOC 20 v1 standard class list (20 classes, indices 0..19)
constexpr std::array<const char*, 20> VOC20_V1_LABELS = {
    "aeroplane", "bicycle", "bird", "boat", "bottle", "bus", "car", "cat", "chair", "cow",
    "diningtable", "dog", "horse", "motorbike", "person", "pottedplant", "sheep", "sofa",
    "train", "tvmonitor"
};

} // anonymous namespace

const char* resolve_standard_label(const std::string& label_set_id, std::uint32_t class_id) noexcept {
    if (label_set_id == LABEL_SET_COCO80_V1) {
        if (class_id < COCO80_V1_LABELS.size()) {
            return COCO80_V1_LABELS[class_id];
        }
    } else if (label_set_id == LABEL_SET_WIDERFACE_V1) {
        if (class_id < WIDERFACE_V1_LABELS.size()) {
            return WIDERFACE_V1_LABELS[class_id];
        }
    } else if (label_set_id == LABEL_SET_VOC20_V1) {
        if (class_id < VOC20_V1_LABELS.size()) {
            return VOC20_V1_LABELS[class_id];
        }
    }
    return nullptr;
}

std::size_t get_standard_label_count(const std::string& label_set_id) noexcept {
    if (label_set_id == LABEL_SET_COCO80_V1) {
        return COCO80_V1_LABELS.size();
    } else if (label_set_id == LABEL_SET_WIDERFACE_V1) {
        return WIDERFACE_V1_LABELS.size();
    } else if (label_set_id == LABEL_SET_VOC20_V1) {
        return VOC20_V1_LABELS.size();
    }
    return 0;
}

bool is_valid_label_for_class(const std::string& label_set_id, std::uint32_t class_id, const std::string& label) noexcept {
    if (label.empty()) {
        return true; // Label is optional; empty is always valid
    }
    const char* canonical = resolve_standard_label(label_set_id, class_id);
    if (canonical != nullptr) {
        return label == canonical;
    }
    // If not a recognized standard label set, it must be a custom set ("custom:...")
    if (label_set_id.rfind("custom:", 0) == 0) {
        return label.size() <= LINEP_V02_MAX_VISION_STRING_BYTES;
    }
    // Unknown non-custom labelset
    return false;
}

bool vision_detect_result::is_valid() const noexcept {
    if (original_width == 0 || original_height == 0 ||
        original_width > 65535 || original_height > 65535) {
        return false;
    }
    if (label_set_id.empty() || label_set_id.size() > LINEP_V02_MAX_VISION_STRING_BYTES) {
        return false;
    }
    if (detections.size() > LINEP_V02_MAX_VISION_DETECTIONS) {
        return false;
    }
    for (const auto& d : detections) {
        if (!d.is_valid()) {
            return false;
        }
        if (!d.label.empty() && !is_valid_label_for_class(label_set_id, d.class_id, d.label)) {
            return false;
        }
    }
    return true;
}

} // namespace linep::v0_2
