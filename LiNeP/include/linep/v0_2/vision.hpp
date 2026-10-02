#pragma once

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace linep::v0_2 {

constexpr std::size_t LINEP_V02_MAX_VISION_IMAGE_BYTES = 16 * 1024 * 1024; // 16 MB
constexpr std::size_t LINEP_V02_MAX_VISION_DETECTIONS = 1000;
constexpr std::size_t LINEP_V02_MAX_VISION_STRING_BYTES = 256;

// Phase 1 Task definition (detect only; future phases will introduce segment, pose, etc.)
enum class vision_task : std::uint8_t {
    unspecified = 0,
    detect = 1,
};

// Normalized 2D bounding box strictly in [0.0, 1.0] relative to original image dimensions
struct vision_box_2d {
    float x_min{0.0f};
    float y_min{0.0f};
    float x_max{0.0f};
    float y_max{0.0f};

    float width() const noexcept { return x_max - x_min; }
    float height() const noexcept { return y_max - y_min; }

    bool is_valid() const noexcept {
        if (std::isnan(x_min) || std::isnan(y_min) || std::isnan(x_max) || std::isnan(y_max) ||
            std::isinf(x_min) || std::isinf(y_min) || std::isinf(x_max) || std::isinf(y_max)) {
            return false;
        }
        // Strict boundary and non-zero area invariants: x_min < x_max and y_min < y_max
        return x_min >= 0.0f && x_min < x_max && x_max <= 1.0f &&
               y_min >= 0.0f && y_min < y_max && y_max <= 1.0f;
    }

    bool operator==(const vision_box_2d& other) const noexcept {
        return x_min == other.x_min && y_min == other.y_min &&
               x_max == other.x_max && y_max == other.y_max;
    }
};

struct vision_detection {
    std::uint32_t class_id{0};
    std::string label; // Optional. If non-empty, must match label_set_id class name.
    float score{0.0f}; // Confidence score in [0.0, 1.0]
    vision_box_2d box{};

    bool is_valid() const noexcept {
        if (std::isnan(score) || std::isinf(score) || score < 0.0f || score > 1.0f) {
            return false;
        }
        if (label.size() > LINEP_V02_MAX_VISION_STRING_BYTES) {
            return false;
        }
        return box.is_valid();
    }

    bool operator==(const vision_detection& other) const noexcept {
        return class_id == other.class_id &&
               label == other.label &&
               score == other.score &&
               box == other.box;
    }
};

struct vision_detect_result {
    std::string label_set_id;
    std::uint32_t original_width{0};  // Must be > 0 and <= 65535
    std::uint32_t original_height{0}; // Must be > 0 and <= 65535
    std::vector<vision_detection> detections;

    bool is_valid() const noexcept;

    bool operator==(const vision_detect_result& other) const noexcept {
        return label_set_id == other.label_set_id &&
               original_width == other.original_width &&
               original_height == other.original_height &&
               detections == other.detections;
    }
};

struct vision_result_payload {
    vision_task task{vision_task::unspecified};
    std::string model_id;
    std::string model_revision;
    vision_detect_result detect;

    bool is_valid() const noexcept {
        if (task != vision_task::detect) {
            return false;
        }
        if (model_id.empty() || model_id.size() > LINEP_V02_MAX_VISION_STRING_BYTES ||
            model_revision.size() > LINEP_V02_MAX_VISION_STRING_BYTES) {
            return false;
        }
        return detect.is_valid();
    }

    bool operator==(const vision_result_payload& other) const noexcept {
        return task == other.task &&
               model_id == other.model_id &&
               model_revision == other.model_revision &&
               detect == other.detect;
    }
};

struct vision_model_descriptor {
    std::string model_id;
    std::string model_revision;
    std::string label_set_id;
    vision_task task{vision_task::detect};
    std::uint32_t max_detections{100};
    std::vector<std::string> custom_labels;

    bool operator==(const vision_model_descriptor& other) const noexcept {
        return model_id == other.model_id &&
               model_revision == other.model_revision &&
               label_set_id == other.label_set_id &&
               task == other.task &&
               max_detections == other.max_detections &&
               custom_labels == other.custom_labels;
    }
};

// Standardized versioned label set identifiers
inline constexpr const char* LABEL_SET_COCO80_V1    = "coco80:v1";
inline constexpr const char* LABEL_SET_WIDERFACE_V1  = "widerface:v1";
inline constexpr const char* LABEL_SET_VOC20_V1      = "voc20:v1";

const char* resolve_standard_label(const std::string& label_set_id, std::uint32_t class_id) noexcept;
bool is_valid_label_for_class(const std::string& label_set_id, std::uint32_t class_id, const std::string& label) noexcept;
std::size_t get_standard_label_count(const std::string& label_set_id) noexcept;

} // namespace linep::v0_2
