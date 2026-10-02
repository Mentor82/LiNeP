#include <cmath>
#include <iostream>
#include <limits>
#include <vector>

#include "linep/v0_2/capabilities.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/vision.hpp"

using namespace linep::v0_2;

#define LINEP_TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void test_vision_positive_coco80_roundtrip() {
    std::cout << "[Test 1] Testing COCO-80 Detections Roundtrip..." << std::endl;

    event_envelope evt{};
    evt.stream = stream_identity{100, 200, 0};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::vision_result;
    evt.timestamp_us = 12345678ULL;

    evt.vision.task = vision_task::detect;
    evt.vision.model_id = "yolov8n-detect";
    evt.vision.model_revision = "v1.0.0";
    evt.vision.detect.label_set_id = LABEL_SET_COCO80_V1;
    evt.vision.detect.original_width = 1920;
    evt.vision.detect.original_height = 1080;

    vision_detection d1;
    d1.class_id = 0; // person
    d1.label = "person";
    d1.score = 0.95f;
    d1.box = vision_box_2d{0.10f, 0.20f, 0.40f, 0.80f};

    vision_detection d2;
    d2.class_id = 2; // car
    d2.label = "car";
    d2.score = 0.88f;
    d2.box = vision_box_2d{0.50f, 0.60f, 0.90f, 0.95f};

    vision_detection d3;
    d3.class_id = 16; // dog
    d3.label = "dog";
    d3.score = 0.77f;
    d3.box = vision_box_2d{0.20f, 0.60f, 0.45f, 0.85f};

    evt.vision.detect.detections = {d1, d2, d3};

    LINEP_TEST_CHECK(evt.is_valid());

    std::vector<std::uint8_t> encoded;
    LINEP_TEST_CHECK(encode_event(evt, encoded));
    LINEP_TEST_CHECK(!encoded.empty());

    event_envelope decoded{};
    LINEP_TEST_CHECK(decode_event(encoded.data(), encoded.size(), decoded));

    LINEP_TEST_CHECK(decoded.event_type == runtime_event_type::vision_result);
    LINEP_TEST_CHECK(decoded.vision.task == vision_task::detect);
    LINEP_TEST_CHECK(decoded.vision.model_id == "yolov8n-detect");
    LINEP_TEST_CHECK(decoded.vision.model_revision == "v1.0.0");
    LINEP_TEST_CHECK(decoded.vision.detect.label_set_id == LABEL_SET_COCO80_V1);
    LINEP_TEST_CHECK(decoded.vision.detect.original_width == 1920);
    LINEP_TEST_CHECK(decoded.vision.detect.original_height == 1080);
    LINEP_TEST_CHECK(decoded.vision.detect.detections.size() == 3);

    const auto& rd1 = decoded.vision.detect.detections[0];
    LINEP_TEST_CHECK(rd1.class_id == 0 && rd1.label == "person");
    LINEP_TEST_CHECK(std::abs(rd1.score - 0.95f) < 1e-5f);
    LINEP_TEST_CHECK(std::abs(rd1.box.x_min - 0.10f) < 1e-5f);
    LINEP_TEST_CHECK(std::abs(rd1.box.y_min - 0.20f) < 1e-5f);
    LINEP_TEST_CHECK(std::abs(rd1.box.x_max - 0.40f) < 1e-5f);
    LINEP_TEST_CHECK(std::abs(rd1.box.y_max - 0.80f) < 1e-5f);

    const auto& rd2 = decoded.vision.detect.detections[1];
    LINEP_TEST_CHECK(rd2.class_id == 2 && rd2.label == "car");
    LINEP_TEST_CHECK(std::abs(rd2.score - 0.88f) < 1e-5f);

    const auto& rd3 = decoded.vision.detect.detections[2];
    LINEP_TEST_CHECK(rd3.class_id == 16 && rd3.label == "dog");
    LINEP_TEST_CHECK(std::abs(rd3.score - 0.77f) < 1e-5f);
}

void test_vision_positive_empty_detections() {
    std::cout << "[Test 2] Testing Empty Detections (No Objects Detected)..." << std::endl;

    event_envelope evt{};
    evt.stream = stream_identity{101, 201, 0};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::vision_result;
    evt.timestamp_us = 999ULL;

    evt.vision.task = vision_task::detect;
    evt.vision.model_id = "scrfd-2.5g";
    evt.vision.model_revision = "v2.1";
    evt.vision.detect.label_set_id = LABEL_SET_WIDERFACE_V1;
    evt.vision.detect.original_width = 640;
    evt.vision.detect.original_height = 480;
    evt.vision.detect.detections = {}; // 0 detections

    LINEP_TEST_CHECK(evt.is_valid());

    std::vector<std::uint8_t> encoded;
    LINEP_TEST_CHECK(encode_event(evt, encoded));

    event_envelope decoded{};
    LINEP_TEST_CHECK(decode_event(encoded.data(), encoded.size(), decoded));
    LINEP_TEST_CHECK(decoded.vision.detect.detections.empty());
    LINEP_TEST_CHECK(decoded.vision.detect.original_width == 640);
    LINEP_TEST_CHECK(decoded.vision.detect.original_height == 480);
}

void test_vision_positive_omitted_label_string() {
    std::cout << "[Test 3] Testing Omitted (Empty) Label String..." << std::endl;

    event_envelope evt{};
    evt.stream = stream_identity{102, 202, 0};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::vision_result;

    evt.vision.task = vision_task::detect;
    evt.vision.model_id = "voc-yolo";
    evt.vision.detect.label_set_id = LABEL_SET_VOC20_V1;
    evt.vision.detect.original_width = 800;
    evt.vision.detect.original_height = 600;

    vision_detection d;
    d.class_id = 0; // aeroplane in VOC20
    d.label = "";   // Omitted label!
    d.score = 0.91f;
    d.box = vision_box_2d{0.05f, 0.15f, 0.85f, 0.65f};
    evt.vision.detect.detections = {d};

    LINEP_TEST_CHECK(evt.is_valid());

    std::vector<std::uint8_t> encoded;
    LINEP_TEST_CHECK(encode_event(evt, encoded));

    event_envelope decoded{};
    LINEP_TEST_CHECK(decode_event(encoded.data(), encoded.size(), decoded));
    LINEP_TEST_CHECK(decoded.vision.detect.detections.size() == 1);
    LINEP_TEST_CHECK(decoded.vision.detect.detections[0].label.empty());
    LINEP_TEST_CHECK(resolve_standard_label(LABEL_SET_VOC20_V1, decoded.vision.detect.detections[0].class_id) == std::string("aeroplane"));
}

void test_vision_positive_custom_label_set() {
    std::cout << "[Test 4] Testing Custom Label Set..." << std::endl;

    event_envelope evt{};
    evt.stream = stream_identity{103, 203, 0};
    evt.event_seq = 1;
    evt.event_type = runtime_event_type::vision_result;

    evt.vision.task = vision_task::detect;
    evt.vision.model_id = "drone-parts-det";
    evt.vision.detect.label_set_id = "custom:drone_parts_v1";
    evt.vision.detect.original_width = 1280;
    evt.vision.detect.original_height = 720;

    vision_detection d;
    d.class_id = 0;
    d.label = "rotor_blade";
    d.score = 0.92f;
    d.box = vision_box_2d{0.2f, 0.3f, 0.5f, 0.7f};
    evt.vision.detect.detections = {d};

    LINEP_TEST_CHECK(evt.is_valid());

    std::vector<std::uint8_t> encoded;
    LINEP_TEST_CHECK(encode_event(evt, encoded));

    event_envelope decoded{};
    LINEP_TEST_CHECK(decode_event(encoded.data(), encoded.size(), decoded));
    LINEP_TEST_CHECK(decoded.vision.detect.detections[0].label == "rotor_blade");
}

void test_vision_capabilities_descriptor() {
    std::cout << "[Test 5] Testing Capabilities Descriptor with Vision Models..." << std::endl;

    capabilities_envelope caps{};
    caps.descriptor.supported_profiles = {runtime_profile::vision};
    caps.descriptor.supported_models = {"yolov8n-detect"};

    vision_model_descriptor vm;
    vm.model_id = "yolov8n-detect";
    vm.model_revision = "v1.0.0";
    vm.label_set_id = LABEL_SET_COCO80_V1;
    vm.task = vision_task::detect;
    vm.max_detections = 100;
    caps.descriptor.supported_vision_models = {vm};

    LINEP_TEST_CHECK(caps.descriptor.supports_profile(runtime_profile::vision));
    LINEP_TEST_CHECK(caps.descriptor.supports_vision_model("yolov8n-detect", vision_task::detect));
    LINEP_TEST_CHECK(!caps.descriptor.supports_vision_model("other-model"));

    std::vector<std::uint8_t> encoded;
    LINEP_TEST_CHECK(encode_capabilities(caps, encoded));

    capabilities_envelope decoded{};
    LINEP_TEST_CHECK(decode_capabilities(encoded.data(), encoded.size(), decoded));
    LINEP_TEST_CHECK(decoded.descriptor.supports_profile(runtime_profile::vision));
    LINEP_TEST_CHECK(decoded.descriptor.supports_vision_model("yolov8n-detect", vision_task::detect));
    LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models.size() == 1);
    LINEP_TEST_CHECK(decoded.descriptor.supported_vision_models[0].label_set_id == LABEL_SET_COCO80_V1);
}

void test_vision_negatives() {
    std::cout << "[Test 6] Testing Negatives (NaN, Inf, Bounds, Collapse, Label Mismatch)..." << std::endl;

    vision_box_2d valid_box{0.1f, 0.2f, 0.4f, 0.5f};
    LINEP_TEST_CHECK(valid_box.is_valid());

    // 1. NaN coordinate
    vision_box_2d nan_box = valid_box;
    nan_box.x_min = std::numeric_limits<float>::quiet_NaN();
    LINEP_TEST_CHECK(!nan_box.is_valid());

    // 2. Inf coordinate
    vision_box_2d inf_box = valid_box;
    inf_box.y_max = std::numeric_limits<float>::infinity();
    LINEP_TEST_CHECK(!inf_box.is_valid());

    // 3. Negative coordinate
    vision_box_2d neg_box = valid_box;
    neg_box.x_min = -0.01f;
    LINEP_TEST_CHECK(!neg_box.is_valid());

    // 4. Collapsed box: x_min == x_max
    vision_box_2d collapsed_x = valid_box;
    collapsed_x.x_min = collapsed_x.x_max;
    LINEP_TEST_CHECK(!collapsed_x.is_valid());

    // 5. Inverted box: x_min > x_max
    vision_box_2d inverted_x = valid_box;
    inverted_x.x_min = 0.6f;
    inverted_x.x_max = 0.4f;
    LINEP_TEST_CHECK(!inverted_x.is_valid());

    // 6. Zero height box: y_min == y_max
    vision_box_2d collapsed_y = valid_box;
    collapsed_y.y_min = collapsed_y.y_max;
    LINEP_TEST_CHECK(!collapsed_y.is_valid());

    // 7. Out-of-bounds: x_max > 1.0
    vision_box_2d oob_box = valid_box;
    oob_box.x_max = 1.01f;
    LINEP_TEST_CHECK(!oob_box.is_valid());

    // 8. Invalid score (< 0.0 or > 1.0 or NaN)
    vision_detection det;
    det.box = valid_box;
    det.score = 1.05f;
    LINEP_TEST_CHECK(!det.is_valid());
    det.score = -0.1f;
    LINEP_TEST_CHECK(!det.is_valid());
    det.score = std::numeric_limits<float>::quiet_NaN();
    LINEP_TEST_CHECK(!det.is_valid());

    // 9. Zero image dimensions
    vision_detect_result res;
    res.label_set_id = LABEL_SET_COCO80_V1;
    res.original_width = 0;
    res.original_height = 1080;
    LINEP_TEST_CHECK(!res.is_valid());

    res.original_width = 1920;
    res.original_height = 0;
    LINEP_TEST_CHECK(!res.is_valid());

    // 10. Label mismatch in standard registry
    // In COCO-80 v1: class 0 is "person", NOT "bicycle" (class 1 is bicycle)
    vision_detection mismatch_det;
    mismatch_det.class_id = 0;
    mismatch_det.label = "bicycle"; // Mismatch!
    mismatch_det.score = 0.9f;
    mismatch_det.box = valid_box;
    LINEP_TEST_CHECK(mismatch_det.is_valid()); // detection struct itself is valid, but result validation fails:

    res.original_width = 1920;
    res.original_height = 1080;
    res.detections = {mismatch_det};
    LINEP_TEST_CHECK(!res.is_valid());

    // Fix label to "person": becomes valid
    mismatch_det.label = "person";
    res.detections = {mismatch_det};
    LINEP_TEST_CHECK(res.is_valid());

    // Empty label: also valid
    mismatch_det.label = "";
    res.detections = {mismatch_det};
    LINEP_TEST_CHECK(res.is_valid());

    // 11. Unsupported task in payload
    vision_result_payload payload;
    payload.task = vision_task::unspecified;
    payload.model_id = "yolo";
    payload.detect = res;
    LINEP_TEST_CHECK(!payload.is_valid());
}

int main() {
    test_vision_positive_coco80_roundtrip();
    test_vision_positive_empty_detections();
    test_vision_positive_omitted_label_string();
    test_vision_positive_custom_label_set();
    test_vision_capabilities_descriptor();
    test_vision_negatives();

    std::cout << "\nAll LiNeP V0.2 PROFILE_VISION (Phase 1) tests PASSED successfully!" << std::endl;
    return 0;
}
