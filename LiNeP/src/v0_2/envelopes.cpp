#include "linep/v0_2/envelopes.hpp"
#include <cstring>

namespace linep::v0_2 {

namespace {

inline void write_u8(std::vector<std::uint8_t>& buf, std::uint8_t val) {
    buf.push_back(val);
}

inline void write_u16(std::vector<std::uint8_t>& buf, std::uint16_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
}

inline void write_u32(std::vector<std::uint8_t>& buf, std::uint32_t val) {
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

inline void write_u64(std::vector<std::uint8_t>& buf, std::uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

inline void write_float(std::vector<std::uint8_t>& buf, float val) {
    std::uint32_t bits{};
    std::memcpy(&bits, &val, sizeof(float));
    write_u32(buf, bits);
}

inline void write_string_u16(std::vector<std::uint8_t>& buf, const std::string& str) {
    auto len = static_cast<std::uint16_t>(str.size());
    write_u16(buf, len);
    if (len > 0) {
        buf.insert(buf.end(), str.data(), str.data() + len);
    }
}

inline void write_string_u32(std::vector<std::uint8_t>& buf, const std::string& str) {
    auto len = static_cast<std::uint32_t>(str.size());
    write_u32(buf, len);
    if (len > 0) {
        buf.insert(buf.end(), str.data(), str.data() + len);
    }
}

class buffer_reader {
public:
    buffer_reader(const std::uint8_t* data, std::size_t size)
        : data_(data), size_(size), offset_(0) {}

    bool has_remaining(std::size_t bytes) const noexcept {
        return (offset_ + bytes) <= size_;
    }

    bool read_u8(std::uint8_t& out) noexcept {
        if (!has_remaining(1)) return false;
        out = data_[offset_++];
        return true;
    }

    bool read_u16(std::uint16_t& out) noexcept {
        if (!has_remaining(2)) return false;
        out = static_cast<std::uint16_t>(data_[offset_]) |
              (static_cast<std::uint16_t>(data_[offset_ + 1]) << 8);
        offset_ += 2;
        return true;
    }

    bool read_u32(std::uint32_t& out) noexcept {
        if (!has_remaining(4)) return false;
        out = static_cast<std::uint32_t>(data_[offset_]) |
              (static_cast<std::uint32_t>(data_[offset_ + 1]) << 8) |
              (static_cast<std::uint32_t>(data_[offset_ + 2]) << 16) |
              (static_cast<std::uint32_t>(data_[offset_ + 3]) << 24);
        offset_ += 4;
        return true;
    }

    bool read_u64(std::uint64_t& out) noexcept {
        if (!has_remaining(8)) return false;
        out = 0;
        for (int i = 0; i < 8; ++i) {
            out |= (static_cast<std::uint64_t>(data_[offset_ + i]) << (i * 8));
        }
        offset_ += 8;
        return true;
    }

    bool read_float(float& out) noexcept {
        std::uint32_t bits{};
        if (!read_u32(bits)) return false;
        std::memcpy(&out, &bits, sizeof(float));
        return true;
    }

    bool read_string_u16(std::string& out) {
        std::uint16_t len{};
        if (!read_u16(len)) return false;
        if (!has_remaining(len)) return false;
        out.assign(reinterpret_cast<const char*>(data_ + offset_), len);
        offset_ += len;
        return true;
    }

    bool read_string_u32(std::string& out) {
        std::uint32_t len{};
        if (!read_u32(len)) return false;
        if (!has_remaining(len)) return false;
        out.assign(reinterpret_cast<const char*>(data_ + offset_), len);
        offset_ += len;
        return true;
    }

    std::size_t remaining() const noexcept { return size_ - offset_; }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_;
};

} // anonymous namespace

void encode_header(const wire_envelope_header& hdr, std::vector<std::uint8_t>& out_buf) {
    write_u32(out_buf, hdr.magic);
    write_u8(out_buf, hdr.version_major);
    write_u8(out_buf, hdr.version_minor);
    write_u8(out_buf, hdr.envelope_type);
    write_u8(out_buf, hdr.flags);
    write_u64(out_buf, hdr.request_id);
    write_u64(out_buf, hdr.execution_id);
    write_u32(out_buf, hdr.output_id);
    write_u32(out_buf, hdr.payload_len);
}

bool decode_header(const std::uint8_t* data, std::size_t size, wire_envelope_header& out_hdr) {
    if (!data || size < LINEP_V02_HEADER_SIZE) {
        return false;
    }
    buffer_reader r(data, LINEP_V02_HEADER_SIZE);
    if (!r.read_u32(out_hdr.magic)) return false;
    if (!r.read_u8(out_hdr.version_major)) return false;
    if (!r.read_u8(out_hdr.version_minor)) return false;
    if (!r.read_u8(out_hdr.envelope_type)) return false;
    if (!r.read_u8(out_hdr.flags)) return false;
    if (!r.read_u64(out_hdr.request_id)) return false;
    if (!r.read_u64(out_hdr.execution_id)) return false;
    if (!r.read_u32(out_hdr.output_id)) return false;
    if (!r.read_u32(out_hdr.payload_len)) return false;
    return true;
}

runtime_envelope_type peek_envelope_type(const std::uint8_t* data, std::size_t size) noexcept {
    wire_envelope_header hdr{};
    if (!decode_header(data, size, hdr)) {
        return runtime_envelope_type::unknown;
    }
    if (hdr.magic != LINEP_V02_MAGIC || hdr.version_major != LINEP_V02_VERSION_MAJOR) {
        return runtime_envelope_type::unknown;
    }
    return static_cast<runtime_envelope_type>(hdr.envelope_type);
}

bool encode_request(const request_envelope& req, std::vector<std::uint8_t>& out_buffer) {
    if (!req.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> payload_buf;
    write_u8(payload_buf, static_cast<std::uint8_t>(req.profile));
    write_string_u16(payload_buf, req.model_id);
    write_string_u32(payload_buf, req.payload);
    write_u32(payload_buf, req.max_tokens);
    write_float(payload_buf, req.temperature);
    write_u8(payload_buf, req.stream_requested ? 1 : 0);

    wire_envelope_header hdr{};
    hdr.magic = LINEP_V02_MAGIC;
    hdr.version_major = LINEP_V02_VERSION_MAJOR;
    hdr.version_minor = LINEP_V02_VERSION_MINOR;
    hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::request);
    hdr.flags = 0;
    hdr.request_id = req.stream.request_id;
    hdr.execution_id = req.stream.execution_id;
    hdr.output_id = req.stream.output_id;
    hdr.payload_len = static_cast<std::uint32_t>(payload_buf.size());

    out_buffer.clear();
    out_buffer.reserve(LINEP_V02_HEADER_SIZE + payload_buf.size());
    encode_header(hdr, out_buffer);
    if (!payload_buf.empty()) {
        out_buffer.insert(out_buffer.end(), payload_buf.begin(), payload_buf.end());
    }
    return true;
}

bool decode_request(const std::uint8_t* data, std::size_t size, request_envelope& out_req) {
    wire_envelope_header hdr{};
    if (!decode_header(data, size, hdr)) {
        return false;
    }

    if (hdr.magic != LINEP_V02_MAGIC ||
        hdr.version_major != LINEP_V02_VERSION_MAJOR ||
        hdr.envelope_type != static_cast<std::uint8_t>(runtime_envelope_type::request)) {
        return false;
    }

    if (size < (LINEP_V02_HEADER_SIZE + hdr.payload_len)) {
        return false; // Truncated buffer
    }

    out_req.stream.request_id = hdr.request_id;
    out_req.stream.execution_id = hdr.execution_id;
    out_req.stream.output_id = hdr.output_id;

    buffer_reader r(data + LINEP_V02_HEADER_SIZE, hdr.payload_len);
    std::uint8_t prof{};
    if (!r.read_u8(prof)) return false;
    out_req.profile = static_cast<runtime_profile>(prof);

    if (!r.read_string_u16(out_req.model_id)) return false;
    if (!r.read_string_u32(out_req.payload)) return false;
    if (!r.read_u32(out_req.max_tokens)) return false;
    if (!r.read_float(out_req.temperature)) return false;

    std::uint8_t stream_req{};
    if (!r.read_u8(stream_req)) return false;
    out_req.stream_requested = (stream_req != 0);

    if (r.remaining() != 0) {
        return false; // Strict canonical framing: reject trailing garbage
    }

    return out_req.is_valid();
}

bool encode_event(const event_envelope& evt, std::vector<std::uint8_t>& out_buffer) {
    if (!evt.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> payload_buf;
    write_u64(payload_buf, evt.event_seq);
    write_u8(payload_buf, static_cast<std::uint8_t>(evt.event_type));
    write_u8(payload_buf, static_cast<std::uint8_t>(evt.outcome));
    write_u8(payload_buf, static_cast<std::uint8_t>(evt.error.category));
    write_u32(payload_buf, evt.error.code);
    write_string_u16(payload_buf, evt.error.message);
    write_string_u16(payload_buf, evt.error.backend_diagnostic);
    write_string_u32(payload_buf, evt.payload);
    write_u64(payload_buf, evt.timestamp_us);

    if (evt.event_type == runtime_event_type::embedding_result) {
        write_string_u16(payload_buf, evt.embedding.space.embedding_space_id);
        write_string_u16(payload_buf, evt.embedding.space.model_id);
        write_string_u16(payload_buf, evt.embedding.space.model_revision);
        write_u32(payload_buf, evt.embedding.space.dimensions);
        write_u8(payload_buf, static_cast<std::uint8_t>(evt.embedding.space.normalization));
        write_u8(payload_buf, static_cast<std::uint8_t>(evt.embedding.space.distance_metric));
        write_u32(payload_buf, static_cast<std::uint32_t>(evt.embedding.vector.size()));
        for (float val : evt.embedding.vector) {
            write_float(payload_buf, val);
        }
    }

    wire_envelope_header hdr{};
    hdr.magic = LINEP_V02_MAGIC;
    hdr.version_major = LINEP_V02_VERSION_MAJOR;
    hdr.version_minor = LINEP_V02_VERSION_MINOR;
    hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::event);
    hdr.flags = 0;
    hdr.request_id = evt.stream.request_id;
    hdr.execution_id = evt.stream.execution_id;
    hdr.output_id = evt.stream.output_id;
    hdr.payload_len = static_cast<std::uint32_t>(payload_buf.size());

    out_buffer.clear();
    out_buffer.reserve(LINEP_V02_HEADER_SIZE + payload_buf.size());
    encode_header(hdr, out_buffer);
    if (!payload_buf.empty()) {
        out_buffer.insert(out_buffer.end(), payload_buf.begin(), payload_buf.end());
    }
    return true;
}

bool decode_event(const std::uint8_t* data, std::size_t size, event_envelope& out_evt) {
    wire_envelope_header hdr{};
    if (!decode_header(data, size, hdr)) {
        return false;
    }

    if (hdr.magic != LINEP_V02_MAGIC ||
        hdr.version_major != LINEP_V02_VERSION_MAJOR ||
        hdr.envelope_type != static_cast<std::uint8_t>(runtime_envelope_type::event)) {
        return false;
    }

    if (size < (LINEP_V02_HEADER_SIZE + hdr.payload_len)) {
        return false;
    }

    out_evt.stream.request_id = hdr.request_id;
    out_evt.stream.execution_id = hdr.execution_id;
    out_evt.stream.output_id = hdr.output_id;

    buffer_reader r(data + LINEP_V02_HEADER_SIZE, hdr.payload_len);
    if (!r.read_u64(out_evt.event_seq)) return false;

    std::uint8_t ev_type{}, outcome{}, err_cat{};
    if (!r.read_u8(ev_type)) return false;
    if (!r.read_u8(outcome)) return false;
    if (!r.read_u8(err_cat)) return false;
    if (!r.read_u32(out_evt.error.code)) return false;
    if (!r.read_string_u16(out_evt.error.message)) return false;
    if (!r.read_string_u16(out_evt.error.backend_diagnostic)) return false;
    if (!r.read_string_u32(out_evt.payload)) return false;
    if (!r.read_u64(out_evt.timestamp_us)) return false;

    out_evt.event_type = static_cast<runtime_event_type>(ev_type);
    out_evt.outcome = static_cast<terminal_outcome>(outcome);
    out_evt.error.category = static_cast<error_category>(err_cat);

    if (out_evt.event_type == runtime_event_type::embedding_result) {
        if (!r.read_string_u16(out_evt.embedding.space.embedding_space_id)) return false;
        if (!r.read_string_u16(out_evt.embedding.space.model_id)) return false;
        if (!r.read_string_u16(out_evt.embedding.space.model_revision)) return false;
        if (!r.read_u32(out_evt.embedding.space.dimensions)) return false;

        std::uint8_t norm{}, dist{};
        if (!r.read_u8(norm)) return false;
        if (!r.read_u8(dist)) return false;
        out_evt.embedding.space.normalization = static_cast<embedding_normalization>(norm);
        out_evt.embedding.space.distance_metric = static_cast<embedding_distance_metric>(dist);

        std::uint32_t vec_count{};
        if (!r.read_u32(vec_count)) return false;

        // Strict fail-closed checks before vector allocation (DoS protection)
        if (vec_count > LINEP_V02_MAX_EMBEDDING_DIMENSIONS) return false;
        if (vec_count > (r.remaining() / sizeof(float))) return false;
        if (vec_count != out_evt.embedding.space.dimensions) return false;

        out_evt.embedding.vector.resize(vec_count);
        for (std::uint32_t i = 0; i < vec_count; ++i) {
            if (!r.read_float(out_evt.embedding.vector[i])) return false;
        }
    }

    if (r.remaining() != 0) {
        return false; // Strict canonical framing: reject trailing garbage
    }

    return out_evt.is_valid();
}

bool encode_control(const control_envelope& ctrl, std::vector<std::uint8_t>& out_buffer) {
    if (!ctrl.is_valid()) {
        return false;
    }

    std::vector<std::uint8_t> payload_buf;
    write_u8(payload_buf, static_cast<std::uint8_t>(ctrl.control_type));
    write_string_u16(payload_buf, ctrl.reason);
    write_u64(payload_buf, ctrl.ack_offset_bytes);

    wire_envelope_header hdr{};
    hdr.magic = LINEP_V02_MAGIC;
    hdr.version_major = LINEP_V02_VERSION_MAJOR;
    hdr.version_minor = LINEP_V02_VERSION_MINOR;
    hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::control);
    hdr.flags = 0;
    hdr.request_id = ctrl.stream.request_id;
    hdr.execution_id = ctrl.stream.execution_id;
    hdr.output_id = ctrl.stream.output_id;
    hdr.payload_len = static_cast<std::uint32_t>(payload_buf.size());

    out_buffer.clear();
    out_buffer.reserve(LINEP_V02_HEADER_SIZE + payload_buf.size());
    encode_header(hdr, out_buffer);
    if (!payload_buf.empty()) {
        out_buffer.insert(out_buffer.end(), payload_buf.begin(), payload_buf.end());
    }
    return true;
}

bool decode_control(const std::uint8_t* data, std::size_t size, control_envelope& out_ctrl) {
    wire_envelope_header hdr{};
    if (!decode_header(data, size, hdr)) {
        return false;
    }

    if (hdr.magic != LINEP_V02_MAGIC ||
        hdr.version_major != LINEP_V02_VERSION_MAJOR ||
        hdr.envelope_type != static_cast<std::uint8_t>(runtime_envelope_type::control)) {
        return false;
    }

    if (size < (LINEP_V02_HEADER_SIZE + hdr.payload_len)) {
        return false;
    }

    out_ctrl.stream.request_id = hdr.request_id;
    out_ctrl.stream.execution_id = hdr.execution_id;
    out_ctrl.stream.output_id = hdr.output_id;

    buffer_reader r(data + LINEP_V02_HEADER_SIZE, hdr.payload_len);
    std::uint8_t ctrl_type{};
    if (!r.read_u8(ctrl_type)) return false;
    out_ctrl.control_type = static_cast<runtime_control_type>(ctrl_type);
    if (!r.read_string_u16(out_ctrl.reason)) return false;
    if (!r.read_u64(out_ctrl.ack_offset_bytes)) return false;

    if (r.remaining() != 0) {
        return false; // Strict canonical framing: reject trailing garbage
    }

    return out_ctrl.is_valid();
}

bool encode_capabilities(const capabilities_envelope& caps, std::vector<std::uint8_t>& out_buffer) {
    std::vector<std::uint8_t> payload_buf;

    const auto& desc = caps.descriptor;
    write_u16(payload_buf, static_cast<std::uint16_t>(desc.supported_profiles.size()));
    for (auto prof : desc.supported_profiles) {
        write_u8(payload_buf, static_cast<std::uint8_t>(prof));
    }

    write_u32(payload_buf, desc.max_context_tokens);
    write_u32(payload_buf, desc.max_output_tokens);
    write_u8(payload_buf, desc.supports_streaming ? 1 : 0);
    write_u8(payload_buf, desc.supports_cancellation ? 1 : 0);
    write_u8(payload_buf, desc.supports_tool_calling ? 1 : 0);
    write_u8(payload_buf, desc.supports_reasoning_deltas ? 1 : 0);

    write_u16(payload_buf, static_cast<std::uint16_t>(desc.supported_models.size()));
    for (const auto& m : desc.supported_models) {
        write_string_u16(payload_buf, m);
    }

    write_u16(payload_buf, static_cast<std::uint16_t>(desc.supported_embedding_spaces.size()));
    for (const auto& sp : desc.supported_embedding_spaces) {
        write_string_u16(payload_buf, sp.embedding_space_id);
        write_string_u16(payload_buf, sp.model_id);
        write_string_u16(payload_buf, sp.model_revision);
        write_u32(payload_buf, sp.dimensions);
        write_u8(payload_buf, static_cast<std::uint8_t>(sp.normalization));
        write_u8(payload_buf, static_cast<std::uint8_t>(sp.distance_metric));
    }

    wire_envelope_header hdr{};
    hdr.magic = LINEP_V02_MAGIC;
    hdr.version_major = LINEP_V02_VERSION_MAJOR;
    hdr.version_minor = LINEP_V02_VERSION_MINOR;
    hdr.envelope_type = static_cast<std::uint8_t>(runtime_envelope_type::capabilities);
    hdr.flags = 0;
    hdr.request_id = 0;
    hdr.execution_id = 0;
    hdr.output_id = 0;
    hdr.payload_len = static_cast<std::uint32_t>(payload_buf.size());

    out_buffer.clear();
    out_buffer.reserve(LINEP_V02_HEADER_SIZE + payload_buf.size());
    encode_header(hdr, out_buffer);
    if (!payload_buf.empty()) {
        out_buffer.insert(out_buffer.end(), payload_buf.begin(), payload_buf.end());
    }
    return true;
}

bool decode_capabilities(const std::uint8_t* data, std::size_t size, capabilities_envelope& out_caps) {
    wire_envelope_header hdr{};
    if (!decode_header(data, size, hdr)) {
        return false;
    }

    if (hdr.magic != LINEP_V02_MAGIC ||
        hdr.version_major != LINEP_V02_VERSION_MAJOR ||
        hdr.envelope_type != static_cast<std::uint8_t>(runtime_envelope_type::capabilities)) {
        return false;
    }

    if (size < (LINEP_V02_HEADER_SIZE + hdr.payload_len)) {
        return false;
    }

    buffer_reader r(data + LINEP_V02_HEADER_SIZE, hdr.payload_len);
    auto& desc = out_caps.descriptor;

    std::uint16_t prof_count{};
    if (!r.read_u16(prof_count)) return false;
    desc.supported_profiles.resize(prof_count);
    for (std::uint16_t i = 0; i < prof_count; ++i) {
        std::uint8_t prof{};
        if (!r.read_u8(prof)) return false;
        desc.supported_profiles[i] = static_cast<runtime_profile>(prof);
    }

    if (!r.read_u32(desc.max_context_tokens)) return false;
    if (!r.read_u32(desc.max_output_tokens)) return false;

    std::uint8_t s_stream{}, s_cancel{}, s_tool{}, s_reason{};
    if (!r.read_u8(s_stream)) return false;
    if (!r.read_u8(s_cancel)) return false;
    if (!r.read_u8(s_tool)) return false;
    if (!r.read_u8(s_reason)) return false;

    desc.supports_streaming = (s_stream != 0);
    desc.supports_cancellation = (s_cancel != 0);
    desc.supports_tool_calling = (s_tool != 0);
    desc.supports_reasoning_deltas = (s_reason != 0);

    std::uint16_t models_count{};
    if (!r.read_u16(models_count)) return false;
    desc.supported_models.resize(models_count);
    for (std::uint16_t i = 0; i < models_count; ++i) {
        if (!r.read_string_u16(desc.supported_models[i])) return false;
    }

    std::uint16_t spaces_count{};
    if (!r.read_u16(spaces_count)) return false;
    desc.supported_embedding_spaces.resize(spaces_count);
    for (std::uint16_t i = 0; i < spaces_count; ++i) {
        auto& sp = desc.supported_embedding_spaces[i];
        if (!r.read_string_u16(sp.embedding_space_id)) return false;
        if (!r.read_string_u16(sp.model_id)) return false;
        if (!r.read_string_u16(sp.model_revision)) return false;
        if (!r.read_u32(sp.dimensions)) return false;

        std::uint8_t norm{}, dist{};
        if (!r.read_u8(norm)) return false;
        if (!r.read_u8(dist)) return false;
        sp.normalization = static_cast<embedding_normalization>(norm);
        sp.distance_metric = static_cast<embedding_distance_metric>(dist);
    }

    if (r.remaining() != 0) {
        return false; // Strict canonical framing: reject trailing garbage
    }

    return true;
}

} // namespace linep::v0_2
