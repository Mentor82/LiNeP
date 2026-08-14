#pragma once
#include <cstdint>
#include <cstring>

namespace linep {

// ── Message types ─────────────────────────────────────────────────────────────
enum MsgType : uint8_t {
    // Presence
    HEARTBEAT        = 0x01,
    REGISTER         = 0x02,
    REGISTER_ACK     = 0x03,
    BYE              = 0x04,
    INVITE           = 0x05,
    INVITE_ACK       = 0x06,
    HEARTBEAT_ACK    = 0x07,

    // Inference
    TASK             = 0x10,
    TASK_ACK         = 0x11,
    RESULT           = 0x12,
    MSG_ERROR        = 0x13,

    // Status
    STATUS_REQUEST   = 0x20,
    STATUS_RESPONSE  = 0x21,

    // Embedding
    EMBED_REQUEST       = 0x30,
    EMBED_RESPONSE      = 0x31,
    SIMILARITY_REQUEST  = 0x32,
    SIMILARITY_RESPONSE = 0x33,

    // Consensus
    CONSENSUS_REQUEST   = 0x40,
    CONSENSUS_RESPONSE  = 0x41,

    // Diagnostics
    PING = 0xF0,
    PONG = 0xF1,
};

// ── Task types ────────────────────────────────────────────────────────────────
enum TaskType : uint8_t {
    TASK_INSTRUCT       = 0x01,
    TASK_CODE           = 0x02,
    TASK_SUMMARIZE      = 0x03,
    TASK_CLASSIFY       = 0x04,
    TASK_VALIDATE       = 0x05,
    TASK_EDGE_TEXT_EVAL = 0x06,
};

// ── Slot types ────────────────────────────────────────────────────────────────
enum SlotType : uint8_t {
    SLOT_TYPE_INSTRUCT   = 0x01,
    SLOT_TYPE_CODER      = 0x02,
    SLOT_TYPE_EMBEDDING  = 0x03,
    SLOT_TYPE_CLASSIFIER = 0x04,
    SLOT_TYPE_SUMMARIZER = 0x05,
    SLOT_TYPE_VALIDATOR  = 0x06,
};

// ── Result status ─────────────────────────────────────────────────────────────
enum ResultStatus : uint8_t {
    RESULT_OK            = 0x00,
    RESULT_REJECTED      = 0x01,
    RESULT_TIMEOUT       = 0x02,
    RESULT_MODEL_ERROR   = 0x03,
    RESULT_INVALID_INPUT = 0x04,
    RESULT_DEGRADED      = 0x05,
};

// ── Consensus level ───────────────────────────────────────────────────────────
enum ConsensusLevel : uint8_t {
    CONSENSUS_FAILED  = 0,   // < 2/3 agree
    CONSENSUS_PARTIAL = 1,   // 2/3 >= threshold
    CONSENSUS_STRONG  = 2,   // 3/3 >= threshold
};

// ── Error codes ───────────────────────────────────────────────────────────────
enum ErrorCode : uint16_t {
    ERR_PROTOCOL_ERROR       = 1000,
    ERR_CRC_ERROR            = 1001,
    ERR_UNSUPPORTED_VERSION  = 1002,
    ERR_UNKNOWN_MSG_TYPE     = 1003,
    ERR_INVALID_PAYLOAD      = 1004,

    ERR_MODEL_NOT_READY      = 2000,
    ERR_MODEL_LOAD_FAILED    = 2001,
    ERR_INFERENCE_FAILED     = 2002,
    ERR_TOKENIZER_FAILED     = 2003,
    ERR_DEVICE_UNAVAILABLE   = 2004,

    ERR_TIMEOUT              = 3000,
    ERR_NO_SLOT_AVAILABLE    = 3001,
    ERR_CONSENSUS_FAILED     = 3002,
};

// ── RESULT payload schema (Scheduler ↔ Helper wire convention) ─────────────────
//
// Byte 0 of every RESULT (0x12) payload is always ResultStatus.
// Bytes 1..N carry a UTF-8 JSON body with the following fields:
//
//   {
//     "text":        "<generated text>",    // main inference output
//     "model":       "<model name>",        // e.g. "Qwen3-1.7B-fp16-ov"
//     "tokens_in":   <uint32>,              // prompt token count
//     "tokens_out":  <uint32>,              // generated token count
//     "latency_ms":  <uint32>               // wall-clock inference time (ms)
//   }
//
// Helpers that pre-date this schema send raw text after the status byte.
// Callers must tolerate missing fields (default: 0 / empty string).

// Diagnostic fields extracted from a RESULT payload.
struct HelperDiag {
    char     model[64]{};
    uint32_t tokens_in{0};
    uint32_t tokens_out{0};
    uint32_t latency_ms{0};
};

// Bounds-safe field extractor — no JSON dependency.
// data/len describe the payload *after* the leading ResultStatus byte.
inline HelperDiag parse_helper_diag(const uint8_t* data, uint32_t len) noexcept {
    HelperDiag d{};
    if (!data || len == 0) return d;

    // Returns position just after the key, or len if not found.
    auto find_key = [data, len](const char* key, uint32_t from) -> uint32_t {
        const uint32_t klen = static_cast<uint32_t>(std::strlen(key));
        if (len < klen) return len;
        for (uint32_t i = from; i + klen <= len; ++i)
            if (std::memcmp(data + i, key, klen) == 0) return i + klen;
        return len;
    };

    auto scan_str = [&](const char* key, char* out, uint32_t out_max) {
        uint32_t pos = find_key(key, 0);
        if (pos >= len) return;
        while (pos < len && (data[pos] == ' ' || data[pos] == ':')) ++pos;
        if (pos >= len || data[pos] != '"') return;
        ++pos;
        uint32_t i = 0;
        while (pos < len && data[pos] != '"' && i + 1 < out_max)
            out[i++] = static_cast<char>(data[pos++]);
        out[i] = '\0';
    };

    auto scan_uint = [&](const char* key) -> uint32_t {
        uint32_t pos = find_key(key, 0);
        if (pos >= len) return 0u;
        while (pos < len && (data[pos] == ' ' || data[pos] == ':')) ++pos;
        if (pos >= len || data[pos] < '0' || data[pos] > '9') return 0u;
        uint32_t v = 0;
        while (pos < len && data[pos] >= '0' && data[pos] <= '9')
            v = v * 10u + static_cast<uint32_t>(data[pos++] - '0');
        return v;
    };

    scan_str("\"model\"",     d.model, sizeof(d.model));
    d.tokens_in  = scan_uint("\"tokens_in\"");
    d.tokens_out = scan_uint("\"tokens_out\"");
    d.latency_ms = scan_uint("\"latency_ms\"");
    return d;
}

// ── msg_type validation helper ────────────────────────────────────────────────
// Returns true for all msg_type values defined in MsgType.
// Use this in receivers to centrally reject unknown message types before
// touching the payload (replaces ad-hoc per-handler checks).
inline bool is_known_msg_type(uint8_t t) noexcept {
    switch (t) {
        case HEARTBEAT:
        case REGISTER:
        case REGISTER_ACK:
        case BYE:
        case INVITE:
        case INVITE_ACK:
        case HEARTBEAT_ACK:
        case TASK:
        case TASK_ACK:
        case RESULT:
        case MSG_ERROR:
        case STATUS_REQUEST:
        case STATUS_RESPONSE:
        case EMBED_REQUEST:
        case EMBED_RESPONSE:
        case SIMILARITY_REQUEST:
        case SIMILARITY_RESPONSE:
        case CONSENSUS_REQUEST:
        case CONSENSUS_RESPONSE:
        case PING:
        case PONG:
            return true;
        default:
            return false;
    }
}

} // namespace linep
