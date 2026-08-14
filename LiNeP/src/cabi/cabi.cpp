#include <linep/cabi.h>

// Internal C++ headers
#include <linep/framing.hpp>
#include <linep/tcp.hpp>
#include <linep/messages.hpp>
#include "../pal/socket.hpp"
#include "../core/crc.hpp"

#include <cstring>
#include <cstdlib>
#include <cassert>
#include <vector>

// ── Layout sanity checks ─────────────────────────────────────────────────────
// These catch any divergence between the C structs in cabi.h and the
// packed C++ structs in types.hpp at compile time.
static_assert(sizeof(linep_header_t)            == sizeof(linep::Header),
              "linep_header_t / linep::Header size mismatch");
static_assert(sizeof(linep_heartbeat_compact_t) == sizeof(linep::HeartbeatCompact),
              "linep_heartbeat_compact_t / linep::HeartbeatCompact size mismatch");
static_assert(sizeof(linep_build_time_ext_t)    == sizeof(linep::HeaderBuildTimeExt),
              "linep_build_time_ext_t / linep::HeaderBuildTimeExt size mismatch");

// ── Opaque handle types ───────────────────────────────────────────────────────
// The C structs are forward-declared in cabi.h; the definitions live here.
struct linep_sender_s {
    linep::tcp::ITcpTaskSender* impl;
};

struct linep_receiver_s {
    linep::tcp::ITcpTaskReceiver* impl;
};

// ── Helper: map ITcpTaskSender return value to LINEP_C_* code ────────────────
// send_task() returns a ResultStatus byte on success, or a sentinel for errors.
// The C++ implementation uses specific ResultStatus values to signal transport
// failures (RESULT_TIMEOUT), and returns RESULT_OK (0) on full success.
// We pass the ResultStatus byte through as a positive value embedded in a
// non-negative int; only transport errors map to negative LINEP_C_ERR codes.
//
// Convention chosen here: if the C++ call returns any valid ResultStatus (0–5),
// we store that in the out-of-band "status" byte (leading byte of result_buf)
// and return LINEP_C_OK so the Python caller can inspect it separately.
// RESULT_TIMEOUT from the underlying layer maps to LINEP_C_ERR_TIMEOUT.

extern "C" {

// ── Network lifecycle ─────────────────────────────────────────────────────────

void linep_net_init(void) {
    linep::pal::net_init();
}

uint32_t linep_get_abi_version(void) {
    return LINEP_C_ABI_VERSION_V0_1_0;
}

void linep_net_cleanup(void) {
    linep::pal::net_cleanup();
}

// ── CRC ───────────────────────────────────────────────────────────────────────

uint8_t linep_crc8(const uint8_t* data, uint32_t len) {
    if (!data) return 0u;
    return linep::core::crc8(data, static_cast<size_t>(len));
}

// ── Framing — Header ──────────────────────────────────────────────────────────

int linep_make_header(
    uint8_t         msg_type,
    uint16_t        flags,
    uint32_t        payload_len,
    uint32_t        sequence,
    uint32_t        correlation_id,
    uint16_t        worker_id,
    uint8_t         slot_id,
    linep_header_t* out)
{
    if (!out) return LINEP_C_ERR_ARG;

    linep::Header h = linep::core::make_header(
        msg_type, flags, payload_len, sequence, correlation_id, worker_id, slot_id);

    static_assert(sizeof(*out) == sizeof(h), "header size check");
    std::memcpy(out, &h, sizeof(h));
    return LINEP_C_OK;
}

int linep_apply_build_time_ext(
    linep_header_t*         header,
    linep_build_time_ext_t* ext_out)
{
    if (!header || !ext_out) return LINEP_C_ERR_ARG;

    linep::Header h{};
    std::memcpy(&h, header, sizeof(h));

    linep::core::apply_build_time_extension(h);
    linep::HeaderBuildTimeExt ext = linep::core::make_build_time_ext_from_build();

    std::memcpy(header, &h, sizeof(h));
    std::memcpy(ext_out, &ext, sizeof(ext));
    return LINEP_C_OK;
}

int linep_validate_header(const linep_header_t* h) {
    if (!h) return LINEP_C_ERR_ARG;

    linep::Header cpp_h{};
    std::memcpy(&cpp_h, h, sizeof(cpp_h));
    return linep::core::validate_header(cpp_h) ? LINEP_C_OK : LINEP_C_ERR_BAD_FRAME;
}

// ── Framing — HeartbeatCompact ────────────────────────────────────────────────

int linep_make_heartbeat_compact(
    uint16_t                   worker_id,
    uint8_t                    slot_id,
    uint8_t                    slot_flags,
    uint8_t                    load,
    uint8_t                    queue_depth,
    uint8_t                    sequence,
    uint16_t                   worker_score,
    uint8_t                    ts_month,
    uint8_t                    ts_day,
    uint8_t                    ts_hour,
    uint8_t                    ts_minute,
    uint8_t                    ts_second,
    linep_heartbeat_compact_t* out)
{
    if (!out) return LINEP_C_ERR_ARG;

    linep::HeartbeatCompact hb = linep::core::make_heartbeat_compact(
        worker_id, slot_id, slot_flags, load, queue_depth, sequence,
        worker_score, ts_month, ts_day, ts_hour, ts_minute, ts_second);

    static_assert(sizeof(*out) == sizeof(hb), "heartbeat size check");
    std::memcpy(out, &hb, sizeof(hb));
    return LINEP_C_OK;
}

int linep_validate_heartbeat_compact(const linep_heartbeat_compact_t* h) {
    if (!h) return LINEP_C_ERR_ARG;

    linep::HeartbeatCompact hb{};
    std::memcpy(&hb, h, sizeof(hb));
    return linep::core::validate_heartbeat_compact(hb) ? LINEP_C_OK : LINEP_C_ERR_BAD_FRAME;
}

// ── Framing — UDP Control Frames ──────────────────────────────────────────────

static_assert(sizeof(linep_udp_invite_t)        == sizeof(linep::UdpInviteFrame),
              "linep_udp_invite_t size mismatch");
static_assert(sizeof(linep_udp_invite_ack_t)    == sizeof(linep::UdpInviteAckFrame),
              "linep_udp_invite_ack_t size mismatch");
static_assert(sizeof(linep_udp_heartbeat_ack_t) == sizeof(linep::UdpHeartbeatAckFrame),
              "linep_udp_heartbeat_ack_t size mismatch");

int linep_make_udp_invite(
    uint8_t             invite_seq,
    uint16_t            worker_id,
    uint8_t             slot_id,
    uint32_t            lease_ttl_ms,
    uint32_t            session_token,
    linep_udp_invite_t* out)
{
    if (!out) return LINEP_C_ERR_ARG;
    linep::UdpInviteFrame inv = linep::core::make_udp_invite(
        invite_seq, worker_id, slot_id, lease_ttl_ms, session_token);
    std::memcpy(out, &inv, sizeof(inv));
    return LINEP_C_OK;
}

int linep_validate_udp_invite(const linep_udp_invite_t* f) {
    if (!f) return LINEP_C_ERR_ARG;
    linep::UdpInviteFrame inv{};
    std::memcpy(&inv, f, sizeof(inv));
    return linep::core::validate_udp_invite(inv) ? LINEP_C_OK : LINEP_C_ERR_BAD_FRAME;
}

int linep_make_udp_invite_ack(
    uint8_t                 invite_seq,
    uint16_t                worker_id,
    uint8_t                 slot_id,
    uint8_t                 accepted,
    uint32_t                session_token,
    linep_udp_invite_ack_t* out)
{
    if (!out) return LINEP_C_ERR_ARG;
    linep::UdpInviteAckFrame ack = linep::core::make_udp_invite_ack(
        invite_seq, worker_id, slot_id, accepted, session_token);
    std::memcpy(out, &ack, sizeof(ack));
    return LINEP_C_OK;
}

int linep_validate_udp_invite_ack(const linep_udp_invite_ack_t* f) {
    if (!f) return LINEP_C_ERR_ARG;
    linep::UdpInviteAckFrame ack{};
    std::memcpy(&ack, f, sizeof(ack));
    return linep::core::validate_udp_invite_ack(ack) ? LINEP_C_OK : LINEP_C_ERR_BAD_FRAME;
}

int linep_make_udp_heartbeat_ack(
    uint8_t                    heartbeat_seq,
    uint16_t                   worker_id,
    uint8_t                    slot_id,
    uint32_t                   scheduler_time_sec,
    linep_udp_heartbeat_ack_t* out)
{
    if (!out) return LINEP_C_ERR_ARG;
    linep::UdpHeartbeatAckFrame hb_ack = linep::core::make_udp_heartbeat_ack(
        heartbeat_seq, worker_id, slot_id, scheduler_time_sec);
    std::memcpy(out, &hb_ack, sizeof(hb_ack));
    return LINEP_C_OK;
}

int linep_validate_udp_heartbeat_ack(const linep_udp_heartbeat_ack_t* f) {
    if (!f) return LINEP_C_ERR_ARG;
    linep::UdpHeartbeatAckFrame hb_ack{};
    std::memcpy(&hb_ack, f, sizeof(hb_ack));
    return linep::core::validate_udp_heartbeat_ack(hb_ack) ? LINEP_C_OK : LINEP_C_ERR_BAD_FRAME;
}

// ── TCP Task Sender ───────────────────────────────────────────────────────────

linep_sender_t* linep_sender_create(void) {
    linep::tcp::ITcpTaskSender* impl = linep::tcp::create_task_sender();
    if (!impl) return nullptr;
    linep_sender_t* handle = static_cast<linep_sender_t*>(
        std::malloc(sizeof(linep_sender_t)));
    if (!handle) {
        linep::tcp::destroy_task_sender(impl);
        return nullptr;
    }
    handle->impl = impl;
    return handle;
}

void linep_sender_destroy(linep_sender_t* s) {
    if (!s) return;
    linep::tcp::destroy_task_sender(s->impl);
    std::free(s);
}

int linep_sender_send_task(
    linep_sender_t* s,
    const char*     host,
    uint16_t        port,
    uint8_t         task_type,
    uint32_t        correlation_id,
    uint16_t        worker_id,
    uint8_t         slot_id,
    const uint8_t*  payload,
    uint32_t        payload_len,
    uint8_t*        result_buf,
    uint32_t*       result_len,
    uint32_t        timeout_ms)
{
    if (!s || !host || !result_buf || !result_len) return LINEP_C_ERR_ARG;

    const uint32_t cap = *result_len;
    if (cap == 0u) return LINEP_C_ERR_BUF_SMALL;

    const uint32_t body_cap = cap - 1u;
    std::vector<uint8_t> body_tmp(body_cap);
    uint32_t body_len = body_cap;

    uint8_t status = s->impl->send_task(
        host, port, task_type, correlation_id, worker_id, slot_id,
        payload, payload_len,
        body_tmp.empty() ? nullptr : body_tmp.data(),
        &body_len,
        timeout_ms);

    // RESULT_TIMEOUT from the wire layer maps to a transport-level error code
    // so Python can distinguish "connected but timed out waiting for result"
    // from a successful (but e.g. rejected) response.
    if (status == linep::RESULT_TIMEOUT) return LINEP_C_ERR_TIMEOUT;

    // C-ABI contract: result_buf always starts with ResultStatus byte,
    // followed by optional body bytes.
    result_buf[0] = status;
    if (body_len > 0u && !body_tmp.empty()) {
        std::memcpy(result_buf + 1, body_tmp.data(), body_len);
    }
    *result_len = 1u + body_len;

    return LINEP_C_OK;
}

// ── TCP Task Receiver ─────────────────────────────────────────────────────────

linep_receiver_t* linep_receiver_create(void) {
    linep::tcp::ITcpTaskReceiver* impl = linep::tcp::create_task_receiver();
    if (!impl) return nullptr;
    linep_receiver_t* handle = static_cast<linep_receiver_t*>(
        std::malloc(sizeof(linep_receiver_t)));
    if (!handle) {
        linep::tcp::destroy_task_receiver(impl);
        return nullptr;
    }
    handle->impl = impl;
    return handle;
}

void linep_receiver_destroy(linep_receiver_t* r) {
    if (!r) return;
    // stop() is idempotent; safe to call even if never started.
    r->impl->stop();
    linep::tcp::destroy_task_receiver(r->impl);
    std::free(r);
}

int linep_receiver_start(
    linep_receiver_t* r,
    uint16_t          port,
    linep_task_cb_t   cb,
    void*             user_data)
{
    if (!r || !cb) return LINEP_C_ERR_ARG;

    // linep_task_cb_t has identical signature to ITcpTaskReceiver::TaskCallback.
    auto cpp_cb = reinterpret_cast<linep::tcp::ITcpTaskReceiver::TaskCallback>(
        reinterpret_cast<void*>(cb));

    bool ok = r->impl->start(port, cpp_cb, user_data);
    return ok ? LINEP_C_OK : LINEP_C_ERR_PORT;
}

void linep_receiver_stop(linep_receiver_t* r) {
    if (!r) return;
    r->impl->stop();
}

int linep_sender_set_sl1_session(
    linep_sender_t* s,
    uint32_t        session_id,
    uint16_t        key_id,
    const uint8_t*  secret_key,
    uint32_t        key_len)
{
    if (!s) return LINEP_C_ERR_ARG;
    s->impl->set_sl1_session(session_id, key_id, secret_key, key_len);
    return LINEP_C_OK;
}

void linep_sender_clear_sl1_session(linep_sender_t* s) {
    if (!s) return;
    s->impl->clear_sl1_session();
}

int linep_receiver_set_sl1_session(
    linep_receiver_t* r,
    uint32_t        session_id,
    uint16_t        key_id,
    const uint8_t*  secret_key,
    uint32_t        key_len,
    int             require_auth)
{
    if (!r) return LINEP_C_ERR_ARG;
    r->impl->set_sl1_session(session_id, key_id, secret_key, key_len, require_auth != 0);
    return LINEP_C_OK;
}

void linep_receiver_clear_sl1_session(linep_receiver_t* r) {
    if (!r) return;
    r->impl->clear_sl1_session();
}

} // extern "C"
