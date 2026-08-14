#include "tcp.hpp"
#include "../core/framing.hpp"
#include "../pal/socket.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

namespace linep::tcp {

namespace {

bool header_log_enabled() {
    const char* v = std::getenv("LINEP_HEADER_LOG");
    return (v != nullptr) && (v[0] != '\0') && (v[0] != '0');
}

std::string format_build_time(const linep::HeaderBuildTimeExt& bt) {
    std::ostringstream os;
    os << "20";
    if (bt.year_2d < 10u) os << '0';
    os << static_cast<int>(bt.year_2d) << '-';
    if (bt.month < 10u) os << '0';
    os << static_cast<int>(bt.month) << '-';
    if (bt.day < 10u) os << '0';
    os << static_cast<int>(bt.day) << ' ';
    if (bt.hour < 10u) os << '0';
    os << static_cast<int>(bt.hour) << ':';
    if (bt.minute < 10u) os << '0';
    os << static_cast<int>(bt.minute) << ':';
    if (bt.second < 10u) os << '0';
    os << static_cast<int>(bt.second) << " UTC";
    return os.str();
}

void log_header(const char* scope,
                const linep::Header& h,
                const uint8_t* ext,
                uint16_t ext_len) {
    if (!header_log_enabled()) return;

    std::cerr << "[linep-hdr] " << scope
              << " msg_type=" << static_cast<int>(h.msg_type)
              << " hdr_len=" << h.header_len
              << " flags=0x" << std::hex << h.flags << std::dec
              << " payload_len=" << h.payload_len
              << " seq=" << h.sequence
              << " corr=" << h.correlation_id
              << " worker=" << h.worker_id
              << " slot=" << static_cast<int>(h.slot_id);

    if ((h.flags & static_cast<uint16_t>(linep::FLAG_BUILD_TIME)) != 0u) {
        linep::HeaderBuildTimeExt bt{};
        if (core::try_parse_build_time_ext(ext, ext_len, bt)) {
            std::cerr << " build_time=" << format_build_time(bt);
        } else {
            std::cerr << " build_time=<invalid ext_len=" << ext_len << ">";
        }
    }

    std::cerr << "\n" << std::flush;
}

} // namespace

// ────────────────────────────────────────────────────────────────────────────
// Task Sender implementation
// ────────────────────────────────────────────────────────────────────────────

class TcpTaskSenderImpl final : public ITcpTaskSender {
public:
    uint8_t send_task(const char*    host,
                      uint16_t       port,
                      uint8_t        task_type,
                      uint32_t       correlation_id,
                      uint16_t       worker_id,
                      uint8_t        slot_id,
                      const uint8_t* payload,
                      uint32_t       payload_len,
                      uint8_t*       result_buf,
                      uint32_t*      result_len,
                      uint32_t       timeout_ms) override
    {
        // Preserve caller-provided output capacity before clearing output length.
        const uint32_t result_cap = result_len ? *result_len : 0u;
        if (result_len) *result_len = 0u;

        pal::Socket s = pal::tcp_connect(host, port, timeout_ms);
        if (!s.valid()) return static_cast<uint8_t>(RESULT_TIMEOUT);

        // TASK wire payload layout: [1 byte task_type] [task body bytes...]
        std::vector<uint8_t> task_payload;
        task_payload.reserve(static_cast<size_t>(payload_len) + 1u);
        task_payload.push_back(task_type);
        if (payload && payload_len > 0u) {
            task_payload.insert(task_payload.end(), payload, payload + payload_len);
        }

        // ── Send TASK header ──────────────────────────────────────────────
        const auto hdr = core::make_header(
            static_cast<uint8_t>(MsgType::TASK),
            static_cast<uint16_t>(FLAG_ACK_REQUIRED),
            static_cast<uint32_t>(task_payload.size()),
            seq_++,
            correlation_id,
            worker_id,
            slot_id);
        linep::Header task_hdr = hdr;
        core::apply_build_time_extension(task_hdr);
        const linep::HeaderBuildTimeExt task_ext = core::make_build_time_ext_from_build();

        int r = pal::tcp_send_all(s,
            reinterpret_cast<const uint8_t*>(&task_hdr),
            static_cast<int>(sizeof(task_hdr)));
        if (r != static_cast<int>(sizeof(task_hdr))) {
            pal::socket_close(s);
            return static_cast<uint8_t>(RESULT_TIMEOUT);
        }

        const uint16_t task_ext_len = static_cast<uint16_t>(
            task_hdr.header_len > sizeof(linep::Header)
            ? task_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        log_header("tx TASK", task_hdr,
                   reinterpret_cast<const uint8_t*>(&task_ext),
                   task_ext_len);
        if (task_ext_len > 0u) {
            r = pal::tcp_send_all(s,
                reinterpret_cast<const uint8_t*>(&task_ext),
                static_cast<int>(task_ext_len));
            if (r != static_cast<int>(task_ext_len)) {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_TIMEOUT);
            }
        }

        if (task_hdr.header_len < sizeof(linep::Header)) {
            pal::socket_close(s);
            return static_cast<uint8_t>(RESULT_TIMEOUT);
        }

        // ── Send payload ──────────────────────────────────────────────────
        if (!task_payload.empty()) {
            r = pal::tcp_send_all(s, task_payload.data(), static_cast<int>(task_payload.size()));
            if (r != static_cast<int>(task_payload.size())) {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_TIMEOUT);
            }
        }

        // ── Receive RESULT header ─────────────────────────────────────────
        Header res_hdr{};
        r = pal::tcp_recv_all(s,
            reinterpret_cast<uint8_t*>(&res_hdr),
            static_cast<int>(sizeof(res_hdr)));
        if (r != static_cast<int>(sizeof(res_hdr)) ||
            !core::validate_header(res_hdr) ||
            res_hdr.msg_type != static_cast<uint8_t>(MsgType::RESULT) ||
            res_hdr.correlation_id != correlation_id)
        {
            pal::socket_close(s);
            return static_cast<uint8_t>(RESULT_MODEL_ERROR);
        }

        const uint16_t res_ext_len = static_cast<uint16_t>(
            res_hdr.header_len > sizeof(linep::Header)
            ? res_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        std::vector<uint8_t> res_ext;
        if (res_ext_len > 0u) {
            res_ext.resize(res_ext_len);
            r = pal::tcp_recv_all(s, res_ext.data(), static_cast<int>(res_ext.size()));
            if (r != static_cast<int>(res_ext.size())) {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_TIMEOUT);
            }
        }
        log_header("rx RESULT", res_hdr,
                   res_ext.empty() ? nullptr : res_ext.data(),
                   res_ext_len);

        // ── Receive RESULT payload ────────────────────────────────────────
        // Payload layout: [1 byte ResultStatus] [response body bytes...]
        if (res_hdr.payload_len == 0u) {
            pal::socket_close(s);
            return static_cast<uint8_t>(RESULT_MODEL_ERROR);
        }

        std::vector<uint8_t> res_payload(res_hdr.payload_len);
        r = pal::tcp_recv_all(s, res_payload.data(),
                              static_cast<int>(res_payload.size()));
        pal::socket_close(s);

        if (r != static_cast<int>(res_payload.size()))
            return static_cast<uint8_t>(RESULT_TIMEOUT);

        const uint8_t status = res_payload[0];

        if (result_buf && result_len && res_payload.size() > 1u)
        {
            const uint32_t body_len =
                static_cast<uint32_t>(res_payload.size()) - 1u;
            const uint32_t copy_len = body_len < result_cap ? body_len : result_cap;
            std::memcpy(result_buf, res_payload.data() + 1, copy_len);
            *result_len = copy_len;
        }

        return status;
    }

    uint8_t send_task_stream(const char*          host,
                              uint16_t             port,
                              uint8_t              task_type,
                              uint32_t             correlation_id,
                              uint16_t             worker_id,
                              uint8_t              slot_id,
                              const uint8_t*      payload,
                              uint32_t             payload_len,
                              StreamChunkCallback  chunk_cb,
                              void*                user_data,
                              uint32_t             timeout_ms) override
    {
        pal::Socket s = pal::tcp_connect(host, port, timeout_ms);
        if (!s.valid()) return static_cast<uint8_t>(RESULT_TIMEOUT);

        std::vector<uint8_t> task_payload;
        task_payload.reserve(static_cast<size_t>(payload_len) + 1u);
        task_payload.push_back(task_type);
        if (payload && payload_len > 0u) {
            task_payload.insert(task_payload.end(), payload, payload + payload_len);
        }

        linep::Header task_hdr = core::make_header(
            static_cast<uint8_t>(MsgType::TASK),
            static_cast<uint16_t>(FLAG_ACK_REQUIRED),
            static_cast<uint32_t>(task_payload.size()),
            seq_++,
            correlation_id,
            worker_id,
            slot_id);
        core::apply_build_time_extension(task_hdr);
        const linep::HeaderBuildTimeExt task_ext = core::make_build_time_ext_from_build();

        int r = pal::tcp_send_all(s, reinterpret_cast<const uint8_t*>(&task_hdr), static_cast<int>(sizeof(task_hdr)));
        if (r != static_cast<int>(sizeof(task_hdr))) {
            pal::socket_close(s);
            return static_cast<uint8_t>(RESULT_TIMEOUT);
        }

        const uint16_t task_ext_len = static_cast<uint16_t>(
            task_hdr.header_len > sizeof(linep::Header)
            ? task_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        log_header("tx TASK stream", task_hdr, reinterpret_cast<const uint8_t*>(&task_ext), task_ext_len);
        if (task_ext_len > 0u) {
            r = pal::tcp_send_all(s, reinterpret_cast<const uint8_t*>(&task_ext), static_cast<int>(task_ext_len));
            if (r != static_cast<int>(task_ext_len)) {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_TIMEOUT);
            }
        }

        if (!task_payload.empty()) {
            r = pal::tcp_send_all(s, task_payload.data(), static_cast<int>(task_payload.size()));
            if (r != static_cast<int>(task_payload.size())) {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_TIMEOUT);
            }
        }

        uint32_t expected_seq = 1u;
        uint8_t last_status = static_cast<uint8_t>(RESULT_OK);

        while (true) {
            Header res_hdr{};
            r = pal::tcp_recv_all(s, reinterpret_cast<uint8_t*>(&res_hdr), static_cast<int>(sizeof(res_hdr)));
            if (r != static_cast<int>(sizeof(res_hdr)) ||
                !core::validate_header(res_hdr) ||
                res_hdr.msg_type != static_cast<uint8_t>(MsgType::RESULT) ||
                res_hdr.correlation_id != correlation_id)
            {
                pal::socket_close(s);
                return static_cast<uint8_t>(RESULT_MODEL_ERROR);
            }

            const uint16_t res_ext_len = static_cast<uint16_t>(
                res_hdr.header_len > sizeof(linep::Header)
                ? res_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
                : 0u);
            if (res_ext_len > 0u) {
                std::vector<uint8_t> tmp_ext(res_ext_len);
                pal::tcp_recv_all(s, tmp_ext.data(), static_cast<int>(tmp_ext.size()));
            }

            std::vector<uint8_t> chunk_payload(res_hdr.payload_len);
            if (!chunk_payload.empty()) {
                r = pal::tcp_recv_all(s, chunk_payload.data(), static_cast<int>(chunk_payload.size()));
                if (r != static_cast<int>(chunk_payload.size())) {
                    pal::socket_close(s);
                    return static_cast<uint8_t>(RESULT_TIMEOUT);
                }
            }

            const uint8_t* chunk_body = chunk_payload.data();
            uint32_t chunk_body_len = static_cast<uint32_t>(chunk_payload.size());

            if (expected_seq == 1u && chunk_body_len > 0u) {
                last_status = chunk_body[0];
                chunk_body++;
                chunk_body_len--;
            }

            if (res_hdr.sequence < expected_seq) {
                // Duplicate chunk -> ignore duplicate chunk, wait for remaining
                if (res_hdr.flags & FLAG_FINAL_FRAGMENT) {
                    pal::socket_close(s);
                    return last_status;
                }
                continue;
            }

            expected_seq = res_hdr.sequence + 1u;

            if (chunk_cb && chunk_body_len > 0u) {
                chunk_cb(correlation_id, res_hdr.sequence, res_hdr.flags, chunk_body, chunk_body_len, user_data);
            }

            if ((res_hdr.flags & static_cast<uint16_t>(FLAG_FINAL_FRAGMENT)) != 0u) {
                pal::socket_close(s);
                return last_status;
            }
        }

        pal::socket_close(s);
        return last_status;
    }

private:
    std::atomic<uint32_t> seq_{0};
};

LINEP_API ITcpTaskSender* create_task_sender()          { return new TcpTaskSenderImpl(); }
LINEP_API void             destroy_task_sender(ITcpTaskSender* p) { delete p; }


// ────────────────────────────────────────────────────────────────────────────
// Task Receiver implementation
// ────────────────────────────────────────────────────────────────────────────

class TcpTaskReceiverImpl final : public ITcpTaskReceiver {
public:
    TcpTaskReceiverImpl() = default;
    ~TcpTaskReceiverImpl() override { stop(); }

    bool start(uint16_t port, TaskCallback cb, void* user_data) override {
        if (running_.load()) return false;
        port_            = port;
        callback_        = cb;
        stream_callback_ = nullptr;
        user_data_       = user_data;
        running_.store(true);
        accept_thread_ = std::thread(&TcpTaskReceiverImpl::accept_loop, this);
        return true;
    }

    bool start_stream(uint16_t port, StreamTaskCallback stream_cb, void* user_data) override {
        if (running_.load()) return false;
        port_            = port;
        callback_        = nullptr;
        stream_callback_ = stream_cb;
        user_data_       = user_data;
        running_.store(true);
        accept_thread_ = std::thread(&TcpTaskReceiverImpl::accept_loop, this);
        return true;
    }

    void stop() override {
        running_.store(false);
        {
            std::lock_guard<std::mutex> lk(listen_mtx_);
            pal::socket_close(listen_socket_);  // unblock blocking accept()
        }
        if (accept_thread_.joinable()) accept_thread_.join();
        // Wait for all active handlers to finish.
        std::lock_guard<std::mutex> lk(handlers_mtx_);
        for (auto& t : handlers_)
            if (t.joinable()) t.join();
        handlers_.clear();
    }

private:
    struct StreamWriterContext {
        pal::Socket          socket;
        uint32_t             correlation_id;
        uint16_t             worker_id;
        uint8_t              slot_id;
        uint32_t             seq{1};
        std::atomic<bool>*   is_cancelled;
    };

    static bool stream_writer_func(const uint8_t* chunk_payload, uint32_t chunk_len, bool is_final, void* writer_arg) {
        auto* ctx = static_cast<StreamWriterContext*>(writer_arg);
        if (!ctx || !ctx->socket.valid() || (ctx->is_cancelled && ctx->is_cancelled->load())) return false;

        uint16_t flags = static_cast<uint16_t>(linep::FLAG_FRAGMENTED);
        if (is_final) {
            flags |= static_cast<uint16_t>(linep::FLAG_FINAL_FRAGMENT);
        }

        std::vector<uint8_t> payload;
        payload.reserve(static_cast<size_t>(chunk_len) + (ctx->seq == 1u ? 1u : 0u));
        if (ctx->seq == 1u) {
            payload.push_back(static_cast<uint8_t>(linep::RESULT_OK));
        }
        if (chunk_payload && chunk_len > 0u) {
            payload.insert(payload.end(), chunk_payload, chunk_payload + chunk_len);
        }

        auto res_hdr = core::make_header(
            static_cast<uint8_t>(MsgType::RESULT),
            flags,
            static_cast<uint32_t>(payload.size()),
            ctx->seq++,
            ctx->correlation_id,
            ctx->worker_id,
            ctx->slot_id);
        core::apply_build_time_extension(res_hdr);
        const auto res_ext = core::make_build_time_ext_from_build();

        int r = pal::tcp_send_all(ctx->socket, reinterpret_cast<const uint8_t*>(&res_hdr), static_cast<int>(sizeof(res_hdr)));
        if (r != static_cast<int>(sizeof(res_hdr))) {
            if (ctx->is_cancelled) ctx->is_cancelled->store(true);
            return false;
        }

        const uint16_t res_ext_len = static_cast<uint16_t>(
            res_hdr.header_len > sizeof(linep::Header)
            ? res_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        if (res_ext_len > 0u) {
            r = pal::tcp_send_all(ctx->socket, reinterpret_cast<const uint8_t*>(&res_ext), static_cast<int>(res_ext_len));
            if (r != static_cast<int>(res_ext_len)) {
                if (ctx->is_cancelled) ctx->is_cancelled->store(true);
                return false;
            }
        }

        if (!payload.empty()) {
            r = pal::tcp_send_all(ctx->socket, payload.data(), static_cast<int>(payload.size()));
            if (r != static_cast<int>(payload.size())) {
                if (ctx->is_cancelled) ctx->is_cancelled->store(true);
                return false;
            }
        }

        return true;
    }

    // ── Accept loop ──────────────────────────────────────────────────────────
    void accept_loop() {
        pal::Socket ls = pal::tcp_listen(port_, 16);
        if (!ls.valid()) { running_.store(false); return; }
        {
            std::lock_guard<std::mutex> lk(listen_mtx_);
            listen_socket_ = ls;
        }

        pal::udp_set_recv_timeout(ls, 500u);

        while (running_.load()) {
            pal::Socket cs = pal::tcp_accept(ls);
            if (!cs.valid()) continue;

            reap_finished_handlers();
            std::lock_guard<std::mutex> lk(handlers_mtx_);
            handlers_.emplace_back(&TcpTaskReceiverImpl::handle_connection,
                                   this, cs);
        }
        pal::socket_close(ls);
        {
            std::lock_guard<std::mutex> lk(listen_mtx_);
            listen_socket_ = {};
        }
    }

    // ── Per-connection handler ────────────────────────────────────────────────
    void handle_connection(pal::Socket cs) {
        Header in_hdr{};
        int r = pal::tcp_recv_all(cs,
            reinterpret_cast<uint8_t*>(&in_hdr),
            static_cast<int>(sizeof(in_hdr)));
        if (r != static_cast<int>(sizeof(in_hdr)) ||
            !core::validate_header(in_hdr) ||
            in_hdr.msg_type != static_cast<uint8_t>(MsgType::TASK))
        {
            pal::socket_close(cs);
            return;
        }

        const uint16_t in_ext_len = static_cast<uint16_t>(
            in_hdr.header_len > sizeof(linep::Header)
            ? in_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        std::vector<uint8_t> in_ext;
        if (in_ext_len > 0u) {
            in_ext.resize(in_ext_len);
            r = pal::tcp_recv_all(cs, in_ext.data(), static_cast<int>(in_ext.size()));
            if (r != static_cast<int>(in_ext.size())) {
                pal::socket_close(cs);
                return;
            }
        }
        log_header("rx TASK", in_hdr,
                   in_ext.empty() ? nullptr : in_ext.data(),
                   in_ext_len);

        std::vector<uint8_t> payload(in_hdr.payload_len);
        if (!payload.empty()) {
            r = pal::tcp_recv_all(cs, payload.data(),
                                  static_cast<int>(payload.size()));
            if (r != static_cast<int>(payload.size())) {
                pal::socket_close(cs);
                return;
            }
        }

        uint8_t task_type = 0u;
        const uint8_t* task_body = nullptr;
        uint32_t task_body_len = 0u;
        if (!payload.empty()) {
            task_type = payload[0];
            if (payload.size() > 1u) {
                task_body = payload.data() + 1;
                task_body_len = static_cast<uint32_t>(payload.size() - 1u);
            }
        }

        if (stream_callback_) {
            std::atomic<bool> is_cancelled{false};
            StreamWriterContext ctx{cs, in_hdr.correlation_id, in_hdr.worker_id, in_hdr.slot_id, 1u, &is_cancelled};

            stream_callback_(
                task_type,
                in_hdr.correlation_id,
                in_hdr.worker_id,
                in_hdr.slot_id,
                task_body,
                task_body_len,
                stream_writer_func,
                &ctx,
                reinterpret_cast<const volatile bool*>(&is_cancelled),
                user_data_);

            pal::socket_close(cs);
            return;
        }

        std::vector<uint8_t> result_body(65536u);
        uint32_t result_len = static_cast<uint32_t>(result_body.size());

        uint8_t status = static_cast<uint8_t>(RESULT_MODEL_ERROR);
        if (callback_) {
            status = callback_(
                task_type,
                in_hdr.correlation_id,
                in_hdr.worker_id,
                in_hdr.slot_id,
                task_body,
                task_body_len,
                result_body.data(),
                static_cast<uint32_t>(result_body.size()),
                &result_len,
                user_data_);
        }

        std::vector<uint8_t> res_payload;
        res_payload.reserve(1u + result_len);
        res_payload.push_back(status);
        if (result_len > 0u)
            res_payload.insert(res_payload.end(),
                               result_body.begin(),
                               result_body.begin() + result_len);

        auto res_hdr = core::make_header(
            static_cast<uint8_t>(MsgType::RESULT),
            0u,
            static_cast<uint32_t>(res_payload.size()),
            in_hdr.sequence + 1u,
            in_hdr.correlation_id,
            in_hdr.worker_id,
            in_hdr.slot_id);
        core::apply_build_time_extension(res_hdr);
        const linep::HeaderBuildTimeExt res_ext = core::make_build_time_ext_from_build();

        pal::tcp_send_all(cs,
            reinterpret_cast<const uint8_t*>(&res_hdr),
            static_cast<int>(sizeof(res_hdr)));
        const uint16_t res_ext_len = static_cast<uint16_t>(
            res_hdr.header_len > sizeof(linep::Header)
            ? res_hdr.header_len - static_cast<uint16_t>(sizeof(linep::Header))
            : 0u);
        log_header("tx RESULT", res_hdr,
                   reinterpret_cast<const uint8_t*>(&res_ext),
                   res_ext_len);
        if (res_ext_len > 0u) {
            pal::tcp_send_all(cs,
                reinterpret_cast<const uint8_t*>(&res_ext),
                static_cast<int>(res_ext_len));
        }
        pal::tcp_send_all(cs,
            res_payload.data(),
            static_cast<int>(res_payload.size()));

        pal::socket_close(cs);
    }

    void reap_finished_handlers() {
        std::lock_guard<std::mutex> lk(handlers_mtx_);
        for (auto it = handlers_.begin(); it != handlers_.end(); ) {
            if (it->joinable()) {
                ++it;
            } else {
                it = handlers_.erase(it);
            }
        }
    }

    uint16_t             port_{0};
    TaskCallback         callback_{nullptr};
    StreamTaskCallback   stream_callback_{nullptr};
    void*                user_data_{nullptr};
    std::atomic<bool>    running_{false};
    std::thread          accept_thread_;
    std::mutex           listen_mtx_;
    pal::Socket          listen_socket_{};
    std::mutex           handlers_mtx_;
    std::vector<std::thread> handlers_;
};

LINEP_API ITcpTaskReceiver* create_task_receiver()                     { return new TcpTaskReceiverImpl(); }
LINEP_API void               destroy_task_receiver(ITcpTaskReceiver* p) { delete p; }

} // namespace linep::tcp
