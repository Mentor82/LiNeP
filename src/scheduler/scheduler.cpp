#include "scheduler.hpp"
#include "score_engine.hpp"
#include "../core/framing.hpp"
#include "../pal/socket.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <condition_variable>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

namespace linep::scheduler {

// ── Embedding consensus helpers ───────────────────────────────────────────────

static double cosine_similarity(const std::vector<float>& a,
                                const std::vector<float>& b)
{
    if (a.empty() || a.size() != b.size()) return 0.0;
    double dot = 0.0, na = 0.0, nb = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        dot += static_cast<double>(a[i]) * static_cast<double>(b[i]);
        na  += static_cast<double>(a[i]) * static_cast<double>(a[i]);
        nb  += static_cast<double>(b[i]) * static_cast<double>(b[i]);
    }
    const double denom = std::sqrt(na) * std::sqrt(nb);
    return (denom > 1e-12) ? (dot / denom) : 0.0;
}

// Returns index of the partial result most similar to all others.
// Falls back to 0 if EmbedFn is null or returns 0 dims for any payload.
static size_t consensus_pick(const std::vector<std::vector<uint8_t>>& payloads,
                             EmbedFn embed_fn, void* embed_user_data)
{
    if (payloads.size() <= 1u || embed_fn == nullptr) return 0u;

    static constexpr uint32_t MAX_DIMS = 4096u;
    std::vector<std::vector<float>> vecs;
    vecs.reserve(payloads.size());

    for (const auto& p : payloads) {
        std::vector<float> vec(MAX_DIMS, 0.0f);
        uint32_t dims = MAX_DIMS;
        const std::string text(reinterpret_cast<const char*>(p.data()), p.size());
        embed_fn(text.c_str(), vec.data(), &dims, embed_user_data);
        if (dims == 0u) return 0u;   // embedding failed — skip consensus
        vec.resize(dims);
        vecs.push_back(std::move(vec));
    }

    size_t best = 0u;
    double best_score = -1.0;
    for (size_t i = 0; i < vecs.size(); ++i) {
        double sum = 0.0;
        for (size_t j = 0; j < vecs.size(); ++j)
            if (i != j) sum += cosine_similarity(vecs[i], vecs[j]);
        const double avg = sum / static_cast<double>(vecs.size() - 1u);
        if (avg > best_score) { best_score = avg; best = i; }
    }
    std::fprintf(stderr, "[scheduler] consensus_embedding best=%zu score=%.4f\n",
                 best, best_score);
    return best;
}

class SchedulerImpl final : public IScheduler {
public:
    static constexpr uint32_t PENDING_QUEUE_CAPACITY = 256u;

    SchedulerImpl()  = default;
    ~SchedulerImpl() override { stop(); }

    // ── IScheduler ────────────────────────────────────────────────────────────

    void register_slot(uint16_t wid, uint8_t sid,
                       linep::TaskType t,
                       const char* ip, uint16_t tcp_port) override
    {
        const SlotKey key{wid, sid};
        std::lock_guard<std::mutex> lk(slots_mu_);
        auto& slot    = slots_[key];
        slot.worker_id = wid;
        slot.slot_id   = sid;
        slot.type      = t;
        slot.tcp_port  = tcp_port;
        std::strncpy(slot.ip, ip, sizeof(slot.ip) - 1u);
    }

    void apply_heartbeat(const linep::HeartbeatCompact& hb) override
    {
        const SlotKey key{hb.worker_id, hb.slot_id};
        std::lock_guard<std::mutex> lk(slots_mu_);
        const bool is_new = (slots_.find(key) == slots_.end());
        auto& slot     = slots_[key];
        slot.worker_id = hb.worker_id;
        slot.slot_id   = hb.slot_id;
        if (is_new)
            slot.conn_state = ConnectionState::SEEN;  // must complete invite/ack before dispatch
        linep::scheduler::apply_heartbeat(slot, hb);
    }

    uint32_t submit(linep::TaskType  type,
                    const uint8_t*   payload, uint32_t len,
                    uint32_t         timeout_ms, uint32_t max_attempts,
                    ResultCallback   callback,   void* user_data) override
    {
        const uint32_t corr_id = corr_gen_.fetch_add(1u);
        PendingTask t;
        t.correlation_id = corr_id;
        t.type           = type;
        t.payload.assign(payload, payload + len);
        t.timeout_ms     = timeout_ms;
        t.max_attempts   = max_attempts;
        t.callback       = callback;
        t.user_data      = user_data;

        if (!enqueue_pending(std::move(t))) {
            if (callback) {
                callback(corr_id,
                         linep::RESULT_REJECTED,
                         nullptr,
                         0u,
                         user_data);
            }
        }

        return corr_id;
    }

    void set_embedding_fn(EmbedFn fn, void* user_data) override
    {
        embed_fn_        = fn;
        embed_user_data_ = user_data;
    }

    bool start() override
    {
        if (running_.exchange(true)) return false;
        pal::net_init();
        loop_thread_ = std::thread(&SchedulerImpl::run_loop, this);
        return true;
    }

    void stop() override
    {
        if (!running_.exchange(false)) return;
        pending_cv_.notify_all();
        if (loop_thread_.joinable()) loop_thread_.join();
        // Wait for all in-flight dispatch threads.
        while (active_dispatch_count_.load() > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        pal::net_cleanup();
    }

private:

    bool enqueue_pending(PendingTask task)
    {
        if (!pending_.push(std::move(task))) {
            std::fprintf(stderr,
                         "[scheduler] pending_queue_full cap=%u backpressure=1\n",
                         PENDING_QUEUE_CAPACITY);
            return false;
        }
        pending_cv_.notify_one();
        return true;
    }

    struct PartialResult {
        SlotKey              slot{};
        linep::ResultStatus  status{linep::RESULT_TIMEOUT};
        std::vector<uint8_t> payload;
        linep::HelperDiag    diag{};  // extracted from RESULT JSON (model/tokens/latency)
    };

    struct SharedDispatchState {
        PendingTask                 task;
        std::atomic<bool>           done{false};
        std::mutex                  result_lock;
        std::vector<PartialResult>  partial_results;
        std::atomic<int>            remaining{0};
    };

    // ── Main loop ─────────────────────────────────────────────────────────────

    void run_loop()
    {
        while (running_.load()) {
            const auto now = std::chrono::steady_clock::now();
            expire_stale(now);
            dispatch_pending(now);
            std::unique_lock<std::mutex> lk(wait_mu_);
            pending_cv_.wait_for(lk, std::chrono::milliseconds(10));
        }
    }

    void expire_stale(std::chrono::steady_clock::time_point now)
    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        for (auto& [key, slot] : slots_) {
            if (slot.last_heartbeat != std::chrono::steady_clock::time_point{} &&
                now > slot.last_heartbeat + HEARTBEAT_TIMEOUT)
            {
                expire_slot(slot);
            }
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    void dispatch_pending(std::chrono::steady_clock::time_point now)
    {
        // Drain queue first, then process without locks.
        std::vector<PendingTask> snapshot;
        snapshot.reserve(16);
        while (true) {
            std::optional<PendingTask> item = pending_.pop();
            if (!item.has_value()) break;
            snapshot.push_back(std::move(item.value()));
        }
        if (snapshot.empty()) return;

        for (auto& task : snapshot) {
            std::vector<SlotKey> selected;
            std::vector<double> selected_scores;
            {
                std::lock_guard<std::mutex> sl(slots_mu_);
                selected = select_best_slots(slots_, task.type, now, 3);
                selected_scores.reserve(selected.size());
                for (const auto& key : selected) {
                    auto it = slots_.find(key);
                    if (it == slots_.end()) continue;
                    selected_scores.push_back(score_slot(it->second));
                    it->second.busy = true;
                    it->second.last_used = now;
                }
            }

            if (selected.empty()) {
                std::fprintf(stderr,
                             "[scheduler] corr=%u eligible_slots=0 fallback=0 reject=ERR_NO_SLOT_AVAILABLE\n",
                             task.correlation_id);
                if (task.callback) {
                    task.callback(task.correlation_id,
                                  linep::RESULT_REJECTED,
                                  nullptr,
                                  0u,
                                  task.user_data);
                }
                continue;
            }

            std::fprintf(stderr,
                         "[scheduler] corr=%u dispatch_slots=%zu fallback=%zu scores=",
                         task.correlation_id,
                         selected.size(),
                         selected.size());
            for (size_t i = 0; i < selected_scores.size(); ++i) {
                std::fprintf(stderr,
                             "%s%.2f",
                             (i == 0u ? "" : ","),
                             selected_scores[i]);
            }
            std::fprintf(stderr, "\n");

            auto shared = std::make_shared<SharedDispatchState>();
            shared->task = task;
            shared->task.attempt_count++;
            shared->remaining.store(static_cast<int>(selected.size()));

            for (const auto& slot : selected) {
                ActiveTask at;
                at.task          = shared->task;
                at.assigned_slot = slot;
                at.started_at    = now;

                active_dispatch_count_.fetch_add(1);
                std::thread(&SchedulerImpl::dispatch_one_slot,
                            this,
                            std::move(at),
                            shared).detach();
            }
        }
    }

    bool complete_task_if_first(const std::shared_ptr<SharedDispatchState>& shared,
                                linep::ResultStatus status,
                                const std::vector<uint8_t>& payload)
    {
        bool expected = false;
        if (!shared->done.compare_exchange_strong(expected, true))
            return false;

        if (shared->task.callback) {
            shared->task.callback(shared->task.correlation_id,
                                  status,
                                  payload.empty() ? nullptr : payload.data(),
                                  static_cast<uint32_t>(payload.size()),
                                  shared->task.user_data);
        }
        return true;
    }

    void on_slot_transport_failure(const SlotKey& key)
    {
        std::lock_guard<std::mutex> lk(slots_mu_);
        auto it = slots_.find(key);
        if (it != slots_.end()) {
            it->second.busy = false;
            it->second.timeout_count++;
            it->second.cooldown_until =
                std::chrono::steady_clock::now() +
                cooldown_for(it->second.timeout_count);
        }
    }

    bool dispatch_transport(ActiveTask at, PartialResult& out)
    {
        // Capture endpoint before touching the slot registry.
        std::string  ip;
        uint16_t     tcp_port = 0u;
        {
            std::lock_guard<std::mutex> lk(slots_mu_);
            auto it = slots_.find(at.assigned_slot);
            if (it == slots_.end()) {
                return false;
            }
            ip       = it->second.ip;
            tcp_port = it->second.tcp_port;
        }

        pal::Socket c = pal::tcp_connect(ip.c_str(), tcp_port, at.task.timeout_ms);
        if (!c.valid()) {
            on_slot_transport_failure(at.assigned_slot);
            return false;
        }

        // Send TASK header + payload.
        const auto h = core::make_header(
            static_cast<uint8_t>(linep::MsgType::TASK),
            0u,
            static_cast<uint32_t>(at.task.payload.size()),
            at.task.correlation_id,
            at.task.correlation_id,
            at.assigned_slot.worker_id,
            at.assigned_slot.slot_id);

        if (pal::tcp_send_all(c,
                reinterpret_cast<const uint8_t*>(&h),
                static_cast<int>(sizeof(h))) != static_cast<int>(sizeof(h))) {
            pal::socket_close(c);
            on_slot_transport_failure(at.assigned_slot);
            return false;
        }
        if (!at.task.payload.empty()) {
            if (pal::tcp_send_all(c,
                    at.task.payload.data(),
                    static_cast<int>(at.task.payload.size()))
                        != static_cast<int>(at.task.payload.size())) {
                pal::socket_close(c);
                on_slot_transport_failure(at.assigned_slot);
                return false;
            }
        }

        // Receive response header.
        linep::Header res_h{};
        int r = pal::tcp_recv_all(c,
                    reinterpret_cast<uint8_t*>(&res_h),
                    static_cast<int>(sizeof(res_h)));
        if (r != static_cast<int>(sizeof(res_h)) || !core::validate_header(res_h)) {
            pal::socket_close(c);
            on_slot_transport_failure(at.assigned_slot);
            return false;
        }

        std::vector<uint8_t> res_payload(res_h.payload_len);
        if (!res_payload.empty()) {
            r = pal::tcp_recv_all(c,
                        res_payload.data(),
                        static_cast<int>(res_payload.size()));
            if (r != static_cast<int>(res_payload.size())) {
                pal::socket_close(c);
                on_slot_transport_failure(at.assigned_slot);
                return false;
            }
        }
        pal::socket_close(c);

        // Parse ResultStatus from first payload byte (as per framing convention).
        linep::ResultStatus status = linep::RESULT_OK;
        if (!res_payload.empty()) {
            status = static_cast<linep::ResultStatus>(res_payload[0]);
            res_payload.erase(res_payload.begin());
        }
        if (res_h.msg_type == static_cast<uint8_t>(linep::MsgType::MSG_ERROR))
            status = linep::RESULT_MODEL_ERROR;

        // Extract diagnostic fields from RESULT JSON payload.
        const linep::HelperDiag diag = linep::parse_helper_diag(
            res_payload.empty() ? nullptr : res_payload.data(),
            static_cast<uint32_t>(res_payload.size()));
        std::fprintf(stderr,
                     "[scheduler] corr=%u worker=%u slot=%u status=%u "
                     "model=%s tokens_in=%u tokens_out=%u latency_ms=%u\n",
                     at.task.correlation_id,
                     at.assigned_slot.worker_id,
                     at.assigned_slot.slot_id,
                     static_cast<unsigned>(status),
                     diag.model[0] ? diag.model : "(unknown)",
                     diag.tokens_in,
                     diag.tokens_out,
                     diag.latency_ms);

        // Mark slot no longer busy, increment success counter.
        {
            std::lock_guard<std::mutex> lk(slots_mu_);
            auto it = slots_.find(at.assigned_slot);
            if (it != slots_.end()) {
                it->second.busy = false;
                it->second.success_count++;
            }
        }

        out.slot    = at.assigned_slot;
        out.status  = status;
        out.payload = std::move(res_payload);
        out.diag    = diag;
        return true;
    }

    void dispatch_one_slot(ActiveTask at, std::shared_ptr<SharedDispatchState> shared)
    {
        PartialResult partial{};
        if (dispatch_transport(at, partial)) {
            {
                std::lock_guard<std::mutex> lk(shared->result_lock);
                shared->partial_results.push_back(partial);
            }

            if (partial.status == linep::RESULT_OK) {
                complete_task_if_first(shared, partial.status, partial.payload);
            }
        }

        if (shared->remaining.fetch_sub(1) == 1) {
            if (!shared->done.load()) {
                std::vector<PartialResult> results;
                {
                    std::lock_guard<std::mutex> lk(shared->result_lock);
                    results = shared->partial_results;
                }

                if (!results.empty()) {
                    // Collect RESULT_OK payloads for consensus.
                    std::vector<const PartialResult*> ok_results;
                    for (const auto& r : results)
                        if (r.status == linep::RESULT_OK) ok_results.push_back(&r);

                    const int ok_count = static_cast<int>(ok_results.size());
                    const int consensus_level = (ok_count >= 3) ? 2 : ((ok_count >= 2) ? 1 : 0);
                    std::fprintf(stderr,
                                 "[scheduler] corr=%u consensus_level=%d ok=%d partial_results=%zu\n",
                                 shared->task.correlation_id,
                                 consensus_level,
                                 ok_count,
                                 results.size());

                    const PartialResult* chosen = nullptr;
                    if (ok_count >= 2) {
                        // Try embedding-based consensus.
                        std::vector<std::vector<uint8_t>> payloads;
                        payloads.reserve(ok_results.size());
                        for (const auto* r : ok_results) payloads.push_back(r->payload);
                        const size_t idx = consensus_pick(payloads,
                                                          embed_fn_,
                                                          embed_user_data_);
                        chosen = ok_results[idx];
                    } else if (ok_count == 1) {
                        chosen = ok_results[0];
                    } else {
                        chosen = &results.front();
                    }
                    std::fprintf(stderr,
                                 "[scheduler] corr=%u chosen worker=%u slot=%u "
                                 "model=%s tokens_in=%u tokens_out=%u latency_ms=%u\n",
                                 shared->task.correlation_id,
                                 chosen->slot.worker_id,
                                 chosen->slot.slot_id,
                                 chosen->diag.model[0] ? chosen->diag.model : "(unknown)",
                                 chosen->diag.tokens_in,
                                 chosen->diag.tokens_out,
                                 chosen->diag.latency_ms);
                    complete_task_if_first(shared, chosen->status, chosen->payload);
                } else if (shared->task.attempt_count < shared->task.max_attempts) {
                    if (!enqueue_pending(shared->task)) {
                        complete_task_if_first(shared, linep::RESULT_REJECTED, {});
                    }
                } else {
                    complete_task_if_first(shared, linep::RESULT_TIMEOUT, {});
                }
            }
        }

        active_dispatch_count_.fetch_sub(1);
    }

    // ── State ─────────────────────────────────────────────────────────────────

    std::map<SlotKey, SlotState> slots_;
    mutable std::mutex           slots_mu_;

    BoundedMpscQueue<PendingTask, PENDING_QUEUE_CAPACITY> pending_;
    std::condition_variable                                pending_cv_;
    std::mutex                                             wait_mu_;

    std::atomic<bool>     running_{false};
    std::atomic<int>      active_dispatch_count_{0};
    std::thread           loop_thread_;
    std::atomic<uint32_t> corr_gen_{1u};

    // Embedding provider for consensus — injected by orchestrator.
    EmbedFn  embed_fn_        = nullptr;
    void*    embed_user_data_ = nullptr;
};

// ── Factory ───────────────────────────────────────────────────────────────────

IScheduler* create_scheduler()            { return new SchedulerImpl(); }
void         destroy_scheduler(IScheduler* p) { delete p; }

} // namespace linep::scheduler
