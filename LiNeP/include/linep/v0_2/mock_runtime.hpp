#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "linep/v0_2/runtime_types.hpp"
#include "linep/v0_2/envelopes.hpp"
#include "linep/v0_2/session.hpp"
#include "linep/v0_2/transport.hpp"

namespace linep::v0_2 {

struct mock_runtime_config {
    std::string model_id{"linep-mock-v02"};
    std::uint32_t delay_per_event_ms{2};
    std::size_t default_tokens{10};
    bool enable_reasoning{true};
    bool delta_mode{true};
    bool snapshot_mode{false};
    std::uint32_t multi_output_count{1};
    int fail_after_n{-1}; // -1 = disabled, >= 0 = force failure after N events
    bool duplicate_event{false};
    bool out_of_order_event{false};
    bool disconnect_before_terminal{false};
    bool ignore_cancel{false};
    bool cancel_after_accept{false};
    bool slow_reader{false};
    std::size_t batch_embed_count{1};
    std::string embedding_space_id{"nomic-embed-v1.5"};
    std::uint32_t embedding_dimensions{768};
    std::size_t max_buffered_bytes_per_stream{1024 * 1024};
};

class mock_runtime_server {
public:
    explicit mock_runtime_server(mock_runtime_config config = {});
    ~mock_runtime_server();

    mock_runtime_server(const mock_runtime_server&) = delete;
    mock_runtime_server& operator=(const mock_runtime_server&) = delete;

    // Start mock runtime server listening on TCP port (0 for ephemeral OS port)
    bool start(std::uint16_t port);

    // Stop mock server and disconnect clients
    void stop();

    bool is_running() const noexcept { return running_; }
    std::uint16_t get_bound_port() const noexcept { return server_.get_bound_port(); }

    const mock_runtime_config& config() const noexcept { return config_; }
    void set_config(const mock_runtime_config& config) { config_ = config; }

private:
    void accept_loop();
    void client_loop(std::shared_ptr<envelope_connection> conn);
    void execute_stream(std::shared_ptr<envelope_connection> conn, session_manager& session, const request_envelope& req);
    void execute_single_output(std::shared_ptr<envelope_connection> conn, session_manager& session, const request_envelope& req, output_id_t output_id);

    mock_runtime_config config_;
    envelope_server server_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    mutable std::mutex conns_mutex_;
    std::vector<std::shared_ptr<envelope_connection>> active_conns_;
};

} // namespace linep::v0_2
