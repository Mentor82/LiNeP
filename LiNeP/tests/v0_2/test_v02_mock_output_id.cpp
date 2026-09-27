#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "linep/v0_2/mock_runtime.hpp"
#include "linep/v0_2/transport.hpp"

#define LINEP_TEST_CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "FAILED: " #expr " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while(0)

using namespace linep::v0_2;

// The mock numbers its output streams from the REQUEST's output_id. A REQUEST
// with output_id != 0 must see every event under that identity (or the
// output_ids that follow it for batches), and a CANCEL for it must take effect.

namespace {

std::unique_ptr<envelope_connection> connect_to(const mock_runtime_server& server) {
    auto conn = envelope_connection::connect("127.0.0.1", server.get_bound_port(), 5000);
    LINEP_TEST_CHECK(conn && conn->is_connected());
    return conn;
}

// Reads events until the terminal event of `id`; returns all events received
std::vector<event_envelope> read_until_terminal(envelope_connection& conn, const stream_identity& id) {
    std::vector<event_envelope> events;
    std::vector<std::uint8_t> raw;
    while (conn.receive_envelope_raw(raw)) {
        event_envelope evt{};
        LINEP_TEST_CHECK(decode_event(raw.data(), raw.size(), evt));
        events.push_back(evt);
        if (evt.stream == id && evt.is_terminal()) {
            return events;
        }
    }
    LINEP_TEST_CHECK(false && "connection closed before the terminal event");
    return events;
}

} // anonymous namespace

int main() {
    // 1. Generate: every event carries the requested identity; CANCEL on it works
    {
        mock_runtime_config cfg{};
        cfg.delay_per_event_ms = 2;
        cfg.default_tokens = 50;
        mock_runtime_server server(cfg);
        LINEP_TEST_CHECK(server.start(0));
        auto conn = connect_to(server);

        const stream_identity id{11, 111, 3};
        request_envelope req{id, runtime_profile::generate, cfg.model_id, "output_id test"};
        LINEP_TEST_CHECK(conn->send_request(req));

        std::vector<std::uint8_t> raw;
        std::size_t events = 0;
        bool cancelled = false;
        while (conn->receive_envelope_raw(raw)) {
            event_envelope evt{};
            LINEP_TEST_CHECK(decode_event(raw.data(), raw.size(), evt));
            LINEP_TEST_CHECK(evt.stream == id);
            if (++events == 3) {
                control_envelope ctrl{id, runtime_control_type::cancel, "output_id cancel test"};
                LINEP_TEST_CHECK(conn->send_control(ctrl));
            }
            if (evt.is_terminal()) {
                cancelled = evt.event_type == runtime_event_type::cancelled && evt.error.code == 499;
                break;
            }
        }
        LINEP_TEST_CHECK(cancelled);
        LINEP_TEST_CHECK(events < cfg.default_tokens); // stopped early, not run to completion
        server.stop();
        std::cout << "[PASS] generate: requested output_id kept, CANCEL takes effect" << std::endl;
    }

    // 2. Embed, single output: vector and terminal under the requested identity
    {
        mock_runtime_config cfg{};
        cfg.embedding_dimensions = 8;
        mock_runtime_server server(cfg);
        LINEP_TEST_CHECK(server.start(0));
        auto conn = connect_to(server);

        const stream_identity id{21, 211, 1};
        request_envelope req{id, runtime_profile::embed, cfg.model_id, "embed me"};
        LINEP_TEST_CHECK(conn->send_request(req));

        auto events = read_until_terminal(*conn, id);
        std::size_t vectors = 0;
        for (const auto& evt : events) {
            LINEP_TEST_CHECK(evt.stream == id);
            if (evt.event_type == runtime_event_type::embedding_result) {
                LINEP_TEST_CHECK(evt.embedding.vector.size() == cfg.embedding_dimensions);
                vectors++;
            }
        }
        LINEP_TEST_CHECK(vectors == 1);
        LINEP_TEST_CHECK(events.back().event_type == runtime_event_type::completed);
        server.stop();
        std::cout << "[PASS] embed: vector under the requested output_id" << std::endl;
    }

    // 3. Embed batch: outputs numbered from the requested output_id
    {
        mock_runtime_config cfg{};
        cfg.embedding_dimensions = 8;
        cfg.batch_embed_count = 3;
        mock_runtime_server server(cfg);
        LINEP_TEST_CHECK(server.start(0));
        auto conn = connect_to(server);

        const stream_identity id{31, 311, 2};
        request_envelope req{id, runtime_profile::embed, cfg.model_id, "embed batch"};
        LINEP_TEST_CHECK(conn->send_request(req));

        auto events = read_until_terminal(*conn, id);
        std::set<output_id_t> outputs;
        for (const auto& evt : events) {
            LINEP_TEST_CHECK(evt.stream.request_id == id.request_id);
            LINEP_TEST_CHECK(evt.stream.execution_id == id.execution_id);
            if (evt.event_type == runtime_event_type::embedding_result) {
                outputs.insert(evt.stream.output_id);
            }
        }
        LINEP_TEST_CHECK((outputs == std::set<output_id_t>{2, 3, 4}));
        LINEP_TEST_CHECK(events.back().stream == id);
        server.stop();
        std::cout << "[PASS] embed batch: outputs 2, 3, 4 for requested output_id 2" << std::endl;
    }

    std::cout << "\nALL MOCK OUTPUT_ID TESTS PASSED" << std::endl;
    return 0;
}
