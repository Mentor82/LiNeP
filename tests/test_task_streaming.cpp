#include "../src/tcp/tcp.hpp"
#include "../src/pal/socket.hpp"
#include "../src/pal/clock.hpp"
#include <linep/types.hpp>
#include <linep/messages.hpp>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::vector<std::string> g_received_chunks;
static bool g_stream_finished = false;

static void on_chunk_received(uint32_t correlation_id,
                               uint32_t sequence,
                               uint16_t flags,
                               const uint8_t* payload,
                               uint32_t len,
                               void* user_data)
{
    (void)correlation_id;
    (void)sequence;
    (void)user_data;
    g_received_chunks.emplace_back(reinterpret_cast<const char*>(payload), len);
    if ((flags & static_cast<uint16_t>(linep::FLAG_FINAL_FRAGMENT)) != 0u) {
        g_stream_finished = true;
    }
}

static uint8_t stream_server_handler(uint8_t task_type,
                                      uint32_t correlation_id,
                                      uint16_t worker_id,
                                      uint8_t slot_id,
                                      const uint8_t* payload,
                                      uint32_t payload_len,
                                      linep::tcp::ITcpTaskReceiver::ChunkWriterCallback writer,
                                      void* writer_arg,
                                      const volatile bool* is_cancelled,
                                      void* user_data)
{
    (void)task_type;
    (void)correlation_id;
    (void)worker_id;
    (void)slot_id;
    (void)payload;
    (void)payload_len;
    (void)user_data;

    const char* chunks[] = {"Hello ", "from ", "LiNeP ", "Streaming!"};
    const size_t num_chunks = 4;

    for (size_t i = 0; i < num_chunks; ++i) {
        if (is_cancelled && *is_cancelled) {
            return static_cast<uint8_t>(linep::RESULT_REJECTED);
        }
        bool is_final = (i == num_chunks - 1);
        bool ok = writer(reinterpret_cast<const uint8_t*>(chunks[i]),
                         static_cast<uint32_t>(std::strlen(chunks[i])),
                         is_final,
                         writer_arg);
        if (!ok) return static_cast<uint8_t>(linep::RESULT_MODEL_ERROR);
    }

    return static_cast<uint8_t>(linep::RESULT_OK);
}

static void test_streaming_roundtrip() {
    linep::pal::net_init();

    auto* receiver = linep::tcp::create_task_receiver();
    const uint16_t port = 9123;
    bool ok = receiver->start_stream(port, stream_server_handler, nullptr);
    assert(ok);

    linep::pal::sleep_ms(50); // wait for server to start listening

    auto* sender = linep::tcp::create_task_sender();
    const char* prompt = "Test Prompt";
    g_received_chunks.clear();
    g_stream_finished = false;

    uint8_t status = sender->send_task_stream(
        "127.0.0.1", port,
        static_cast<uint8_t>(linep::TASK_INSTRUCT),
        /*correlation_id*/ 777u,
        /*worker_id*/ 1u,
        /*slot_id*/ 0u,
        reinterpret_cast<const uint8_t*>(prompt),
        static_cast<uint32_t>(std::strlen(prompt)),
        on_chunk_received,
        nullptr,
        /*timeout_ms*/ 3000);

    assert(status == static_cast<uint8_t>(linep::RESULT_OK));
    assert(g_received_chunks.size() == 4);
    assert(g_received_chunks[0] == "Hello ");
    assert(g_received_chunks[1] == "from ");
    assert(g_received_chunks[2] == "LiNeP ");
    assert(g_received_chunks[3] == "Streaming!");
    assert(g_stream_finished == true);

    receiver->stop();
    linep::tcp::destroy_task_receiver(receiver);
    linep::tcp::destroy_task_sender(sender);
    linep::pal::net_cleanup();
}

int main() {
    test_streaming_roundtrip();
    std::puts("[PASS] test_task_streaming");
    return 0;
}
