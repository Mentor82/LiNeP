#ifndef LINEP_SL_CABI_SL_H
#define LINEP_SL_CABI_SL_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #if defined(LINEP_SL_BUILDING_DLL)
    #define LINEP_SL_API __declspec(dllexport)
  #else
    #define LINEP_SL_API __declspec(dllimport)
  #endif
#else
  #define LINEP_SL_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Capability bitmasks */
#define LINEP_CAP_NONE            0x00ULL
#define LINEP_CAP_INFERENCE_READ  0x01ULL
#define LINEP_CAP_INFERENCE_WRITE 0x02ULL
#define LINEP_CAP_ADMIN           0x04ULL
#define LINEP_CAP_SLOT_MANAGE     0x08ULL
#define LINEP_CAP_METRICS_READ    0x10ULL

#pragma pack(push, 1)

typedef struct {
    uint32_t session_id;
    uint16_t key_id;
    uint32_t auth_seq;
    uint8_t  mac[16];
} linep_sl_auth_ext_t;

typedef struct {
    uint32_t session_id;
    uint64_t granted_caps;
    uint64_t expires_at_sec;
    uint8_t  cap_mac[16];
} linep_sl_cap_ext_t;

#pragma pack(pop)

LINEP_SL_API int linep_sl_compute_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, uint32_t session_id,
    uint16_t key_id, uint32_t auth_seq,
    const uint8_t* payload, uint32_t payload_len,
    uint8_t out_mac[16]);

LINEP_SL_API int linep_sl_verify_mac(
    const uint8_t* secret_key, uint32_t key_len,
    const void* header_ptr, const linep_sl_auth_ext_t* auth_ext,
    const uint8_t* payload, uint32_t payload_len);

LINEP_SL_API int linep_sl_create_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    uint32_t session_id, uint64_t granted_caps,
    uint64_t expires_at_sec, linep_sl_cap_ext_t* out_token);

LINEP_SL_API int linep_sl_verify_cap_token(
    const uint8_t* secret_key, uint32_t key_len,
    const linep_sl_cap_ext_t* cap_token,
    uint32_t expected_session_id,
    uint64_t current_time_sec,
    uint64_t required_capability);

#ifdef __cplusplus
}
#endif

#endif // LINEP_SL_CABI_SL_H
