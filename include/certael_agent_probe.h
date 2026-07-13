#ifndef CERTAEL_AGENT_PROBE_H
#define CERTAEL_AGENT_PROBE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum certael_probe_result {
    CERTAEL_PROBE_OK = 0,
    CERTAEL_PROBE_INVALID_ARGUMENT = 1,
    CERTAEL_PROBE_BUFFER_TOO_SMALL = 2,
    CERTAEL_PROBE_INTERNAL_ERROR = 255
} certael_probe_result;
uint32_t certael_probe_abi_version(void);
certael_probe_result certael_probe_bind_nonce(const uint8_t *nonce, size_t nonce_len,
                                               uint8_t *output, size_t output_len);
#ifdef __cplusplus
}
#endif
#endif
