#ifndef CERTAEL_AGENT_PROBE_H
#define CERTAEL_AGENT_PROBE_H
#include <stddef.h>
#include <stdint.h>
#define CERTAEL_PROBE_ABI_VERSION_1 1u
#ifdef __cplusplus
extern "C" {
#endif
typedef enum certael_probe_result {
    CERTAEL_PROBE_OK = 0,
    CERTAEL_PROBE_INVALID_ARGUMENT = 1,
    CERTAEL_PROBE_BUFFER_TOO_SMALL = 2,
    CERTAEL_PROBE_NOT_CONNECTED = 3,
    CERTAEL_PROBE_INVALID_FRAME = 4,
    CERTAEL_PROBE_UNSUPPORTED_PLATFORM = 5,
    CERTAEL_PROBE_INTERNAL_ERROR = 255
} certael_probe_result;
typedef struct certael_agent_channel certael_agent_channel;
uint32_t certael_probe_abi_version(void);
certael_probe_result certael_probe_bind_nonce(const uint8_t *nonce, size_t nonce_len,
                                               uint8_t *output, size_t output_len);
certael_probe_result certael_agent_channel_open(certael_agent_channel **output);
certael_probe_result certael_agent_channel_read(certael_agent_channel *channel,
                                                uint8_t *message_type,
                                                uint8_t *output, size_t capacity,
                                                size_t *written);
certael_probe_result certael_agent_channel_write(certael_agent_channel *channel,
                                                 uint8_t message_type,
                                                 const uint8_t *payload,
                                                 size_t payload_len);
void certael_agent_channel_destroy(certael_agent_channel *channel);
#ifdef __cplusplus
}
#endif
#endif
