/**
 * @file    app_main.c
 * @brief   App-layer bring-up: platform init and USB/command-protocol wiring.
 *
 * This is what a PRODUCT build actually needs: app_init() (debug UART) and app_command_protocol_init()/_poll()
 * (bring up platform_usb.h and Middleware/CommandProtocol, register every service's protocol adapter). It does not
 * exercise or validate anything itself -- Core_app/App/app_self_test.c does that (dev/QA builds only, see that
 * file's own doc comment for why it was split out of this one on 2026-09-24).
 */
#include "app_main.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "platform.h"
#include "board.h"
#include "app_trace.h"
#include "command_protocol.h"
#include "qrng_service.h"
#include "security_service.h"

/* Defined in Core_app/App/protocol_adapters/{security,biometric,qrng}_protocol.c
 * -- not declared in any shared header, since only this file needs to
 * know these adapters exist, to register them. */
extern bool security_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                       uint16_t *response_len, uint16_t max_response_len);
#if EVT2_ENABLE_BIOMETRIC
extern bool biometric_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                        uint16_t *response_len, uint16_t max_response_len);
#endif
extern bool qrng_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                   uint16_t *response_len, uint16_t max_response_len);
/* Defined in Core_app/App/protocol_adapters/ca_protocol.c -- CA-based key-exchange handshake (CMD_TYPE_CA), same
 * shape as the three handlers above. */
extern bool ca_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                 uint16_t *response_len, uint16_t max_response_len);
#if EVT2_FACTORY_PROVISION
/* Defined in Core_app/App/protocol_adapters/provision_protocol.c -- factory provisioning of the CA identity
 * (CMD_TYPE_PROVISION). FACTORY IMAGE ONLY: the product image neither compiles nor registers it. */
extern bool provision_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                        uint16_t *response_len, uint16_t max_response_len);
#endif
/* Pushes CMD_TYPE_QRNG continuous-stream frames armed by
 * qrng_protocol_handler()'s STREAM_NOISE_START/STREAM_ENTROPY_START --
 * see qrng_protocol.c's doc comment. Must run every main-loop iteration
 * (not just when a command arrives), same as app_command_protocol_poll()
 * itself. */
extern void qrng_protocol_poll(void);

/* Defined in Core_app/App/protocol_adapters/media_protocol.c -- the
 * video-call media session state machine (CMD_TYPE_MEDIA_FIRST..
 * CMD_TYPE_MEDIA_LAST, 0x03-0x10), registered via the separate
 * command_protocol_register_media() (not command_protocol_register()
 * above -- see cmd_protocol_media_handler_t's doc comment for why). */
extern void media_protocol_init(void);
extern void media_protocol_handler(const cmd_protocol_packet_t *pkt);
extern void media_protocol_poll(void); /* session timeout GC -- call every main-loop iteration */

/* Debug-log formatting helpers -- NOT static: Core_app/App/app_self_test.c (dev/QA builds) uses these too via its
 * own `extern` declarations, so there is exactly one implementation. A product build that drops app_self_test.c
 * still links these fine (app_command_protocol_init() below uses them itself). */
void app_log(const char *msg)
{
#if defined(BOARD_DEBUG_UART)
    platform_uart_transmit(BOARD_DEBUG_UART, (const uint8_t *)msg, (uint16_t)strlen(msg), 100U);
#else
    (void)msg; /* the board has no debug UART (board.h) */
#endif
}

void app_log_hex(const uint8_t *data, size_t len)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    for (size_t i = 0; i < len; i++) {
        char byte_str[4] = { hex_digits[(data[i] >> 4) & 0xFU], hex_digits[data[i] & 0xFU], ' ', '\0' };
        app_log(byte_str);
    }
    app_log("\r\n");
}

/* No sprintf/printf here on purpose -- same reason app_log_hex() above
 * hand-rolls its own hex formatting instead of using one: keeps this
 * file's footprint independent of the C library's formatting machinery. */
void app_log_uint(uint32_t value)
{
    char digits[10]; /* UINT32_MAX = 4294967295 = 10 digits */
    size_t n = 0;

    do {
        digits[n++] = (char)('0' + (value % 10U));
        value /= 10U;
    } while (value != 0U && n < sizeof(digits));

    char out[sizeof(digits) + 1];
    for (size_t i = 0; i < n; i++) {
        out[i] = digits[n - 1U - i];
    }
    out[n] = '\0';
    app_log(out);
}

/* The project's random source handed to the Security service (it must not depend on the QRNG service itself):
 * QRNG first, MCU TRNG fallback -- qrng_service_random_bytes(). */
static bool app_random_source(uint8_t *buf, size_t len)
{
    return qrng_service_random_bytes(buf, len, NULL) == QRNG_OK;
}

void app_init(void)
{
#if defined(BOARD_DEBUG_UART)
    platform_uart_init(BOARD_DEBUG_UART);
#endif
    /* MCU crypto blocks the protocol adapters use directly: TRNG (GCM/CA nonce fallback, software ECDH randomness),
     * HASH (HKDF/HMAC, SHA-256) and CRYP (media AES-GCM). They used to be attached only inside qrng_service_init(),
     * so a board whose QRNG is off (V8Y analog safety lock: qrng_service_init() returns before reaching them) had
     * none of them. Each is idempotent; qrng_service_init() calling them again later is harmless. */
    (void)platform_rng_init();
    (void)platform_hash_init();
    (void)platform_crypto_init();
    /* Before security_service_init() (Src/main.c), so its SCP03 host challenge already uses it. */
    security_service_set_random_source(app_random_source);
}

bool app_command_protocol_init(void)
{
    app_log("=== USB command-protocol init ===\r\n");

    if (platform_usb_init() != PLATFORM_OK) {
        app_log("platform_usb_init: FAIL\r\n");
        return false;
    }
    app_log("platform_usb_init: OK\r\n");

    if (command_protocol_init() != CMD_PROTO_OK) {
        app_log("command_protocol_init: FAIL\r\n");
        return false;
    }

    if (command_protocol_register(CMD_TYPE_SECURITY, security_protocol_handler) != CMD_PROTO_OK ||
#if EVT2_ENABLE_BIOMETRIC /* without it CMD_TYPE_BIOMETRIC stays unregistered, answered like any unknown type */
        command_protocol_register(CMD_TYPE_BIOMETRIC, biometric_protocol_handler) != CMD_PROTO_OK ||
#endif
        command_protocol_register(CMD_TYPE_QRNG, qrng_protocol_handler) != CMD_PROTO_OK ||
        command_protocol_register(CMD_TYPE_CA, ca_protocol_handler) != CMD_PROTO_OK ||
#if EVT2_FACTORY_PROVISION
        command_protocol_register(CMD_TYPE_PROVISION, provision_protocol_handler) != CMD_PROTO_OK ||
#endif
        false) {
        app_log("command_protocol_register: FAIL\r\n");
        return false;
    }

    media_protocol_init();
    if (command_protocol_register_media(media_protocol_handler) != CMD_PROTO_OK) {
        app_log("command_protocol_register_media: FAIL\r\n");
        return false;
    }

#if EVT2_ENABLE_BIOMETRIC
    app_log("command_protocol: OK -> Security/Biometric/QRNG/CA/Media registered\r\n");
#else
    app_log("command_protocol: OK -> Security/QRNG/CA/Media registered (biometric disabled)\r\n");
#endif
    return true;
}

void app_command_protocol_poll(void)
{
    APP_TRACE_BC(TRC_POLL_CMD, 0U);
    command_protocol_poll();
    APP_TRACE_BC(TRC_POLL_QRNG, 0U);
    qrng_protocol_poll();
    APP_TRACE_BC(TRC_POLL_MEDIA, 0U);
    media_protocol_poll();
}
