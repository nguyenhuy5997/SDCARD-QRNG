/**
 * @file    biometric_protocol.c
 * @brief   App-layer command_protocol.h adapter for Middleware/Biometric (CMD_TYPE_BIOMETRIC).
 *
 * Lives under Core_app/App, not Core_app/Middleware/Biometric -- see
 * qrng_protocol.c's doc comment for why (this file depends on both
 * command_protocol.h and biometric_service.h; App is the only layer
 * allowed to depend on more than one Middleware module at once).
 *
 * Covers the whole biometric_service.h surface app_main.c's
 * app_biometric_self_test() already exercises internally (is_ready,
 * list/delete_templates, enroll, identify, reset, navigation start/poll/
 * stop) -- one sub-command per function, same shape as qrng_protocol.c's
 * mapping onto qrng_service.h.
 *
 * ENROLL/IDENTIFY are blocking on purpose, same as
 * QRNG_CMD_BENCH_NOISE/_ENTROPY in qrng_protocol.c: command_protocol_poll()
 * is not called again until the whole touch-timeout window elapses (or a
 * touch arrives), so the host just waits for the one response -- no
 * per-touch progress push over the wire (bio_enroll_progress_cb_t is
 * passed NULL here; app_main.c's own self-test is still the place to
 * watch per-touch feedback over the debug UART, not this protocol).
 */
/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "command_protocol.h"
#include "biometric_service.h"

typedef enum {
    BIO_CMD_IS_READY         = 0x01, /* -> response: [sub_cmd][is_ready: 0/1] */
    BIO_CMD_LIST_TEMPLATES   = 0x02, /* -> response: [sub_cmd][status][count:1B][ids: count*2B little-endian] */
    BIO_CMD_TEMPLATE_EXISTS  = 0x03, /* payload: [template_id:u16 LE] -> response: [sub_cmd][exists: 0/1] */
    BIO_CMD_ENROLL           = 0x04, /* payload: [timeout_ms:u32 LE] -> response: [sub_cmd][status] (BIO_OK/BIO_TIMEOUT/BIO_ERROR) */
    BIO_CMD_IDENTIFY         = 0x05, /* payload: [timeout_ms:u32 LE] -> response: [sub_cmd][status][matched_id:u16 LE] (id only meaningful on BIO_OK) */
    BIO_CMD_DELETE_TEMPLATE  = 0x06, /* payload: [template_id:u16 LE, 0xFFFF=ALL] -> response: [sub_cmd][status] */
    BIO_CMD_RESET            = 0x07, /* -> response: [sub_cmd][status] -- required before NAV_START if enroll/identify/delete ran this session */
    BIO_CMD_NAV_START        = 0x08, /* payload: [orientation:1B, bio_nav_orientation_t] -> response: [sub_cmd][status] */
    BIO_CMD_NAV_POLL         = 0x09, /* -> response: [sub_cmd][status][gesture:1B, bio_nav_gesture_t] -- call repeatedly while in nav mode */
    BIO_CMD_NAV_STOP         = 0x0A, /* -> response: [sub_cmd][status] */
} biometric_cmd_t;

static uint32_t read_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

bool biometric_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                 uint16_t *response_len, uint16_t max_response_len)
{
    uint8_t sub_cmd = payload[0];
    response[0] = sub_cmd;

    switch (sub_cmd) {
        case BIO_CMD_IS_READY: {
            if (max_response_len < 2U) {
                return false;
            }
            response[1] = biometric_service_is_ready() ? 1U : 0U;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_LIST_TEMPLATES: {
            if (max_response_len < 3U) {
                return false;
            }
            uint16_t ids[32];
            size_t count = sizeof(ids) / sizeof(ids[0]);
            bio_status_t st = biometric_service_list_templates(ids, &count);

            response[1] = (uint8_t)st;
            if (st != BIO_OK || max_response_len < (uint16_t)(3U + count * 2U)) {
                response[2] = 0U;
                *response_len = 3U;
                return true;
            }
            response[2] = (uint8_t)count;
            for (size_t i = 0; i < count; i++) {
                response[3U + i * 2U] = (uint8_t)(ids[i]);
                response[3U + i * 2U + 1U] = (uint8_t)(ids[i] >> 8);
            }
            *response_len = (uint16_t)(3U + count * 2U);
            return true;
        }
        case BIO_CMD_TEMPLATE_EXISTS: {
            if (payload_len < 3U || max_response_len < 2U) {
                return false;
            }
            response[1] = biometric_service_template_exists(read_u16le(&payload[1])) ? 1U : 0U;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_ENROLL: {
            if (payload_len < 5U || max_response_len < 2U) {
                return false;
            }
            uint32_t timeout_ms = read_u32le(&payload[1]);
            bio_status_t st = biometric_service_enroll(NULL, timeout_ms);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_IDENTIFY: {
            if (payload_len < 5U || max_response_len < 4U) {
                return false;
            }
            uint32_t timeout_ms = read_u32le(&payload[1]);
            uint16_t matched_id = 0U;
            bio_status_t st = biometric_service_identify(&matched_id, timeout_ms);
            response[1] = (uint8_t)st;
            response[2] = (uint8_t)(matched_id);
            response[3] = (uint8_t)(matched_id >> 8);
            *response_len = 4U;
            return true;
        }
        case BIO_CMD_DELETE_TEMPLATE: {
            if (payload_len < 3U || max_response_len < 2U) {
                return false;
            }
            bio_status_t st = biometric_service_delete_template(read_u16le(&payload[1]));
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_RESET: {
            if (max_response_len < 2U) {
                return false;
            }
            bio_status_t st = biometric_service_reset();
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_NAV_START: {
            if (payload_len < 2U || max_response_len < 2U) {
                return false;
            }
            bio_status_t st = biometric_service_navigation_start((bio_nav_orientation_t)payload[1]);
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        case BIO_CMD_NAV_POLL: {
            if (max_response_len < 3U) {
                return false;
            }
            bio_nav_gesture_t gesture = BIO_NAV_NONE;
            bio_status_t st = biometric_service_navigation_poll(&gesture);
            response[1] = (uint8_t)st;
            response[2] = (uint8_t)gesture;
            *response_len = 3U;
            return true;
        }
        case BIO_CMD_NAV_STOP: {
            if (max_response_len < 2U) {
                return false;
            }
            bio_status_t st = biometric_service_navigation_stop();
            response[1] = (uint8_t)st;
            *response_len = 2U;
            return true;
        }
        default:
            return false;
    }
}

#endif /* EVT2_ENABLE_BIOMETRIC */
