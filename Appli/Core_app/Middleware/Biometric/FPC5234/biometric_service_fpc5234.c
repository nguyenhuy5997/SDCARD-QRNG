/**
 * @file    biometric_service_fpc5234.c
 * @brief   FPC5234 backend of the chip-agnostic biometric_service interface.
 *
 * Wraps Core_app/Drivers/FPC5234's FPC host library (fpc_hal.h/
 * fpc_host_sample.h) behind biometric_service.h so App never touches
 * fpc_cmd_*_request()/fpc_host_sample_handle_rx_data() or the
 * fpc_cmd_callbacks_t registration directly -- same boundary
 * Core_app/Middleware/Security/SE052F/security_service_se052f.c keeps
 * for the SE05x host library.
 *
 * The FPC5234 protocol is asynchronous: a request function only queues a
 * command frame, and the actual result arrives later as an event/response
 * frame that fpc_host_sample_handle_rx_data() parses and dispatches to
 * callbacks (see Core_app/Drivers/FPC5234/fpc_host_sample.c). Every
 * function below turns that into an ordinary blocking call by registering
 * this file's own callbacks once (s_callbacks) and pumping
 * fpc_hal_data_available()/fpc_host_sample_handle_rx_data()/fpc_hal_wfi()
 * in a loop until the relevant callback fires, an error is reported, or
 * `timeout_ms` elapses -- the same loop shape
 * Core_app/Drivers/FPC5234/tests/enroll_identify.c's main loop uses, just
 * collapsed into one blocking call per operation instead of an app-level
 * state machine.
 */
/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "biometric_service.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "hal_common.h"
#include "fpc_api.h"
#include "fpc_hal.h"
#include "fpc_host_sample.h"

#define BIOMETRIC_SERVICE_INIT_TIMEOUT_MS 5000U
#define BIOMETRIC_SERVICE_CMD_TIMEOUT_MS  3000U

static bool s_ready;

/* Updated by on_status(), which the sensor pushes after completing any
 * stateful operation (boot, enroll, identify, delete, ...). */
static volatile bool s_status_seen;
static volatile uint16_t s_device_state;
static volatile bool s_device_app_ready;

static volatile bool s_error_pending;
static volatile uint16_t s_error_code;

static uint16_t *s_list_out_ids;
static size_t s_list_out_capacity;
static size_t s_list_out_count;
static volatile bool s_list_done;

static bio_enroll_progress_cb_t s_enroll_progress_cb;

static volatile bool s_identify_done;
static volatile bool s_identify_matched;
static volatile uint16_t s_identify_id;

/* Navigation is a streaming mode, not a one-shot request/response like
 * enroll/identify/list/delete above -- s_nav_active tracks whether
 * biometric_service_navigation_start() has run without a matching stop(),
 * and each poll() waits for exactly one more on_navigation() callback. */
static bool s_nav_active;
static volatile bool s_nav_gesture_pending;
static volatile int s_nav_raw_gesture;
static bio_nav_gesture_cb_t s_nav_gesture_cb;

static void on_error(uint16_t error)
{
    s_error_pending = true;
    s_error_code = error;
}

static void on_status(uint16_t event, uint16_t state)
{
    (void)event;
    s_device_state = state;
    if ((state & STATE_APP_FW_READY) != 0U) {
        s_device_app_ready = true;
    }
    s_status_seen = true;
}

static void on_enroll(uint8_t feedback, uint8_t samples_remaining)
{
    if (s_enroll_progress_cb != NULL) {
        s_enroll_progress_cb(feedback, samples_remaining);
    }
}

static void on_identify(int is_match, uint16_t id)
{
    s_identify_matched = (is_match != 0);
    s_identify_id = id;
    s_identify_done = true;
}

static void on_list_templates(int num_templates, uint16_t *template_ids)
{
    /* template_ids points inside fpc_host_sample_handle_rx_data()'s
     * malloc'd frame buffer, freed the moment this callback returns --
     * copy out now, never hold onto the pointer. */
    size_t n = (size_t)num_templates;
    if (s_list_out_ids != NULL) {
        size_t copy_n = (n < s_list_out_capacity) ? n : s_list_out_capacity;
        memcpy(s_list_out_ids, template_ids, copy_n * sizeof(uint16_t));
    }
    s_list_out_count = n;
    s_list_done = true;
}

static void on_navigation(int gesture)
{
    s_nav_raw_gesture = gesture;
    s_nav_gesture_pending = true;
}

static bio_nav_gesture_t map_nav_gesture(int gesture)
{
    switch (gesture) {
    case CMD_NAV_EVENT_UP:         return BIO_NAV_UP;
    case CMD_NAV_EVENT_DOWN:       return BIO_NAV_DOWN;
    case CMD_NAV_EVENT_RIGHT:      return BIO_NAV_RIGHT;
    case CMD_NAV_EVENT_LEFT:       return BIO_NAV_LEFT;
    case CMD_NAV_EVENT_PRESS:      return BIO_NAV_PRESS;
    case CMD_NAV_EVENT_LONG_PRESS: return BIO_NAV_LONG_PRESS;
    case CMD_NAV_EVENT_NONE:
    default:
        return BIO_NAV_NONE;
    }
}

static const fpc_cmd_callbacks_t s_callbacks = {
    .on_error = on_error,
    .on_status = on_status,
    .on_enroll = on_enroll,
    .on_identify = on_identify,
    .on_list_templates = on_list_templates,
    .on_navigation = on_navigation,
};

/** Pump the event loop until `*done` is set, on_error() fires, or
 *  `timeout_ms` elapses (0 = no timeout). Callers must set `*done` false
 *  and send their request before calling this. */
static bio_status_t pump_until(volatile bool *done, uint32_t timeout_ms)
{
    uint32_t start = platform_get_tick_ms();

    s_error_pending = false;
    while (!*done) {
        if (fpc_hal_data_available()) {
            (void)fpc_host_sample_handle_rx_data();
        } else {
            (void)fpc_hal_wfi();
        }

        if (s_error_pending) {
            return BIO_ERROR;
        }
        if (timeout_ms != 0U && (platform_get_tick_ms() - start) > timeout_ms) {
            return BIO_TIMEOUT;
        }
    }
    return BIO_OK;
}

bio_status_t biometric_service_init(void)
{
    if (s_ready) {
        return BIO_OK;
    }

    s_device_app_ready = false;

    /* Bring the transport (RX streaming included) up before pulsing
     * reset, not after -- otherwise the sensor's very first status push
     * right after boot can arrive before anything is listening. Matches
     * the order Core_app/Drivers/FPC5234/tests/enroll_identify.c uses
     * (fpc_host_sample_init() then hal_reset_device()). */
    if (fpc_host_sample_init((fpc_cmd_callbacks_t *)&s_callbacks) != FPC_RESULT_OK) {
        return BIO_ERROR;
    }

    hal_reset_device();

    /* Wait for the sensor's own "firmware ready" status push instead of a
     * fixed boot delay -- matches
     * Core_app/Drivers/FPC5234/tests/enroll_identify.c's
     * APP_STATE_WAIT_READY. */
    bio_status_t status = pump_until(&s_device_app_ready, BIOMETRIC_SERVICE_INIT_TIMEOUT_MS);
    if (status != BIO_OK) {
        return status;
    }

    s_ready = true;
    return BIO_OK;
}

bio_status_t biometric_service_deinit(void)
{
    s_ready = false;
    return BIO_OK;
}

bool biometric_service_is_ready(void)
{
    return s_ready;
}

bio_status_t biometric_service_list_templates(uint16_t *ids, size_t *count)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }
    if (count == NULL) {
        return BIO_INVALID_PARAM;
    }

    s_list_out_ids = ids;
    s_list_out_capacity = *count;
    s_list_out_count = 0;
    s_list_done = false;

    if (fpc_cmd_list_templates_request() != FPC_RESULT_OK) {
        return BIO_ERROR;
    }

    bio_status_t status = pump_until(&s_list_done, BIOMETRIC_SERVICE_CMD_TIMEOUT_MS);
    if (status != BIO_OK) {
        return status;
    }

    *count = s_list_out_count;
    return BIO_OK;
}

bool biometric_service_template_exists(uint16_t template_id)
{
    if (!s_ready) {
        return false;
    }

    /* Unlike security_service_key_exists() (a single direct "does this id
     * exist" APDU on the SE052F), the FPC5234 protocol only exposes a
     * bulk list -- so this asks for the count first, then the full list,
     * and searches it. */
    size_t total = 0;
    if (biometric_service_list_templates(NULL, &total) != BIO_OK || total == 0U) {
        return false;
    }

    uint16_t stack_ids[16];
    uint16_t *ids = stack_ids;
    size_t capacity = sizeof(stack_ids) / sizeof(stack_ids[0]);
    uint16_t *heap_ids = NULL;

    if (total > capacity) {
        heap_ids = malloc(total * sizeof(uint16_t));
        if (heap_ids == NULL) {
            return false;
        }
        ids = heap_ids;
        capacity = total;
    }

    size_t count = capacity;
    bool found = false;
    if (biometric_service_list_templates(ids, &count) == BIO_OK) {
        for (size_t i = 0; i < count; i++) {
            if (ids[i] == template_id) {
                found = true;
                break;
            }
        }
    }

    if (heap_ids != NULL) {
        free(heap_ids);
    }
    return found;
}

bio_status_t biometric_service_enroll(bio_enroll_progress_cb_t progress_cb, uint32_t timeout_ms)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }
    if (s_nav_active) {
        return BIO_WRONG_STATE;
    }

    s_enroll_progress_cb = progress_cb;
    s_device_state = 0;

    fpc_id_type_t id = { ID_TYPE_GENERATE_NEW, 0 };
    if (fpc_cmd_enroll_request(&id) != FPC_RESULT_OK) {
        s_enroll_progress_cb = NULL;
        return BIO_ERROR;
    }
    uint32_t start = platform_get_tick_ms();
    s_error_pending = false;
    bio_status_t result = BIO_OK;
    bool enroll_seen_active = false;

    for (;;) {
        if (fpc_hal_data_available()) {
            (void)fpc_host_sample_handle_rx_data();
        } else {
            (void)fpc_hal_wfi();
        }

        if (s_error_pending) {
            result = BIO_ERROR;
            break;
        }

        if ((s_device_state & STATE_ENROLL) != 0U) {
            enroll_seen_active = true;
        } else if (enroll_seen_active) {
            /* STATE_ENROLL was set and has now cleared -- the sensor
             * considers enrollment finished (matches
             * Core_app/Drivers/FPC5234/tests/enroll_identify.c's
             * APP_STATE_WAIT_ENROLL exit condition; samples_remaining
             * alone is not a reliable "done" signal since a rejected
             * touch does not count down). */
            break;
        }

        if (timeout_ms != 0U && (platform_get_tick_ms() - start) > timeout_ms) {
            result = BIO_TIMEOUT;
            break;
        }
    }

    if (result != BIO_OK) {
        /* On BIO_OK the sensor already finished enrollment and returned
         * to idle on its own -- nothing to abort. On BIO_TIMEOUT/
         * BIO_ERROR, the sensor is (or may be) still mid-enrollment,
         * still waiting on its own end for the next touch that is never
         * coming -- without telling it to stop, it silently rejects the
         * *next* fpc_cmd_enroll_request()/fpc_cmd_identify_request()
         * this session, which surfaces as an unrelated-looking BIO_ERROR
         * on some later, completely separate call. Same fire-and-forget
         * CMD_ABORT biometric_service_navigation_stop() already sends
         * (see its doc comment -- no CMD_ABORT response to wait on
         * either way). */
        (void)fpc_cmd_abort();
    }

    s_enroll_progress_cb = NULL;
    return result;
}

bio_status_t biometric_service_identify(uint16_t *matched_template_id, uint32_t timeout_ms)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }
    if (s_nav_active) {
        return BIO_WRONG_STATE;
    }

    s_identify_done = false;
    s_identify_matched = false;
    s_identify_id = 0;

    fpc_id_type_t id = { ID_TYPE_ALL, 0 };
    if (fpc_cmd_identify_request(&id, 0) != FPC_RESULT_OK) {
        return BIO_ERROR;
    }

    bio_status_t status = pump_until(&s_identify_done, timeout_ms);
    if (status != BIO_OK) {
        /* Same reasoning as biometric_service_enroll()'s BIO_TIMEOUT/
         * BIO_ERROR path -- pump_until() timing out here means the
         * sensor is still waiting on its own end for the identify touch
         * that never came; tell it to stop or the *next* enroll/identify
         * request this session gets silently rejected. */
        (void)fpc_cmd_abort();
        return status;
    }

    if (!s_identify_matched) {
        return BIO_NO_MATCH;
    }
    if (matched_template_id != NULL) {
        *matched_template_id = s_identify_id;
    }
    return BIO_OK;
}

bio_status_t biometric_service_delete_template(uint16_t template_id)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }

    fpc_id_type_t id = (template_id == BIO_TEMPLATE_ID_ALL)
                            ? (fpc_id_type_t){ ID_TYPE_ALL, 0 }
                            : (fpc_id_type_t){ ID_TYPE_SPECIFIED, template_id };

    s_status_seen = false;

    if (fpc_cmd_delete_template_request(&id) != FPC_RESULT_OK) {
        return BIO_ERROR;
    }

    /* fpc_host_sample.c's parse_cmd() has no case for CMD_DELETE_TEMPLATE's
     * own response frame -- it is silently dropped ("Parse Cmd: Unexpected
     * Command ID" in that file). The best available completion signal is
     * the next CMD_STATUS event, which the sensor pushes after finishing
     * a stateful operation -- the same assumption
     * Core_app/Drivers/FPC5234/tests/enroll_identify.c's unguarded
     * APP_STATE_WAIT_DELETE_TEMPLATES transition relies on. This is a
     * heuristic, not a confirmed per-command acknowledgement; if the FPC
     * protocol docs turn up a real CMD_DELETE_TEMPLATE response format,
     * add a parse_cmd() case for it upstream and switch this to wait on
     * that instead. */
    return pump_until(&s_status_seen, BIOMETRIC_SERVICE_CMD_TIMEOUT_MS);
}

bio_status_t biometric_service_reset(void)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }

    s_device_app_ready = false;
    hal_reset_device();

    return pump_until(&s_device_app_ready, BIOMETRIC_SERVICE_INIT_TIMEOUT_MS);
}

bio_status_t biometric_service_navigation_start(bio_nav_orientation_t orientation)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }
    if (orientation > BIO_NAV_ORIENTATION_270) {
        return BIO_INVALID_PARAM;
    }

    if (fpc_cmd_navigation_request((uint8_t)orientation) != FPC_RESULT_OK) {
        return BIO_ERROR;
    }

    s_nav_active = true;
    return BIO_OK;
}

bio_status_t biometric_service_navigation_poll(bio_nav_gesture_t *gesture)
{
    if (!s_ready) {
        return BIO_NOT_READY;
    }
    if (!s_nav_active) {
        return BIO_WRONG_STATE;
    }
    if (gesture == NULL) {
        return BIO_INVALID_PARAM;
    }

    *gesture = BIO_NAV_NONE;

    /* Single non-blocking pass: process one already-arrived frame if
     * there is one, otherwise return immediately -- never calls
     * fpc_hal_wfi()/sleeps here, unlike pump_until(), so the caller's
     * own loop stays in control and can call this every iteration for
     * continuous, real-time gesture tracking. */
    if (fpc_hal_data_available()) {
        (void)fpc_host_sample_handle_rx_data();
    }

    if (s_error_pending) {
        s_error_pending = false;
        return BIO_ERROR;
    }

    if (s_nav_gesture_pending) {
        s_nav_gesture_pending = false;
        *gesture = map_nav_gesture(s_nav_raw_gesture);
        if (s_nav_gesture_cb != NULL) {
            s_nav_gesture_cb(*gesture);
        }
    }

    return BIO_OK;
}

void biometric_service_navigation_set_callback(bio_nav_gesture_cb_t callback)
{
    s_nav_gesture_cb = callback;
}

bio_status_t biometric_service_navigation_stop(void)
{
    if (!s_nav_active) {
        return BIO_OK;
    }

    /* Fire-and-forget, same rigor Core_app/Drivers/FPC5234/tests/navigation.c
     * itself uses for its abort-on-button-press path -- there is no
     * parse_cmd() case for CMD_ABORT's response either (same gap noted on
     * biometric_service_delete_template()), so there is nothing reliable
     * to wait on here. */
    s_nav_active = false;

    if (fpc_cmd_abort() != FPC_RESULT_OK) {
        return BIO_ERROR;
    }
    return BIO_OK;
}

#endif /* EVT2_ENABLE_BIOMETRIC */
