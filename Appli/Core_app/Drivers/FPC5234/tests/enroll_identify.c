/*
 * Copyright (c) 2024 Fingerprint Cards AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/**
 * @file    enroll_identify.c
 * @brief   Main file for FPC2534 Enroll / Identify example.
 */

/* Vendor example/test code, dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS && EVT2_ENABLE_BIOMETRIC

#include <unistd.h>
#include <string.h>

#include "hal_common.h"
#include "uart_debug.h"
#include "uart_host.h"

#include "fpc_api.h"
#include "fpc_hal.h"
#include "fpc_host_sample.h"

#define N_FINGERS_TO_ENROLL 2

/* Application states */
typedef enum {
    APP_STATE_WAIT_READY = 0,
    APP_STATE_WAIT_VERSION,
    APP_STATE_WAIT_LIST_TEMPLATES,
    APP_STATE_WAIT_ENROLL,
    APP_STATE_WAIT_IDENTIFY,
    APP_STATE_WAIT_ABORT,
    APP_STATE_WAIT_DELETE_TEMPLATES
} app_state_t;

static int quit = 0;
/* Current application state */
static app_state_t app_state = APP_STATE_WAIT_READY;
/* Set after device ready status is received */
static int device_ready = 0;
/* Set after version command response is received */
static int version_read = 0;
/* Set after list templates command response is received */
static int list_templates_done = 0;
/* Updated at each status event from device */
static uint16_t device_state = 0;
/* Set after list templates command response is received */
static int n_templates_on_device = 0;

/* Number of fingers left to enroll */
static int n_fingers_to_enroll = N_FINGERS_TO_ENROLL;

static void log_print(const char *format, ...)
{
    va_list arglist;

    va_start(arglist, format);
    uart_debug_vprintf(format, arglist);
    va_end(arglist);
}

/* Command callbacks */
static void on_error(uint16_t error)
{
    hal_set_led_status(HAL_LED_STATUS_ERROR);
    log_print("Got error %d.\n", error);
    quit = 1;
}

static void on_status(uint16_t event, uint16_t state)
{
    if (state & STATE_APP_FW_READY) {
        device_ready = 1;
    }
    device_state = state;
}

static void on_version(char* version)
{
    log_print("Got version: %s", version);
    version_read = 1;
}

static void on_enroll(uint8_t feedback, uint8_t samples_remaining)
{
    extern char *get_enroll_feedback_str_(uint8_t feedback);
    log_print("Enroll samples remaining: %d, feedback: %s (%d)", samples_remaining,
        get_enroll_feedback_str_(feedback), feedback);
}

static void on_identify(int is_match, uint16_t id)
{
    if (is_match) {
        hal_set_led_status(HAL_LED_STATUS_MATCH);
        log_print("Identify match on id %d", id);
    }
    else {
        hal_set_led_status(HAL_LED_STATUS_NO_MATCH);
        log_print("Identify no match");
    }
}

static void on_list_templates(int num_templates, uint16_t *template_ids)
{
    log_print("Found %d template(s) on device", num_templates);

    list_templates_done = 1;
    n_templates_on_device = num_templates;
}

static const fpc_cmd_callbacks_t cmd_cb = {
    .on_error = on_error,
    .on_status = on_status,
    .on_version = on_version,
    .on_enroll = on_enroll,
    .on_identify = on_identify,
    .on_list_templates = on_list_templates
};

static void process_state(void)
{
    app_state_t next_state = app_state;

    switch(app_state) {
        case APP_STATE_WAIT_READY:
            if (device_ready) {
                next_state = APP_STATE_WAIT_VERSION;
                fpc_cmd_version_request();
            }
            break;
        case APP_STATE_WAIT_VERSION:
            if (version_read) {
                next_state = APP_STATE_WAIT_LIST_TEMPLATES;
                fpc_cmd_list_templates_request();
            }
            break;
        case APP_STATE_WAIT_LIST_TEMPLATES:
            if (list_templates_done) {
                if (n_templates_on_device < N_FINGERS_TO_ENROLL) {
                    fpc_id_type_t id_type = {ID_TYPE_GENERATE_NEW, 0};
                    n_fingers_to_enroll = N_FINGERS_TO_ENROLL - n_templates_on_device;
                    log_print("\nStarting enroll %d fingers\n", n_fingers_to_enroll);
                    next_state = APP_STATE_WAIT_ENROLL;
                    fpc_cmd_enroll_request(&id_type);
                }
                else {
                    fpc_id_type_t id_type = {ID_TYPE_ALL, 0};
                    log_print("\nStarting identify\n");
                    next_state = APP_STATE_WAIT_IDENTIFY;
                    fpc_cmd_identify_request(&id_type, 0);
                }
            }
            break;
        case APP_STATE_WAIT_ENROLL:
            if ((device_state & STATE_ENROLL) == 0) {
                log_print("\nEnroll one finger done.\n");
                n_fingers_to_enroll--;
                if (n_fingers_to_enroll > 0) {
                    fpc_id_type_t id_type = {ID_TYPE_GENERATE_NEW, 0};
                    log_print("\nStarting enroll\n");
                    fpc_cmd_enroll_request(&id_type);
                } else {
                    fpc_id_type_t id_type = {ID_TYPE_ALL, 0};
                    log_print("\nStarting identify\n");
                    next_state = APP_STATE_WAIT_IDENTIFY;
                    fpc_cmd_identify_request(&id_type, 0);
                }
            }
            break;
        case APP_STATE_WAIT_IDENTIFY:
            if ((device_state & STATE_IDENTIFY) == 0) {
                fpc_id_type_t id_type = {ID_TYPE_ALL, 0};
                fpc_hal_delay_ms(100);
                fpc_cmd_identify_request(&id_type, 0);
            }
            break;
        case APP_STATE_WAIT_ABORT:
            if ((device_state & (STATE_ENROLL | STATE_IDENTIFY)) == 0) {
                fpc_id_type_t id_type = {ID_TYPE_ALL, 0};
                log_print("\nDeleting templates.\n");
                next_state = APP_STATE_WAIT_DELETE_TEMPLATES;
                fpc_cmd_delete_template_request(&id_type);
            }
            break;
        // Will run after next status event is received in response to delete template request.
        case APP_STATE_WAIT_DELETE_TEMPLATES:
        {
            fpc_id_type_t id_type = {ID_TYPE_GENERATE_NEW, 0};
            n_fingers_to_enroll = N_FINGERS_TO_ENROLL;
            hal_set_led_status(HAL_LED_STATUS_WAITTOUCH);
            log_print("\nStarting enroll.\n");
            next_state = APP_STATE_WAIT_ENROLL;
            fpc_cmd_enroll_request(&id_type);
            break;
        }
        default:
            break;
    }

    if (next_state != app_state) {
        log_print("State transition %d -> %d\n", app_state, next_state);
        app_state = next_state;
    }
}

void enroll_identify ()
{
    fpc_result_t result;
    fpc_host_sample_init((fpc_cmd_callbacks_t*)&cmd_cb);
    uart_debug_init();

    hal_set_led_status(HAL_LED_STATUS_READY);

    // Toggle device reset
    hal_reset_device();
#if defined(HOST_IF_SPI)
    log_print("FPC2534 enroll/identify example app (SPI)\n");
#elif defined(HOST_IF_UART)
    log_print("FPC2534 enroll/identify example app (UART)\n");
#elif defined(HOST_IF_I2C)
    log_print("FPC2534 enroll/identify example app (I2C)\n");
#endif

    // Start by waiting for device status (APP_FW_RDY).
    // All state handling is done in the process_state function.

    // Run through supported commands
    while (!quit) {

        // Wait for device IRQ or button
        fpc_hal_wfi();

        if (hal_check_button_pressed() > 200) {
            log_print("Button pressed");
            app_state = APP_STATE_WAIT_ABORT;
            fpc_cmd_abort();
        }

        if (fpc_hal_data_available()) {
            result = fpc_host_sample_handle_rx_data();
            if (result != FPC_RESULT_OK && result != FPC_PENDING_OPERATION) {
                log_print("Bad incoming data (%d). Wait and try again in some sec",
                    result);
                fpc_hal_delay_ms(100);
                uart_host_rx_data_clear();
            }
            process_state();
        }

    }

    return;
}

#endif /* EVT2_DIAGNOSTICS */
