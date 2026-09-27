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
 * @file    main.c
 * @brief   Main file for FPC2534 Secure Communication example.
 */

/* Vendor example/test code, dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS && EVT2_ENABLE_BIOMETRIC

#include <unistd.h>
#include <stdlib.h>
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
    APP_STATE_WAIT_GET_CONFIG_SETTINGS,
    APP_STATE_WAIT_SET_CONFIG_SETTINGS,
    APP_STATE_WAIT_SECURE_COM_ENABLED,
    APP_STATE_WAIT_READY_AFTER_RESTART,
    APP_STATE_WAIT_DELETE_TEMPLATES,
    APP_STATE_WAIT_ENROLL,
    APP_STATE_WAIT_GET_TEMPLATE,
    APP_STATE_WAIT_PUT_TEMPLATE,
    APP_STATE_WAIT_BUTTON_PRESSED_BEFORE_FACTORY_RESET,
    APP_STATE_WAIT_FACTORY_RESET,
    APP_STATE_WAIT_BUTTON_PRESSED
} app_state_t;

static int quit = 0;
/* Current application state */
static app_state_t app_state = APP_STATE_WAIT_READY;
/* Set after device ready status is received */
static int device_ready = 0;
/* Set after device secure interface status is received */
static int secure_com_enabled = 0;
/* Set after system config has been read */
static int system_config_read = 0;
/* Updated at each status event from device */
static uint16_t device_state = 0;
/* System config */
static fpc_system_config_t system_config;
/* Set when data transfer is done */
static int data_transfer_done = 0;
/* Template data */
static uint8_t *template_data = NULL;
/* Template size */
static uint16_t template_size = 0;
/* Set when button is pressed */
static int button_pressed = 0;

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
    if (state & STATE_SECURE_INTERFACE) {
        secure_com_enabled = 1;
    } else {
        secure_com_enabled = 0;
    }
    device_state = state;
}

static void on_enroll(uint8_t feedback, uint8_t samples_remaining)
{
    extern char *get_enroll_feedback_str_(uint8_t feedback);
    log_print("Enroll samples remaining: %d, feedback: %s (%d)", samples_remaining,
        get_enroll_feedback_str_(feedback), feedback);
}

static void on_data_transfer_done(uint8_t *data, size_t size)
{
    if (data && size) {
        template_data = malloc(size);
        template_size = size;
        assert(template_data != NULL);
        memcpy(template_data, data, size);
    } else {
        free(template_data);
        template_data = NULL;
    }
    data_transfer_done = 1;
}

void on_system_config_get(fpc_system_config_t *cfg)
{
    system_config = *cfg;
    system_config_read = 1;
}

static const fpc_cmd_callbacks_t cmd_cb = {
    .on_error = on_error,
    .on_status = on_status,
    .on_enroll = on_enroll,
    .on_system_config_get = on_system_config_get,
    .on_data_transfer_done = on_data_transfer_done,
};

static void process_state(void)
{
    static int enter = 0;
    app_state_t next_state = app_state;

    switch(app_state) {
        case APP_STATE_WAIT_READY:
            if (device_ready) {
                next_state = APP_STATE_WAIT_GET_CONFIG_SETTINGS;
            }
            break;
        case APP_STATE_WAIT_GET_CONFIG_SETTINGS:
            if (enter) {
                system_config_read = 0;
                fpc_cmd_system_config_get_request(FPC_SYS_CFG_TYPE_DEFAULT);
            }
            if (system_config_read) {
                next_state = APP_STATE_WAIT_SET_CONFIG_SETTINGS;
            }
            break;
        case APP_STATE_WAIT_SET_CONFIG_SETTINGS:
            if (enter) {
                device_state = 0;
                system_config.sys_flags |= CFG_SYS_FLAG_ALLOW_FACTORY_RESET;
                fpc_cmd_system_config_set_request(&system_config);
            }
            if (device_state != 0) {
                log_print("\nConfig settings written.\n");
                if (device_state & STATE_SECURE_INTERFACE) {
                    log_print("\nSecure communication enabled.\n");
                    next_state = APP_STATE_WAIT_DELETE_TEMPLATES;
                } else {
                    next_state = APP_STATE_WAIT_SECURE_COM_ENABLED;
                }
            }
            break;
        case APP_STATE_WAIT_SECURE_COM_ENABLED:
            if (enter) {
                device_state = 0;
                fpc_cmd_set_crypto_key_request();
            }
            if (device_state != 0) {
                log_print("\nKeys written. Secure communication enabled.\n");
                next_state = APP_STATE_WAIT_READY_AFTER_RESTART;
            }
            break;
        case APP_STATE_WAIT_READY_AFTER_RESTART:
            if (enter) {
                button_pressed = 0;
                device_ready = 0;
                secure_com_enabled = 0;
                hal_reset_device();
            }
            if (device_ready && secure_com_enabled) {
                log_print("\nSecure communication enabled after restart.\n");
                next_state = APP_STATE_WAIT_DELETE_TEMPLATES;
            }
            break;
        case APP_STATE_WAIT_DELETE_TEMPLATES:
            if (enter) {
                fpc_id_type_t id_type = {ID_TYPE_ALL, 0};
                device_state = 0;
                fpc_cmd_delete_template_request(&id_type);
            }
            if (device_state != 0) {
                log_print("\nDelete templates done.\n");
                next_state = APP_STATE_WAIT_ENROLL;
            }
            break;
        case APP_STATE_WAIT_ENROLL:
            if (enter) {
                fpc_id_type_t id_type = {ID_TYPE_GENERATE_NEW, 0};
                fpc_cmd_enroll_request(&id_type);
                log_print("\nStarting enroll.\n");
                device_state |= STATE_ENROLL;
            }
            if ((device_state & (STATE_ENROLL | STATE_FINGER_DOWN)) == 0) {
                log_print("\nEnroll one finger done.\n");
                next_state = APP_STATE_WAIT_GET_TEMPLATE;
            }
            break;
        case APP_STATE_WAIT_GET_TEMPLATE:
            if (enter) {
                data_transfer_done = 0;
                fpc_cmd_get_template_data_request(1);
            }
            if (data_transfer_done) {
                log_print("\nTemplate read.\n");
                next_state = APP_STATE_WAIT_PUT_TEMPLATE;
            }
            break;
        case APP_STATE_WAIT_PUT_TEMPLATE:
            if (enter) {
                data_transfer_done = 0;
                fpc_cmd_put_template_data_request(2, template_data, template_size);
            }
            if (data_transfer_done) {
                log_print("\nTemplate written.\n");
                next_state = APP_STATE_WAIT_BUTTON_PRESSED_BEFORE_FACTORY_RESET;
            }
            break;
        case APP_STATE_WAIT_BUTTON_PRESSED_BEFORE_FACTORY_RESET:
            if (enter) {
                log_print("\nPress button to do Factory Reset.\n");
            }
            if (button_pressed) {
                button_pressed = 0;
                device_ready = 0;
                next_state = APP_STATE_WAIT_FACTORY_RESET;
            }
            break;
        case APP_STATE_WAIT_FACTORY_RESET:
            if (enter) {
                device_state = 0;
                fpc_cmd_factory_reset_request();
            }
            if (device_state != 0) {
                log_print("\nFactory Reset done.\n");
                next_state = APP_STATE_WAIT_BUTTON_PRESSED;
            }
            break;
        case APP_STATE_WAIT_BUTTON_PRESSED:
            if (enter) {
                log_print("\nPress button to do restart sequence.\n");
            }
            if (button_pressed) {
                button_pressed = 0;
                device_ready = 0;
                hal_reset_device();
                next_state = APP_STATE_WAIT_READY;
            }
            break;
        default:
            break;
    }

    if (next_state != app_state) {
        log_print("State transition %d -> %d\n", app_state, next_state);
        app_state = next_state;
        enter = 1;
    } else {
        enter = 0;
    }
}

void secure_com()
{
    fpc_result_t result;
    fpc_host_sample_init((fpc_cmd_callbacks_t*)&cmd_cb);
    uart_debug_init();

    hal_set_led_status(HAL_LED_STATUS_READY);

    // Toggle device reset
    hal_reset_device();
#if defined(HOST_IF_SPI)
    log_print("FPC2534 secure communication example app (SPI)\n");
#elif defined(HOST_IF_UART)
    log_print("FPC2534 secure communication example app (UART)\n");
#elif defined(HOST_IF_I2C)
    log_print("FPC2534 secure communication example app (I2C)\n");
#endif

    // Start by waiting for device status (APP_FW_RDY).
    // All state handling is done in the process_state function.

    // Run through supported commands
    while (!quit) {

        // Wait for device IRQ or button
        fpc_hal_wfi();

        if (hal_check_button_pressed() > 200) {
            log_print("Button pressed");
            button_pressed = 1;
        }

        if (fpc_hal_data_available()) {
            result = fpc_host_sample_handle_rx_data();
            if (result != FPC_RESULT_OK && result != FPC_PENDING_OPERATION) {
                log_print("Bad incoming data (%d). Wait and try again in some sec",
                    result);
                fpc_hal_delay_ms(100);
                uart_host_rx_data_clear();
            }
        }
        process_state();

    }

    return;
}

#endif /* EVT2_DIAGNOSTICS */
