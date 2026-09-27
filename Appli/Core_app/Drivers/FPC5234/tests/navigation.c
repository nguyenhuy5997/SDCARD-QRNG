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
 * @brief   Main file for FPC2534 Navigation example.
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

typedef enum {
    APP_STATE_WAIT_READY = 0,
    APP_STATE_WAIT_NAVIGATION_DONE
} app_state_t;

static int quit = 0;
static app_state_t app_state = APP_STATE_WAIT_READY;

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
    if (app_state == APP_STATE_WAIT_READY) {
        app_state = APP_STATE_WAIT_NAVIGATION_DONE;
        log_print("Starting navigation");
        fpc_cmd_navigation_request(0);
    }
}

static void on_version(char* version)
{
}

static void on_enroll(uint8_t feedback, uint8_t samples_remaining)
{
}

static void on_identify(int is_match, uint16_t id)
{
}

static void on_list_templates(int num_templates, uint16_t *template_ids)
{
}

static void on_navigation(int gesture)
{
    switch(gesture) {
        case CMD_NAV_EVENT_NONE:
            log_print("Nav event: None");
            break;
        case CMD_NAV_EVENT_UP:
            log_print("Nav event: Up");
            break;
        case CMD_NAV_EVENT_DOWN:
            log_print("Nav event: Down");
            break;
        case CMD_NAV_EVENT_RIGHT:
            log_print("Nav event: Right");
            break;
        case CMD_NAV_EVENT_LEFT:
            log_print("Nav event: Left");
            break;
        case CMD_NAV_EVENT_PRESS:
            log_print("Nav event: Press");
            break;
        case CMD_NAV_EVENT_LONG_PRESS:
            log_print("Nav event: Long Press");
            break;
        default:
            break;
    }
}

static const fpc_cmd_callbacks_t cmd_cb = {
    .on_error = on_error,
    .on_status = on_status,
    .on_version = on_version,
    .on_enroll = on_enroll,
    .on_identify = on_identify,
    .on_list_templates = on_list_templates,
    .on_navigation = on_navigation
};

void navigation()
{
    fpc_result_t result;
    fpc_host_sample_init((fpc_cmd_callbacks_t*)&cmd_cb);
    uart_debug_init();

    hal_set_led_status(HAL_LED_STATUS_READY);

    hal_reset_device();
#if defined(HOST_IF_SPI)
    log_print("FPC2534 navigation example app (SPI)\n");
#elif defined(HOST_IF_UART)
    log_print("FPC2534 navigation example app (UART)\n");
#elif defined(HOST_IF_I2C)
    log_print("FPC2534 navigation example app (I2C)\n");
#endif

    // Run through supported commands
    while (!quit) {

        fpc_hal_wfi();

        if (hal_check_button_pressed() > 200) {
            log_print("Button pressed, aborting navigation");
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
        }
    }

    return;
}

#endif /* EVT2_DIAGNOSTICS */
