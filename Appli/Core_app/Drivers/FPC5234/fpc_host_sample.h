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
 * @file    fpc_host_sample.h
 * @brief   Sample code for FPC AllKey host implementation
 *
 */

/**
 * @brief Callback functions for command responses (optional).
 */
#include <stdint.h>
#include <stddef.h> /* size_t, used below -- used to arrive transitively
                     * through fpc_api.h's now-removed main.h include; see
                     * that header's comment. */
#include "fpc_api.h"

typedef struct {
    void (*on_error)(uint16_t error);
    void (*on_status)(uint16_t event, uint16_t state);
    void (*on_version)(char* version);
    void (*on_enroll)(uint8_t feedback, uint8_t samples_remaining);
    void (*on_identify)(int is_match, uint16_t id);
    void (*on_list_templates)(int num_templates, uint16_t *template_ids);
    void (*on_navigation)(int gesture);
    void (*on_gpio_control)(uint8_t state);
    void (*on_system_config_get)(fpc_system_config_t *cfg);
    void (*on_bist_done)(uint16_t test_verdict);
    void (*on_data_transfer_done)(uint8_t *data, size_t size);
} fpc_cmd_callbacks_t;


/**
 * @brief Populate and transfer a CMD_STATUS request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_status_request(void);

/**
 * @brief Populate and transfer a CMD_VERSION request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_version_request(void);

/**
 * @brief Populate and transfer a CMD_ENROLL request.
 *
 * id type can be ID_TYPE_SPECIFIED or ID_TYPE_GENERATE_NEW
 *
 * @param id The User ID to be used for the new template.
 * @return Result Code
 */
fpc_result_t fpc_cmd_enroll_request(fpc_id_type_t *id);

/**
 * @brief Populate and transfer a CMD_IDENTIFY Request.
 *
 * id type can be ID_TYPE_SPECIFIED or ID_TYPE_ALL
 *
 * @param id The User ID to be used for the new template.
 * @param tag Operation tag. Will be returned in the response.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_identify_request(fpc_id_type_t *id, uint16_t tag);

/**
 * @brief Populate and transfer a CMD_ABORT request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_abort(void);

/**
 * @brief Populate and transfer a CMD_LIST_TEMPLATES request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_list_templates_request(void);

/**
 * @brief Populate and transfer a CMD_DEL_TEMPLATE request.
 *
 * id type can be ID_TYPE_SPECIFIED or ID_TYPE_ALL
 *
 * @param id The User ID to be deleted.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_delete_template_request(fpc_id_type_t *id);

/**
 * @brief Populate and transfer a CMD_RESET request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_reset_request(void);

/**
 * @brief Populate and transfer a CMD_SET_CRYPTO_KEY request.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_set_crypto_key_request(void);

/**
 * @brief Populate and transfer a CMD_NAVIGATION request.
 *
 * Starts the navigation mode.
 *
 * @param orientation Orientation in 90 degrees per step (0-3).
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_navigation_request(uint8_t orientation);

/**
 * @brief Populate and transfer a CMD_BIST request.
 *
 * Runs the BuiltIn Self Test.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_bist_request(void);

/**
 * @brief Populate and transfer a CMD_GPIO_CONTROL request for SET.
 *
 * Configure gpio pins.
 *
 * @param pin   Pin to configure (see product specification).
 * @param mode  Mode selection (GPIO_CONTROL_MODE_*).
 * @param state State of pin if output (GPIO_CONTROL_STATE_*).
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_gpio_set_request(uint8_t pin, uint8_t mode, uint8_t state);

/**
 * @brief Populate and transfer a CMD_GPIO_CONTROL request for GET.
 *
 * Configure gpio pins.
 *
 * @param pin Pin to get state of (see product specification).
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_gpio_get_request(uint8_t pin);

/**
 * @brief Populate and transfer a CMD_SET_SYSTEM_CONFIG request.
 *
 * Configure various system settings.
 *
 * @param cfg Pointer to ::fpc_system_config_t.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_system_config_set_request(fpc_system_config_t *cfg);

/**
 * @brief Populate and transfer a CMD_GET_SYSTEM_CONFIG request.
 *
 * Configure various system settings.
 *
 * @param type One of FPC_SYS_CFG_TYPE_*.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_system_config_get_request(uint8_t type);

/**
 * @brief Populate and transfer a CMD_PUT_TEMPLATE_DATA request
 *
 * Send template to device.
 *
 * @param id   Template id.
 * @param data Pointer to template data.
 * @param size Size of template data.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_put_template_data_request(uint16_t id, uint8_t* data, size_t size);

/**
 * @brief Populate and transfer a CMD_GET_TEMPLATE_DATA request.
 *
 * Read template from device. This function will allocate memory for the template and
 * return data and size in the callback function (on_data_transfer_done).
 *
 * @param id Template id.
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_get_template_data_request(uint16_t id);

/**
 * @brief Populate and transfer a CMD_FACTORY_RESET request.
 *
 * Perform factory reset (system config flags must be set to support this).
 *
 * @return Result Code
 */
fpc_result_t fpc_cmd_factory_reset_request(void);

/**
 * @brief Handle rx data and parse commands.
 *
 * @return Result Code
 */
fpc_result_t fpc_host_sample_handle_rx_data(void);

/**
 * @brief Initialization of the sample code.
 *
 * @param callbacks Callback functions for command responses and events (optional).
 *
 * @return Result Code
 */
fpc_result_t fpc_host_sample_init(fpc_cmd_callbacks_t *callbacks);

/**
 * @brief Command Handler Loop.
 *
 * This function typically needs to be rewritten to fit the target
 * platform.
 *
 * @return Result Code
 */
fpc_result_t fpc_host_sample_run(void);

/**
 * @brief Stop/Exit Command Handler Loop.
 *
 * Calling this function will make fpc_host_sample_run() exit.
 */
void fpc_host_sample_stop(void);
