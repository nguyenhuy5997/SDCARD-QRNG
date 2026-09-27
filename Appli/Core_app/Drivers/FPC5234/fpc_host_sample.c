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
 * @file    fpc_host_sample.c
 * @brief   Sample code for FPC AllKey host implementation
 *
 */

/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "fpc_host_sample.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>

#include "fpc_api.h"
#include "fpc_hal.h"


#define TIMEOUT         5000

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

typedef struct {
    uint32_t total_size;
    uint32_t transferred_size;
    uint32_t remaining_size;

    uint32_t max_chunk_size;
    uint8_t* data_buf;
} data_transfer_session_t;

static data_transfer_session_t transfer_session;

/** Flag to control when to exit the sample main loop. */
int keep_on_going = 1;

/** Flag to control usage of secure or non-secure interface
 * In order for the fpc2534 to support the secure interface, a key must have
 * been provisioned using the CMD_SET_CRYPTO_KEY command.
*/
bool use_secure_interface = false;

/** Optional command callback functions. */
static fpc_cmd_callbacks_t cmd_callbacks;

/* Helper Functions */

char *get_id_type_str_(uint16_t id_type)
{
    switch (id_type) {
    case ID_TYPE_NONE: return "ID.None";
    case ID_TYPE_ALL: return "ID.All";
    case ID_TYPE_SPECIFIED: return "ID.Specified";
    case ID_TYPE_GENERATE_NEW: return "ID.Generate";
    }
    return "ID.Unknown";
}

char *get_event_str_(uint16_t evt)
{
    switch (evt) {
    case EVENT_NONE: return "Evt.None";
    case EVENT_IDLE: return "Evt.Idle";
    case EVENT_FINGER_DETECT: return "Evt.FingerDetect";
    case EVENT_FINGER_LOST: return "Evt.FingerLost";
    case EVENT_IMAGE_READY: return "Evt.ImageCaptured";
    case EVENT_CMD_FAILED: return "Evt.Failure";
    }
    return "Evt.Unknown";
}

char *get_enroll_feedback_str_(uint8_t feedback)
{
    switch (feedback) {
    case ENROLL_FEEDBACK_DONE: return "Done";
    case ENROLL_FEEDBACK_PROGRESS: return "Progress";
    case ENROLL_FEEDBACK_REJECT_LOW_QUALITY: return "Reject.LowQuality";
    case ENROLL_FEEDBACK_REJECT_LOW_COVERAGE: return "Reject.LowCoverage";
    case ENROLL_FEEDBACK_REJECT_LOW_MOBILITY: return "Reject.LowMobility";
    case ENROLL_FEEDBACK_REJECT_OTHER: return "Reject.Other";
    case ENROLL_FEEDBACK_PROGRESS_IMMOBILE: return "Progress.Immobile";
    default:
        break;
    }
    return "Unknown";
}

char *get_gesture_str_(uint8_t gesture)
{
    switch (gesture) {
    case CMD_NAV_EVENT_NONE: return "None";
    case CMD_NAV_EVENT_UP: return "Gesture.Up";
    case CMD_NAV_EVENT_DOWN: return "Gesture.Down";
    case CMD_NAV_EVENT_RIGHT: return "Gesture.Right";
    case CMD_NAV_EVENT_LEFT: return "Gesture.Left";
    case CMD_NAV_EVENT_PRESS: return "Gesture.Press";
    case CMD_NAV_EVENT_LONG_PRESS: return "Gesture.LongPress";
    default:
        break;
    }
    return "Unknown";
}

char *get_gpio_state_str_(uint8_t state)
{
    switch (state) {
    case GPIO_CONTROL_STATE_RESET: return "State.Reset";
    case GPIO_CONTROL_STATE_SET: return "State.Set";
    default:
        break;
    }
    return "Unknown";
}


/* Command Requests */

/**
 * @brief Creates a CMD Packet and transfers it on the active interface.
 *
 * Creates a CMD Frame Header and adds the command data to it.
 *
 * @param cmd Command Header with payload.
 * @param size Size of cmd.
 * @return Result Code
 */
static fpc_result_t fpc_send_request_normal(fpc_cmd_hdr_t *cmd, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_frame_hdr_t frame = {0};

    if (!cmd) {
        fpc_sample_logf("Invalid command");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        frame.version = FPC_FRAME_PROTOCOL_VERSION;
        frame.type = FPC_FRAME_TYPE_CMD_REQUEST;
        frame.flags = FPC_FRAME_FLAG_SENDER_HOST;
        frame.payload_size = (uint16_t)size;

        /* Send frame header. */
        result = fpc_hal_tx((uint8_t*)&frame, sizeof(fpc_frame_hdr_t), TIMEOUT, 0);
    }

    if (result == FPC_RESULT_OK) {
        /* Send payload. */
        result = fpc_hal_tx((uint8_t*)cmd, size, TIMEOUT, 1);
    }

    return result;
}


/**
 * @brief Creates a SECURE CMD Packet and transfers it on active interface.
 *
 * Creates a Secure CMD Frame Header and adds the command data to it.
 *
 * @param cmd Command Header with payload.
 * @param size Size of cmd.
 * @return Result Code
 */
static fpc_result_t fpc_send_request_secure(fpc_cmd_hdr_t *cmd, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_frame_hdr_t frame = {0};
    fpc_frame_hdr_sec_addon_t *frame_addon = NULL;

    uint8_t *secure_payload = NULL;

    if (!cmd) {
        fpc_sample_logf("Invalid command");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        /* Setup Header */
        frame.version = FPC_FRAME_PROTOCOL_VERSION;
        frame.type = FPC_FRAME_TYPE_CMD_REQUEST;
        frame.flags = FPC_FRAME_FLAG_SENDER_HOST | FPC_FRAME_FLAG_SECURE;
        /* NB, add space for the secure addon information. */
        frame.payload_size = (uint16_t)size + sizeof(fpc_frame_hdr_sec_addon_t);

        /* Allocate a buffer for the addon data and encrypted payload. */
        secure_payload = malloc(frame.payload_size);
        if (secure_payload) {
            frame_addon = (fpc_frame_hdr_sec_addon_t*)secure_payload;
        }
        else {
            result = FPC_RESULT_OUT_OF_MEMORY;
        }
    }

    if (result == FPC_RESULT_OK) {
        /* Create IV (random number) */
        result = fpc_hal_crypto_gen_random(frame_addon->iv, FPC_AES_GCM_IV_SIZE);
    }
    else {
       	fpc_sample_logf("Setup Header Fail");
    }
    if (result == FPC_RESULT_OK) {
        result = fpc_hal_crypto_encrypt_aes_gcm(
            frame_addon->iv,
            (uint8_t*)&frame, sizeof(fpc_frame_hdr_t), // <= AAD
            (uint8_t*)cmd, size,
            frame_addon->ciphertext,
            frame_addon->gmac_tag);
    }
    else {
       	fpc_sample_logf("Create IV fail");
    }
    if (result == FPC_RESULT_OK) {
        /* Send frame header . */
        result = fpc_hal_tx((uint8_t*)&frame, sizeof(fpc_frame_hdr_t), TIMEOUT, 0);
    }
    else {
       	fpc_sample_logf("Encrypt_aes IV fail");
    }
    if (result == FPC_RESULT_OK) {
        /* Send payload. */
        result = fpc_hal_tx(secure_payload, frame.payload_size, TIMEOUT, 1);
    }
    else {
       	fpc_sample_logf("Send frame header fail");
    }
    if (secure_payload) {
        free(secure_payload);
    }
    if(result != FPC_RESULT_OK){
    	fpc_sample_logf("Send payload fail");
    }
    return result;
}


/**
 * @brief Send Request. Disapatcher for normal vs secure send function.
 *
 * Routes the command to the globally selected send function.
 *
 * @param cmd Command Header with payload.
 * @param size Size of cmd.
 * @return Result Code
 */
static fpc_result_t fpc_send_request(fpc_cmd_hdr_t *cmd, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;

    if (use_secure_interface) {
        result = fpc_send_request_secure(cmd, size);
        if(result != FPC_RESULT_OK) {
        	fpc_sample_logf("Send request Encrypt Fail");
        }
    }
    else {
        result = fpc_send_request_normal(cmd, size);
    }

    return result;
}


static fpc_result_t fpc_cmd_data_get_setup(uint32_t total_size, uint32_t max_chunk_size)
{
    fpc_result_t result = FPC_RESULT_OK;

    transfer_session.data_buf = malloc(total_size);
    if (transfer_session.data_buf == NULL) {
        fpc_sample_logf("Data allocation failed");
        return FPC_RESULT_OUT_OF_MEMORY;
    }

    transfer_session.total_size = total_size;
    transfer_session.transferred_size = 0;
    transfer_session.remaining_size = total_size;
    transfer_session.max_chunk_size = max_chunk_size;

    fpc_sample_logf("GET: total size %d, chunk size %d", total_size, max_chunk_size);

    return result;
}


static fpc_result_t fpc_cmd_data_put_setup(uint8_t *data, uint32_t total_size)
{
    fpc_result_t result = FPC_RESULT_OK;

    transfer_session.max_chunk_size = 0;
    transfer_session.data_buf = data;
    transfer_session.total_size = total_size;
    transfer_session.remaining_size = total_size;
    transfer_session.transferred_size = 0;

    return result;
}


/**
 * @brief Sends a CMD_DATA_GET request.
 *
 * Called to either start a transfer or continuing from parse_cmd_data_...
 *
 * @return Result Code
 */
static fpc_result_t fpc_cmd_data_get_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_data_get_request_t cmd_req;

    cmd_req.cmd.cmd_id = CMD_DATA_GET;
    cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    cmd_req.request_size = min(transfer_session.remaining_size, transfer_session.max_chunk_size);
    result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_data_get_request_t));

    return result;
}


/**
 * @brief Sends a CMD_DATA_PUT request.
 *
 * Called to either start a transfer or continuing from parse_cmd_data_...
 *
 * @param max_chunk_size Max chunk size.
 *
 * @return Result Code
 */
static fpc_result_t fpc_cmd_data_put_request(uint32_t max_chunk_size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_data_put_request_t *cmd_req = NULL;
    uint32_t chunk_size = min(transfer_session.remaining_size, max_chunk_size);
    uint32_t packet_size = sizeof(fpc_cmd_data_put_request_t) + chunk_size;

    if (transfer_session.data_buf == NULL) {
        fpc_sample_logf("PUT: No session");
        result = FPC_RESULT_WRONG_STATE;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req = malloc(packet_size);
        if (cmd_req == NULL) {
            result = FPC_RESULT_OUT_OF_MEMORY;
        }
    }

    if (result == FPC_RESULT_OK) {
        cmd_req->data_size = chunk_size;
        memcpy(cmd_req->data, transfer_session.data_buf + transfer_session.transferred_size,
            chunk_size);
        cmd_req->remaining_size = transfer_session.remaining_size - chunk_size;

        transfer_session.max_chunk_size = max_chunk_size;
        transfer_session.remaining_size -= chunk_size;
        transfer_session.transferred_size += chunk_size;

        cmd_req->cmd.cmd_id = CMD_DATA_PUT;
        cmd_req->cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        result = fpc_send_request(&cmd_req->cmd, packet_size);
    }

    if (cmd_req) {
        free(cmd_req);
    }

    return result;

}


fpc_result_t fpc_cmd_status_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* Status Command Request has no payload */
    cmd.cmd_id = CMD_STATUS;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_STATUS");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_version_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* Version Command Request has no payload */
    cmd.cmd_id = CMD_VERSION;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_VERSION");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_enroll_request(fpc_id_type_t *id)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_enroll_request_t cmd_req;

    if (id->type != ID_TYPE_SPECIFIED && id->type != ID_TYPE_GENERATE_NEW) {
        fpc_sample_logf("Enroll Request: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_ENROLL;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        cmd_req.tpl_id.type = id->type;
        cmd_req.tpl_id.id = id->id;

        fpc_sample_logf(">>> CMD_ENROLL (id.type=%s, id=%d)",
            get_id_type_str_(id->type), id->id);

        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_enroll_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_identify_request(fpc_id_type_t *id, uint16_t tag)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_identify_request_t cmd_req;

    if (id->type != ID_TYPE_SPECIFIED && id->type != ID_TYPE_ALL) {
        fpc_sample_logf("Identify: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_IDENTIFY;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        cmd_req.tpl_id.type = id->type;
        cmd_req.tpl_id.id = id->id;
        cmd_req.tag = tag;

        fpc_sample_logf(">>> CMD_IDENTIFY (tag=%d, id.type=%s, id=%d)",
            tag, get_id_type_str_(id->type), id->id);

        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_identify_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_abort(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* Abort Command Request has no payload */
    cmd.cmd_id = CMD_ABORT;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_ABORT");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_list_templates_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* List Template Command Request has no payload */
    cmd.cmd_id = CMD_LIST_TEMPLATES;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_LIST_TEMPLATES");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_delete_template_request(fpc_id_type_t *id)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_delete_request_t cmd_req;

    if (id->type != ID_TYPE_SPECIFIED && id->type != ID_TYPE_ALL) {
        fpc_sample_logf("Delete Tpl: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_DELETE_TEMPLATE;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        cmd_req.tpl_id.type = id->type;
        cmd_req.tpl_id.id = id->id;

        fpc_sample_logf(">>> CMD_DELETE_TEMPLATE (id.type=%s, id=%d)",
            get_id_type_str_(id->type), id->id);

        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_template_delete_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_reset_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* Reset Command Request has no payload */
    cmd.cmd_id = CMD_RESET;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_RESET");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_set_crypto_key_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    uint8_t *cmd_buf = NULL;
    uint8_t *key = NULL;
    uint32_t key_size = 0;

    result = fpc_hal_crypto_get_aes_key(&key, &key_size);

    if (result == FPC_RESULT_OK) {
        cmd_buf = malloc(sizeof(fpc_cmd_set_crypto_key_request_t) + key_size);
        if (!cmd_buf) {
            result = FPC_RESULT_OUT_OF_MEMORY;
        }
    }

    if (result == FPC_RESULT_OK) {
        fpc_cmd_set_crypto_key_request_t *key_req =
            (fpc_cmd_set_crypto_key_request_t*)cmd_buf;

        key_req->key_size = key_size;
        memcpy(key_req->key, key, key_size);

        key_req->cmd.cmd_id = CMD_SET_CRYPTO_KEY;
        key_req->cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        fpc_sample_logf(">>> CMD_SET_CRYPTO_KEY");
        result = fpc_send_request(&key_req->cmd,
            sizeof(fpc_cmd_set_crypto_key_request_t) + key_size);
    }

    return result;
}


fpc_result_t fpc_cmd_navigation_request(uint8_t orientation)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_navigation_request_t cmd_req;

    if (orientation > 3) {
        fpc_sample_logf("Navigation: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_NAVIGATION;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;
        cmd_req.config = orientation;

        fpc_sample_logf(">>> CMD_NAVIGATION (orientation=%d)", orientation);
        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_navigation_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_bist_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* BIST Command Request has no payload */
    cmd.cmd_id = CMD_BIST;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_BIST");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


fpc_result_t fpc_cmd_gpio_set_request(uint8_t pin, uint8_t mode, uint8_t state)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_pinctrl_gpio_request_t cmd_req;

    if ((mode > GPIO_CONTROL_MODE_INPUT_PULL_DOWN) || (state > GPIO_CONTROL_STATE_SET)) {
        fpc_sample_logf("GPIO: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_GPIO_CONTROL;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        cmd_req.sub_cmd = GPIO_CONTROL_SUB_CMD_SET;
        cmd_req.pin = pin;
        cmd_req.mode = mode;
        cmd_req.state = state;

        fpc_sample_logf(">>> CMD_GPIO_CONTROL (set pin=%d, mode=%d, state=%d)",
            pin, mode, state);
        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_pinctrl_gpio_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_gpio_get_request(uint8_t pin)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_pinctrl_gpio_request_t cmd_req;

    cmd_req.cmd.cmd_id = CMD_GPIO_CONTROL;
    cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    cmd_req.sub_cmd = GPIO_CONTROL_SUB_CMD_GET;
    cmd_req.pin = pin;
    cmd_req.mode = 0;
    cmd_req.state = 0;

    fpc_sample_logf(">>> CMD_GPIO_CONTROL (get pin=%d)", pin);
    result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_pinctrl_gpio_request_t));

    return result;
}


fpc_result_t fpc_cmd_system_config_set_request(fpc_system_config_t *cfg)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_set_config_request_t cmd_req;

    if (cfg == NULL) {
        fpc_sample_logf("Set System Config: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_SET_SYSTEM_CONFIG;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

        cmd_req.cfg = *cfg;

        fpc_sample_logf(">>> CMD_SET_SYSTEM_CONFIG");
        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_set_config_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_system_config_get_request(uint8_t type)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_get_config_request_t cmd_req;

    if (type > FPC_SYS_CFG_TYPE_CUSTOM) {
        fpc_sample_logf("Get System Config: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_GET_SYSTEM_CONFIG;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;
        cmd_req.config_type = type;

        fpc_sample_logf(">>> CMD_GET_SYSTEM_CONFIG (type=%d)", type);
        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_get_config_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_put_template_data_request(uint16_t id, uint8_t* data, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_data_request_t cmd_req;

    if (data == NULL) {
        return FPC_RESULT_INVALID_PARAM;
    }

    result = fpc_cmd_data_put_setup(data, size);

    if (result == FPC_RESULT_OK) {
        cmd_req.cmd.cmd_id = CMD_PUT_TEMPLATE_DATA;
        cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;
        cmd_req.id = id;
        cmd_req.total_size = size;

        fpc_sample_logf(">>> CMD_PUT_TEMPLATE_DATA (id=%d, size=%d)", id, size);
        result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_template_data_request_t));
    }

    return result;
}


fpc_result_t fpc_cmd_get_template_data_request(uint16_t id)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_data_request_t cmd_req;

    cmd_req.cmd.cmd_id = CMD_GET_TEMPLATE_DATA;
    cmd_req.cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;
    cmd_req.id = id;
    // Total Size is not needed when we request a template.
    cmd_req.total_size = 0;

    fpc_sample_logf(">>> CMD_GET_TEMPLATE_DATA (id=%d)", id);
    result = fpc_send_request(&cmd_req.cmd, sizeof(fpc_cmd_template_data_request_t));

    return result;
}


fpc_result_t fpc_cmd_factory_reset_request(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t cmd;

    /* Factory Reset Command Request has no payload */
    cmd.cmd_id = CMD_FACTORY_RESET;
    cmd.type = FPC_FRAME_TYPE_CMD_REQUEST;

    fpc_sample_logf(">>> CMD_FACTORY_RESET");
    result = fpc_send_request(&cmd, sizeof(fpc_cmd_hdr_t));

    return result;
}


/* Command Responses / Events */

static fpc_result_t parse_cmd_status(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_status_response_t *status = (fpc_cmd_status_response_t*)cmd_hdr;

    if (size != sizeof(fpc_cmd_status_response_t)) {
        fpc_sample_logf("CMD_STATUS invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_status_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_STATUS.event = %s (%04X)",
            get_event_str_(status->event), status->event);
        fpc_sample_logf("CMD_STATUS.state = %04X", status->state);
        fpc_sample_logf("CMD_STATUS.error = %d", status->app_fail_code);

        if (status->state & STATE_SECURE_INTERFACE) {
            /* The device supports secure interface. Set the flag to indicate
               that the secure interface shall be used. */
            use_secure_interface = true;
        }
        else {
            use_secure_interface = false;
        }
    }

    if ((status->app_fail_code != 0) && cmd_callbacks.on_error) {
        cmd_callbacks.on_error(status->app_fail_code);
    }
    else if (cmd_callbacks.on_status) {
        cmd_callbacks.on_status(status->event, status->state);
    }

    return result;
}


static fpc_result_t parse_cmd_version(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_version_response_t *ver = (fpc_cmd_version_response_t*)cmd_hdr;
    size_t full_size = 0;

    /* The full size of the command must include the length of the
       version string (unset array) */
    full_size = sizeof(fpc_cmd_version_response_t) +
        ver->version_str_len;

    if (size != full_size) {
        fpc_sample_logf("CMD_VERSION invalid size (%d vs %d)", size, full_size);
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_VERSION.fw_id = %d", ver->fw_id);
        fpc_sample_logf("CMD_VERSION.unique_id = %08X %08X %08X",
            ver->mcu_unique_id[0],
            ver->mcu_unique_id[1],
            ver->mcu_unique_id[2]);
        fpc_sample_logf("CMD_VERSION.fuse_level = %d", ver->fw_fuse_level);
        fpc_sample_logf("CMD_VERSION.version_str_len = %d", ver->version_str_len);
        fpc_sample_logf("CMD_VERSION.version = %s", ver->version_str);
    }

    if (cmd_callbacks.on_version) {
        cmd_callbacks.on_version(ver->version_str);
    }

    return result;
}


static fpc_result_t parse_cmd_enroll_status(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_enroll_status_response_t *status = (fpc_cmd_enroll_status_response_t*)cmd_hdr;

    if (size != sizeof(fpc_cmd_enroll_status_response_t)) {
        fpc_sample_logf("CMD_ENROLL invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_enroll_status_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_ENROLL.id = %d", status->id);
        fpc_sample_logf("CMD_ENROLL.feedback = %s",
            get_enroll_feedback_str_(status->feedback));
        fpc_sample_logf("CMD_ENROLL.samples_remaining = %d", status->samples_remaining);
    }

    if (cmd_callbacks.on_enroll) {
        cmd_callbacks.on_enroll(status->feedback, status->samples_remaining);
    }

    return result;
}


static fpc_result_t parse_cmd_identify(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_identify_status_response_t *id_res = (fpc_cmd_identify_status_response_t*)cmd_hdr;

    if (size != sizeof(fpc_cmd_identify_status_response_t)) {
        fpc_sample_logf("CMD_IDENTIFY invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_identify_status_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_IDENTIFY.result = %s (0x%04X)",
            (id_res->match == IDENTIFY_RESULT_MATCH) ? "MATCH" : "No Match", id_res->match);
        fpc_sample_logf("CMD_IDENTIFY.id_type = %s", get_id_type_str_(id_res->tpl_id.type));
        fpc_sample_logf("CMD_IDENTIFY.id = %d", id_res->tpl_id.id);
        fpc_sample_logf("CMD_IDENTIFY.tag = %d", id_res->tag);
    }

    if (cmd_callbacks.on_identify) {
        cmd_callbacks.on_identify(id_res->match == IDENTIFY_RESULT_MATCH, id_res->tpl_id.id);
    }

    return result;
}


static fpc_result_t parse_cmd_list_templates(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_info_response_t *list = (fpc_cmd_template_info_response_t*)cmd_hdr;
    size_t total_pl_size = 0;
    uint16_t i;

    total_pl_size = sizeof(fpc_cmd_template_info_response_t) +
        (sizeof(uint16_t) * list->number_of_templates);

    if (size != total_pl_size) {
        fpc_sample_logf("CMD_LIST_TEMPLATES invalid size (%d vs %d)", size,
            total_pl_size);
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_LIST_TEMPLATES.nbr_of_tpls = %d",
            list->number_of_templates);

        for (i = 0; i < list->number_of_templates; i++) {
            fpc_sample_logf("CMD_LIST_TEMPLATES.id = %d", list->template_id_list[i]);
        }
    }

    if (cmd_callbacks.on_list_templates) {
        cmd_callbacks.on_list_templates(list->number_of_templates, list->template_id_list);
    }

    return result;
}


static fpc_result_t parse_cmd_navigation_event(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_navigation_status_event_t *cmd_nav = (fpc_cmd_navigation_status_event_t*)cmd_hdr;

    if (size != sizeof(fpc_cmd_navigation_status_event_t)) {
        fpc_sample_logf("CMD_NAVIGATION invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_navigation_status_event_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_NAVIGATION.gesture = %s", get_gesture_str_(cmd_nav->gesture));
    }

    if (cmd_callbacks.on_navigation) {
        cmd_callbacks.on_navigation(cmd_nav->gesture);
    }

    return result;
}


static fpc_result_t parse_cmd_gpio_control(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_pinctrl_gpio_response_t *cmd_rsp = (fpc_cmd_pinctrl_gpio_response_t*)cmd_hdr;

    if (size != sizeof(fpc_cmd_pinctrl_gpio_response_t)) {
        fpc_sample_logf("CMD_GPIO_CONTROL invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_pinctrl_gpio_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_GPIO_CONTROL.state = %s", get_gpio_state_str_(cmd_rsp->state));
    }

    if (cmd_callbacks.on_gpio_control) {
        cmd_callbacks.on_gpio_control(cmd_rsp->state);
    }

    return result;
}


static fpc_result_t parse_cmd_get_system_config(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_get_config_response_t *cmd_cfg = (fpc_cmd_get_config_response_t*)cmd_hdr;

    if (size < sizeof(fpc_cmd_get_config_response_t)) {
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_get_config_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("%s Config:", cmd_cfg->config_type == 0 ? "Default" : "Custom");
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.ver = %d", cmd_cfg->cfg.version);

        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.sys_flags = %08X:", cmd_cfg->cfg.sys_flags);

        if (cmd_cfg->cfg.sys_flags & CFG_SYS_FLAG_STATUS_EVT_AT_BOOT)
            fpc_sample_logf(" - CFG_SYS_FLAG_STATUS_EVT_AT_BOOT");
        if (cmd_cfg->cfg.sys_flags & CFG_SYS_FLAG_UART_IN_STOP_MODE)
            fpc_sample_logf(" - CFG_SYS_FLAG_UART_IN_STOP_MODE");
        if (cmd_cfg->cfg.sys_flags & CFG_SYS_FLAG_UART_IRQ_BEFORE_TX)
            fpc_sample_logf(" - CFG_SYS_FLAG_UART_IRQ_BEFORE_TX");
        if (cmd_cfg->cfg.sys_flags & CFG_SYS_FLAG_ALLOW_FACTORY_RESET)
            fpc_sample_logf(" - CFG_SYS_FLAG_ALLOW_FACTORY_RESET");

        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.uart_irq_dly = %d ms",
            cmd_cfg->cfg.uart_delay_before_irq_ms);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.uart_baudrate_idx = %d",
            cmd_cfg->cfg.uart_baudrate);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.finger_scan_intv = %d ms",
            cmd_cfg->cfg.finger_scan_interval_ms);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.idfy_max_consecutive_fails = %d",
                 cmd_cfg->cfg.idfy_max_consecutive_fails);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.idfy_lockout_time_s = %d s",
            cmd_cfg->cfg.idfy_lockout_time_s);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.idle_time_before_sleep_ms = %d ms",
                cmd_cfg->cfg.idle_time_before_sleep_ms);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.enroll_touches = %d", cmd_cfg->cfg.enroll_touches);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.enroll_immobile_touches = %d",
            cmd_cfg->cfg.enroll_immobile_touches);
        fpc_sample_logf("CMD_GET_SYSTEM_CONFIG.i2c_address = %x", cmd_cfg->cfg.i2c_address);
    }

    if (cmd_callbacks.on_system_config_get) {
        cmd_callbacks.on_system_config_get(&cmd_cfg->cfg);
    }

    return result;
}


static fpc_result_t parse_cmd_bist(fpc_cmd_hdr_t *cmd_hdr, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_bist_response_t *cmd_rsp = (fpc_cmd_bist_response_t*)cmd_hdr;

    if (size < sizeof(fpc_cmd_bist_response_t)) {
        fpc_sample_logf("CMD_BIST invalid size (%d vs %d)", size,
            sizeof(fpc_cmd_pinctrl_gpio_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("CMD_BIST.sensor_test_result = %d", cmd_rsp->sensor_test_result);
        fpc_sample_logf("CMD_BIST.test_verdict = %d", cmd_rsp->test_verdict);
    }

    if (cmd_callbacks.on_bist_done) {
        cmd_callbacks.on_bist_done(cmd_rsp->test_verdict);
    }

    return result;
}


static fpc_result_t parse_cmd_get_template_data(fpc_cmd_hdr_t *cmd, uint16_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_data_response_t *data = (fpc_cmd_template_data_response_t*)cmd;

    if (size < sizeof(fpc_cmd_template_data_response_t)) {
        fpc_sample_logf("CMD_GET_TEMPLATE_DATA invalid size (%d vs %d)",
            size, sizeof(fpc_cmd_template_data_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("Setup Template Data Transfer. Max chunk size = %d", data->max_chunk_size);
        // Start transfer loop
        result = fpc_cmd_data_get_setup(data->total_size, data->max_chunk_size);
    }

    if (result == FPC_RESULT_OK) {
        result = fpc_cmd_data_get_request();
    }

    return FPC_RESULT_OK;
}


static fpc_result_t parse_cmd_put_template_data(fpc_cmd_hdr_t *cmd, uint16_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_template_data_response_t *data = (fpc_cmd_template_data_response_t*)cmd;

    if (size < sizeof(fpc_cmd_template_data_response_t)) {
        fpc_sample_logf("CMD_PUT_TEMPLATE_DATA invalid size (%d vs %d)",
            size, sizeof(fpc_cmd_template_data_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        // Start transfer loop
        result = fpc_cmd_data_put_request(data->max_chunk_size);
    }

    return result;
}


static fpc_result_t parse_cmd_data_get(fpc_cmd_hdr_t *cmd, uint16_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_data_get_response_t *cmd_rsp = (fpc_cmd_data_get_response_t*)cmd;

    if (transfer_session.data_buf == NULL) {
        fpc_sample_logf("CMD_DATA_GET no data buffer allocated");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        if (size < sizeof(fpc_cmd_data_get_response_t)) {
            fpc_sample_logf("CMD_DATA_GET invalid size (%d vs %d)",
                size, sizeof(fpc_cmd_data_get_response_t));
            result = FPC_RESULT_INVALID_PARAM;
        }
    }

    if (result == FPC_RESULT_OK) {
        if (size != (sizeof(fpc_cmd_data_get_response_t) + cmd_rsp->data_size))
        {
            fpc_sample_logf("CMD_DATA_GET invalid size, incl data (%d vs %d)",
                size, sizeof(fpc_cmd_data_get_response_t) + cmd_rsp->data_size);
            result = FPC_RESULT_INVALID_PARAM;
        }
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("Data: Got %d, remaining %d", cmd_rsp->data_size,
            cmd_rsp->remaining_size);

        memcpy(transfer_session.data_buf + transfer_session.transferred_size, cmd_rsp->data,
            cmd_rsp->data_size);

        transfer_session.transferred_size += cmd_rsp->data_size;
        transfer_session.remaining_size = cmd_rsp->remaining_size;

        if (cmd_rsp->remaining_size > 0) {
            fpc_cmd_data_get_request();
        }
        else {
            fpc_sample_logf("CMD_DATA_GET done");
            if (cmd_callbacks.on_data_transfer_done) {
                cmd_callbacks.on_data_transfer_done(transfer_session.data_buf,
                    transfer_session.total_size);
            }
            free(transfer_session.data_buf);
            transfer_session.data_buf = NULL;
        }
    }

    return result;
}


static fpc_result_t parse_cmd_data_put(fpc_cmd_hdr_t *cmd, uint16_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_data_put_response_t *cmd_rsp = (fpc_cmd_data_put_response_t*)cmd;
    (void)cmd_rsp; /* only read by fpc_sample_logf(), which is empty without EVT2_DIAGNOSTICS */

    if (size < sizeof(fpc_cmd_data_put_response_t)) {
        fpc_sample_logf( "CMD_DATA_PUT invalid size (%d vs %d)",
            size, sizeof(fpc_cmd_data_put_response_t));
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        fpc_sample_logf("DATA Put Response (total put = %d)", cmd_rsp->total_received);

        if (transfer_session.remaining_size == 0) {
            fpc_sample_logf("CMD_DATA_PUT done");
            if (cmd_callbacks.on_data_transfer_done) {
                cmd_callbacks.on_data_transfer_done(NULL, 0);
            }
        }
        else {
            result = fpc_cmd_data_put_request(transfer_session.max_chunk_size);
        }
    }

    return result;
}


static fpc_result_t parse_cmd(uint8_t *frame_payload, size_t size)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_cmd_hdr_t *cmd_hdr;

    cmd_hdr = (fpc_cmd_hdr_t*)frame_payload;

    if (!cmd_hdr) {
        fpc_sample_logf("Parse Cmd: Invalid parameter");
        result = FPC_RESULT_INVALID_PARAM;
    }

    if (result == FPC_RESULT_OK) {
        if (cmd_hdr->type != FPC_FRAME_TYPE_CMD_EVENT &&
            cmd_hdr->type != FPC_FRAME_TYPE_CMD_RESPONSE) {
            fpc_sample_logf("Parse Cmd: Invalid parameter (type)");
            result = FPC_RESULT_INVALID_PARAM;
        }
    }

    if (result == FPC_RESULT_OK) {
        switch (cmd_hdr->cmd_id) {
        case CMD_STATUS:
            return parse_cmd_status(cmd_hdr, size);
            break;
        case CMD_VERSION:
            return parse_cmd_version(cmd_hdr, size);
            break;
        case CMD_ENROLL:
            return parse_cmd_enroll_status(cmd_hdr, size);
            break;
        case CMD_IDENTIFY:
            return parse_cmd_identify(cmd_hdr, size);
            break;
        case CMD_LIST_TEMPLATES:
            return parse_cmd_list_templates(cmd_hdr, size);
            break;
        case CMD_NAVIGATION:
            return parse_cmd_navigation_event(cmd_hdr, size);
            break;
        case CMD_GPIO_CONTROL:
            return parse_cmd_gpio_control(cmd_hdr, size);
            break;
        case CMD_GET_SYSTEM_CONFIG:
            return parse_cmd_get_system_config(cmd_hdr, size);
            break;
        case CMD_BIST:
            return parse_cmd_bist(cmd_hdr, size);
            break;
        case CMD_GET_TEMPLATE_DATA:
            return parse_cmd_get_template_data(cmd_hdr, size);
            break;
        case CMD_PUT_TEMPLATE_DATA:
            return parse_cmd_put_template_data(cmd_hdr, size);
            break;
        case CMD_DATA_GET:
            return parse_cmd_data_get(cmd_hdr, size);
            break;
        case CMD_DATA_PUT:
            return parse_cmd_data_put(cmd_hdr, size);
            break;
        default:
            fpc_sample_logf("Parse Cmd: Unexpected Command ID");
            break;
        };
    }

    return result;
}


fpc_result_t fpc_host_sample_handle_rx_data(void)
{
    fpc_result_t result = FPC_RESULT_OK;
    fpc_frame_hdr_t frame_hdr;
    uint8_t *frame_payload_buffer = NULL;
    uint8_t *frame_payload = NULL;

    /* Step 1: Read Frame Header */
    result = fpc_hal_rx((uint8_t*)&frame_hdr, sizeof(fpc_frame_hdr_t), TIMEOUT, 1);

    if (result == FPC_RESULT_OK) {
        /* Sanity Check */
        if (frame_hdr.version != FPC_FRAME_PROTOCOL_VERSION ||
            ((frame_hdr.flags & FPC_FRAME_FLAG_SENDER_FW_APP) == 0) ||
            (frame_hdr.type != FPC_FRAME_TYPE_CMD_RESPONSE &&
             frame_hdr.type != FPC_FRAME_TYPE_CMD_EVENT)) {
            fpc_sample_logf("Sanity check of rx data failed");
            result = FPC_RESULT_IO_BAD_DATA;
        }
    }
    fpc_sample_logf("frame_hdr.version: 0x%04X\nframe_hdr.flags: 0x%04X\nframe_hdr.type: 0x%04X\n", \
    				frame_hdr.version, frame_hdr.flags, frame_hdr.type);

    if (result == FPC_RESULT_OK) {
        frame_payload_buffer = malloc(frame_hdr.payload_size);
        frame_payload = frame_payload_buffer;
        if (!frame_payload_buffer) {
            fpc_sample_logf("Failed to malloc");
            result = FPC_RESULT_OUT_OF_MEMORY;
        }
    }

    if (result == FPC_RESULT_OK) {
        /* Step 2: Read Frame Payload (Command) */
        result = fpc_hal_rx(frame_payload, frame_hdr.payload_size, TIMEOUT, 0);
    }

    if ((frame_hdr.flags & FPC_FRAME_FLAG_SECURE) != 0) {

        // Frame is encrypted => Decrypt it.

        // FRAME HEADER (AAD) ||| AES-GCM ADDON ||| CMD DATA (PAYLOAD)

        fpc_frame_hdr_sec_addon_t *gcm_data =
                (fpc_frame_hdr_sec_addon_t*)frame_payload;

        uint8_t *encrypted_payload =
                frame_payload + sizeof(fpc_frame_hdr_sec_addon_t);

        uint32_t gmac_validation = 0;

        int payload_size =
                frame_hdr.payload_size - sizeof(fpc_frame_hdr_sec_addon_t);

        if (payload_size < 0) {
            fpc_sample_logf("Invalid sec pl size (%d)", frame_hdr.payload_size);
            result = FPC_RESULT_INVALID_PARAM;
        }

        if (result == FPC_RESULT_OK) {

            result = fpc_hal_crypto_decrypt_and_verify_aes_gcm( gcm_data->iv,
																(uint8_t*)&frame_hdr, sizeof(fpc_frame_hdr_t), // AAD
																encrypted_payload, payload_size,
																encrypted_payload,
																gcm_data->gmac_tag,
																&gmac_validation);
            if(result != FPC_RESULT_OK)
            {
            	fpc_sample_logf("Decrypt fail, error: %d", result);
            }
            // Update the payload (that is, exclude the addon part)
            frame_hdr.payload_size = payload_size;
            frame_payload += sizeof(fpc_frame_hdr_sec_addon_t);
        }

        if (result == FPC_RESULT_OK) {
            // Do an extra check of the gmac tag
            if (gmac_validation != FPC_GMAC_VALID) {
                fpc_sample_logf("Invalid GMAC");
                result = FPC_RESULT_FAILURE;
            }
        }
    }

    if (result == FPC_RESULT_OK) {
        result = parse_cmd(frame_payload, frame_hdr.payload_size);
    }

    if (frame_payload_buffer) {
        free(frame_payload_buffer);
    }

    if (result != FPC_RESULT_OK) {
        fpc_sample_logf("Failed to handle RX data, error %d", result);
        // Make sure CS is restored.
        (void)fpc_hal_rx(NULL, 0, 0, 0);
    }

    return result;
}


fpc_result_t fpc_host_sample_init(fpc_cmd_callbacks_t *callbacks)
{
    fpc_result_t result = FPC_RESULT_OK;

    if (callbacks) {
        cmd_callbacks = *callbacks;
    }
    result = fpc_hal_init();

    return result;
}


fpc_result_t fpc_host_sample_run(void)
{
    fpc_result_t result = FPC_RESULT_OK;

    while (keep_on_going) {

        if (fpc_hal_data_available()) {

            result = fpc_host_sample_handle_rx_data();
            if (result != FPC_RESULT_OK) {
                fpc_sample_logf("Failed to handle RX data, error %d", result);
                fpc_hal_delay_ms(1000);
            }
        }

        result = fpc_hal_wfi();
        if (result != FPC_RESULT_OK) {
            fpc_sample_logf("Failed to handle wfi, error %d", result);
        }
    }

    return result;
}

void fpc_host_sample_stop(void)
{
    keep_on_going = 0;
}

#endif /* EVT2_ENABLE_BIOMETRIC */
