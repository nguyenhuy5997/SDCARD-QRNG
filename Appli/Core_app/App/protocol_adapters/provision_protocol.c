/**
 * @file    provision_protocol.c
 * @brief   App-layer command_protocol.h adapter for factory provisioning of the CA identity (CMD_TYPE_PROVISION).
 *
 * FACTORY IMAGE ONLY: compiled and registered only when EVT2_FACTORY_PROVISION is 1 (compiler define). The product image
 * has no CMD_TYPE_PROVISION handler, so the identity cannot be written, replaced or erased over USB in the field -- the
 * same reason the generic keystore commands were removed from security_service's USB adapter (security_protocol.c).
 * Every write goes to one of the fixed CA objects (ca_store.h); the host never passes an object id.
 *
 * Lives in App (not Middleware/CA) for the same reason as ca_protocol.c: it depends on command_protocol.h,
 * Middleware/CA and Middleware/Security at once. Driven by tools/ca_provision.py.
 *
 * Every response: [sub_cmd][status: ca_status_t][data...]
 *   0x01 GET_INFO         -> [presence:1][uid_ok:1][uid:18][pub_ok:1][pub:65][ca_ready:1]
 *                            presence = ca_provision_presence() bit mask; uid/pub are zero-filled when not ok;
 *                            ca_ready = ca_service_init() status of the current content (0 = CA_OK)
 *   0x02 GEN_IDENTITY     -> [pub:65]              identity key pair generated INSIDE the chip
 *   0x03 SIGN_POP         [nonce:32] -> [sig_len:1][sig]   SHA-256("EVT2-POP-v1" || nonce || Q || uid), see ca_provision.h
 *   0x04 WRITE_BLOB       [which:1][data] -> ()   which = ca_prov_blob_t
 *   0x05 READ_BLOB        [which:1] -> [len:2 LE][data]
 *   0x06 FINALIZE         -> ()                    status = ca_service_init() on the stored content (must be CA_OK)
 *   0x07 ERASE            -> ()                    deletes the identity key and all six values
 */
#if defined(EVT2_FACTORY_PROVISION) && EVT2_FACTORY_PROVISION

#include "command_protocol.h"
#include "ca_provision.h"
#include "ca_service.h"
#include "security_service.h"

#include <string.h>

typedef enum {
    PROV_CMD_GET_INFO = 0x01,
    PROV_CMD_GEN_IDENTITY = 0x02,
    PROV_CMD_SIGN_POP = 0x03,
    PROV_CMD_WRITE_BLOB = 0x04,
    PROV_CMD_READ_BLOB = 0x05,
    PROV_CMD_FINALIZE = 0x06,
    PROV_CMD_ERASE = 0x07,
} prov_cmd_t;

#define PROV_POINT_LEN 65U

bool provision_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response, uint16_t *response_len,
                                uint16_t max_response_len)
{
    uint8_t sub_cmd = payload[0];
    response[0] = sub_cmd;
    *response_len = 2U;

    switch (sub_cmd) {
        case PROV_CMD_GET_INFO: {
            if (payload_len != 1U || max_response_len < 2U + 1U + 1U + SEC_UNIQUE_ID_LEN + 1U + PROV_POINT_LEN + 1U) {
                return false;
            }
            size_t o = 2U;
            response[o++] = ca_provision_presence();
            bool uid_ok = security_service_read_unique_id(&response[o + 1U]) == SEC_OK;
            response[o++] = uid_ok ? 1U : 0U;
            if (!uid_ok) {
                memset(&response[o], 0, SEC_UNIQUE_ID_LEN);
            }
            o += SEC_UNIQUE_ID_LEN;
            bool pub_ok = ca_provision_read_identity_pubkey(&response[o + 1U]) == CA_OK;
            response[o++] = pub_ok ? 1U : 0U;
            if (!pub_ok) {
                memset(&response[o], 0, PROV_POINT_LEN);
            }
            o += PROV_POINT_LEN;
            response[o++] = (uint8_t)ca_service_init();
            response[1] = (uint8_t)(security_service_is_ready() ? CA_OK : CA_NOT_READY);
            *response_len = (uint16_t)o;
            return true;
        }
        case PROV_CMD_GEN_IDENTITY: {
            if (payload_len != 1U || max_response_len < 2U + PROV_POINT_LEN) {
                return false;
            }
            ca_status_t st = ca_provision_generate_identity(&response[2]);
            response[1] = (uint8_t)st;
            if (st == CA_OK) {
                *response_len = 2U + PROV_POINT_LEN;
            }
            return true;
        }
        case PROV_CMD_SIGN_POP: {
            if (payload_len != 1U + 32U || max_response_len < 2U + 1U + 72U) {
                return false;
            }
            size_t sig_len = 72U;
            ca_status_t st = ca_provision_sign_pop(&payload[1], &response[3], &sig_len);
            response[1] = (uint8_t)st;
            if (st == CA_OK) {
                response[2] = (uint8_t)sig_len;
                *response_len = (uint16_t)(3U + sig_len);
            }
            return true;
        }
        case PROV_CMD_WRITE_BLOB: {
            if (payload_len < 3U) {
                return false;
            }
            response[1] = (uint8_t)ca_provision_write_blob((ca_prov_blob_t)payload[1], &payload[2], payload_len - 2U);
            return true;
        }
        case PROV_CMD_READ_BLOB: {
            if (payload_len != 2U || max_response_len < 4U) {
                return false;
            }
            size_t len = (size_t)max_response_len - 4U;
            ca_status_t st = ca_provision_read_blob((ca_prov_blob_t)payload[1], &response[4], &len);
            response[1] = (uint8_t)st;
            if (st == CA_OK) {
                response[2] = (uint8_t)(len & 0xFFU);
                response[3] = (uint8_t)((len >> 8) & 0xFFU);
                *response_len = (uint16_t)(4U + len);
            }
            return true;
        }
        case PROV_CMD_FINALIZE: {
            if (payload_len != 1U) {
                return false;
            }
            response[1] = (uint8_t)ca_service_init();
            return true;
        }
        case PROV_CMD_ERASE: {
            if (payload_len != 1U) {
                return false;
            }
            ca_status_t st = ca_provision_erase();
            (void)ca_service_init(); /* drop the cached identity: ca_service is no longer ready */
            response[1] = (uint8_t)st;
            return true;
        }
        default:
            return false;
    }
}

#endif /* EVT2_FACTORY_PROVISION */
