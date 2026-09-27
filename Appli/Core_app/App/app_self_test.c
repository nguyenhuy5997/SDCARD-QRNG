/**
 * @file    app_self_test.c
 * @brief   App-layer self-test exercising the whole Core_app stack -- dev/QA builds only.
 *
 * Not a unit test framework -- a real, runnable smoke test that proves
 * Platform (GPIO/UART/I2C/ADC/Timer/Time/RNG/DAC/Hash), Core_app/BSP/board.h
 * and Middleware/Security, Middleware/Biometric and Middleware/QRNG all
 * fit together the way the rest of Core_app assumes. App code only ever
 * includes platform.h/board.h/security_service.h/biometric_service.h/
 * qrng_service.h, never anything under Core_app/Drivers (SE05x, FPC5234
 * or QRNG) or a vendor HAL directly -- that boundary is exactly what
 * this file exercises.
 *
 * Split out of app_main.c (2026-09-24): app_main.c now holds only what a product build actually needs (app_init(),
 * app_command_protocol_init()/_poll() -- bring-up and USB/command-protocol wiring); this file is the dev/QA-only
 * exerciser and is simply not linked into a build that does not call these functions. Src/main.c's boot sequence
 * calls both app_main.h's and this file's functions today; a product build removes the calls into this file (and
 * can drop app_self_test.c from the project) without touching app_main.c at all.
 */
/* Dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS

#include "app_self_test.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "platform.h"
#include "platform_crypto.h"
#include "board.h"
#include "security_service.h"
#if EVT2_ENABLE_BIOMETRIC
#include "biometric_service.h"
#endif
#include "qrng_service.h"
#include "ca_service.h"
#include "pqc_kem.h"
#include "pqc_kem_kat_vector.h"
#include "pqc_sign.h"
#include "pqc_sign_kat_vector.h"

/* Defined in Core_app/App/app_main.c -- not declared in any shared header, same convention as this file's other
 * `extern`s below: only this file needs to know app_main.c owns the debug-log formatting helpers (it also uses them
 * itself, e.g. inside app_command_protocol_init()), so there is exactly one implementation. */
extern void app_log(const char *msg);
extern void app_log_hex(const uint8_t *data, size_t len);
extern void app_log_uint(uint32_t value);

/* Defined in Core_app/App/protocol_adapters/qrng_protocol.c -- not declared in any shared header, since only this
 * file's app_qrng_protocol_self_test() needs to know these exist. */
extern bool qrng_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                   uint16_t *response_len, uint16_t max_response_len);
extern void qrng_protocol_poll(void);

/* Defined in Core_app/App/protocol_adapters/security_protocol.c -- same shape as qrng_protocol_handler() above. */
extern bool security_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                      uint16_t *response_len, uint16_t max_response_len);

/* Defined in Core_app/App/protocol_adapters/ca_protocol.c -- CA-based key-exchange handshake (CMD_TYPE_CA), same
 * shape as qrng_protocol_handler() above. */
extern bool ca_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response,
                                 uint16_t *response_len, uint16_t max_response_len);
/* TEST ONLY, not part of the wire protocol -- see ca_protocol_test_set_peer_id()'s own doc comment in
 * ca_protocol.c. Used only by app_ca_protocol_self_test() below. */
extern bool ca_protocol_test_set_peer_id(const uint8_t *id, size_t len);
extern bool ca_protocol_get_session_keys(uint8_t send_key[32], uint8_t recv_key[32]);

/* Expected output of qrng_service_self_test_toeplitz() (fixed
 * xorshift32(seed=0x12345678) matrix/input) -- captured 2026-09-17 from
 * a direct, single-firmware, single-flash A/B run on this same board
 * against a byte-for-byte copy of the unmodified
 * D:\Workspace\STM32\vQRNG1.0\Core\Src\toeplitz.c
 * (toeplitz_build_lookup/toeplitz_extractor_ultra_fast, only the two
 * entry-point names suffixed to avoid a link collision) fed the
 * identical seed/loop -- confirmed bit-for-bit identical. Kept here so
 * every later build re-verifies the port against that confirmed result
 * without needing the original sources at hand. */
static const uint8_t s_toeplitz_kat_expected[QRNG_TOEPLITZ_KAT_BYTES] = {
    0x39, 0xF0, 0xC2, 0x21, 0x1C, 0xDE, 0xA2, 0xED, 0xB7, 0x50, 0x02, 0x6F,
    0x60, 0xA5, 0xEE, 0xDE, 0x01, 0x1E, 0x1C, 0x46, 0xAC, 0xF9, 0x68, 0xE6,
    0x23, 0xEA, 0x3F, 0x40, 0xE2, 0xE0, 0xAB, 0x83, 0x20, 0x81, 0x9C, 0xDB,
    0x17, 0xFA, 0x7E, 0x37, 0x1C, 0xF4, 0x4C, 0xEB, 0xF2, 0x16, 0x24, 0x2A,
    0xDE, 0xCF, 0x36, 0xDE, 0xD0, 0x3F, 0x60, 0xF8, 0xE5, 0x84, 0xB3, 0xD8,
    0x80, 0xF1, 0x72, 0x1B, 0x95, 0xC3, 0x90, 0x05, 0x77, 0x0F, 0xD6, 0xF2,
    0xEE, 0x48, 0x28, 0x6C, 0x5F, 0xA0, 0xC4, 0x63, 0xCD, 0xE7, 0x70, 0x95,
    0x92, 0x27, 0x0F, 0xA1, 0x83, 0x1C, 0xC2, 0x7F, 0xE8, 0xA5, 0x50, 0xCA,
    0xCD, 0x8E, 0x9B, 0x5E, 0x16, 0x82, 0x22, 0xFE, 0xB1, 0x45, 0xE8, 0x0A,
    0x77, 0xE0, 0x39, 0x8B, 0x82, 0xF2, 0xFC, 0x4A, 0x57, 0xC1, 0xE1, 0x55,
    0x9F, 0xD6, 0x6E, 0x7D, 0x5E, 0xD2, 0x85, 0xB5, 0x52, 0xCC, 0x7C, 0x76,
    0x2B, 0x11, 0xE2, 0x8D, 0xDF, 0x96, 0xA7, 0x61, 0xAF, 0x78, 0x59, 0x9E,
    0x3C, 0xAF, 0x96, 0x69, 0x47, 0x76, 0xEC, 0x9C, 0x7C, 0xFE, 0x45, 0xF6,
    0xA3, 0xC2, 0xCB, 0xDC, 0xBE, 0x85, 0xA7, 0xCB, 0x5D, 0xA7, 0x08, 0x41,
    0x95, 0x45, 0xE2, 0x4F, 0x19, 0x5C, 0x1C, 0x6D, 0xED, 0xE6, 0x35, 0x1E,
    0xDB, 0x8E, 0xD8, 0x41, 0xDE, 0xDD, 0x39, 0xDA, 0x02, 0x2F, 0x48, 0x4D,
    0x20, 0x85, 0xE2, 0x58, 0xFA, 0x34, 0xEA, 0x4F, 0xAB, 0x48, 0xD2, 0x6E,
    0x50, 0xCB, 0x52, 0x41, 0xEE, 0xF2, 0x99, 0xBF, 0x93, 0x8C, 0x50, 0x3A,
    0xA2, 0xC7, 0x4E, 0xEE, 0xD7, 0x5C, 0x70, 0x78, 0xAF, 0xF6, 0x43, 0x83,
    0xCA, 0xFB, 0x19, 0x48, 0x78, 0x4C, 0x55, 0x2D, 0x0C, 0xF4, 0x4B, 0x46,
    0x3F, 0x87, 0x98, 0x30, 0xA7, 0xD4, 0x2A, 0x35, 0xF9, 0x36, 0xB9, 0x29,
    0xE8, 0x9C, 0xE3, 0xEA, 0x2C, 0x57, 0x2F, 0x72, 0xF3, 0x85, 0x5C, 0x90,
    0xF3, 0x3C, 0xEA, 0xA2, 0x1C, 0x71, 0x0E, 0xB5, 0x0F, 0x6D, 0xC0, 0x46,
    0x6B, 0x57, 0x0E, 0xE3, 0xC8, 0x62, 0x63, 0xD1, 0x57, 0x55, 0x1C, 0x6F,
    0x32, 0xF4, 0x3F, 0x13, 0x9D, 0xCC, 0xB0, 0x11, 0x0F, 0xF7, 0x68, 0xFE,
    0x7A, 0x5D, 0x51, 0x8E, 0x93, 0x72, 0xB5, 0x20, 0x0B, 0xD2, 0x2C, 0x14,
    0x39, 0x4E, 0xA5, 0xCF, 0xEE, 0x1D, 0x1C, 0x31, 0xD9, 0xA1, 0x06, 0xBA,
    0x86, 0x49, 0x33, 0x84, 0x62, 0xF4, 0xF6, 0xAE, 0xC6, 0xEF, 0x20, 0x30,
    0x36, 0xCA, 0x9D, 0x40, 0xF9, 0x6D, 0xCC, 0x04, 0x28, 0x09, 0xDB, 0x07,
    0xD4, 0x52, 0x5A, 0xB4, 0xDF, 0xB5, 0x50, 0x4B, 0xEE, 0xF6, 0xDB, 0xDC,
    0x6B, 0xBF, 0x38, 0xE2, 0x5F, 0x2D, 0xC8, 0x27, 0xE3, 0x3E, 0x16, 0x63,
    0xB9, 0xE1, 0x46, 0xC4, 0xBD, 0x82, 0x02, 0x99, 0x94, 0xC4, 0xF2, 0x35,
    0x26, 0x17, 0x6D, 0xB9, 0x3C, 0xFE, 0xD5, 0x5E, 0x40, 0x41, 0x4B, 0x68,
    0xEE, 0x5E, 0x89, 0x89, 0xC9, 0x7F, 0x80, 0x6A, 0x93, 0xE8, 0x80, 0xB2,
    0x07, 0xE3, 0x3F, 0x8E, 0xCB, 0x38, 0xC5, 0x31, 0x41, 0x7F, 0xA7, 0x73,
    0x2C, 0xC0, 0x91, 0x9E, 0xFF, 0x3B, 0x51, 0xBC, 0x74, 0xB4, 0xCD, 0x75,
    0xFE, 0xDA, 0x7A, 0xAB, 0x81, 0x81, 0xEF, 0xB4, 0xC3, 0x43, 0xEE, 0x93,
    0x7F, 0x8E, 0x0F, 0x2F, 0xD5, 0x9F, 0xBA, 0x94, 0x64, 0x8D, 0x7E, 0xDE,
    0xB5, 0xE9, 0x79, 0xFE, 0x6D, 0xFB, 0x3D, 0x54, 0xC5, 0x55, 0xB9, 0xEB,
    0x57, 0x15, 0x03, 0x58, 0x19, 0x44, 0x59, 0xA3, 0x09, 0x5B, 0x33, 0x42,
    0x39, 0xD0, 0xAC, 0x27, 0xB5, 0x84, 0x4F, 0x68, 0xD5, 0x3C, 0x63, 0x25,
    0x56, 0xCA, 0xD0, 0x1C, 0x6F, 0xD3, 0x5E, 0x15, 0x2C, 0x54, 0x80, 0xDF,
    0x9A, 0x6E, 0x61, 0x65, 0x2B, 0xE5, 0x7A, 0x9B, 0x56, 0x5A, 0xA8, 0xF7,
    0x03, 0x6B, 0x3A, 0xF9, 0x52, 0x60, 0xAF, 0xDA, 0xE7, 0x9F, 0x9E, 0x44,
    0x9B, 0xDA, 0x43, 0xF7, 0x08, 0xAB, 0xD3, 0x10, 0x0B, 0x2F, 0xEF, 0xF4,
    0x71, 0x95, 0x25, 0xE3, 0x94, 0x2F, 0x37, 0x16, 0xB3, 0x4B, 0x92, 0x3F,
    0x6E, 0x52, 0xDE, 0xD7, 0x92, 0x07, 0x6E, 0xEF, 0x90, 0x42, 0x7A, 0xBA,
    0xD4, 0x7B, 0xD1, 0x95, 0x5F, 0xE6, 0xA8, 0x8E, 0x11, 0x5B, 0xBC, 0x3C,
    0x51, 0x99, 0x22, 0x05, 0xFD, 0xA6, 0x91, 0xFC, 0x5F, 0x15, 0x6E, 0xC4,
    0x3E, 0x69, 0x2B, 0xFD, 0x1C, 0x9D, 0x59, 0x1A, 0x53, 0xD3, 0xA2, 0x19,
    0x64, 0xC6, 0x6B, 0x8C, 0xDF, 0x3E, 0xD2, 0x3E, 0x24, 0x9D, 0x32, 0x42,
    0x93, 0x78, 0x8C, 0xCE, 0x33, 0xC5, 0x72, 0x14, 0x69, 0x9B, 0x54, 0x8D,
    0xFB, 0x96, 0x9C, 0xEA, 0x25, 0x55, 0x27, 0x81, 0xD6, 0x71, 0xB7, 0x68,
    0x60, 0xAC, 0x39, 0x9D, 0x83, 0x7E, 0x87, 0x53, 0x09, 0xB9, 0x81, 0x45,
    0xAB, 0xA5, 0x31, 0xFC, 0xB0, 0x21, 0x87, 0xFD, 0xAE, 0x13, 0xDF, 0x4F,
    0x62, 0xFF, 0xA7, 0x3C, 0x52, 0xEE, 0x55, 0x45, 0xD1, 0xC2, 0x1E, 0xDC,
    0x8C, 0x97, 0x47, 0xE6, 0xFF, 0x34, 0x85, 0xD1, 0xA1, 0xCD, 0xB2, 0x6A,
    0xD4, 0xD3, 0xD9, 0xF0, 0xF3, 0xF1, 0x07, 0x3D, 0x36, 0xA9, 0x14, 0x40,
    0x26, 0xFE, 0x3C, 0x3E, 0xCC, 0x11, 0x3D, 0x60, 0x9E, 0x03, 0xD2, 0x43,
    0x72, 0x16, 0x6B, 0x3C, 0xBD, 0x53, 0x8D, 0xA1, 0xEE, 0xCD, 0xE3, 0x9E,
    0xEC, 0x0D, 0x8B, 0x8F, 0xC1, 0xE8, 0x23, 0x0C, 0x04, 0xAA, 0x9C, 0x03,
    0xBA, 0x6B, 0xEA, 0xFD, 0x56, 0x4C, 0x34, 0xA4, 0x01, 0x35, 0xF5, 0x6C,
    0x61, 0xB3, 0xD3, 0x27, 0xD1, 0xE1, 0x51, 0x26, 0x46, 0x21, 0xCE, 0x80,
    0x92, 0xA7, 0x34, 0x2A, 0x95, 0x40, 0x41, 0xDA, 0x83, 0xCC, 0x51, 0xD4,
    0x59, 0xF8, 0x6A, 0x9D, 0x14, 0xCD, 0x36, 0x52, 0xF0, 0x5D, 0x73, 0x9F,
    0x15, 0x96, 0x5B, 0x28, 0x0E, 0xDD, 0x3E, 0x17, 0xC1, 0xA4, 0xF7, 0xB7,
    0x6D, 0x8D, 0x28, 0xCB, 0x2A, 0xDC, 0x8B, 0x90, 0x74, 0x8B, 0x70, 0x1D,
    0x5A, 0xE0, 0x7A, 0x08, 0x17, 0x04, 0x68, 0x13, 0x72, 0x82, 0xAA, 0xC5,
    0x8E, 0x27, 0x5C, 0xEC, 0xE6, 0xF8, 0x99, 0xAB, 0x87, 0xF8, 0xE0, 0xD8,
    0xD4, 0xFD, 0x8E, 0x6F, 0x42, 0x51, 0x32, 0x7D, 0x4E, 0x11, 0x3E, 0x51,
    0xE9, 0x16, 0x9B, 0xED, 0xE1, 0x93, 0x92, 0xE4, 0x67, 0x86, 0xB2, 0xDB,
    0x22, 0xFA, 0x0B, 0x68, 0xD5, 0x01, 0xA1, 0x5E, 0x1A, 0x5A, 0xB0, 0x14,
    0x11, 0xE1, 0x3E, 0x75, 0x6E, 0x6F, 0xA0, 0x73, 0xBA, 0x27, 0x9C, 0x19,
    0x5F, 0x20, 0x0D, 0x81, 0xB8, 0x13, 0x2A, 0x2C, 0x23, 0xBC, 0xE1, 0x6F,
    0x0C, 0x0E, 0xD1, 0xC5, 0xE7, 0xC0, 0x5F, 0x7D, 0xB3, 0x24, 0xF8, 0xC7,
    0x62, 0x86, 0xED, 0x32, 0x25, 0x7B, 0x7D, 0x4A, 0x85, 0x9D, 0x6C, 0xAD,
    0x56, 0xA3, 0x90, 0xDE, 0xF9, 0x18, 0xAF, 0xA4, 0x4D, 0xA0, 0x2C, 0x52,
    0xBB, 0x8A, 0x09, 0x04, 0x9E, 0x99, 0xFB, 0x89, 0xFC, 0xAC, 0x47, 0x0D,
    0x2B, 0x7D, 0xC4, 0xEA, 0x1B, 0x7D, 0x97, 0x6E, 0xC0, 0x7B, 0xE2, 0xC0,
    0x38, 0x04, 0xD1, 0x96, 0x39, 0x46, 0x24, 0x10, 0xFB, 0x01, 0xE5, 0xFE,
    0xFD, 0x8C, 0x81, 0x09, 0x17, 0x49, 0xE8, 0xBB, 0x9E, 0x7B, 0xC3, 0x6F,
    0xC3, 0xF5, 0x6C, 0x15, 0x38, 0xED, 0x76, 0x24, 0xD1, 0x0A, 0x14, 0x9A,
    0x82, 0xA8, 0xCC, 0x10, 0x0C, 0x7A, 0xEE, 0xA9, 0x74, 0x1C, 0x45, 0x0B,
    0x39, 0xA4, 0xED, 0xA9, 0x96, 0xBA, 0x57, 0xE5, 0x40, 0xFF, 0xBD, 0x9D,
    0xCF, 0x70, 0xFE, 0xF3, 0xA0, 0x19, 0x5D, 0xAE, 0xD5, 0x5D, 0x72, 0x39,
    0xEB, 0x01, 0x42, 0x42,
};

/* Customer object-ID range (0x00000001-0x7BFFFFFF); see
 * Core_app/Drivers/SE05x/tests/se052_sign_example.c for why this range
 * matters and how to pick a value that will not collide with anything
 * already provisioned on a given SE052F. Two distinct IDs -- secure
 * objects share one ID namespace regardless of type, so the EC key pair
 * and the stored secret below must not collide. */
#define APP_SELF_TEST_KEY_ID 0x00223344U
#define APP_SELF_TEST_SECRET_ID 0x00223345U

bool app_self_test(void)
{
    app_log("=== Core_app stack self-test ===\r\n");

    if (security_service_init() != SEC_OK) {
        app_log("security_service_init: FAIL (check PLUG_AND_TRUST_STM32_ENABLE_SCP03 and wiring)\r\n");
        return false;
    }
    app_log("security_service_init: OK\r\n");

    /* Reads the device identity (key pair + certs/trust anchor) a one-time factory provisioning step already put in
     * the SE052F -- see ca_service.c's own doc comment. Not fatal: a failure here only disables the CA-based key
     * exchange, the rest of the self-test and the media path do not depend on it. */
    ca_status_t ca_st = ca_service_init();
    if (ca_st == CA_OK) {
        app_log("ca_service_init: OK (identity read from SE052F, public key matches, sign/verify ok)\r\n");
    }
    else {
        app_log("ca_service_init: FAIL status=");
        app_log_uint((uint32_t)ca_st);
        app_log(" (1=not ready 2=invalid param 3=not provisioned 4=provision 5=readback 6=key mismatch 7=sign test)\r\n");
    }

    uint8_t random_bytes[8];
    bool random_ok = security_service_get_random(random_bytes, sizeof(random_bytes)) == SEC_OK;
    if (random_ok) {
        app_log("get_random: OK -> ");
        app_log_hex(random_bytes, sizeof(random_bytes));
    }
    else {
        app_log("get_random: FAIL\r\n");
    }

    if (security_service_ensure_ec_keypair(APP_SELF_TEST_KEY_ID) != SEC_OK) {
        app_log("ensure_ec_keypair: FAIL\r\n");
        return false;
    }
    app_log("ensure_ec_keypair: OK\r\n");

    static const uint8_t message[] = "Core_app stack self-test";
    uint8_t signature[80];
    size_t sig_len = sizeof(signature);

    if (security_service_sign_message(APP_SELF_TEST_KEY_ID, message, sizeof(message) - 1U, signature, &sig_len) !=
        SEC_OK) {
        app_log("sign_message: FAIL\r\n");
        return false;
    }
    app_log("sign_message: OK -> ");
    app_log_hex(signature, sig_len);

    bool valid = false;
    sec_status_t verify_status = security_service_verify_message(
        APP_SELF_TEST_KEY_ID, message, sizeof(message) - 1U, signature, sig_len, &valid);
    if (verify_status != SEC_OK || !valid) {
        app_log("verify_message: FAIL\r\n");
        return false;
    }
    app_log("verify_message: OK\r\n");

    static const uint8_t demo_secret[] = "demo-secret-0123456789";

    if (security_service_store_secret(APP_SELF_TEST_SECRET_ID, demo_secret, sizeof(demo_secret) - 1U) != SEC_OK) {
        app_log("store_secret: FAIL\r\n");
        return false;
    }
    app_log("store_secret: OK\r\n");

    uint8_t loaded_secret[sizeof(demo_secret)];
    size_t loaded_len = sizeof(loaded_secret);
    if (security_service_load_secret(APP_SELF_TEST_SECRET_ID, loaded_secret, &loaded_len) != SEC_OK) {
        app_log("load_secret: FAIL\r\n");
        return false;
    }
    if (loaded_len != sizeof(demo_secret) - 1U || memcmp(loaded_secret, demo_secret, loaded_len) != 0) {
        app_log("load_secret: MISMATCH\r\n");
        return false;
    }
    app_log("load_secret: OK -> ");
    app_log_hex(loaded_secret, loaded_len);

    /* Clean up the scratch secret so re-running this self-test doesn't
     * leave stale objects behind. The EC key pair (APP_SELF_TEST_KEY_ID)
     * is deliberately NOT deleted here -- security_service_ensure_ec_keypair()
     * is idempotent, so a real device identity key is meant to persist
     * across boots instead of being regenerated (and rendered useless to
     * anyone who trusted the old public key) every self-test run. Call
     * security_service_delete_key(APP_SELF_TEST_KEY_ID) explicitly if you
     * actually need to retire it. */
    if (security_service_delete_key(APP_SELF_TEST_SECRET_ID) != SEC_OK) {
        app_log("delete_key(secret): FAIL\r\n");
        return false;
    }
    if (security_service_key_exists(APP_SELF_TEST_SECRET_ID)) {
        app_log("delete_key(secret): STILL EXISTS\r\n");
        return false;
    }
    app_log("delete_key(secret): OK\r\n");

    bool all_ok = random_ok; /* every other step above already returned false on its own failure */
    app_log(all_ok ? "=== ALL PASS ===\r\n" : "=== PARTIAL FAIL (see get_random) ===\r\n");
    return all_ok;
}

#if EVT2_ENABLE_BIOMETRIC /* fingerprint stack, see Core/Src/main.c */
static void app_biometric_enroll_progress(uint8_t feedback, uint8_t samples_remaining)
{
    app_log("  enroll touch -- feedback=");
    app_log_uint(feedback);
    app_log(", samples_remaining=");
    app_log_uint(samples_remaining);
    app_log("\r\n");
}

/* Demonstrates biometric_service_navigation_set_callback(): a subscriber
 * elsewhere in App (not the code driving the navigation_poll() loop
 * below) that just wants to react to gestures as they happen -- e.g. a
 * menu/UI module would put its own logic here instead of a log line. */
static void app_navigation_gesture_cb(bio_nav_gesture_t gesture)
{
    static const char *const names[] = {
        "NONE", "UP", "DOWN", "RIGHT", "LEFT", "PRESS", "LONG_PRESS",
    };
    app_log("  [callback] gesture -> ");
    app_log((gesture < (sizeof(names) / sizeof(names[0]))) ? names[gesture] : "?");
    app_log("\r\n");
}

/* How long to wait for a human to actually touch the sensor before
 * giving up on that one step. Chosen to be long enough for someone
 * physically present to react, short enough that an unattended boot
 * doesn't stall for a long time. */
#define APP_BIO_TEST_ENROLL_TIMEOUT_MS   15000U
#define APP_BIO_TEST_IDENTIFY_TIMEOUT_MS 10000U
#define APP_BIO_TEST_NAV_TIMEOUT_MS       5000U

bool app_biometric_self_test(void)
{
    app_log("=== Biometric (FPC5234) stack self-test ===\r\n");

    if (biometric_service_init() != BIO_OK) {
        app_log("biometric_service_init: FAIL (check HOST_IF_UART, wiring, board bring-up)\r\n");
        return false;
    }
    app_log("biometric_service_init: OK\r\n");

    if (!biometric_service_is_ready()) {
        app_log("biometric_service_is_ready: FAIL (should be true right after a successful init)\r\n");
        return false;
    }
    app_log("biometric_service_is_ready: OK\r\n");

    uint16_t template_ids[16];
    size_t template_count = sizeof(template_ids) / sizeof(template_ids[0]);
    if (biometric_service_list_templates(template_ids, &template_count) != BIO_OK) {
        app_log("list_templates: FAIL\r\n");
        return false;
    }
    app_log("list_templates: OK -> ");
    app_log_uint((uint32_t)template_count);
    app_log(" template(s) on device\r\n");
    /* Clear the device down to a known-empty state so enroll() below is
     * guaranteed to run (and its new template is the only one on the
     * device afterwards, so re-listing finds it -- see the id-recovery
     * comment further down). This DELETES ANY TEMPLATE ALREADY ENROLLED --
     * see the WARNING on app_biometric_self_test()'s declaration in
     * app_self_test.h; this function is an API-surface exerciser for a dev
     * board, not a safe-by-default production boot check. */
    if (template_count > 0U) {
        app_log("delete_template(ALL): clearing existing template(s) first\r\n");
        if (biometric_service_delete_template(BIO_TEMPLATE_ID_ALL) != BIO_OK) {
            app_log("delete_template(ALL): FAIL\r\n");
            return false;
        }

        template_count = sizeof(template_ids) / sizeof(template_ids[0]);
        if (biometric_service_list_templates(template_ids, &template_count) != BIO_OK || template_count != 0U) {
            app_log("delete_template(ALL): VERIFY FAIL (template(s) still present)\r\n");
            return false;
        }
        app_log("delete_template(ALL): OK (verified device is now empty)\r\n");
    }

    app_log("enroll: touch the sensor within ");
    app_log_uint(APP_BIO_TEST_ENROLL_TIMEOUT_MS / 1000U);
    app_log("s to enroll one (times out harmlessly if untouched)\r\n");

    bool enrolled = false;
    uint16_t new_template_id = 0;
    bio_status_t enroll_status =
        biometric_service_enroll(app_biometric_enroll_progress, APP_BIO_TEST_ENROLL_TIMEOUT_MS);
    if (enroll_status == BIO_OK) {
        /* biometric_service_enroll() does not return the new template's
         * id directly (see its doc comment) -- recover it by listing
         * again. The device was verified empty just above, so whatever
         * comes back now is exactly the template this call just created. */
        size_t count_after = sizeof(template_ids) / sizeof(template_ids[0]);
        if (biometric_service_list_templates(template_ids, &count_after) == BIO_OK && count_after > 0U) {
            new_template_id = template_ids[0];
            enrolled = true;
            app_log("enroll: OK -> new template id ");
            app_log_uint(new_template_id);
            app_log("\r\n");
        }
        else {
            app_log("enroll: reported OK but no template found afterwards -- FAIL\r\n");
            return false;
        }
    }
    else if (enroll_status == BIO_TIMEOUT) {
        app_log("enroll: TIMEOUT (no touch -- not a failure)\r\n");
    }
    else {
        app_log("enroll: FAIL\r\n");
        return false;
    }

    if (enrolled) {
        if (!biometric_service_template_exists(new_template_id)) {
            app_log("template_exists: FAIL (new template not found)\r\n");
            return false;
        }
        app_log("template_exists: OK (new template found)\r\n");
    }

    app_log("identify: touch the sensor within ");
    app_log_uint(APP_BIO_TEST_IDENTIFY_TIMEOUT_MS / 1000U);
    app_log("s to test matching (times out harmlessly if untouched)\r\n");

    uint16_t matched_id = 0;
    bio_status_t identify_status = biometric_service_identify(&matched_id, APP_BIO_TEST_IDENTIFY_TIMEOUT_MS);
    if (identify_status == BIO_OK) {
        app_log("identify: MATCH -> template id ");
        app_log_uint(matched_id);
        app_log("\r\n");
    }
    else if (identify_status == BIO_NO_MATCH) {
        app_log("identify: NO MATCH\r\n");
    }
    else if (identify_status == BIO_TIMEOUT) {
        app_log("identify: TIMEOUT (no touch -- not a failure)\r\n");
    }
    else {
        app_log("identify: FAIL\r\n");
        return false;
    }

    /* Clean up the scratch template so re-running this self-test starts
     * from empty again next time too (mirrors app_self_test() deleting
     * APP_SELF_TEST_SECRET_ID at the end). */
    if (enrolled) {
        if (biometric_service_delete_template(new_template_id) != BIO_OK) {
            app_log("delete_template(scratch): FAIL\r\n");
            return false;
        }
        if (biometric_service_template_exists(new_template_id)) {
            app_log("delete_template(scratch): STILL EXISTS\r\n");
            return false;
        }
        app_log("delete_template(scratch): OK\r\n");
    }

    /* The sensor only accepts CMD_NAVIGATION right after boot -- enroll/
     * identify/delete_template above already used the session, so reset
     * first (see biometric_service_reset()'s doc comment); otherwise the
     * sensor rejects navigation with FPC_RESULT_WRONG_STATE the moment a
     * touch arrives. This does not erase any enrolled template. */
    app_log("navigation: resetting sensor first (required before navigation)\r\n");
    if (biometric_service_reset() != BIO_OK) {
        app_log("reset (pre-navigation): FAIL\r\n");
        return false;
    }

    app_log("navigation: entering navigation mode, gesture within ");
    app_log_uint(APP_BIO_TEST_NAV_TIMEOUT_MS / 1000U);
    app_log("s (times out harmlessly if untouched)\r\n");

    if (biometric_service_navigation_start(BIO_NAV_ORIENTATION_0) != BIO_OK) {
        app_log("navigation_start: FAIL\r\n");
        return false;
    }

    /* Subscribe a second, independent consumer to prove the callback
     * path works alongside the direct poll() return value below -- see
     * app_navigation_gesture_cb()'s comment. */
    biometric_service_navigation_set_callback(app_navigation_gesture_cb);

    /* Navigation is a continuous stream of gesture events for as long as
     * the sensor sees finger movement, not a single request/response --
     * so poll it non-blocking on every loop iteration for the whole
     * window instead of stopping at the first gesture, reporting each
     * one as it happens in real time. */
    uint32_t nav_start = platform_get_tick_ms();
    uint32_t nav_gesture_count = 0;
    bool nav_error = false;

    while ((platform_get_tick_ms() - nav_start) < APP_BIO_TEST_NAV_TIMEOUT_MS) {
        bio_nav_gesture_t gesture = BIO_NAV_NONE;
        bio_status_t poll_status = biometric_service_navigation_poll(&gesture);

        if (poll_status != BIO_OK) {
            app_log("navigation: FAIL\r\n");
            nav_error = true;
            break;
        }
        if (gesture != BIO_NAV_NONE) {
            nav_gesture_count++;
            app_log("navigation: gesture detected (id ");
            app_log_uint((uint32_t)gesture);
            app_log(")\r\n");
        }
    }

    /* Always leave navigation mode before returning, whatever the loop
     * above ended with -- enroll()/identify() refuse to run while it is
     * active (BIO_WRONG_STATE). */
    biometric_service_navigation_stop();
    biometric_service_navigation_set_callback(NULL);

    if (nav_error) {
        return false;
    }
    if (nav_gesture_count == 0U) {
        app_log("navigation: TIMEOUT (no gesture -- not a failure)\r\n");
    }
    else {
        app_log("navigation: OK -> ");
        app_log_uint(nav_gesture_count);
        app_log(" gesture(s) detected\r\n");
    }

    app_log("=== Biometric self-test PASS (transport+protocol OK;\r\n");
    app_log("    enroll/identify/navigation outcomes above depend on whether a finger touched the sensor) ===\r\n");
    return true;
}
#endif /* EVT2_ENABLE_BIOMETRIC */

bool app_qrng_self_test(void)
{
    app_log("=== QRNG (ADC noise) stack self-test ===\r\n");

    /* Porting-fidelity KAT: pure algorithm math, no live ADC/DAC/RNG --
     * runs before qrng_service_init() on purpose. HMAC-SHA256 checks
     * itself against the published RFC 4231 vector (self-contained,
     * PASS/FAIL is conclusive on its own). The Toeplitz KAT has no
     * independently-published reference, so it is not self-checking --
     * it prints its full output so it can be diffed against a matching
     * KAT harness run against the original, unmodified
     * D:\Workspace\STM32\vQRNG1.0\Core\Src\toeplitz.c/toeplitz_util.c. */
    app_log("--- porting-fidelity KAT (fixed input, no RNG/ADC involved) ---\r\n");

    bool hmac_match = false;
    if (qrng_service_self_test_hmac(&hmac_match) != QRNG_OK) {
        app_log("self_test_hmac: FAIL (platform_hmac_sha256 error)\r\n");
        return false;
    }
    app_log(hmac_match ? "self_test_hmac: PASS (matches RFC 4231 Test Case 2 exactly)\r\n"
                        : "self_test_hmac: FAIL (digest does NOT match RFC 4231)\r\n");
    if (!hmac_match) {
        return false;
    }

    static uint8_t toeplitz_kat[QRNG_TOEPLITZ_KAT_BYTES];
    if (qrng_service_self_test_toeplitz(toeplitz_kat) != QRNG_OK) {
        app_log("self_test_toeplitz: FAIL\r\n");
        return false;
    }
    app_log("self_test_toeplitz: computed (seed 0x12345678) -> compare vs vQRNG1.0 reference run:\r\n");
    app_log_hex(toeplitz_kat, sizeof(toeplitz_kat));

    if (memcmp(toeplitz_kat, s_toeplitz_kat_expected, sizeof(toeplitz_kat)) == 0) {
        app_log("self_test_toeplitz: PASS -- bit-for-bit identical to the confirmed vQRNG1.0 reference\r\n");
    }
    else {
        app_log("self_test_toeplitz: FAIL -- diverges from the confirmed vQRNG1.0 reference\r\n");
        return false;
    }

    bool aes_match = false;
    if (qrng_service_self_test_aes(&aes_match) != QRNG_OK) {
        app_log("self_test_aes: FAIL (platform_aes128_cbc_mac error)\r\n");
        return false;
    }
    app_log(aes_match ? "self_test_aes: PASS (matches FIPS-197 Appendix B exactly)\r\n"
                       : "self_test_aes: FAIL (MAC does NOT match FIPS-197)\r\n");
    if (!aes_match) {
        return false;
    }

    bool aes_batch_match = false;
    if (qrng_service_self_test_aes_batch(&aes_batch_match) != QRNG_OK) {
        app_log("self_test_aes_batch: FAIL (platform_aes128_cbc_mac_batch error)\r\n");
        return false;
    }
    app_log(aes_batch_match ? "self_test_aes_batch: PASS (batch path matches single-call path)\r\n"
                             : "self_test_aes_batch: FAIL (batch path diverges from single-call path)\r\n");
    if (!aes_batch_match) {
        return false;
    }

    app_log("--- end porting-fidelity KAT ---\r\n");

    bool qrng_init_ok = (qrng_service_init() == QRNG_OK);

    /* TEMPORARY diagnostic -- see qrng_service_debug_get_boot_diag()'s
     * doc comment in qrng_service.h. Printed on both pass and fail so a
     * passing run's numbers are available as a baseline to compare a
     * failing run against. */
    {
        uint32_t adc_sps = 0, last_status = 0, last_healthy = 0;
        uint16_t snapshot[8] = {0};
        qrng_service_debug_get_boot_diag(&adc_sps, &last_status, &last_healthy, snapshot, 8);
        app_log("  [diag] adc_sps="); app_log_uint(adc_sps);
        app_log(" last_health_status="); app_log_uint(last_status);
        app_log(" (0=OK 1=RCT_ERR 2=APT_ERR 0xFFFFFFFF=no buffer arrived)");
        app_log(" last_healthy_samples="); app_log_uint(last_healthy);
        app_log("\r\n  [diag] sample_snapshot=");
        app_log_hex((const uint8_t *)snapshot, sizeof(snapshot));

        int n = qrng_service_debug_get_attempt_count();
        for (int i = 0; i < n; i++) {
            uint32_t st = 0, healthy = 0;
            uint16_t s0 = 0, s1 = 0;
            qrng_service_debug_get_attempt(i, &st, &healthy, &s0, &s1);
            app_log("  [diag] attempt="); app_log_uint((uint32_t)i);
            app_log(" status="); app_log_uint(st);
            app_log(" healthy="); app_log_uint(healthy);
            app_log(" sample0="); app_log_uint(s0);
            app_log(" sample1="); app_log_uint(s1);
            app_log("\r\n");
        }
    }

    if (!qrng_init_ok) {
        app_log("qrng_service_init: FAIL (check AD5398/analog enable wiring, startup health test)\r\n");
        return false;
    }
    app_log("qrng_service_init: OK\r\n");

    if (!qrng_service_is_ready()) {
        app_log("qrng_service_is_ready: FAIL (should be true right after a successful init)\r\n");
        return false;
    }
    app_log("qrng_service_is_ready: OK\r\n");

    static uint8_t noise[QRNG_NOISE_BYTES];
    if (qrng_service_get_noise(noise, sizeof(noise)) != QRNG_OK) {
        app_log("get_noise: FAIL\r\n");
        return false;
    }
    app_log("get_noise: OK -> ");
    app_log_hex(noise, 8U); /* first 8 of 2048 bytes -- full dump would flood the log */

    static uint8_t entropy[QRNG_ENTROPY_BYTES];

    if (qrng_service_set_extractor(QRNG_EXTRACTOR_TOEPLITZ) != QRNG_OK) {
        app_log("set_extractor(TOEPLITZ): FAIL\r\n");
        return false;
    }
    if (qrng_service_get_entropy(entropy, sizeof(entropy)) != QRNG_OK) {
        app_log("get_entropy(TOEPLITZ): FAIL\r\n");
        return false;
    }
    app_log("get_entropy(TOEPLITZ): OK -> ");
    app_log_hex(entropy, 8U);

    if (qrng_service_set_extractor(QRNG_EXTRACTOR_HMAC_SHA256) != QRNG_OK) {
        app_log("set_extractor(HMAC_SHA256): FAIL\r\n");
        return false;
    }
    if (qrng_service_get_entropy(entropy, sizeof(entropy)) != QRNG_OK) {
        app_log("get_entropy(HMAC_SHA256): FAIL\r\n");
        return false;
    }
    app_log("get_entropy(HMAC_SHA256): OK -> ");
    app_log_hex(entropy, 8U);

    if (qrng_service_set_extractor(QRNG_EXTRACTOR_AES) != QRNG_OK) {
        app_log("set_extractor(AES): FAIL\r\n");
        return false;
    }
    /* A single draw can legitimately trip NIST 800-90B's RCT/APT online
     * health test (QRNG_HEALTH_FAIL) purely by its designed, non-zero
     * false-alarm rate -- confirmed empirically: 300 individual
     * GET_ENTROPY(AES) calls over the real USB command protocol gave 0
     * CRYP-hardware-attributable errors and exactly 1 QRNG_HEALTH_FAIL
     * (0.33%). run_startup_health_check() in
     * qrng_service_adc_noise.c already retries for exactly this reason;
     * this self-test step didn't, so it could report a false FAIL on
     * unlucky timing. A few retries makes this step's result reflect
     * whether the AES pipeline actually works, not whether it drew the
     * unlucky sample. */
    qrng_status_t aes_entropy_status = QRNG_ERROR;
    for (int attempt = 0; attempt < 5 && aes_entropy_status != QRNG_OK; attempt++) {
        aes_entropy_status = qrng_service_get_entropy(entropy, sizeof(entropy));
    }
    if (aes_entropy_status != QRNG_OK) {
        app_log("get_entropy(AES): FAIL\r\n");
        return false;
    }
    app_log("get_entropy(AES): OK -> ");
    app_log_hex(entropy, 8U);

    if (!qrng_service_is_healthy()) {
        app_log("is_healthy: FAIL (online health test flagged the last draw)\r\n");
        return false;
    }
    app_log("is_healthy: OK\r\n");

    if (qrng_service_reseed_extractor() != QRNG_OK) {
        app_log("reseed_extractor: FAIL\r\n");
        return false;
    }
    app_log("reseed_extractor: OK\r\n");

    app_log("=== QRNG self-test PASS ===\r\n");
    return true;
}

/* Exact byte offsets qrng_protocol.c's qrng_cmd_t uses -- duplicated here
 * rather than shared via a header, same reasoning as this file's other
 * `extern`s: only this test needs to know these values, and they are the
 * public wire-protocol contract (see qrng_protocol.c), not an internal
 * detail that could drift silently. */
#define APP_QRNG_PROTO_GET_NOISE                0x01U
#define APP_QRNG_PROTO_GET_ENTROPY              0x02U
#define APP_QRNG_PROTO_IS_HEALTHY               0x03U
#define APP_QRNG_PROTO_SET_HEALTH_TEST          0x04U
#define APP_QRNG_PROTO_STREAM_NOISE_START       0x05U
#define APP_QRNG_PROTO_STREAM_ENTROPY_START     0x06U
#define APP_QRNG_PROTO_STREAM_STOP              0x07U
#define APP_QRNG_PROTO_GET_STARTUP_HEALTH_RECORD 0x08U
#define APP_QRNG_PROTO_SET_AUTO_RESEED          0x09U
#define APP_QRNG_PROTO_REGEN_KEY                0x0AU
#define APP_QRNG_PROTO_SET_EXTRACTOR            0x0BU

/* How many qrng_protocol_poll() ticks to pump per continuous-stream
 * direction below -- enough to prove more than one frame gets pushed
 * (session/seq bookkeeping, repeat draws) without meaningfully slowing
 * down boot; each tick draws a real buffer the same way a single
 * GET_NOISE/GET_ENTROPY call above already does. */
#define APP_QRNG_TEST_STREAM_TICKS 3U

bool app_qrng_protocol_self_test(void)
{
    app_log("=== QRNG command-protocol adapter self-test (qrng_protocol_handler(), all sub-commands) ===\r\n");

    static uint8_t resp[2U + QRNG_NOISE_BYTES]; /* largest response: GET_NOISE/GET_STARTUP_HEALTH_RECORD, both 2048B */
    uint16_t resp_len;
    uint8_t req[2];

    req[0] = APP_QRNG_PROTO_GET_NOISE;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK ||
        resp_len != 2U + QRNG_NOISE_BYTES) {
        app_log("protocol GET_NOISE: FAIL\r\n");
        return false;
    }
    app_log("protocol GET_NOISE: OK\r\n");

    req[0] = APP_QRNG_PROTO_GET_ENTROPY;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK ||
        resp_len != 2U + QRNG_ENTROPY_BYTES) {
        app_log("protocol GET_ENTROPY: FAIL\r\n");
        return false;
    }
    app_log("protocol GET_ENTROPY: OK\r\n");

    req[0] = APP_QRNG_PROTO_IS_HEALTHY;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp_len != 2U) {
        app_log("protocol IS_HEALTHY: FAIL\r\n");
        return false;
    }
    app_log(resp[1] != 0U ? "protocol IS_HEALTHY: OK -> healthy\r\n" : "protocol IS_HEALTHY: OK -> NOT healthy\r\n");

    /* Disable then re-enable -- must not leave the online health test
     * disabled for whatever runs after this self-test. */
    req[0] = APP_QRNG_PROTO_SET_HEALTH_TEST;
    req[1] = 0U;
    if (!qrng_protocol_handler(req, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol SET_HEALTH_TEST(disable): FAIL\r\n");
        return false;
    }
    req[1] = 1U;
    if (!qrng_protocol_handler(req, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol SET_HEALTH_TEST(enable): FAIL\r\n");
        return false;
    }
    app_log("protocol SET_HEALTH_TEST: OK (disable+re-enable)\r\n");

    /* All 3 algorithms -- ends on QRNG_EXTRACTOR_AES (2); harmless, the
     * next get_entropy caller always selects the extractor it wants
     * first, same as app_qrng_self_test() above does. */
    for (uint8_t algo = 0U; algo <= 2U; algo++) {
        req[0] = APP_QRNG_PROTO_SET_EXTRACTOR;
        req[1] = algo;
        if (!qrng_protocol_handler(req, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
            app_log("protocol SET_EXTRACTOR: FAIL\r\n");
            return false;
        }
    }
    app_log("protocol SET_EXTRACTOR: OK (all 3 algorithms accepted)\r\n");

    req[0] = APP_QRNG_PROTO_REGEN_KEY;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol REGEN_KEY: FAIL\r\n");
        return false;
    }
    app_log("protocol REGEN_KEY: OK\r\n");

    /* Enable then disable -- leave it back at qrng_service.h's
     * disabled-by-default state. */
    req[0] = APP_QRNG_PROTO_SET_AUTO_RESEED;
    req[1] = 1U;
    if (!qrng_protocol_handler(req, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol SET_AUTO_RESEED(enable): FAIL\r\n");
        return false;
    }
    req[1] = 0U;
    if (!qrng_protocol_handler(req, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol SET_AUTO_RESEED(disable): FAIL\r\n");
        return false;
    }
    app_log("protocol SET_AUTO_RESEED: OK (enable+disable)\r\n");

    req[0] = APP_QRNG_PROTO_GET_STARTUP_HEALTH_RECORD;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK ||
        resp_len != 2U + QRNG_STARTUP_HEALTH_RECORD_BYTES) {
        app_log("protocol GET_STARTUP_HEALTH_RECORD: FAIL\r\n");
        return false;
    }
    app_log("protocol GET_STARTUP_HEALTH_RECORD: OK -> ");
    app_log_hex(&resp[2], 8U);

    req[0] = APP_QRNG_PROTO_STREAM_NOISE_START;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol STREAM_NOISE_START: FAIL\r\n");
        return false;
    }
    for (uint32_t i = 0U; i < APP_QRNG_TEST_STREAM_TICKS; i++) {
        qrng_protocol_poll();
    }
    req[0] = APP_QRNG_PROTO_STREAM_STOP;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol STREAM_NOISE_START/STOP: FAIL (stop)\r\n");
        return false;
    }
    app_log("protocol STREAM_NOISE_START/STOP: OK (");
    app_log_uint(APP_QRNG_TEST_STREAM_TICKS);
    app_log(" poll tick(s) pumped)\r\n");

    req[0] = APP_QRNG_PROTO_STREAM_ENTROPY_START;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol STREAM_ENTROPY_START: FAIL\r\n");
        return false;
    }
    for (uint32_t i = 0U; i < APP_QRNG_TEST_STREAM_TICKS; i++) {
        qrng_protocol_poll();
    }
    req[0] = APP_QRNG_PROTO_STREAM_STOP;
    if (!qrng_protocol_handler(req, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != (uint8_t)QRNG_OK) {
        app_log("protocol STREAM_ENTROPY_START/STOP: FAIL (stop)\r\n");
        return false;
    }
    app_log("protocol STREAM_ENTROPY_START/STOP: OK (");
    app_log_uint(APP_QRNG_TEST_STREAM_TICKS);
    app_log(" poll tick(s) pumped)\r\n");

    app_log("=== QRNG command-protocol self-test PASS (all 11 sub-commands exercised) ===\r\n");
    return true;
}

/* Exact byte offsets ca_protocol.c's ca_cmd_t uses -- duplicated here for the
 * same reason as APP_QRNG_PROTO_*'s above: this is the public wire-protocol
 * contract (see ca_protocol.c), and only this test needs the numeric values. */
#define APP_CA_PROTO_GET_IDENTITY     0x01U
#define APP_CA_PROTO_GET_STATUS_TOKEN 0x02U
#define APP_CA_PROTO_BEGIN            0x03U
#define APP_CA_PROTO_SIGN_TRANSCRIPT  0x04U
#define APP_CA_PROTO_VERIFY_PEER      0x05U
#define APP_CA_PROTO_DERIVE_KEYS      0x06U
#define APP_CA_PROTO_CONFIRM          0x07U
#define APP_CA_PROTO_VERIFY_CONFIRM   0x08U
#define APP_CA_PROTO_END_SESSION      0x09U

/* Scratch SE052F object id for this self-test's simulated "peer" ephemeral key -- outside ca_protocol.c's own
 * 0x00690001..0x00690004 range (see that file), so it can never collide with the session it is testing. */
#define APP_CA_TEST_PEER_EPH_ID 0x00690099U

/* Appends ca_protocol.c's mandatory ML-KEM-768 extension (read_kem_ext()'s wire form -- CA_PROTO_VERSION 2, Giai
 * đoạn 1) after a 195-byte quad already written at `out`: [pk_kem_a_len:2LE][pk_kem_a][ct_kem_b_len:2LE][ct_kem_b].
 * Used by both this file's classical self-test (always zero-length, i.e. classical-only) and its hybrid extension
 * below (both slots filled) -- every quad-carrying sub-command now requires this trailer, even when empty, so both
 * tests build their payloads through this one helper rather than duplicating the length-prefix bookkeeping twice. */
static size_t ca_test_append_ext(uint8_t *out, size_t o, const uint8_t *pk_kem_a, size_t pk_kem_a_len,
                                  const uint8_t *ct_kem_b, size_t ct_kem_b_len)
{
    out[o++] = (uint8_t)(pk_kem_a_len & 0xFFU);
    out[o++] = (uint8_t)((pk_kem_a_len >> 8) & 0xFFU);
    if (pk_kem_a_len != 0U) {
        memcpy(&out[o], pk_kem_a, pk_kem_a_len);
        o += pk_kem_a_len;
    }
    out[o++] = (uint8_t)(ct_kem_b_len & 0xFFU);
    out[o++] = (uint8_t)((ct_kem_b_len >> 8) & 0xFFU);
    if (ct_kem_b_len != 0U) {
        memcpy(&out[o], ct_kem_b, ct_kem_b_len);
        o += ct_kem_b_len;
    }
    return o;
}

bool app_ca_protocol_self_test(void)
{
    app_log("=== CA command-protocol self-test ===\r\n");
    if (!ca_service_is_ready()) {
        app_log("ca_service not ready (ca_service_init already reported why) -- skipping\r\n");
        return true; /* not this test's failure to report again */
    }

    /* payload sized for VERIFY_PEER's worst case (quad + zero-length PQC ext + issuing/leaf certs + token + sig) --
     * PQC material stays zero-length throughout THIS test's OWN requests (classical-only). resp must still be sized
     * for CA_CMD_BEGIN's response worst case regardless: ca_protocol_handler()'s BEGIN case gates on
     * max_response_len being large enough for a successful ML-KEM-768 keygen (2+32+65+2+1184 = 1285 bytes) BEFORE
     * it knows whether that keygen will actually succeed -- a too-small buffer fails BEGIN outright, it does not
     * just omit the PQC field (found on real hardware, 2026-09-24: "BEGIN: FAIL" with the original 256-byte resp,
     * since ca_protocol.c has no way to know in advance this test would never end up using the hybrid PQC path). */
    static uint8_t payload[1400];
    static uint8_t resp[1400];
    uint16_t resp_len;

    /* ---- BEGIN: my (role A) ephemeral key pair + fresh QRNG nonce (+ an ML-KEM-768 public key, unused by this
     * classical-only test -- see app_ca_protocol_hybrid_self_test() for that) ---- */
    payload[0] = APP_CA_PROTO_BEGIN;
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U || resp_len < 2U + 32U + 65U + 2U) {
        app_log("BEGIN: FAIL\r\n");
        return false;
    }
    uint8_t nA[32];
    uint8_t epkA[65];
    memcpy(nA, &resp[2], sizeof(nA));
    memcpy(epkA, &resp[2U + sizeof(nA)], sizeof(epkA));
    app_log("BEGIN: OK -> nA=");
    app_log_hex(nA, sizeof(nA));

    /* ---- simulate the peer's side of BEGIN directly (no second board): a second ephemeral key pair + a second QRNG
     * draw for nB. This is real key material on this same chip, just not tracked by ca_protocol.c's one-session state --
     * DERIVE_KEYS below still does a genuine ECDH against it. */
    if (security_service_generate_ephemeral_ec_keypair(APP_CA_TEST_PEER_EPH_ID, SEC_EC_CURVE_P256) != SEC_OK) {
        app_log("simulated peer ephemeral key: FAIL\r\n");
        return false;
    }
    uint8_t epkB[65];
    size_t epkB_len = sizeof(epkB);
    if (security_service_read_ec_public_key(APP_CA_TEST_PEER_EPH_ID, epkB, &epkB_len) != SEC_OK || epkB_len != 65U) {
        app_log("simulated peer ephemeral pubkey: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    static uint8_t entropy2[QRNG_ENTROPY_BYTES];
    uint8_t nB[32];
    if (qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, entropy2, sizeof(entropy2)) != QRNG_OK) {
        app_log("simulated peer nonce (QRNG draw): FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    memcpy(nB, entropy2, sizeof(nB));
    memset(entropy2, 0, sizeof(entropy2));
    app_log("simulated peer (ephemeral key + nB): OK\r\n");

    /* quad = [role][nA][epkA][nB][epkB], reused (with role/nA/nB/epkA/epkB placed identically) by SIGN_TRANSCRIPT,
     * VERIFY_PEER, DERIVE_KEYS, CONFIRM and VERIFY_CONFIRM -- see ca_protocol.c's ca_quad_t. */
    uint8_t quad[1U + 32U + 65U + 32U + 65U];
    quad[0] = 1U; /* role: A (initiator) -- this board's own identity signs/derives as A throughout this test */
    memcpy(&quad[1], nA, 32U);
    memcpy(&quad[33], epkA, 65U);
    memcpy(&quad[98], nB, 32U);
    memcpy(&quad[130], epkB, 65U);

    /* ---- SIGN_TRANSCRIPT (classical -- zero-length PQC ext, see ca_test_append_ext()) ---- */
    payload[0] = APP_CA_PROTO_SIGN_TRANSCRIPT;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t st_len = ca_test_append_ext(payload, 1U + sizeof(quad), NULL, 0U, NULL, 0U);
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)st_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("SIGN_TRANSCRIPT: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    uint8_t sig_len = resp[2];
    static uint8_t sig[72];
    memcpy(sig, &resp[3], sig_len);
    app_log("SIGN_TRANSCRIPT: OK (");
    app_log_uint(sig_len);
    app_log(" byte signature)\r\n");

    /* ---- VERIFY_PEER, fed OUR OWN certificate chain as "the peer's" (no second identity exists on one board) --
     * this must reach the reflection guard (peer id == own id) and stop there with CA_PEER_SELF, not CA_PEER_OK.
     * It still exercises the real parsing + ca_chain_verify() + transcript-signature check on the way there: only
     * the LAST check (self-id) is expected to reject it. Genuinely accepting a different peer's chain was verified
     * once already, offboard (2026-09-22 CA review, "Test 4") -- see app_ca_protocol_self_test()'s doc comment. */
    {
        ca_blob_t cert = ca_service_get_device_cert();
        ca_blob_t issuing = ca_service_get_issuing_cert();
        ca_blob_t token = ca_service_get_status_token();
        size_t o = 0;
        payload[o++] = APP_CA_PROTO_VERIFY_PEER;
        memcpy(&payload[o], quad, sizeof(quad));
        o += sizeof(quad);
        o = ca_test_append_ext(payload, o, NULL, 0U, NULL, 0U); /* classical -- see ca_test_append_ext() */
        payload[o++] = (uint8_t)(issuing.len & 0xFFU);
        payload[o++] = (uint8_t)((issuing.len >> 8) & 0xFFU);
        memcpy(&payload[o], issuing.data, issuing.len);
        o += issuing.len;
        payload[o++] = (uint8_t)(cert.len & 0xFFU);
        payload[o++] = (uint8_t)((cert.len >> 8) & 0xFFU);
        memcpy(&payload[o], cert.data, cert.len);
        o += cert.len;
        payload[o++] = (uint8_t)token.len;
        memcpy(&payload[o], token.data, token.len);
        o += token.len;
        payload[o++] = sig_len;
        memcpy(&payload[o], sig, sig_len);
        o += sig_len;
        resp_len = sizeof(resp);
        if (!ca_protocol_handler(payload, (uint16_t)o, resp, &resp_len, sizeof(resp))) {
            app_log("VERIFY_PEER: FAIL (dispatch)\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        if (resp[1] != 3U /* CA_PEER_SELF */) {
            app_log("VERIFY_PEER: FAIL -- expected CA_PEER_SELF(3), got result=");
            app_log_uint(resp[1]);
            app_log(" ca_x509_status=");
            app_log_uint(resp[2]);
            app_log("\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        app_log("VERIFY_PEER: OK (own chain correctly rejected as CA_PEER_SELF; chain+signature parsing all ran)\r\n");

        /* negative: no status token at all -> CA_PEER_BAD_PARAM(4), rejected before any chain parsing */
        size_t o2 = o - sig_len - 1U - token.len - 1U; /* rewind to just after issuing+leaf, before the token length byte */
        payload[o2++] = 0U; /* token_len = 0 */
        payload[o2++] = sig_len;
        memcpy(&payload[o2], sig, sig_len);
        o2 += sig_len;
        resp_len = sizeof(resp);
        if (!ca_protocol_handler(payload, (uint16_t)o2, resp, &resp_len, sizeof(resp)) || resp[1] != 4U) {
            app_log("VERIFY_PEER (no token): FAIL -- expected CA_PEER_BAD_PARAM(4), got ");
            app_log_uint(resp[1]);
            app_log("\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        app_log("VERIFY_PEER (no token): OK -> rejected CA_PEER_BAD_PARAM(4)\r\n");
    }

    /* ---- DERIVE_KEYS: real ECDH between my ephemeral key and the simulated peer's (classical -- zero-length ext) ---- */
    payload[0] = APP_CA_PROTO_DERIVE_KEYS;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t dk_len = ca_test_append_ext(payload, 1U + sizeof(quad), NULL, 0U, NULL, 0U);
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)dk_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("DERIVE_KEYS: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    uint8_t send_key[32];
    uint8_t recv_key[32];
    /* ca_protocol_get_session_keys() will still return false here on purpose -- since the 2026-09-24 "fix leakage
     * CA" #1 change, it only starts handing out keys once CA_SESSION_ESTABLISHED (a matching VERIFY_CONFIRM), not
     * merely after DERIVE_KEYS -- see that function's own doc comment. This used to check-and-zero the keys right
     * here (before that change existed) and would now always fail this exact call, a real regression this session
     * hit on real hardware after flashing (log: "DERIVE_KEYS: FAIL (no session keys held after a successful
     * derive)") -- the actual sanity check (present, non-zero, distinct) moved to right after "VERIFY_CONFIRM
     * (matching)" below, the earliest point the new contract actually allows it. */
    app_log("DERIVE_KEYS: OK\r\n");

    /* CONFIRM/VERIFY_CONFIRM's id-binding (ca_protocol.c's append_ids()) needs s_peer_id populated the way a real
     * VERIFY_PEER success would -- impossible here (see the VERIFY_PEER block above: this test can only ever reach
     * CA_PEER_SELF/CA_PEER_BAD_PARAM with no second identity on the board), so populate it directly with this
     * device's own id (hex, uppercase -- same convention ca_protocol.c's own hex_upper()/subject_cn comparison
     * uses). This is exactly what a genuine self-dial's peer id WOULD be, which is the only way CONFIRM's and
     * VERIFY_CONFIRM's deliberately-mirrored id formulas (see those handlers' own comments) land on the same
     * bytes from a single identity -- see ca_protocol_test_set_peer_id()'s own doc comment for why. */
    {
        ca_blob_t own_id = ca_service_get_device_id();
        static const char hex_digits[] = "0123456789ABCDEF";
        uint8_t own_id_hex[64];
        if (own_id.len * 2U > sizeof(own_id_hex)) {
            app_log("CA self-test setup: own id too long for hex buffer -- FAIL\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        for (size_t i = 0; i < own_id.len; i++) {
            own_id_hex[2U * i] = (uint8_t)hex_digits[own_id.data[i] >> 4];
            own_id_hex[2U * i + 1U] = (uint8_t)hex_digits[own_id.data[i] & 0x0FU];
        }
        if (!ca_protocol_test_set_peer_id(own_id_hex, own_id.len * 2U)) {
            app_log("ca_protocol_test_set_peer_id: FAIL\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
    }

    /* ---- CONFIRM + VERIFY_CONFIRM (classical -- zero-length ext) ---- */
    payload[0] = APP_CA_PROTO_CONFIRM;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t cf_len = ca_test_append_ext(payload, 1U + sizeof(quad), NULL, 0U, NULL, 0U);
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)cf_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U ||
        resp_len != 2U + 32U) {
        app_log("CONFIRM: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    uint8_t mac[32];
    memcpy(mac, &resp[2], sizeof(mac));
    app_log("CONFIRM: OK\r\n");

    payload[0] = APP_CA_PROTO_VERIFY_CONFIRM;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t vc_len = ca_test_append_ext(payload, 1U + sizeof(quad), NULL, 0U, NULL, 0U);
    size_t mac_offset = vc_len;
    memcpy(&payload[vc_len], mac, sizeof(mac));
    vc_len += sizeof(mac);
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)vc_len, resp, &resp_len, sizeof(resp)) ||
        resp[1] != 0U) {
        app_log("VERIFY_CONFIRM (matching): FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("VERIFY_CONFIRM (matching): OK\r\n");

    /* Only NOW does ca_protocol_get_session_keys() return true -- CA_SESSION_ESTABLISHED requires this exact
     * matching VERIFY_CONFIRM, not merely DERIVE_KEYS having run (see that function's own doc comment). This is
     * the sanity check that used to run right after DERIVE_KEYS, moved here to match the new contract. */
    if (!ca_protocol_get_session_keys(send_key, recv_key)) {
        app_log("VERIFY_CONFIRM: FAIL (no session keys held after mutual confirmation established)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    static const uint8_t all_zero32[32];
    if (memcmp(send_key, all_zero32, 32U) == 0 || memcmp(recv_key, all_zero32, 32U) == 0 ||
        memcmp(send_key, recv_key, 32U) == 0) {
        app_log("VERIFY_CONFIRM: FAIL (send/recv key all-zero or identical -- ECDH/HKDF did not actually run)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    memset(send_key, 0, sizeof(send_key)); /* this test never needs the raw bytes past the sanity check above */
    memset(recv_key, 0, sizeof(recv_key));
    app_log("VERIFY_CONFIRM: session keys present, distinct, non-zero after CA_SESSION_ESTABLISHED\r\n");

    payload[mac_offset] ^= 0x01U; /* flip one bit of the MAC */
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)vc_len, resp, &resp_len, sizeof(resp)) ||
        resp[1] != 1U) {
        app_log("VERIFY_CONFIRM (tampered): FAIL -- expected mismatch(1), got ");
        app_log_uint(resp[1]);
        app_log("\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("VERIFY_CONFIRM (tampered): OK -> correctly reported mismatch\r\n");

    /* ---- END_SESSION + cleanup ---- */
    payload[0] = APP_CA_PROTO_END_SESSION;
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("END_SESSION: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID); /* this test's own scratch object, not ca_protocol.c's */
    /* DERIVE_KEYS above created a session-key snapshot in ca_protocol.c's RAM; END_SESSION must have wiped it. */
    if (ca_protocol_get_session_keys(send_key, recv_key)) {
        app_log("END_SESSION: FAIL (session keys still held after end)\r\n");
        return false;
    }
    app_log("END_SESSION: OK -> ephemeral/confirm SE052F objects and session keys all cleared\r\n");

    app_log("=== CA command-protocol self-test PASS (9/9 sub-commands exercised) ===\r\n");
    return true;
}

/* Giai đoạn 1 hybrid-PQC extension of app_ca_protocol_self_test() (2026-09-24, see CLAUDE.md) -- same single-board
 * simulated-peer technique as that test (no second identity/board exists, so this device signs/derives/confirms
 * against its own ephemeral material presented back to it as "the peer's"), but exercising the ML-KEM-768 hybrid
 * path this time: BEGIN's pk_kem, SIGN_TRANSCRIPT's role-B-shaped encapsulation (done directly via pqc_kem.h here,
 * standing in for a real peer B's firmware doing the exact same call), and -- the one thing Giai đoạn 0's spike
 * could not touch -- CA_CMD_DERIVE_KEYS's hybrid branch: security_service_ecdh_to_host() (never exercised on this
 * project's chip before this test, see that function's own doc comment about the SE05x FIPS-mode gate) combined
 * with pqc_kem_decapsulate() through the software HKDF in ca_protocol.c. Run only after app_ca_protocol_self_test()
 * (BEGIN resets any session that one left behind) and after app_qrng_self_test() (BEGIN's nonce, and
 * pqc_kem_encapsulate()'s own randomness, both draw from qrng_service.h). Returns true if every step succeeded, or
 * if BEGIN's ML-KEM-768 keygen itself is unavailable this boot (best-effort per BEGIN's own contract -- not this
 * test's failure to report). */
bool app_ca_protocol_hybrid_self_test(void)
{
    app_log("=== CA hybrid-PQC (ML-KEM-768) self-test (Giai doan 1) ===\r\n");
    if (!ca_service_is_ready()) {
        app_log("ca_service not ready -- skipping\r\n");
        return true;
    }

    /* Sized for VERIFY_PEER's worst case: quad(195) + full hybrid ext (2+1184+2+1088) + issuing/leaf certs + token +
     * sig -- see ca_protocol.c's CA_MSG_BUF_LEN for the same accounting done for the on-chip message buffer. */
    static uint8_t payload[3600];
    static uint8_t resp[1400];
    uint16_t resp_len;

    payload[0] = APP_CA_PROTO_BEGIN;
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U || resp_len < 2U + 32U + 65U + 2U) {
        app_log("BEGIN: FAIL\r\n");
        return false;
    }
    uint8_t nA[32];
    uint8_t epkA[65];
    memcpy(nA, &resp[2], sizeof(nA));
    memcpy(epkA, &resp[2U + sizeof(nA)], sizeof(epkA));
    uint16_t pk_kem_a_len = (uint16_t)(resp[2U + 32U + 65U] | (resp[2U + 32U + 65U + 1U] << 8));
    if (pk_kem_a_len == 0U) {
        app_log("BEGIN: ML-KEM-768 keygen unavailable this boot (best-effort, see ca_protocol.c) -- skipping hybrid test\r\n");
        return true;
    }
    if (pk_kem_a_len != PQC_KEM_PUBLICKEY_BYTES || resp_len < 2U + 32U + 65U + 2U + PQC_KEM_PUBLICKEY_BYTES) {
        app_log("BEGIN: FAIL (bad pk_kem_a_len)\r\n");
        return false;
    }
    static uint8_t pk_kem_a[PQC_KEM_PUBLICKEY_BYTES];
    memcpy(pk_kem_a, &resp[2U + 32U + 65U + 2U], sizeof(pk_kem_a));
    app_log("BEGIN: OK -> pk_kem_a offered (");
    app_log_uint(pk_kem_a_len);
    app_log(" bytes)\r\n");

    /* ---- simulate peer B's side directly (no second board -- same technique as the classical test's second
     * ephemeral EC key): a second ephemeral EC key pair for epkB/nB, and a LOCAL pqc_kem_encapsulate() against this
     * device's own pk_kem_a, standing in for what a real peer B's firmware would compute from the same public key
     * once M1 carried it to them. ct_kem_b_sim/z_kem_b_sim are exactly what that peer would send back in M2 /
     * privately hold, respectively. */
    if (security_service_generate_ephemeral_ec_keypair(APP_CA_TEST_PEER_EPH_ID, SEC_EC_CURVE_P256) != SEC_OK) {
        app_log("simulated peer ephemeral key: FAIL\r\n");
        return false;
    }
    uint8_t epkB[65];
    size_t epkB_len = sizeof(epkB);
    if (security_service_read_ec_public_key(APP_CA_TEST_PEER_EPH_ID, epkB, &epkB_len) != SEC_OK || epkB_len != 65U) {
        app_log("simulated peer ephemeral pubkey: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    static uint8_t entropy2[QRNG_ENTROPY_BYTES];
    uint8_t nB[32];
    if (qrng_service_get_entropy_with(QRNG_EXTRACTOR_TOEPLITZ, entropy2, sizeof(entropy2)) != QRNG_OK) {
        app_log("simulated peer nonce (QRNG draw): FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    memcpy(nB, entropy2, sizeof(nB));
    memset(entropy2, 0, sizeof(entropy2));
    static uint8_t ct_kem_b_sim[PQC_KEM_CIPHERTEXT_BYTES];
    uint8_t z_kem_b_sim[PQC_KEM_SHARED_SECRET_BYTES];
    if (!pqc_kem_encapsulate(pk_kem_a, ct_kem_b_sim, z_kem_b_sim)) {
        app_log("simulated peer encapsulate: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    memset(z_kem_b_sim, 0, sizeof(z_kem_b_sim)); /* this test only needs it implicitly, via VERIFY_CONFIRM matching */
    app_log("simulated peer (ephemeral key + nB + ML-KEM-768 encapsulate): OK\r\n");

    uint8_t quad[1U + 32U + 65U + 32U + 65U];
    quad[0] = 1U; /* role: A, same convention as app_ca_protocol_self_test() */
    memcpy(&quad[1], nA, 32U);
    memcpy(&quad[33], epkA, 65U);
    memcpy(&quad[98], nB, 32U);
    memcpy(&quad[130], epkB, 65U);

    /* ---- SIGN_TRANSCRIPT (hybrid: both ML-KEM-768 slots filled) ---- */
    payload[0] = APP_CA_PROTO_SIGN_TRANSCRIPT;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t st_len =
        ca_test_append_ext(payload, 1U + sizeof(quad), pk_kem_a, sizeof(pk_kem_a), ct_kem_b_sim, sizeof(ct_kem_b_sim));
    resp_len = sizeof(resp);
    bool st_dispatch_ok = ca_protocol_handler(payload, (uint16_t)st_len, resp, &resp_len, sizeof(resp));
    if (!st_dispatch_ok || resp[1] != 0U) {
        app_log("SIGN_TRANSCRIPT: FAIL -- dispatch=");
        app_log_uint(st_dispatch_ok ? 1U : 0U);
        app_log(" status=");
        app_log_uint(resp[1]);
        app_log(" payload_len=");
        app_log_uint((uint32_t)st_len);
        app_log("\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    uint8_t sig_len = resp[2];
    static uint8_t sig[72];
    memcpy(sig, &resp[3], sig_len);
    uint16_t echoed_ct_len = (uint16_t)(resp[3U + sig_len] | (resp[3U + sig_len + 1U] << 8));
    if (echoed_ct_len != PQC_KEM_CIPHERTEXT_BYTES ||
        memcmp(&resp[3U + sig_len + 2U], ct_kem_b_sim, PQC_KEM_CIPHERTEXT_BYTES) != 0) {
        app_log("SIGN_TRANSCRIPT: FAIL (echoed ct_kem_b does not match what was offered)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("SIGN_TRANSCRIPT: OK (hybrid, ct_kem_b echoed back correctly)\r\n");

    /* ---- VERIFY_PEER, own chain as "the peer's" (same CA_PEER_SELF expectation as the classical test), but now
     * with the hybrid ext included -- proves VERIFY_PEER's read_kem_ext()+build_msg() rebuild the exact bytes
     * SIGN_TRANSCRIPT signed above (the reflection guard is only reached if the signature check passed first). ---- */
    {
        ca_blob_t cert = ca_service_get_device_cert();
        ca_blob_t issuing = ca_service_get_issuing_cert();
        ca_blob_t token = ca_service_get_status_token();
        size_t o = 0;
        payload[o++] = APP_CA_PROTO_VERIFY_PEER;
        memcpy(&payload[o], quad, sizeof(quad));
        o += sizeof(quad);
        o = ca_test_append_ext(payload, o, pk_kem_a, sizeof(pk_kem_a), ct_kem_b_sim, sizeof(ct_kem_b_sim));
        payload[o++] = (uint8_t)(issuing.len & 0xFFU);
        payload[o++] = (uint8_t)((issuing.len >> 8) & 0xFFU);
        memcpy(&payload[o], issuing.data, issuing.len);
        o += issuing.len;
        payload[o++] = (uint8_t)(cert.len & 0xFFU);
        payload[o++] = (uint8_t)((cert.len >> 8) & 0xFFU);
        memcpy(&payload[o], cert.data, cert.len);
        o += cert.len;
        payload[o++] = (uint8_t)token.len;
        memcpy(&payload[o], token.data, token.len);
        o += token.len;
        payload[o++] = sig_len;
        memcpy(&payload[o], sig, sig_len);
        o += sig_len;
        resp_len = sizeof(resp);
        if (!ca_protocol_handler(payload, (uint16_t)o, resp, &resp_len, sizeof(resp)) || resp[1] != 3U /* CA_PEER_SELF */) {
            app_log("VERIFY_PEER: FAIL -- expected CA_PEER_SELF(3), got result=");
            app_log_uint(resp[1]);
            app_log(" ca_x509_status=");
            app_log_uint(resp[2]);
            app_log("\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        app_log("VERIFY_PEER: OK (own hybrid transcript correctly rejected as CA_PEER_SELF)\r\n");
    }

    /* ---- DERIVE_KEYS: the actual hybrid combiner -- security_service_ecdh_to_host() (Z_ecdh, real ECDH against
     * the simulated peer's epkB) + pqc_kem_decapsulate() (Z_kem, against ct_kem_b_sim -- must reproduce
     * z_kem_b_sim's value bit-for-bit, though this test never reads the peer's copy back to compare directly: the
     * proof is CONFIRM/VERIFY_CONFIRM's MAC matching below, exactly as the classical test relies on for its own
     * Z/HKDF chain) + hkdf_sha256_extract_expand_32() (software HKDF) -- this is the FIRST time this exact call
     * sequence has ever run on real hardware (Giai đoạn 0 only reached pqc_kem_decapsulate() on its own, and
     * security_service_ecdh_to_host() has never been called by this project before -- see its own doc comment). ---- */
    payload[0] = APP_CA_PROTO_DERIVE_KEYS;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t dk_len =
        ca_test_append_ext(payload, 1U + sizeof(quad), pk_kem_a, sizeof(pk_kem_a), ct_kem_b_sim, sizeof(ct_kem_b_sim));
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)dk_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("DERIVE_KEYS: FAIL -- expected OK, got status=");
        app_log_uint(resp[1]);
        app_log(" (see security_service_ecdh_to_host()'s doc comment: SE05x may gate this on a chip FIPS-mode\r\n"
                "config outside this host code's control)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("DERIVE_KEYS: OK (hybrid combiner ran end to end on real hardware)\r\n");

    {
        ca_blob_t own_id = ca_service_get_device_id();
        static const char hex_digits[] = "0123456789ABCDEF";
        uint8_t own_id_hex[64];
        if (own_id.len * 2U > sizeof(own_id_hex)) {
            app_log("CA hybrid self-test setup: own id too long for hex buffer -- FAIL\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
        for (size_t i = 0; i < own_id.len; i++) {
            own_id_hex[2U * i] = (uint8_t)hex_digits[own_id.data[i] >> 4];
            own_id_hex[2U * i + 1U] = (uint8_t)hex_digits[own_id.data[i] & 0x0FU];
        }
        if (!ca_protocol_test_set_peer_id(own_id_hex, own_id.len * 2U)) {
            app_log("ca_protocol_test_set_peer_id: FAIL\r\n");
            (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
            return false;
        }
    }

    /* ---- CONFIRM + VERIFY_CONFIRM (hybrid) ---- */
    payload[0] = APP_CA_PROTO_CONFIRM;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t cf_len =
        ca_test_append_ext(payload, 1U + sizeof(quad), pk_kem_a, sizeof(pk_kem_a), ct_kem_b_sim, sizeof(ct_kem_b_sim));
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)cf_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U ||
        resp_len != 2U + 32U) {
        app_log("CONFIRM: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    uint8_t mac[32];
    memcpy(mac, &resp[2], sizeof(mac));
    app_log("CONFIRM: OK\r\n");

    payload[0] = APP_CA_PROTO_VERIFY_CONFIRM;
    memcpy(&payload[1], quad, sizeof(quad));
    size_t vc_len =
        ca_test_append_ext(payload, 1U + sizeof(quad), pk_kem_a, sizeof(pk_kem_a), ct_kem_b_sim, sizeof(ct_kem_b_sim));
    size_t mac_offset = vc_len;
    memcpy(&payload[vc_len], mac, sizeof(mac));
    vc_len += sizeof(mac);
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)vc_len, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("VERIFY_CONFIRM (matching): FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("VERIFY_CONFIRM (matching): OK -- both sides' hybrid Z_ecdh||Z_kem->HKDF chains agree\r\n");

    uint8_t send_key[32];
    uint8_t recv_key[32];
    if (!ca_protocol_get_session_keys(send_key, recv_key)) {
        app_log("VERIFY_CONFIRM: FAIL (no session keys held after mutual confirmation established)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    static const uint8_t all_zero32[32];
    if (memcmp(send_key, all_zero32, 32U) == 0 || memcmp(recv_key, all_zero32, 32U) == 0 ||
        memcmp(send_key, recv_key, 32U) == 0) {
        app_log("VERIFY_CONFIRM: FAIL (send/recv key all-zero or identical -- hybrid combiner did not actually run)\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    memset(send_key, 0, sizeof(send_key));
    memset(recv_key, 0, sizeof(recv_key));
    app_log("VERIFY_CONFIRM: hybrid session keys present, distinct, non-zero after CA_SESSION_ESTABLISHED\r\n");

    payload[mac_offset] ^= 0x01U; /* flip one bit of the MAC */
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, (uint16_t)vc_len, resp, &resp_len, sizeof(resp)) || resp[1] != 1U) {
        app_log("VERIFY_CONFIRM (tampered): FAIL -- expected mismatch(1), got ");
        app_log_uint(resp[1]);
        app_log("\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    app_log("VERIFY_CONFIRM (tampered): OK -> correctly reported mismatch\r\n");

    payload[0] = APP_CA_PROTO_END_SESSION;
    resp_len = sizeof(resp);
    if (!ca_protocol_handler(payload, 1U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
        app_log("END_SESSION: FAIL\r\n");
        (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);
        return false;
    }
    (void)security_service_delete_key(APP_CA_TEST_PEER_EPH_ID);

    app_log("=== CA hybrid-PQC self-test PASS ===\r\n");
    return true;
}

bool app_pqc_kem_self_test(void)
{
    app_log("=== PQC ML-KEM-768 self-test (Giai doan 0 spike) ===\r\n");

    /* ---- Part 1: decapsulate a fixed cross-implementation vector (pqc_kem_kat_vector.h) ---- */
    {
        uint32_t t0 = platform_get_tick_ms();
        uint8_t ss[PQC_KEM_SHARED_SECRET_BYTES];
        bool ok = pqc_kem_decapsulate(KAT_DK, KAT_CT, ss);
        uint32_t elapsed = platform_get_tick_ms() - t0;
        if (!ok) {
            app_log("decapsulate(KAT vector): FAIL (pqc_kem_decapsulate returned false)\r\n");
            return false;
        }
        if (memcmp(ss, KAT_EXPECTED_SS, sizeof(ss)) != 0) {
            app_log("decapsulate(KAT vector): FAIL -- shared secret does NOT match the independent Python "
                     "reference (pqc_kem_kat_vector.h) -- got: ");
            app_log_hex(ss, sizeof(ss));
            return false;
        }
        app_log("decapsulate(KAT vector): PASS -- shared secret matches independent kyber-py reference, ");
        app_log_uint(elapsed);
        app_log(" ms\r\n");
    }

    /* ---- Part 2: full on-device round trip (keygen -> encapsulate -> decapsulate) ---- */
    {
        static uint8_t pk[PQC_KEM_PUBLICKEY_BYTES];
        static uint8_t sk[PQC_KEM_SECRETKEY_BYTES];
        static uint8_t ct[PQC_KEM_CIPHERTEXT_BYTES];
        uint8_t ss_encap[PQC_KEM_SHARED_SECRET_BYTES];
        uint8_t ss_decap[PQC_KEM_SHARED_SECRET_BYTES];

        uint32_t t0 = platform_get_tick_ms();
        if (!pqc_kem_keygen(pk, sk)) {
            app_log("keygen: FAIL\r\n");
            return false;
        }
        uint32_t t_keygen = platform_get_tick_ms();

        if (!pqc_kem_encapsulate(pk, ct, ss_encap)) {
            app_log("encapsulate: FAIL\r\n");
            return false;
        }
        uint32_t t_encap = platform_get_tick_ms();

        if (!pqc_kem_decapsulate(sk, ct, ss_decap)) {
            app_log("decapsulate: FAIL\r\n");
            return false;
        }
        uint32_t t_decap = platform_get_tick_ms();

        static const uint8_t all_zero32[PQC_KEM_SHARED_SECRET_BYTES];
        if (memcmp(ss_encap, all_zero32, sizeof(ss_encap)) == 0 ||
            memcmp(ss_encap, ss_decap, sizeof(ss_encap)) != 0) {
            app_log("round trip: FAIL (shared secrets zero or do not match between encapsulate/decapsulate)\r\n");
            return false;
        }
        memset(sk, 0, sizeof(sk)); /* scratch key for this test only -- never used for a real session */
        memset(ss_encap, 0, sizeof(ss_encap));
        memset(ss_decap, 0, sizeof(ss_decap));

        app_log("round trip: PASS -- keygen=");
        app_log_uint(t_keygen - t0);
        app_log("ms encapsulate=");
        app_log_uint(t_encap - t_keygen);
        app_log("ms decapsulate=");
        app_log_uint(t_decap - t_encap);
        app_log("ms\r\n");
    }

    app_log("=== PQC ML-KEM-768 self-test PASS ===\r\n");
    return true;
}

/* One level's worth of app_pqc_sign_self_test() below -- broken out to avoid triplicating the same sequence for
 * ML-DSA-44/65/87. `kat_seed`/`kat_pk`/`kat_sig`/`kat_sig_len` come from pqc_sign_kat_vector.h (see its own doc
 * comment for how they were generated, independently, by the Python `dilithium-py` package). */
static bool app_pqc_sign_self_test_one_level(pqc_sign_level_t level, const char *name, const uint8_t *kat_seed,
                                             const uint8_t *kat_pk, const uint8_t *kat_sig, size_t kat_sig_len)
{
    size_t pk_len = pqc_sign_publickey_bytes(level);
    size_t sk_len = pqc_sign_secretkey_bytes(level);
    size_t max_sig_len = pqc_sign_max_signature_bytes(level);

    app_log("--- ");
    app_log(name);
    app_log(" ---\r\n");

    /* ---- Part 1: keygen_from_seed() must reproduce the independent Python reference's public key bit-for-bit,
     * and verify() must accept a signature that reference independently produced (deterministic mode, see
     * pqc_sign_kat_vector.h -- firmware itself never signs deterministically, only verifies here). ---- */
    static uint8_t pk[PQC_SIGN_MAX_PUBLICKEY_BYTES];
    static uint8_t sk[PQC_SIGN_MAX_SECRETKEY_BYTES];
    uint32_t t0 = platform_get_tick_ms();
    if (!pqc_sign_keygen_from_seed(level, kat_seed, pk, sk)) {
        app_log("keygen_from_seed(KAT vector): FAIL\r\n");
        return false;
    }
    uint32_t t_keygen = platform_get_tick_ms();
    if (memcmp(pk, kat_pk, pk_len) != 0) {
        app_log("keygen_from_seed(KAT vector): FAIL -- public key does NOT match the independent dilithium-py "
                 "reference\r\n");
        memset(sk, 0, sk_len);
        return false;
    }
    app_log("keygen_from_seed(KAT vector): PASS -- public key matches independent dilithium-py reference, ");
    app_log_uint(t_keygen - t0);
    app_log(" ms\r\n");

    if (!pqc_sign_verify(level, kat_pk, PQC_SIGN_KAT_MSG, sizeof(PQC_SIGN_KAT_MSG), kat_sig, kat_sig_len)) {
        app_log("verify(KAT vector): FAIL -- rejected a signature the independent dilithium-py reference produced\r\n");
        memset(sk, 0, sk_len);
        return false;
    }
    app_log("verify(KAT vector): PASS -- accepted independent dilithium-py reference's signature\r\n");

    /* ---- Part 2: full on-device round trip (this device's own keygen -> sign -> verify), same secret key from
     * Part 1 -- proves the vendored PQClean C sign/verify pair agree with EACH OTHER too, not just that verify()
     * alone accepts someone else's output. Uses the default randomized/hedged signing mode (see pqc_sign.h), the
     * same mode a real "Ký số" signing operation would use -- unlike Part 1's deterministic KAT signature. ---- */
    static uint8_t sig[PQC_SIGN_MAX_BYTES];
    size_t sig_len = max_sig_len;
    uint32_t t_sign_start = platform_get_tick_ms();
    if (!pqc_sign_sign(level, sk, PQC_SIGN_KAT_MSG, sizeof(PQC_SIGN_KAT_MSG), sig, &sig_len)) {
        app_log("sign: FAIL\r\n");
        memset(sk, 0, sk_len);
        return false;
    }
    uint32_t t_sign_end = platform_get_tick_ms();
    memset(sk, 0, sk_len); /* done with the secret key the moment the signature exists */

    if (!pqc_sign_verify(level, pk, PQC_SIGN_KAT_MSG, sizeof(PQC_SIGN_KAT_MSG), sig, sig_len)) {
        app_log("round trip: FAIL (this device's own signature did not verify against its own public key)\r\n");
        return false;
    }
    app_log("round trip: PASS -- sign=");
    app_log_uint(t_sign_end - t_sign_start);
    app_log("ms (");
    app_log_uint((uint32_t)sig_len);
    app_log(" byte signature, max ");
    app_log_uint((uint32_t)max_sig_len);
    app_log(")\r\n");
    return true;
}

/* Giai đoạn 4 spike (2026-09-24, xem CLAUDE.md) for PQC-for-"Ký số" (ML-DSA, FIPS 204): exercises
 * Core_app/Middleware/PQC/pqc_sign.h across all three vendored levels (ML-DSA-44/65/87, PQClean crypto_sign/
 * ml-dsa-{44,65,87}/clean) the same two ways app_pqc_kem_self_test() exercised ML-KEM-768 for Giai đoạn 0: (1) a
 * fixed cross-implementation vector (pqc_sign_kat_vector.h, independent Python `dilithium-py`) -- proves
 * keygen-from-seed and verify agree with someone else's implementation of the same standard; (2) a full on-device
 * sign -> verify round trip -- proves the two on-device operations agree with each other, including the seed-only
 * persistent-identity design (pqc_randombytes_pin_next(), randombytes.h) this feature's whole key-storage
 * approach depends on. Also logs wall-clock timing for keygen/sign per level. Returns true if every level's both
 * checks pass. */
bool app_pqc_sign_self_test(void)
{
    app_log("=== PQC ML-DSA self-test (Giai doan 4 spike) ===\r\n");
    bool ok = true;
    ok = app_pqc_sign_self_test_one_level(PQC_SIGN_MLDSA44, "ML-DSA-44", PQC_SIGN_KAT_MLDSA44_SEED,
                                          PQC_SIGN_KAT_MLDSA44_PK, PQC_SIGN_KAT_MLDSA44_SIG,
                                          sizeof(PQC_SIGN_KAT_MLDSA44_SIG)) && ok;
    ok = app_pqc_sign_self_test_one_level(PQC_SIGN_MLDSA65, "ML-DSA-65", PQC_SIGN_KAT_MLDSA65_SEED,
                                          PQC_SIGN_KAT_MLDSA65_PK, PQC_SIGN_KAT_MLDSA65_SIG,
                                          sizeof(PQC_SIGN_KAT_MLDSA65_SIG)) && ok;
    ok = app_pqc_sign_self_test_one_level(PQC_SIGN_MLDSA87, "ML-DSA-87", PQC_SIGN_KAT_MLDSA87_SEED,
                                          PQC_SIGN_KAT_MLDSA87_PK, PQC_SIGN_KAT_MLDSA87_SIG,
                                          sizeof(PQC_SIGN_KAT_MLDSA87_SIG)) && ok;
    if (!ok) {
        app_log("=== PQC ML-DSA self-test FAIL ===\r\n");
        return false;
    }
    app_log("=== PQC ML-DSA self-test PASS ===\r\n");
    return true;
}

/* Exact byte offsets security_protocol.c's security_cmd_t uses for the ML-DSA family -- same duplication
 * convention as APP_CA_PROTO_* / APP_QRNG_PROTO_* above (this is the public wire-protocol contract, only this
 * test needs the numeric values). */
#define APP_SEC_CMD_ENSURE_MLDSA_KEYPAIR  0x16U
#define APP_SEC_CMD_MLDSA_SIGN            0x17U
#define APP_SEC_CMD_MLDSA_VERIFY          0x18U
#define APP_SEC_CMD_READ_MLDSA_PUBLIC_KEY 0x19U

/* Giai đoạn 4 (2026-09-24, xem CLAUDE.md): exercises security_protocol.c's ML-DSA sub-commands (0x16-0x19)
 * directly (bypassing USB framing, same technique app_qrng_protocol_self_test()/app_ca_protocol_self_test() use)
 * -- unlike app_pqc_sign_self_test() above (which calls Core_app/Middleware/PQC/pqc_sign.h directly and already
 * proves the ML-DSA math itself is correct against an independent Python reference), THIS test's job is the wire
 * plumbing: ENSURE_MLDSA_KEYPAIR's seed actually persists across separate calls (security_service_store_secret()/
 * load_secret()), SIGN/VERIFY/READ_PUBLIC_KEY parse their variable-length fields correctly, and a real signature
 * produced through the USB-shaped path verifies against a real public key read back through it too -- for all
 * three levels. Must run after app_self_test() (security_service_init() already succeeded there). */
bool app_security_mldsa_protocol_self_test(void)
{
    app_log("=== Security ML-DSA command-protocol self-test (Giai doan 4) ===\r\n");
    if (!security_service_is_ready()) {
        app_log("security_service not ready -- skipping\r\n");
        return true;
    }

    /* Sized for VERIFY's worst case (level 87): 1+1+1+1+32 (fixed prefix+digest) + 2+2592 (pk) + 2+4627 (sig). */
    static uint8_t payload[7300];
    static uint8_t resp[4700];
    uint16_t resp_len;
    static const uint8_t digest[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    }; /* not actually SHA-256 of anything -- ML-DSA does not care what produced it, see this sub-command's own
        * doc comment in security_protocol.c; a fixed pattern is enough to exercise the wire path. */

    static const struct {
        pqc_sign_level_t level;
        const char *name;
    } cases[3] = {
        {PQC_SIGN_MLDSA44, "ML-DSA-44"},
        {PQC_SIGN_MLDSA65, "ML-DSA-65"},
        {PQC_SIGN_MLDSA87, "ML-DSA-87"},
    };

    for (size_t i = 0; i < 3U; i++) {
        pqc_sign_level_t level = cases[i].level;
        app_log("--- ");
        app_log(cases[i].name);
        app_log(" ---\r\n");

        /* ---- ENSURE_MLDSA_KEYPAIR, called twice -- second call must also succeed (idempotent: a stored seed
         * already exists, so this proves "create if missing" doesn't error out when there is nothing to create). */
        for (int attempt = 0; attempt < 2; attempt++) {
            payload[0] = APP_SEC_CMD_ENSURE_MLDSA_KEYPAIR;
            payload[1] = (uint8_t)level;
            resp_len = sizeof(resp);
            if (!security_protocol_handler(payload, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
                app_log("ENSURE_MLDSA_KEYPAIR: FAIL (attempt ");
                app_log_uint((uint32_t)attempt);
                app_log(")\r\n");
                return false;
            }
        }
        app_log("ENSURE_MLDSA_KEYPAIR: OK (twice -- idempotent)\r\n");

        /* ---- MLDSA_SIGN ---- */
        payload[0] = APP_SEC_CMD_MLDSA_SIGN;
        payload[1] = (uint8_t)level;
        payload[2] = (uint8_t)SEC_HASH_SHA256; /* sanity-check field only, see security_protocol.c's doc comment */
        payload[3] = (uint8_t)sizeof(digest);
        memcpy(&payload[4], digest, sizeof(digest));
        resp_len = sizeof(resp);
        if (!security_protocol_handler(payload, (uint16_t)(4U + sizeof(digest)), resp, &resp_len, sizeof(resp)) ||
            resp[1] != 0U) {
            app_log("MLDSA_SIGN: FAIL\r\n");
            return false;
        }
        uint16_t sig_len = (uint16_t)(resp[2] | (resp[3] << 8));
        static uint8_t sig[PQC_SIGN_MAX_BYTES];
        memcpy(sig, &resp[4], sig_len);
        if (sig_len != pqc_sign_max_signature_bytes(level)) {
            /* ML-DSA signatures are not always exactly the maximum size in general, but with this fixed
             * digest/seed pair in practice they land on the max here -- if this ever legitimately varies, relax
             * this to a range check instead of exact equality. */
            app_log("MLDSA_SIGN: WARN -- signature length differs from the usual max (not necessarily a bug)\r\n");
        }
        app_log("MLDSA_SIGN: OK (");
        app_log_uint(sig_len);
        app_log(" byte signature)\r\n");

        /* ---- READ_MLDSA_PUBLIC_KEY ---- */
        payload[0] = APP_SEC_CMD_READ_MLDSA_PUBLIC_KEY;
        payload[1] = (uint8_t)level;
        resp_len = sizeof(resp);
        if (!security_protocol_handler(payload, 2U, resp, &resp_len, sizeof(resp)) || resp[1] != 0U) {
            app_log("READ_MLDSA_PUBLIC_KEY: FAIL\r\n");
            return false;
        }
        uint16_t pk_len = (uint16_t)(resp[2] | (resp[3] << 8));
        static uint8_t pk[PQC_SIGN_MAX_PUBLICKEY_BYTES];
        memcpy(pk, &resp[4], pk_len);
        if (pk_len != pqc_sign_publickey_bytes(level)) {
            app_log("READ_MLDSA_PUBLIC_KEY: FAIL (unexpected public key length)\r\n");
            return false;
        }
        app_log("READ_MLDSA_PUBLIC_KEY: OK (");
        app_log_uint(pk_len);
        app_log(" bytes)\r\n");

        /* ---- MLDSA_VERIFY (matching) ---- */
        {
            size_t o = 0;
            payload[o++] = APP_SEC_CMD_MLDSA_VERIFY;
            payload[o++] = (uint8_t)level;
            payload[o++] = (uint8_t)SEC_HASH_SHA256;
            payload[o++] = (uint8_t)sizeof(digest);
            memcpy(&payload[o], digest, sizeof(digest));
            o += sizeof(digest);
            payload[o++] = (uint8_t)(pk_len & 0xFFU);
            payload[o++] = (uint8_t)((pk_len >> 8) & 0xFFU);
            memcpy(&payload[o], pk, pk_len);
            o += pk_len;
            payload[o++] = (uint8_t)(sig_len & 0xFFU);
            payload[o++] = (uint8_t)((sig_len >> 8) & 0xFFU);
            memcpy(&payload[o], sig, sig_len);
            o += sig_len;
            resp_len = sizeof(resp);
            if (!security_protocol_handler(payload, (uint16_t)o, resp, &resp_len, sizeof(resp)) || resp[2] != 1U) {
                app_log("MLDSA_VERIFY (matching): FAIL\r\n");
                return false;
            }
            app_log("MLDSA_VERIFY (matching): OK -- signature produced through the wire verifies against the "
                     "public key read back through it\r\n");

            /* ---- tamper control: flip one bit of the signature, expect rejection ---- */
            payload[o - 1U] ^= 0x01U; /* last byte of sig, still within the just-written sig region */
            resp_len = sizeof(resp);
            if (!security_protocol_handler(payload, (uint16_t)o, resp, &resp_len, sizeof(resp)) || resp[2] != 0U) {
                app_log("MLDSA_VERIFY (tampered): FAIL -- expected rejection\r\n");
                return false;
            }
            app_log("MLDSA_VERIFY (tampered): OK -> correctly rejected\r\n");
        }
    }

    app_log("=== Security ML-DSA command-protocol self-test PASS ===\r\n");
    return true;
}

/* See app_self_test.h's doc comment. */
bool app_gcm_edge_size_self_test(void)
{
    static const uint16_t sizes[] = { 16u, 17u, 32u, 33u, 48u, 3200u, 58u, 87u, 95u, 115u, 7157u };
    /* Two buffers, not three: the plaintext is the formula (i & 0xFF), so decrypt writes back into `plain` and is
     * checked against the formula instead of against a saved copy (saves 7KB of AXI RAM). */
    static uint8_t plain[7157];
    static uint8_t cipher[7157];
    bool all_ok = true;
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t tag[16];

    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)(0x40U + i);
    }
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0x80U + i);
    }

    app_log("=== GCM edge-size self-test (isolates HW/HAL from USB/session) ===\r\n");

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint16_t len = sizes[s];
        for (uint32_t i = 0; i < len; i++) {
            plain[i] = (uint8_t)(i & 0xFFU);
        }

        if (platform_aes256_gcm_encrypt(key, nonce, plain, len, cipher, tag) != PLATFORM_OK) {
            app_log("  len="); app_log_uint(len); app_log(": ENCRYPT FAILED\r\n");
            return false;
        }
        memset(plain, 0, len);
        platform_status_t dec = platform_aes256_gcm_decrypt(key, nonce, cipher, len, tag, plain);
        if (dec != PLATFORM_OK) {
            app_log("  len="); app_log_uint(len); app_log(" mod16="); app_log_uint(len % 16u);
            app_log(": DECRYPT FAILED (tag mismatch) -- reproduced in isolation, no USB/session involved\r\n");
            all_ok = false;
            continue;
        }
        bool match = true;
        for (uint32_t i = 0; i < len; i++) {
            if (plain[i] != (uint8_t)(i & 0xFFU)) {
                match = false;
                break;
            }
        }
        if (!match) {
            app_log("  len="); app_log_uint(len); app_log(": decrypt OK but PLAINTEXT MISMATCH\r\n");
            all_ok = false;
            continue;
        }
        app_log("  len="); app_log_uint(len); app_log(" mod16="); app_log_uint(len % 16u); app_log(": round-trip OK\r\n");
    }

    app_log(all_ok ? "=== GCM edge-size self-test PASS ===\r\n" : "=== GCM edge-size self-test FAIL ===\r\n");

    return all_ok;
}

#endif /* EVT2_DIAGNOSTICS */
