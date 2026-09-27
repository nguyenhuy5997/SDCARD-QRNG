/**
 * @file    app_se05x_probe.c
 * @brief   TEMPORARY (2026-09-26): run every security_service function the firmware uses once against the SE050F2 of
 *          the STM32H7S3V8Y6TR board and record the result, because the chip (applet 3.6.0, FIPS mode) is not the SE052F
 *          the code was written for. The board has no UART, so results go to RAM and are read over SWD:
 *            g_se05x_probe[i]      = sec_status_t of step i (0 = SEC_OK, 1 = SEC_ERROR, 2 = NOT_READY, 3 = INVALID_PARAM),
 *                                    0x40 = call OK but the verify said "invalid", 0xEE = step not reached.
 *            g_se05x_probe_done    = 0x600D0000 | number of steps run.
 *          Only scratch objects 0x7E0000xx are created, and every one is deleted at the end.
 */
#include "app_se05x_probe.h"

#if EVT2_SE05X_PROBE

#include <string.h>

#include "security_service.h"
#include "app_trace.h"
#include "bsp_hal.h" /* HAL_Delay */

#define PROBE_STEPS 64U

volatile uint8_t g_se05x_probe[PROBE_STEPS];
volatile uint32_t g_se05x_probe_done;
volatile uint32_t g_se05x_probe_iter; /* completed probe loops in this boot */
volatile uint8_t g_se05x_probe_hkdf[32]; /* HKDF(IKM = 0xA0..0xBF, no salt, info "info", L = 32) for an RFC 5869 check */
volatile uint32_t g_se05x_probe_sw[PROBE_STEPS]; /* last failing APDU during the step: INS<<24 | P1<<16 | SW */
static volatile uint32_t g_se05x_last_sw;           /* was set by a temporary line in se05x_tlv.c (removed) */

static uint32_t s_step;

static void rec(sec_status_t st)
{
    if (s_step < PROBE_STEPS) {
        g_se05x_probe[s_step] = (uint8_t)st;
        g_se05x_probe_sw[s_step] = g_se05x_last_sw;
    }
    s_step++;
}

static void rec_verify(sec_status_t st, bool valid)
{
    rec((st == SEC_OK && !valid) ? (sec_status_t)0x40 : st);
}

/* Progress marker written BEFORE each step: if the chip hangs, g_se05x_probe_done = 0xB0000000 | step that hung. */
#define PAUSE()    do { if (EVT2_SE05X_PROBE_PAUSE_MS > 0) { HAL_Delay(EVT2_SE05X_PROBE_PAUSE_MS); } } while (0)
#define REC(...)   do { PAUSE(); app_watchdog_kick(); g_se05x_probe_done = 0xB0000000U | s_step; g_se05x_last_sw = 0U; rec(__VA_ARGS__); } while (0)
#define REC_V(...) do { PAUSE(); app_watchdog_kick(); g_se05x_probe_done = 0xB0000000U | s_step; g_se05x_last_sw = 0U; rec_verify(__VA_ARGS__); } while (0)

#define ID_EC_BASE    0x7E000010U /* + curve */
#define ID_EC_IMPORT  0x7E000020U
#define ID_RSA_BASE   0x7E000030U /* + bits index */
#define ID_RSA_IMPORT 0x7E000038U
#define ID_SECRET     0x7E000040U
#define ID_EC_PAIR    0x7E000050U
#define ID_EPHEMERAL  0x7E000060U
#define ID_HMAC       0x7E000070U
#define ID_HKDF_OUT   0x7E000071U

static const sec_hash_t s_curve_hash[] = {
    SEC_HASH_SHA256, SEC_HASH_SHA384, SEC_HASH_SHA512, SEC_HASH_SHA256, SEC_HASH_SHA384, SEC_HASH_SHA512,
    SEC_HASH_SHA256,
};
static const size_t s_hash_len[] = { 28U, 32U, 48U, 64U }; /* indexed by sec_hash_t */

static void app_se05x_probe_once(void);

#if EVT2_SE05X_PROBE == 2
/* HKDF-only probe (2026-09-27): per variant v, g_hkdf_st[v] = sec_status_t, g_hkdf_sw[v] = last failing APDU
 * (INS << 24 | P1 << 16 | SW, 0 = none), g_hkdf_out[v][0..63] = output. HMAC key = 0xA0..0xBF (32 bytes).
 *   v0: no salt, info "info", L 32    v1: salt 0x00..0x1F, info "info", L 32
 *   v2: no salt, info "info", L 64    v3: no salt, no info, L 32 */
volatile uint32_t g_hkdf_st[4];
volatile uint32_t g_hkdf_sw[4];
volatile uint8_t g_hkdf_out[4][64];
volatile uint32_t g_hkdf_hmac_st;

static void app_se05x_hkdf_probe(void)
{
    uint8_t key[32], salt[32], out[64];
    for (size_t i = 0; i < 32U; i++) {
        key[i] = (uint8_t)(0xA0U + i);
        salt[i] = (uint8_t)i;
    }
    g_se05x_last_sw = 0U;
    g_hkdf_hmac_st = (uint32_t)security_service_write_transient_hmac_key(ID_HMAC, key, sizeof(key)) |
                     (g_se05x_last_sw << 8);
    static const struct { int salt; size_t len; int info; } v[4] = { {0, 32, 1}, {1, 32, 1}, {0, 64, 1}, {0, 32, 0} };
    for (size_t k = 0; k < 4U; k++) {
        memset(out, 0, sizeof(out));
        g_se05x_last_sw = 0U;
        g_hkdf_st[k] = (uint32_t)security_service_hkdf_export(ID_HMAC, v[k].salt ? salt : NULL, v[k].salt ? 32U : 0U,
                                                              v[k].info ? (const uint8_t *)"info" : NULL,
                                                              v[k].info ? 4U : 0U, out, v[k].len);
        g_hkdf_sw[k] = g_se05x_last_sw;
        for (size_t i = 0; i < 64U; i++) {
            g_hkdf_out[k][i] = out[i];
        }
    }
    (void)security_service_delete_key(ID_HMAC);

    /* v4: same as v0 but with a PERSISTENT HMAC key (st in g_hkdf_st[3], sw in g_hkdf_sw[3], out in g_hkdf_out[3]) */
    {
        extern sec_status_t security_service_debug_write_persistent_hmac_key(uint32_t, const uint8_t *, size_t);
        g_se05x_last_sw = 0U;
        g_hkdf_hmac_st |= (uint32_t)security_service_debug_write_persistent_hmac_key(ID_HMAC, key, sizeof(key)) << 16;
        memset(out, 0, sizeof(out));
        g_se05x_last_sw = 0U;
        g_hkdf_st[3] = (uint32_t)security_service_hkdf_export(ID_HMAC, NULL, 0U, (const uint8_t *)"info", 4U, out, 32U);
        g_hkdf_sw[3] = g_se05x_last_sw;
        for (size_t i = 0; i < 64U; i++) {
            g_hkdf_out[3][i] = out[i];
        }
        (void)security_service_delete_key(ID_HMAC);
    }
    g_se05x_probe_done = 0x600DF00DU;
}
#endif

void app_se05x_probe(void)
{
#if EVT2_SE05X_PROBE == 2
    app_se05x_hkdf_probe();
    return;
#endif
    for (uint32_t i = 0; i < EVT2_SE05X_PROBE_LOOPS; i++) {
        app_se05x_probe_once();
        g_se05x_probe_iter = i + 1U;
    }
}

static void app_se05x_probe_once(void)
{
    static uint8_t buf[600];
    static uint8_t buf2[600];
    uint8_t digest[64];
    uint8_t sig[520];
    size_t len, len2, sig_len;
    bool valid;
    sec_status_t st;

    memset((void *)g_se05x_probe, 0xEE, sizeof(g_se05x_probe));
    s_step = 0U;
    g_se05x_probe_done = 0xA0000000U; /* started: removing leftovers of an earlier run */
    for (uint32_t id = 0x7E000010U; id <= 0x7E000072U; id++) {
        if (security_service_key_exists(id)) {
            (void)security_service_delete_key(id);
        }
    }
    for (size_t i = 0; i < sizeof(digest); i++) {
        digest[i] = (uint8_t)(0xA0U + i);
    }

    /* 0: random, 1: SHA-256 */
    REC(security_service_get_random(buf, 32U));
    REC(security_service_sha256((const uint8_t *)"abc", 3U, buf));

    /* 2..29: per EC curve (7 x 4): generate persistent key pair, sign, verify, read public key */
    for (uint32_t c = 0; c <= (uint32_t)SEC_EC_CURVE_SECP256K1; c++) {
        uint32_t id = ID_EC_BASE + c;
        sec_hash_t h = s_curve_hash[c];
        st = security_service_ensure_ec_keypair_ex(id, (sec_ec_curve_t)c);
        REC(st);
        sig_len = sizeof(sig);
        sec_status_t sst = security_service_ecdsa_sign_ex(id, h, digest, s_hash_len[h], sig, &sig_len);
        REC(sst);
        valid = false;
        REC_V(sst == SEC_OK ? security_service_ecdsa_verify_ex(id, h, digest, s_hash_len[h], sig, sig_len, &valid)
                                 : SEC_ERROR, valid);
        len = sizeof(buf);
        REC(security_service_read_ec_public_key(id, buf, &len));
    }

    /* 30..31: import the P-256 public key as a peer key and verify a signature with it */
    len = sizeof(buf);
    st = security_service_read_ec_public_key(ID_EC_BASE + SEC_EC_CURVE_P256, buf, &len);
    REC(st == SEC_OK ? security_service_import_ec_public_key(ID_EC_IMPORT, SEC_EC_CURVE_P256, buf, len) : st);
    sig_len = sizeof(sig);
    st = security_service_ecdsa_sign_ex(ID_EC_BASE + SEC_EC_CURVE_P256, SEC_HASH_SHA256, digest, 32U, sig, &sig_len);
    valid = false;
    REC_V(st == SEC_OK ? security_service_ecdsa_verify_ex(ID_EC_IMPORT, SEC_HASH_SHA256, digest, 32U, sig, sig_len,
                                                               &valid)
                            : st,
               valid);

    /* 32..33: secret blob store/load (CA identity data uses this) */
    for (size_t i = 0; i < 64U; i++) {
        buf[i] = (uint8_t)i;
    }
    REC(security_service_store_secret(ID_SECRET, buf, 64U));
    len = sizeof(buf2);
    st = security_service_load_secret(ID_SECRET, buf2, &len);
    REC((st == SEC_OK && (len != 64U || memcmp(buf, buf2, 64U) != 0)) ? (sec_status_t)0x40 : st);

    /* 34: import a plaintext P-256 key pair (how the CA identity key got onto the SE052F) -- fixed test vector:
     * private key = 1, public key = the P-256 generator G */
    {
        static const uint8_t priv[32] = { [31] = 1 };
        static const uint8_t pub[65] = {
            0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
            0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
            0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
            0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5 };
        REC(security_service_import_ec_keypair(ID_EC_PAIR, SEC_EC_CURVE_P256, priv, sizeof(priv), pub, sizeof(pub)));
    }

    /* 35: transient (RAM-only) ephemeral EC key pair, 36: ECDH with the result returned to the host (hybrid path),
     * 37: ECDH into a chip object (SE052F-only path, expected SEC_ERROR on applet 3.x) */
    REC(security_service_generate_ephemeral_ec_keypair(ID_EPHEMERAL, SEC_EC_CURVE_P256));
    len = sizeof(buf);
    st = security_service_read_ec_public_key(ID_EC_BASE + SEC_EC_CURVE_P256, buf, &len);
    REC(st == SEC_OK ? security_service_ecdh_to_host(ID_EPHEMERAL, buf, len, buf2) : st);
    REC(st == SEC_OK ? security_service_ecdh_to_secret(ID_EPHEMERAL, buf, len, ID_HKDF_OUT + 1U) : st);

    /* 38: transient HMAC key written from the host, 39: HMAC in the chip, 40: HKDF back to the host,
     * 41: HKDF into a chip object */
    REC(security_service_write_transient_hmac_key(ID_HMAC, digest, 32U));
    REC(security_service_hmac_sha256_with_secret(ID_HMAC, (const uint8_t *)"abc", 3U, buf));
    REC(security_service_hkdf_export(ID_HMAC, NULL, 0U, (const uint8_t *)"info", 4U, buf, 32U));
    for (size_t i = 0; i < 32U; i++) {
        g_se05x_probe_hkdf[i] = buf[i];
    }
    REC(security_service_hkdf_to_secret(ID_HMAC, NULL, 0U, (const uint8_t *)"info", 4U, ID_HKDF_OUT, 32U));

    /* 42..57: RSA 2048 / 3072 (8 steps each): generate, sign PKCS#1 v1.5, verify, sign PSS, verify, read public key,
     * import public key, verify v1.5 with the imported key */
    for (uint32_t b = 0; b < 2U; b++) {
        uint32_t id = ID_RSA_BASE + b;
        REC(security_service_ensure_rsa_keypair(id, (sec_rsa_key_bits_t)b));
        sig_len = sizeof(sig);
        st = security_service_rsa_sign_digest(id, SEC_RSA_PADDING_PKCS1_V15, SEC_HASH_SHA256, digest, 32U, sig,
                                              &sig_len);
        REC(st);
        valid = false;
        REC_V(st == SEC_OK ? security_service_rsa_verify_digest(id, SEC_RSA_PADDING_PKCS1_V15, SEC_HASH_SHA256,
                                                                     digest, 32U, sig, sig_len, &valid)
                                : st,
                   valid);
        size_t v15_len = sig_len;
        uint8_t v15_first = sig[0];
        sig_len = sizeof(sig);
        st = security_service_rsa_sign_digest(id, SEC_RSA_PADDING_PSS, SEC_HASH_SHA256, digest, 32U, sig, &sig_len);
        REC(st);
        valid = false;
        REC_V(st == SEC_OK ? security_service_rsa_verify_digest(id, SEC_RSA_PADDING_PSS, SEC_HASH_SHA256, digest,
                                                                     32U, sig, sig_len, &valid)
                                : st,
                   valid);
        len = sizeof(buf);
        len2 = 8U;
        st = security_service_read_rsa_public_key(id, buf, &len, buf2, &len2);
        REC(st);
        REC(st == SEC_OK ? security_service_import_rsa_public_key(ID_RSA_IMPORT, buf, len, buf2, len2) : st);
        /* re-sign v1.5 and verify with the imported public key */
        sig_len = sizeof(sig);
        st = security_service_rsa_sign_digest(id, SEC_RSA_PADDING_PKCS1_V15, SEC_HASH_SHA256, digest, 32U, sig,
                                              &sig_len);
        valid = false;
        REC_V(st == SEC_OK ? security_service_rsa_verify_digest(ID_RSA_IMPORT, SEC_RSA_PADDING_PKCS1_V15,
                                                                     SEC_HASH_SHA256, digest, 32U, sig, sig_len,
                                                                     &valid)
                                : st,
                   valid);
        (void)v15_len;
        (void)v15_first;
        (void)security_service_delete_key(ID_RSA_IMPORT);
    }

    /* cleanup: every scratch object */
    for (uint32_t c = 0; c <= (uint32_t)SEC_EC_CURVE_SECP256K1; c++) {
        (void)security_service_delete_key(ID_EC_BASE + c);
    }
    static const uint32_t ids[] = { ID_EC_IMPORT, ID_RSA_BASE, ID_RSA_BASE + 1U, ID_RSA_IMPORT, ID_SECRET, ID_EC_PAIR,
                                    ID_EPHEMERAL, ID_HMAC, ID_HKDF_OUT, ID_HKDF_OUT + 1U };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        if (security_service_key_exists(ids[i])) {
            (void)security_service_delete_key(ids[i]);
        }
    }
    /* 58: nothing left behind */
    bool left = false;
    for (uint32_t id = 0x7E000010U; id <= 0x7E000072U; id++) {
        if (security_service_key_exists(id)) {
            left = true;
        }
    }
    REC(left ? SEC_ERROR : SEC_OK);

    g_se05x_probe_done = 0x600D0000U | s_step;
}

#endif /* EVT2_SE05X_PROBE */
