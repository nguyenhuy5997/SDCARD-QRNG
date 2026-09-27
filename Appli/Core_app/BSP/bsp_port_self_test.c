/**
 * @file    bsp_port_self_test.c
 * @brief   Boot-time checks for the STM32H7S3 port specifically -- the pieces that changed vs EVT2 (H753) and can be
 *          verified on a bare NUCLEO-H7S3L8 with none of EVT2's external chips (SE052F, FPC2530, noise front-end).
 *
 * Covers:
 *  - CRYP AES-256-GCM (platform_crypto.c): NIST GCM Test Case 14 (all-zero key/IV) and Test Case 15 (non-zero
 *    key/IV, 64-byte plaintext). Case 15 is the one that proves the __REV() key/IV byte order and the ICB
 *    counter=2 preload are right on this CRYP -- an all-zero key/IV cannot detect a byte-order mistake. Vectors
 *    cross-checked with Python `cryptography` (AESGCM) before being written here. Also: decrypt round trip and a
 *    1-bit tag tamper that must be rejected.
 *  - HASH SHA-256 (platform_hash.c, new H7RS HASH API): FIPS 180-2 "abc".
 *  - RNG (platform_rng.c, HSI48 kernel clock).
 *  - Memory layout: where the main stack, .dtcm_bss, the DMA window and the PQC alternate stack actually landed.
 * The PQC alternate stack itself (ML-KEM moved onto it by this port) is exercised by app_pqc_kem_self_test() /
 * app_pqc_sign_self_test(), run right after this from main().
 */
/* Dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS

#include "bsp_hal.h"
#include "platform.h"

#include <string.h>

extern void app_log(const char *msg);
extern void app_log_hex(const uint8_t *data, size_t len);
extern void app_log_uint(uint32_t value);

extern uint8_t __dma_noncache_region_start__[];
extern uint8_t __main_stack_limit__[];
extern uint8_t _estack[];
extern uint8_t __heap_limit__[];
extern uint8_t end[];

static const uint8_t TC15_KEY[32] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
};
static const uint8_t TC15_IV[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
static const uint8_t TC15_PT[64] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
};
static const uint8_t TC15_CT[64] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
};
static const uint8_t TC15_TAG[16] = {
    0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
};
static const uint8_t TC14_CT[16] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
};
static const uint8_t TC14_TAG[16] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
};
static const uint8_t SHA256_ABC[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static bool check(const char *what, bool ok)
{
    app_log(what);
    app_log(ok ? ": PASS\r\n" : ": FAIL\r\n");
    return ok;
}

static void log_addr(const char *what, const void *p)
{
    app_log(what);
    app_log(" = ");
    app_log_uint((uint32_t)p);
    app_log("\r\n");
}

/* AES-128 single block via the CBC-MAC path (KeyIVConfigSkip ONCE, AES-128, 8-bit data type) -- the QRNG AES
 * extractor's code path, which differs from GCM in key size, chaining mode and key/IV reload policy.
 * FIPS-197 Appendix B: key 000102..0f, plaintext 00112233..ff -> 69c4e0d8 6a7b0430 d8cdb780 70b4c55a.
 * Run both before and after the GCM checks: GCM leaves CRYP in GCM mode, so this also shows whether the CBC path
 * depends on what ran before it. */
static bool check_aes128_fips197(const char *label)
{
    static const uint8_t k[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    static const uint8_t p[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    static const uint8_t c[16] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                   0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    uint8_t mac[16] = {0};
    platform_status_t st = platform_aes128_cbc_mac(k, p, 16U, mac);
    bool ok = st == PLATFORM_OK && memcmp(mac, c, 16U) == 0;
    (void)check(label, ok);
    if (!ok) {
        app_log("  status=");
        app_log_uint((uint32_t)st);
        app_log(" got: ");
        app_log_hex(mac, 16U);
        app_log("\r\n");
    }
    return ok;
}

bool bsp_port_self_test(void)
{
    bool all = true;
    static uint8_t out[64];
    static uint8_t back[64];
    uint8_t tag[16];

    app_log("=== H7S3 port self-test ===\r\n");
    log_addr("main stack limit (DTCM)", __main_stack_limit__);
    log_addr("main stack top  (_estack)", _estack);
    log_addr("DMA window (.dma_noncache, MPU non-cacheable)", __dma_noncache_region_start__);
    log_addr("heap start", end);
    log_addr("heap limit", __heap_limit__);

    all &= check("platform_crypto_init", platform_crypto_init() == PLATFORM_OK);
    all &= check("platform_hash_init", platform_hash_init() == PLATFORM_OK);
    all &= check("platform_rng_init", platform_rng_init() == PLATFORM_OK);

    all &= check_aes128_fips197("AES-128 CBC-MAC FIPS-197 (before any GCM)");

    /* NIST GCM Test Case 14: K = 0^256, IV = 0^96, P = 0^128. */
    {
        static const uint8_t zero32[32] = {0};
        static const uint8_t zero16[16] = {0};
        bool ok = platform_aes256_gcm_encrypt(zero32, zero32, zero16, 16U, out, tag) == PLATFORM_OK &&
                  memcmp(out, TC14_CT, 16U) == 0 && memcmp(tag, TC14_TAG, 16U) == 0;
        all &= check("GCM encrypt NIST TC14", ok);
    }

    /* NIST GCM Test Case 15 (non-zero key/IV -> byte order + ICB counter are really exercised). */
    {
        uint32_t t0 = platform_get_cycle_count();
        bool ok = platform_aes256_gcm_encrypt(TC15_KEY, TC15_IV, TC15_PT, 64U, out, tag) == PLATFORM_OK;
        uint32_t t1 = platform_get_cycle_count();
        ok = ok && memcmp(out, TC15_CT, 64U) == 0 && memcmp(tag, TC15_TAG, 16U) == 0;
        all &= check("GCM encrypt NIST TC15", ok);
        if (!ok) {
            app_log("  got ct : ");
            app_log_hex(out, 64U);
            app_log("\r\n  got tag: ");
            app_log_hex(tag, 16U);
            app_log("\r\n");
        }
        app_log("  TC15 encrypt cycles = ");
        app_log_uint(t1 - t0);
        app_log("\r\n");

        ok = platform_aes256_gcm_decrypt(TC15_KEY, TC15_IV, TC15_CT, 64U, TC15_TAG, back) == PLATFORM_OK &&
             memcmp(back, TC15_PT, 64U) == 0;
        all &= check("GCM decrypt NIST TC15", ok);

        uint8_t bad_tag[16];
        memcpy(bad_tag, TC15_TAG, 16U);
        bad_tag[0] ^= 0x01U;
        ok = platform_aes256_gcm_decrypt(TC15_KEY, TC15_IV, TC15_CT, 64U, bad_tag, back) != PLATFORM_OK;
        all &= check("GCM decrypt rejects 1-bit tag tamper", ok);
    }

    all &= check_aes128_fips197("AES-128 CBC-MAC FIPS-197 (after GCM)");

    {
        uint8_t digest[32];
        bool ok = platform_sha256((const uint8_t *)"abc", 3U, digest) == PLATFORM_OK &&
                  memcmp(digest, SHA256_ABC, 32U) == 0;
        all &= check("SHA-256(\"abc\") FIPS 180-2", ok);
    }

    {
        uint8_t r1[16];
        uint8_t r2[16];
        bool ok = platform_rng_get_bytes(r1, sizeof(r1)) == PLATFORM_OK &&
                  platform_rng_get_bytes(r2, sizeof(r2)) == PLATFORM_OK && memcmp(r1, r2, sizeof(r1)) != 0;
        all &= check("RNG two draws differ", ok);
    }

    app_log(all ? "=== H7S3 port self-test PASS ===\r\n" : "=== H7S3 port self-test FAIL ===\r\n");
    return all;
}

#endif /* EVT2_DIAGNOSTICS */
