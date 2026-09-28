/**
 * @file    platform_crypto.c
 * @brief   STM32H7RSxx implementation of the Platform block-cipher interface.
 *
 * Ported from EVT2's STM32H7xx version with only the RCC clock-enable bit
 * changed (CRYP moved from AHB2ENR on H7 to AHB3ENR on H7RS). The rest was
 * checked against the H7RS HAL (STM32Cube_FW_H7RS V1.3.0), not assumed:
 * CRYP_InitTypeDef keeps DataType/KeySize/pKey/pInitVect/DataWidthUnit/
 * HeaderWidthUnit/KeyIVConfigSkip, CRYP_CR_FFLUSH exists, and
 * stm32h7rsxx_hal_cryp.c's own "Table 1. Initial Counter Block" documents
 * the GCM ICB counter as 0x2 -- the same value gcm_pack_icb_words() below
 * loads. H7RS also has an SAES instance; this file only ever drives CRYP.
 *
 * Clock and the base HAL_CRYP_Init() are done by bsp_h7s3.c's
 * MX_CRYP_Init(), called from main() before any
 * application code runs (that generated init leaves hcryp configured for
 * CRYP_AES_GCM with a placeholder all-zero key/IV -- just enough to bring
 * the peripheral up).
 *
 * IMPORTANT: the MCU has exactly one physical CRYP peripheral, but this
 * file is not its only user -- Core_app/Drivers/FPC5234/fpc_hal_crypto.c
 * (vendor code) also drives it, through its own separate, local
 * `CRYP_HandleTypeDef aes_gcm` (a different C struct, same hardware:
 * both set `.Instance = CRYP`), and calls HAL_CRYP_DeInit() on it after
 * every biometric AES-GCM operation. HAL_CRYP_DeInit() disables
 * RCC_AHB3ENR_CRYPEN (H7RS; AHB2ENR on H7) -- the peripheral's one shared clock-enable bit --
 * regardless of which handle asked for it. That leaves this file's
 * `hcryp` silently clocked-off, even though `hcryp.State` (a separate
 * struct field the other handle's DeInit never touches) still reads
 * HAL_CRYP_STATE_READY -- so a plain HAL_CRYP_Init() call would skip
 * MspInit (it only re-runs while State == HAL_CRYP_STATE_RESET) and
 * never notice the clock is gone, and every register access afterwards
 * would silently no-op against unclocked hardware. platform_aes128_cbc_mac()
 * below forces `hcryp.State = HAL_CRYP_STATE_RESET` before every
 * HAL_CRYP_Init() call specifically to defend against that -- it is the
 * only reliable way to recover the clock after another owner's DeInit on
 * this shared peripheral. This file still never calls HAL_CRYP_DeInit()
 * itself, to avoid inflicting the same problem back onto FPC5234.
 *
 * Separately, the key/IV and DOUT byte-ordering quirks documented inline
 * in platform_aes128_cbc_mac() below (verified against the published
 * FIPS-197 Appendix B AES-128 vector) are a second, independent issue
 * from the clock-sharing one above -- both had to be fixed for this file
 * to produce correct output at all.
 */
#include "platform.h"
#include "bsp_hal.h"
#include <string.h>

extern CRYP_HandleTypeDef hcryp;

static bool s_ready;

platform_status_t platform_crypto_init(void)
{
    if (s_ready) {
        return PLATFORM_OK;
    }
    if (HAL_CRYP_GetState(&hcryp) == HAL_CRYP_STATE_RESET) {
        /* MX_CRYP_Init() has not run yet -- a call-order bug in the
         * caller, not something Platform can fix by initializing the
         * peripheral itself. */
        return PLATFORM_ERROR;
    }

    s_ready = true;
    return PLATFORM_OK;
}

platform_status_t platform_aes128_cbc_mac(const uint8_t key[16], const uint8_t *data, size_t data_len,
                                           uint8_t mac[16])
{
    return platform_aes128_cbc_mac_batch(key, data, data_len, 1U, mac);
}

platform_status_t platform_aes128_cbc_mac_batch(const uint8_t key[16], const uint8_t *data, size_t block_len,
                                                 size_t num_blocks, uint8_t *mac_out)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (key == NULL || data == NULL || mac_out == NULL || block_len == 0U || (block_len % 16U) != 0U ||
        num_blocks == 0U) {
        return PLATFORM_INVALID_PARAM;
    }

    /* Standard AES-CBC-MAC per sub-block: encrypt `block_len` bytes under
     * CBC with a zero IV, keep only the final ciphertext block. */
    static uint32_t s_zero_iv[4] = { 0, 0, 0, 0 };
    static uint32_t s_swapped_key[4];
    static uint32_t s_output[/* AES_INPUT_EXTRACTOR_SIZE upstream max */ 64];

    if ((block_len / 4U) > (sizeof(s_output) / sizeof(s_output[0]))) {
        return PLATFORM_INVALID_PARAM;
    }

    /* CRYP_DATATYPE_8B (byte swap) below only swaps the DIN/DOUT data
     * path -- it does NOT apply to the key/IV registers, which the
     * hardware always loads as raw 32-bit reads of the buffer's native
     * (little-endian) memory order. To get the conventional MSB-first
     * key byte order AES test vectors and this port's own key buffers
     * assume, each key word must be byte-reversed before handing it to
     * CRYP -- same fix (and same __REV()-per-word technique) as
     * Core_app/Drivers/FPC5234/fpc_hal_crypto.c's swap_endian_to_buffer()
     * applies to its own AES-GCM key/IV for the exact same reason (see
     * that file's "STM notes: CRYP_BYTE_SWAP does not apply for
     * key"/"...for iv" comments). s_zero_iv is all-zero, so it needs no
     * such swap. */
    for (size_t i = 0; i < 4U; i++) {
        s_swapped_key[i] = __REV(((const uint32_t *)(const void *)key)[i]);
    }

    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
    hcryp.Init.pKey = s_swapped_key;
    hcryp.Init.pInitVect = s_zero_iv;
    hcryp.Init.Algorithm = CRYP_AES_CBC;
    /* Load the key/IV registers only on the first sub-block's
     * HAL_CRYP_Encrypt() call below, not on every one -- all
     * `num_blocks` sub-blocks share the same key, and CRYP_KEYIVCONFIG_ONCE
     * is exactly ST's supported mechanism for that (HAL_CRYP_Init()
     * resets hcryp.KeyIVConfig to 0, so the first Encrypt() call still
     * loads key+IV as normal and sets it to 1; every later call with
     * KeyIVConfig==1 skips that register write). Each sub-block still
     * needs its OWN fresh zero IV (this is `num_blocks` *independent*
     * CBC-MACs, not one long chained CBC pass), so the loop below writes
     * IV0LR/IV0RR/IV1LR/IV1RR directly before every call after the
     * first -- a handful of cheap MMIO writes, versus HAL's own
     * key+IV reload (8 register writes plus its surrounding
     * DoKeyIVConfig bookkeeping) that CRYP_KEYIVCONFIG_ONCE lets us skip
     * for the key half. */
    hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ONCE;
    /* HAL_CRYP_Encrypt() below is given a WORD count (block_len / 4U). hcryp is shared with the GCM path further
     * down, which sets DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE -- so without resetting it here, the first CBC-MAC
     * after any GCM call had its Size read as BYTES, processed a single word and returned 69c4e0d8 00000000...
     * for the FIPS-197 vector (reproduced 2/2 on NUCLEO-H7S3L8 by running GCM before the first CBC-MAC).
     * Latent in EVT2's H753 original too (same HAL field, same missing assignment); it only stayed hidden
     * because EVT2's boot order ran the QRNG AES self-test before any GCM. */
    hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
    hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;

    /* See file doc comment: force MspInit (and its
     * __HAL_RCC_CRYP_CLK_ENABLE()) to re-run only when the shared clock
     * is ACTUALLY found disabled right now (RCC readback, not the
     * cached hcryp.State field -- see file doc comment for why that
     * field can't be trusted here). An earlier version of this forced
     * the full reinit unconditionally on every call; that was changed
     * to this checked version purely to avoid redundant clock churn (up
     * to 64 disable+enable cycles per qrng_service_get_entropy() AES
     * draw -- QRNG_ADC_SAMPLES/QRNG_AES_INPUT_EXTRACTOR_SIZE calls), NOT
     * because of a measured bug in the unconditional version: an
     * intermittent "get_entropy(AES) fails sometimes" symptom that
     * prompted this change was root-caused separately (300 individual
     * GET_ENTROPY(AES) calls over the real USB command protocol, status
     * byte tallied per call: 0 CRYP-attributable QRNG_ERROR, 1
     * QRNG_HEALTH_FAIL out of 300) to Core_app/Drivers/QRNG/entropy.c's
     * NIST 800-90B RCT/APT online health test doing its job -- those
     * tests have a non-zero designed false-alarm rate, this is expected
     * statistical behavior on a real noise source, not a CRYP fault. */
    if ((RCC->AHB3ENR & RCC_AHB3ENR_CRYPEN) == 0U) {
        hcryp.State = HAL_CRYP_STATE_RESET;
    }
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return PLATFORM_ERROR;
    }

    for (size_t b = 0; b < num_blocks; b++) {
        const uint8_t *block = data + b * block_len;
        uint8_t *mac = mac_out + b * 16U;

        if (b != 0U) {
            ((CRYP_TypeDef *)hcryp.Instance)->IV0LR = 0U;
            ((CRYP_TypeDef *)hcryp.Instance)->IV0RR = 0U;
            ((CRYP_TypeDef *)hcryp.Instance)->IV1LR = 0U;
            ((CRYP_TypeDef *)hcryp.Instance)->IV1RR = 0U;
        }

        /* Flush the IN/OUT FIFOs -- leftover state from GCM (this file's
         * own prior use, or FPC5234's aes_gcm sharing the same hardware
         * FIFOs) can otherwise block the OFNE flag from ever asserting
         * during the encrypt call below. */
        ((CRYP_TypeDef *)hcryp.Instance)->CR |= CRYP_CR_FFLUSH;

        if (HAL_CRYP_Encrypt(&hcryp, (uint32_t *)(const void *)block, (uint16_t)(block_len / 4U), s_output, 100U) !=
            HAL_OK) {
            return PLATFORM_ERROR;
        }

        /* Last 16 bytes (4 words) of the CBC ciphertext == the CBC-MAC.
         * Output words come back through DOUT byte-reversed relative to
         * the conventional MSB-first representation (same swap-does-not-
         * apply-to-register-loads asymmetry as the key -- see the
         * DataType/key comment above), so extract LSB-first to undo it. */
        const uint32_t *last_block = &s_output[(block_len / 4U) - 4U];
        for (size_t i = 0; i < 4U; i++) {
            mac[i * 4U + 0U] = (uint8_t)(last_block[i]);
            mac[i * 4U + 1U] = (uint8_t)(last_block[i] >> 8);
            mac[i * 4U + 2U] = (uint8_t)(last_block[i] >> 16);
            mac[i * 4U + 3U] = (uint8_t)(last_block[i] >> 24);
        }
    }

    return PLATFORM_OK;
}

/* ---- AES-256-GCM (video-call media encryption) ---------------------------
 *
 * Ported from usb_encrypt_host/firmware's aes_gcm_encrypt() (that project's
 * own encrypt-only reference implementation) after verifying, against
 * EVT2's *own* Drivers/STM32H7xx_HAL_Driver sources rather than assuming
 * compatibility by analogy, that this HAL package:
 *   - has NO `hcryp.Init.GCMCMACPhase` field (that reference file's own doc
 *     comment flags this as the one detail that varies across Cube FW
 *     versions) -- confirmed via stm32h7xx_hal_cryp.h's CRYP_ConfigTypeDef,
 *     which instead has Header/HeaderSize/DataWidthUnit/HeaderWidthUnit/
 *     KeyIVConfigSkip fields for GCM;
 *   - drives Init+Header+Payload as ONE blocking HAL_CRYP_Encrypt()/
 *     HAL_CRYP_Decrypt() call (stm32h7xx_hal_cryp.c: both route GCM through
 *     the same internal CRYP_AESGCM_Process(), called once per
 *     Encrypt/Decrypt with the Header phase driven internally via
 *     CRYP_GCMCCM_SetHeaderPhase() before the payload phase) -- so a
 *     separate HAL_CRYPEx_AESGCM_GenerateAuthTAG() call for the tag is
 *     correct and sufficient, matching the reference's assumption exactly.
 *
 * platform_aes256_gcm_decrypt() itself is NOT in the reference (that
 * project is encrypt-only, one direction, matching its own "host encrypts,
 * far end just needs the ciphertext" use case) -- the video-call flow needs
 * both directions on the same device (encrypt this device's outgoing
 * stream, decrypt the peer's incoming stream), so it is written here from
 * HAL_CRYP_Decrypt()'s own source (same CRYP_AESGCM_Process() path, just
 * with CRYP_CR_ALGODIR set to DECRYPT beforehand -- confirmed by reading
 * HAL_CRYP_Decrypt()'s `case CRYP_AES_GCM` branch directly) plus a local
 * tag comparison, not copied from anywhere. */

static platform_status_t gcm_reload_clock_if_needed(void)
{
    /* Same shared-peripheral clock hazard as platform_aes128_cbc_mac_batch()
     * -- see this file's top doc comment (FPC5234's own aes_gcm handle
     * calls HAL_CRYP_DeInit() after every biometric operation, which clears
     * the ONE physical CRYP peripheral's shared RCC_AHB3ENR_CRYPEN bit (H7RS)
     * regardless of which handle asked). Checked here too since video-call
     * media encryption interleaves with biometric use on the same
     * peripheral exactly like QRNG's AES draw does. */
    if ((RCC->AHB3ENR & RCC_AHB3ENR_CRYPEN) == 0U) {
        hcryp.State = HAL_CRYP_STATE_RESET;
    }
    return PLATFORM_OK;
}

/* BUG FOUND 2026-09-25 (see CLAUDE.md): the CRYP peripheral's own hardware GCM mode
 * (CRYP_AESGCM_Process(), driving both HAL_CRYP_Encrypt()/_Decrypt() for CRYP_AES_GCM) mis-computes the
 * authentication tag for ANY payload whose length is not an exact multiple of 16 bytes -- reproduced in
 * complete isolation (bare self-test, no USB/session/network involved: encrypt then immediately decrypt
 * on this same device with a fixed key/nonce), confirmed identical on BOTH the legacy CRYP instance and
 * the SAES instance (ST's own NUCLEO-H7S3L8 GCM example uses SAES, not CRYP, but never itself tests a
 * non-16-byte-aligned length), and confirmed NOT specific to GCM's NPBLB last-block handling: even plain
 * CRYP_AES_CTR mode (no authentication, no NPBLB at all) silently drops any trailing partial WORD (its
 * main loop only processes hcryp->Size/4 whole words, no partial-word tail handling exists). Exactly-
 * 16-byte-aligned lengths (16, 32, 48, 3200, ...) always round-trip correctly on this hardware/HAL, but
 * real H.264/HEVC video chunks are essentially never a multiple of 16 bytes, while fixed-size 3200B PCM
 * audio chunks always are -- explaining the video-only failures a real phone/PC call showed.
 *
 * Fix: stop using the hardware's own GCM mode (and CTR mode) for anything but single, always-word-
 * aligned 16-byte blocks, where this hardware is proven correct (every "len=16/32/48" self-test case
 * passed). platform_aes256_gcm_encrypt()/_decrypt() below instead build GCM themselves: AES-256-ECB of
 * one 16-byte block at a time via aes256_ecb_block() below (100% hardware, CBC-with-zero-IV == ECB,
 * reusing platform_aes128_cbc_mac_batch()'s own proven-correct key/IV/DOUT byte-ordering fixes) for the
 * GHASH subkey H, the J0 tag mask, and every keystream block; ghash_mul() below does the GF(2^128)
 * block multiplication in software -- not AES, just a ~128-iteration XOR/shift accumulator, negligible
 * next to the hardware AES calls it rides on top of (a 7157B video chunk is ~447 hardware single-block
 * calls plus 447 tiny software multiplies, not 447 software AES rounds). Fully wire-compatible: produces
 * the exact standard NIST SP 800-38D tag/ciphertext a real GCM implementation (PC's software AES-GCM,
 * Android's expectations) already computes for the TRUE length -- no protocol change on any other
 * codebase. */

/** Encrypts exactly one 16-byte block: AES-256-CBC with an all-zero IV, which for a single block is
 *  bit-for-bit identical to AES-256-ECB (ciphertext = AES_encrypt(plaintext XOR IV), IV=0). Reuses
 *  platform_aes128_cbc_mac_batch()'s own established, FIPS-197-verified conventions: `in`/`out` are
 *  plain, conventional (MSB-first) byte order -- the DIN/DOUT FIFOs handle the DataType=8B swap
 *  automatically -- while `key_words` must already be __REV()'d per word (raw register loads are NOT
 *  swapped). WORD-oriented DataWidthUnit (exactly 4 words, always) sidesteps both the GCM-mode NPBLB bug
 *  and the plain-mode partial-word truncation above: a fixed 16-byte block is never partial. */
static platform_status_t aes256_ecb_block(const uint32_t key_words[8], const uint8_t in[16], uint8_t out[16])
{
    static const uint32_t s_zero_iv[4] = {0U, 0U, 0U, 0U};
    static uint32_t s_output[4];

    hcryp.Init.DataType        = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize         = CRYP_KEYSIZE_256B;
    hcryp.Init.pKey            = (uint32_t *)(void *)(uintptr_t)(const void *)key_words;
    hcryp.Init.pInitVect       = (uint32_t *)(void *)(uintptr_t)(const void *)s_zero_iv;
    hcryp.Init.Algorithm       = CRYP_AES_CBC;
    hcryp.Init.DataWidthUnit   = CRYP_DATAWIDTHUNIT_WORD;
    hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
    hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;

    (void)gcm_reload_clock_if_needed();
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    /* See platform_aes128_cbc_mac_batch()'s comment -- leftover FIFO state from another user of this
     * shared peripheral can otherwise block OFNE from ever asserting. */
    ((CRYP_TypeDef *)hcryp.Instance)->CR |= CRYP_CR_FFLUSH;

    if (HAL_CRYP_Encrypt(&hcryp, (uint32_t *)(const void *)in, 4U, s_output, 100U) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    /* DOUT comes back byte-reversed relative to the conventional MSB-first representation -- same
     * asymmetry as platform_aes128_cbc_mac_batch()'s own DOUT extraction, extracted LSB-first to undo it. */
    for (size_t i = 0; i < 4U; i++) {
        out[i * 4U + 0U] = (uint8_t)(s_output[i]);
        out[i * 4U + 1U] = (uint8_t)(s_output[i] >> 8);
        out[i * 4U + 2U] = (uint8_t)(s_output[i] >> 16);
        out[i * 4U + 3U] = (uint8_t)(s_output[i] >> 24);
    }
    return PLATFORM_OK;
}

/** X = X * H in GF(2^128), per NIST SP 800-38D section 6.3 -- the textbook shift-and-reduce GHASH block
 *  multiplication (bit 0 of byte 0 is the highest-degree coefficient, GCM's usual bit-reflected
 *  convention; reduction polynomial x^128+x^7+x^2+x+1, i.e. 0xE1 in the top byte). Not AES, not even a
 *  hash function -- one polynomial multiply, ~128 XOR/shift steps, called once per 16-byte block.
 *  Branch-free on purpose: H = E(K, 0) is secret, so the conditional XOR and the reduction step are
 *  done with all-ones/all-zeros masks instead of `if`, keeping timing independent of H and X. */
static void ghash_mul(uint8_t x[16], const uint8_t h[16]) __attribute__((unused));
static void ghash_mul(uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16U);
    for (int i = 0; i < 128; i++) {
        uint8_t bit_mask = (uint8_t)(0U - (uint8_t)((x[i / 8] >> (7 - (i % 8))) & 1U));
        for (int j = 0; j < 16; j++) {
            z[j] = (uint8_t)(z[j] ^ (v[j] & bit_mask));
        }
        uint8_t lsb_mask = (uint8_t)(0U - (uint8_t)(v[15] & 1U));
        for (int j = 15; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1U) << 7));
        }
        v[0] = (uint8_t)((v[0] >> 1) ^ (0xE1U & lsb_mask));
    }
    memcpy(x, z, 16U);
    memset(z, 0, sizeof(z));
    memset(v, 0, sizeof(v));
}

/* ---- Table-driven GHASH (2026-09-29, CPU load at 120 MHz) ----
 * ghash_mul() above is ~128 shift/XOR rounds over 16 bytes per block; with ~450 blocks in a 7 KB video chunk it
 * was the largest share of the board's CPU time in a call. This is the 4-bit (Shoup) table method used by mbedTLS:
 * a 16-entry table of H multiples built once per call, then 32 table steps per block. Same result, bit for bit
 * (checked against ghash_mul() and against a library AES-GCM for lengths 1..7157, 2026-09-29). The table is indexed
 * by X (ciphertext-dependent) -- the usual mbedTLS trade-off; ghash_mul() stays for reference. */
typedef struct {
    uint64_t hl[16];
    uint64_t hh[16];
} ghash_table_t;

static const uint16_t s_ghash_last4[16] = {
    0x0000U, 0x1c20U, 0x3840U, 0x2460U, 0x7080U, 0x6ca0U, 0x48c0U, 0x54e0U,
    0xe100U, 0xfd20U, 0xd940U, 0xc560U, 0x9180U, 0x8da0U, 0xa9c0U, 0xb5e0U,
};

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0U;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void ghash_table_init(ghash_table_t *t, const uint8_t h[16])
{
    uint64_t vh = be64(h);
    uint64_t vl = be64(h + 8);
    t->hl[0] = 0U;
    t->hh[0] = 0U;
    t->hl[8] = vl;
    t->hh[8] = vh;
    for (uint32_t i = 4U; i > 0U; i >>= 1) {
        const uint64_t tt = (vl & 1U) * 0xe1000000ULL;
        vl = (vh << 63) | (vl >> 1);
        vh = (vh >> 1) ^ (tt << 32);
        t->hl[i] = vl;
        t->hh[i] = vh;
    }
    for (uint32_t i = 2U; i <= 8U; i *= 2U) {
        vh = t->hh[i];
        vl = t->hl[i];
        for (uint32_t j = 1U; j < i; j++) {
            t->hh[i + j] = vh ^ t->hh[j];
            t->hl[i + j] = vl ^ t->hl[j];
        }
    }
}

/** x = x * H using the table (same contract as ghash_mul()). */
static void ghash_mul_table(uint8_t x[16], const ghash_table_t *t)
{
    uint32_t lo = x[15] & 0xFU;
    uint64_t zh = t->hh[lo];
    uint64_t zl = t->hl[lo];
    for (int i = 15; i >= 0; i--) {
        lo = x[i] & 0xFU;
        const uint32_t hi = (x[i] >> 4) & 0xFU;
        uint32_t rem;
        if (i != 15) {
            rem = (uint32_t)(zl & 0xFU);
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4) ^ ((uint64_t)s_ghash_last4[rem] << 48);
            zh ^= t->hh[lo];
            zl ^= t->hl[lo];
        }
        rem = (uint32_t)(zl & 0xFU);
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4) ^ ((uint64_t)s_ghash_last4[rem] << 48);
        zh ^= t->hh[hi];
        zl ^= t->hl[hi];
    }
    for (int i = 0; i < 8; i++) {
        x[i] = (uint8_t)(zh >> (56 - 8 * i));
        x[8 + i] = (uint8_t)(zl >> (56 - 8 * i));
    }
}

/* ---- AES-256-ECB over many blocks in ONE CRYP run (2026-09-29) ----
 * aes256_ecb_block() re-initialises CRYP (key load) for every 16-byte block. The GCM keystream blocks are
 * independent, so up to GCM_ECB_BATCH counter blocks are encrypted per HAL_CRYP_Encrypt() call in ECB mode --
 * always a multiple of 16 bytes, which this hardware handles correctly (see above). Checked once against
 * aes256_ecb_block() on first use; on any mismatch the per-block path is used from then on. */
#define GCM_ECB_BATCH 32U
static uint32_t s_ecb_in[GCM_ECB_BATCH * 4U];
static uint32_t s_ecb_out[GCM_ECB_BATCH * 4U];
static int8_t s_ecb_batch_ok = -1; /* -1 = not checked yet, 0 = use per-block, 1 = batch works */

static platform_status_t aes256_ecb_batch(const uint32_t key_words[8], uint32_t nblocks)
{
    hcryp.Init.DataType        = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize         = CRYP_KEYSIZE_256B;
    hcryp.Init.pKey            = (uint32_t *)(void *)(uintptr_t)(const void *)key_words;
    hcryp.Init.pInitVect       = NULL;
    hcryp.Init.Algorithm       = CRYP_AES_ECB;
    hcryp.Init.DataWidthUnit   = CRYP_DATAWIDTHUNIT_WORD;
    hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
    hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;

    (void)gcm_reload_clock_if_needed();
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    ((CRYP_TypeDef *)hcryp.Instance)->CR |= CRYP_CR_FFLUSH;
    if (HAL_CRYP_Encrypt(&hcryp, s_ecb_in, (uint16_t)(nblocks * 4U), s_ecb_out, 100U) != HAL_OK) {
        return PLATFORM_ERROR;
    }
    return PLATFORM_OK;
}

/** Byte `i` (0..15) of output block `b` of the last aes256_ecb_batch() -- DOUT words come back byte-reversed,
 *  same extraction as aes256_ecb_block(). */
static inline uint8_t ecb_out_byte(uint32_t b, uint32_t i)
{
    return (uint8_t)(s_ecb_out[b * 4U + i / 4U] >> (8U * (i % 4U)));
}

/** Builds the AES-CTR counter block for GCM payload block `block_index` (0-based): 96-bit nonce ||
 *  32-bit big-endian counter, counter = 2 + block_index (block 0 uses counter=2 -- J0's counter=1 is
 *  reserved for the tag mask, see aes256_gcm_run()'s doc comment). */
static void gcm_counter_block(const uint8_t nonce[12], uint32_t block_index, uint8_t out[16])
{
    memcpy(out, nonce, 12U);
    uint32_t counter = 2U + block_index;
    out[12] = (uint8_t)(counter >> 24);
    out[13] = (uint8_t)(counter >> 16);
    out[14] = (uint8_t)(counter >> 8);
    out[15] = (uint8_t)(counter);
}

/** Shared encrypt/decrypt core: `src` is the plaintext (encrypt) or ciphertext (decrypt) input, `dst`
 *  the opposite; GHASH always accumulates over whichever buffer holds the CIPHERTEXT bytes
 *  (`encrypting ? dst : src`), per GCM's definition -- this is the only difference between the two
 *  directions once the AES-CTR keystream math is factored out. */
static platform_status_t aes256_gcm_run(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *src,
                                         uint32_t len, uint8_t *dst, uint8_t tag_io[16], bool encrypting)
{
    uint32_t key_words[8];
    for (size_t i = 0; i < 8U; i++) {
        key_words[i] = __REV(((const uint32_t *)(const void *)key)[i]);
    }

    static const uint8_t zero_block[16] = {0};
    uint8_t h_subkey[16];
    if (aes256_ecb_block(key_words, zero_block, h_subkey) != PLATFORM_OK) {
        return PLATFORM_ERROR;
    }

    uint8_t j0[16];
    memcpy(j0, nonce, 12U);
    j0[12] = 0U; j0[13] = 0U; j0[14] = 0U; j0[15] = 1U;
    uint8_t tag_mask[16];
    if (aes256_ecb_block(key_words, j0, tag_mask) != PLATFORM_OK) {
        return PLATFORM_ERROR;
    }

    static ghash_table_t s_gt; /* static: 256 B, not on the stack; wiped below */
    ghash_table_init(&s_gt, h_subkey);

    if (s_ecb_batch_ok < 0) { /* first use: the batch path must match the proven per-block path */
        uint8_t ref[16];
        uint8_t blk[16];
        gcm_counter_block(nonce, 0U, blk);
        memcpy(&s_ecb_in[0], blk, 16U);
        gcm_counter_block(nonce, 1U, blk);
        memcpy(&s_ecb_in[4], blk, 16U);
        int8_t ok = (aes256_ecb_batch(key_words, 2U) == PLATFORM_OK) ? 1 : 0;
        uint32_t saved[8];
        memcpy(saved, s_ecb_out, sizeof(saved));
        for (uint32_t b = 0U; ok != 0 && b < 2U; b++) {
            gcm_counter_block(nonce, b, blk);
            if (aes256_ecb_block(key_words, blk, ref) != PLATFORM_OK) {
                return PLATFORM_ERROR;
            }
            for (uint32_t i = 0U; i < 16U; i++) {
                if ((uint8_t)(saved[b * 4U + i / 4U] >> (8U * (i % 4U))) != ref[i]) {
                    ok = 0;
                }
            }
        }
        memset(saved, 0, sizeof(saved));
        s_ecb_batch_ok = ok;
    }

    uint8_t y[16] = {0};
    const uint32_t num_blocks = (len + 15U) / 16U;
    for (uint32_t first = 0U; first < num_blocks; first += GCM_ECB_BATCH) {
        const uint32_t n = (num_blocks - first < GCM_ECB_BATCH) ? (num_blocks - first) : GCM_ECB_BATCH;
        if (s_ecb_batch_ok > 0) {
            for (uint32_t b = 0U; b < n; b++) {
                gcm_counter_block(nonce, first + b, (uint8_t *)(void *)&s_ecb_in[b * 4U]);
            }
            if (aes256_ecb_batch(key_words, n) != PLATFORM_OK) {
                return PLATFORM_ERROR;
            }
        }
        for (uint32_t b = 0U; b < n; b++) {
            uint8_t keystream[16];
            if (s_ecb_batch_ok > 0) {
                for (uint32_t i = 0U; i < 16U; i++) {
                    keystream[i] = ecb_out_byte(b, i);
                }
            }
            else {
                uint8_t ctr_block[16];
                gcm_counter_block(nonce, first + b, ctr_block);
                if (aes256_ecb_block(key_words, ctr_block, keystream) != PLATFORM_OK) {
                    return PLATFORM_ERROR;
                }
            }

            const uint32_t off = (first + b) * 16U;
            const uint32_t chunk = (len - off < 16U) ? (len - off) : 16U;
            uint8_t cipher_block[16] = {0};

            if (encrypting) {
                for (uint32_t i = 0; i < chunk; i++) {
                    uint8_t c = (uint8_t)(src[off + i] ^ keystream[i]);
                    dst[off + i] = c;
                    cipher_block[i] = c;
                }
            } else {
                memcpy(cipher_block, &src[off], chunk);
                for (uint32_t i = 0; i < chunk; i++) {
                    dst[off + i] = (uint8_t)(src[off + i] ^ keystream[i]);
                }
            }

            for (int j = 0; j < 16; j++) {
                y[j] = (uint8_t)(y[j] ^ cipher_block[j]);
            }
            ghash_mul_table(y, &s_gt);
        }
    }
    memset(s_ecb_out, 0, sizeof(s_ecb_out)); /* keystream */

    /* Final GHASH block: 64-bit AAD bit-length (always 0 -- this file never uses GCM AAD) || 64-bit
     * ciphertext bit-length, big-endian, per NIST SP 800-38D. */
    uint8_t len_block[16] = {0};
    uint64_t bitlen = (uint64_t)len * 8U;
    for (int i = 0; i < 8; i++) {
        len_block[8 + i] = (uint8_t)(bitlen >> (56 - (8 * i)));
    }
    for (int j = 0; j < 16; j++) {
        y[j] = (uint8_t)(y[j] ^ len_block[j]);
    }
    ghash_mul_table(y, &s_gt);
    memset(&s_gt, 0, sizeof(s_gt)); /* derived from the secret H */

    if (encrypting) {
        for (int i = 0; i < 16; i++) {
            tag_io[i] = (uint8_t)(y[i] ^ tag_mask[i]);
        }
        return PLATFORM_OK;
    }

    uint8_t diff = 0U;
    for (int i = 0; i < 16; i++) {
        diff = (uint8_t)(diff | (uint8_t)((y[i] ^ tag_mask[i]) ^ tag_io[i]));
    }
    return (diff == 0U) ? PLATFORM_OK : PLATFORM_ERROR;
}

platform_status_t platform_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *plain,
                                               uint32_t len, uint8_t *cipher_out, uint8_t tag_out[16])
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (key == NULL || nonce == NULL || plain == NULL || cipher_out == NULL || tag_out == NULL || len == 0U ||
        len > 0xFFFFU) {
        return PLATFORM_INVALID_PARAM;
    }
    return aes256_gcm_run(key, nonce, plain, len, cipher_out, tag_out, true);
}

platform_status_t platform_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *cipher,
                                               uint32_t len, const uint8_t tag[16], uint8_t *plain_out)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (key == NULL || nonce == NULL || cipher == NULL || tag == NULL || plain_out == NULL || len == 0U ||
        len > 0xFFFFU) {
        return PLATFORM_INVALID_PARAM;
    }
    uint8_t tag_copy[16];
    memcpy(tag_copy, tag, 16U);
    platform_status_t st = aes256_gcm_run(key, nonce, cipher, len, plain_out, tag_copy, false);
    if (st != PLATFORM_OK) {
        /* aes256_gcm_run() writes plaintext block by block BEFORE the tag is known -- on a tag mismatch (or a
         * hardware error part-way through) never leave unauthenticated plaintext in the caller's buffer. */
        memset(plain_out, 0, len);
    }
    return st;
}
