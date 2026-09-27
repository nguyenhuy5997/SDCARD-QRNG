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

    uint8_t y[16] = {0};
    uint32_t num_blocks = (len + 15U) / 16U;
    for (uint32_t b = 0; b < num_blocks; b++) {
        uint8_t ctr_block[16];
        gcm_counter_block(nonce, b, ctr_block);
        uint8_t keystream[16];
        if (aes256_ecb_block(key_words, ctr_block, keystream) != PLATFORM_OK) {
            return PLATFORM_ERROR;
        }

        uint32_t off = b * 16U;
        uint32_t chunk = (len - off < 16U) ? (len - off) : 16U;
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
        ghash_mul(y, h_subkey);
    }

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
    ghash_mul(y, h_subkey);

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
