/**
 * @file    aes_cbc_mac.c
 * @brief   AES-128 CBC-MAC extractor.
 *
 * See aes_cbc_mac.h's doc comment -- hardware CRYP path only, through
 * Core_app/Platform/platform_crypto.h.
 */
#include "aes_cbc_mac.h"
#include "platform.h"

static const uint8_t *s_key;

void aes_cbc_mac_init(void)
{
    /* Nothing to do -- platform_aes128_cbc_mac() re-inits the CRYP
     * peripheral with the current key on every call. */
}

void aes_cbc_mac_set_key(const uint8_t key[QRNG_AES_BLOCK_SIZE])
{
    s_key = key;
}

bool aes_cbc_mac_extractor(const uint8_t *input, uint32_t inLen, uint8_t output[QRNG_AES_BLOCK_SIZE])
{
    return platform_aes128_cbc_mac(s_key, input, inLen, output) == PLATFORM_OK;
}

bool aes_cbc_mac_extractor_batch(const uint8_t *input, uint32_t block_len, uint32_t num_blocks, uint8_t *output)
{
    return platform_aes128_cbc_mac_batch(s_key, input, block_len, num_blocks, output) == PLATFORM_OK;
}
