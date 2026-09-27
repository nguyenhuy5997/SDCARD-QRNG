/**
 * @file    hmac_sha256.c
 * @brief   HMAC-SHA256 extractor.
 *
 * Ported from D:\Workspace\STM32\vQRNG1.0\Core\Src\hmac_sha256.c,
 * hardware-accelerated path only -- see hmac_sha256.h's doc comment.
 */
#include "hmac_sha256.h"
#include "platform.h"

static const uint8_t *s_key;
static uint32_t s_key_len;

void hmac_sha256_init(void)
{
    /* Nothing to do -- platform_hmac_sha256() re-inits the HASH
     * peripheral with the current key on every call. */
}

void hmac_sha256_set_key(const uint8_t *key, uint32_t keySize)
{
    s_key = key;
    s_key_len = keySize;
}

bool hmac_sha256_extractor(const uint8_t *input, uint32_t inLen, uint8_t output[QRNG_HMAC_BLOCK_SIZE])
{
    return platform_hmac_sha256(s_key, s_key_len, input, inLen, output) == PLATFORM_OK;
}
