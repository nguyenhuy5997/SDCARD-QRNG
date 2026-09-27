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
 * @file    fpc_hal_crypto.c
 * @brief   Implementation of the crypto part of the HAL API.
 */

/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bsp_hal.h"

#include "fpc_api.h"
#include "fpc_hal.h"

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

#define FPC_AES128_KEY_SIZE         16
#define FPC_AES256_KEY_SIZE         32

#define AES_KEY_SIZE                FPC_AES256_KEY_SIZE

/** Important TODO: Replace these test keys with your actual keys */

/** AES128 */
uint8_t test_key_16[16] = { 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26 };

/** AES256 */
uint8_t test_key_32[32] = { 31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,
                            71,72,73,74,75,76,77,78,79,50,81,82,83,84,85,86 };


/* ============= General ============= */

fpc_result_t fpc_hal_crypto_gen_random(uint8_t *data, uint32_t size)
{
    fpc_result_t result = FPC_RESULT_FAILURE;
    RNG_HandleTypeDef hrng = {0};

    // Size must be 4 byte aligned
    if (!data || ((size & 3) != 0) || size == 0) {
        return FPC_RESULT_INVALID_PARAM;
    }

    hrng.Instance = RNG;
    if (HAL_RNG_Init(&hrng) != HAL_OK) {
        return FPC_RESULT_FAILURE;
    }

    while(size) {
        result = FPC_RESULT_FAILURE;
        if (HAL_RNG_GenerateRandomNumber(&hrng, (uint32_t*)data) == HAL_OK) {
            result = FPC_RESULT_OK;
        }
        else {
            result = FPC_RESULT_FAILURE;
            break;
        }
        data += 4;
        size -=4;
    }

    if (HAL_RNG_DeInit(&hrng) != HAL_OK) {
        return FPC_RESULT_FAILURE;;
    }

    return result;
}

fpc_result_t fpc_hal_crypto_get_aes_key(uint8_t **key, uint32_t *len)
{
    if (!key || !len) {
        return FPC_RESULT_INVALID_PARAM;
    }

    if (AES_KEY_SIZE == FPC_AES128_KEY_SIZE) {
        *key = test_key_16;
        *len = sizeof(test_key_16);
    }
    else {
        *key = test_key_32;
        *len = sizeof(test_key_32);
    }

    return FPC_RESULT_OK;
}


/* ============= AES GCM ============= */

static void swap_endian_to_buffer(uint8_t *to, const uint8_t *from, uint16_t len)
{
    for (int i=0; i<len; i+=4) {
        *((uint32_t *)&to[i]) = __REV(*((uint32_t *)&from[i]));
    }
}


static fpc_result_t init_aes_gcm(CRYP_HandleTypeDef *aes_gcm,
        const uint8_t *aes_key, uint32_t aes_key_len,
        const uint8_t *aad, uint32_t aad_len,
        const uint8_t *iv)
{
    HAL_StatusTypeDef status;

    uint32_t st_key_len = CRYP_KEYSIZE_128B;

    switch(aes_key_len) {
        case FPC_AES128_KEY_SIZE:
            st_key_len = CRYP_KEYSIZE_128B;
            break;
        case FPC_AES256_KEY_SIZE:
            st_key_len = CRYP_KEYSIZE_256B;
            break;
        default:
            return FPC_RESULT_INVALID_PARAM;
            break;
    }

    memset(aes_gcm, 0, sizeof(CRYP_HandleTypeDef));

    aes_gcm->Instance = CRYP;
    aes_gcm->Init.DataType = CRYP_BYTE_SWAP;
    aes_gcm->Init.KeySize = st_key_len;
    aes_gcm->Init.pKey = (uint32_t*)aes_key;
    aes_gcm->Init.pInitVect = (uint32_t*)iv;
    aes_gcm->Init.Algorithm = CRYP_AES_GCM;
    aes_gcm->Init.Header = (uint32_t*)aad;
    aes_gcm->Init.HeaderSize = aad_len;
    aes_gcm->Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
    aes_gcm->Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_BYTE;
    aes_gcm->Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ONCE;


    status = HAL_CRYP_Init(aes_gcm);
    if (status != HAL_OK) {
        return FPC_RESULT_FAILURE;
    }

    return FPC_RESULT_OK;
}


fpc_result_t fpc_hal_crypto_encrypt_aes_gcm(
    const uint8_t *iv_12b,
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *pt_in, uint32_t pt_len,
    uint8_t *ct_out,
    uint8_t *gmac_tag)
{
    fpc_result_t result = FPC_RESULT_FAILURE;
    HAL_StatusTypeDef status;
    CRYP_HandleTypeDef aes_gcm;
    uint8_t iv[FPC_AES_GCM_IV_SIZE+4];
    uint8_t key[FPC_AES256_KEY_SIZE];

    uint8_t *aes_key;
    uint32_t aes_key_len;

    if (!iv_12b || !pt_in || !ct_out || !gmac_tag) {
        return FPC_RESULT_INVALID_PARAM;
    }

    result = fpc_hal_crypto_get_aes_key(&aes_key, &aes_key_len);
    if (result != FPC_RESULT_OK) {
        return FPC_RESULT_FAILURE;
    }

    // STM notes: CRYP_BYTE_SWAP does not apply for iv.
    swap_endian_to_buffer(iv, iv_12b, FPC_AES_GCM_IV_SIZE);

    // STM notes: AES GCM iv is 96 bits, but ST input field is 128 bits.
    // Must be padded with exactly this:
    iv[12] = 0x02;
    iv[13] = 0x00;
    iv[14] = 0x00;
    iv[15] = 0x00;

    // STM notes: CRYP_BYTE_SWAP does not apply for key.
    swap_endian_to_buffer(key, aes_key, aes_key_len);

    result = init_aes_gcm(&aes_gcm, key, aes_key_len, aad, aad_len, iv);
    if (result != FPC_RESULT_OK) {
        goto exit;
    }

    while (pt_len > 0) {

        const uint8_t *data_in_p = pt_in;
        uint8_t *data_out_p = ct_out;

        uint8_t dummy_in[16];
        uint8_t dummy_out[16];

        uint16_t chunk_size = min(pt_len, 0xFFF0) & ~0x0F;

        /* Check if there is any remaining data that is not 16-byte aligned */
        if (chunk_size == 0 && pt_len > 0 && pt_len < 16) {
            // Must move data to separate buffers, otherwise ST will do buffer overrun.
            memset(dummy_in, 0, sizeof(dummy_in));
            memcpy(dummy_in, data_in_p, pt_len);

            data_in_p = dummy_in;
            data_out_p = dummy_out;

            chunk_size = pt_len;
        }

        status = HAL_CRYP_Encrypt(&aes_gcm, (uint32_t*)data_in_p, chunk_size,
                (uint32_t*)data_out_p, 2000);

        if (pt_len > 0 && pt_len < 16) {
            // Copy data to ct_out
            memcpy(ct_out, data_out_p, pt_len);
        }

        if (status != HAL_OK) {
            goto exit;
        }

        pt_in += chunk_size;
        ct_out += chunk_size;
        pt_len -= chunk_size;
    }

    status = HAL_CRYPEx_AESGCM_GenerateAuthTAG(&aes_gcm, (uint32_t*)gmac_tag, 2000);
    if (status != HAL_OK) {
        goto exit;
    }

    result = FPC_RESULT_OK;

exit:
    memset(key, 0, FPC_AES256_KEY_SIZE);

    status = HAL_CRYP_DeInit(&aes_gcm);
    if (status != HAL_OK) {
        goto exit;
    }

    return result;
}


fpc_result_t fpc_hal_crypto_decrypt_and_verify_aes_gcm(
    const uint8_t *iv_12b,
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *ct_in, uint32_t ct_len,
    uint8_t *pt_out,
    const uint8_t *gmac_tag,
    uint32_t *gmac_validation)
{
    fpc_result_t result = FPC_RESULT_FAILURE;
    HAL_StatusTypeDef status;
    CRYP_HandleTypeDef aes_gcm;
    uint8_t iv[FPC_AES_GCM_IV_SIZE+4];
    uint8_t gmac_new[FPC_AES_GCM_TAG_SIZE];
    uint8_t key[FPC_AES256_KEY_SIZE];

    uint32_t diff = 0;

    uint8_t *aes_key;
    uint32_t aes_key_len;

    if (!iv_12b || !ct_in || !pt_out || !gmac_tag || !gmac_validation) {
        return FPC_RESULT_INVALID_PARAM;
    }

    *gmac_validation = 0;

    result = fpc_hal_crypto_get_aes_key(&aes_key, &aes_key_len);
    if (result != FPC_RESULT_OK) {
        return FPC_RESULT_FAILURE;
    }

    // STM notes: CRYP_BYTE_SWAP does not apply for iv.
    swap_endian_to_buffer(iv, iv_12b, FPC_AES_GCM_IV_SIZE);

    // STM notes: AES GCM iv is 96 bits, but ST input field is 128 bits.
    // Must be padded with exactly this:
    iv[12] = 0x02;
    iv[13] = 0x00;
    iv[14] = 0x00;
    iv[15] = 0x00;

    // STM notes: CRYP_BYTE_SWAP does not apply for key.
    swap_endian_to_buffer(key, aes_key, aes_key_len);

    result = init_aes_gcm(&aes_gcm, key, aes_key_len, aad, aad_len, iv);
    if (result != FPC_RESULT_OK) {
        goto exit;
    }

    while (ct_len > 0) {

        const uint8_t *data_in_p = ct_in;
        uint8_t *data_out_p = pt_out;

        uint8_t dummy_in[16];
        uint8_t dummy_out[16];

        uint16_t chunk_size = min(ct_len, 0xFFF0) & ~0x0F;

        /* Check if there is any remaining data that is not 16-byte aligned */
        if (chunk_size == 0 && ct_len > 0 && ct_len < 16) {
            // Must move data to separate buffers, otherwise ST will do buffer overrun.
            memset(dummy_in, 0, sizeof(dummy_in));
            memcpy(dummy_in, data_in_p, ct_len);

            data_in_p = dummy_in;
            data_out_p = dummy_out;

            chunk_size = ct_len;
        }

        status = HAL_CRYP_Decrypt(&aes_gcm, (uint32_t*)data_in_p, chunk_size,
                (uint32_t*)data_out_p, 2000);

        if (status != HAL_OK) {
            goto exit;
        }

        if (chunk_size > 0 && chunk_size < 16) {
            // Copy data to pt_out
            memcpy(pt_out, data_out_p, chunk_size);
        }

        ct_in += chunk_size;
        pt_out += chunk_size;
        ct_len -= chunk_size;
    }

    status = HAL_CRYPEx_AESGCM_GenerateAuthTAG(&aes_gcm, (uint32_t*)gmac_new, 2000);
    if (status != HAL_OK) {
        goto exit;
    }

    for (int i=0; i<FPC_AES_GCM_TAG_SIZE; i++) {
        diff += (gmac_new[i] != gmac_tag[i]);
    }

    if (diff == 0) {
        result = FPC_RESULT_OK;
    }
    else {
        result = FPC_RESULT_FAILURE;
    }

exit:

    memset(key, 0, FPC_AES256_KEY_SIZE);

    status = HAL_CRYP_DeInit(&aes_gcm);
    if (status != HAL_OK) {
        result = FPC_RESULT_FAILURE;
    }

    if (diff == 0 && result == FPC_RESULT_OK) {
        *gmac_validation = FPC_GMAC_VALID;
    }

    return result;
}

#endif /* EVT2_ENABLE_BIOMETRIC */
