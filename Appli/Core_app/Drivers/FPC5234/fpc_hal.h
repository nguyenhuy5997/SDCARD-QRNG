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
 *
 * The function prototypes in this file shall be implemented on the target
 * platform.
 *
 */

/**
 * @file    fpc_hal.h
 * @brief   HAL definitions for SDK example
 *
 * The function prototypes in this file shall be implemented on the target
 * platform.
 *
 */

#ifndef FPC_HAL_H_
#define FPC_HAL_H_

#include <stddef.h> /* size_t, used below -- used to arrive transitively
                     * through fpc_api.h's now-removed main.h include; see
                     * that header's comment. */
#include "fpc_api.h"
/**
 * @brief Debug log printouts follow the project-wide EVT2_DIAGNOSTICS switch (see Core/Src/main.c).
*/
#if EVT2_DIAGNOSTICS
/**
 * @brief Debug Log function. Printf style
 */
void fpc_sample_logf(const char *format, ...);
#else
/**
 * @brief Debug Log function when logging is disabled => Void.
 */
#define fpc_sample_logf(...)
#endif


/**
 * @brief HAL Initialization function.
 *
 * This function is called from the fpc_host_sample_init function. If the HAL
 * initialization is already taken care of elsewhere, this function can be made
 * with an empty body, returning FPC_RESULT_OK.
 *
 * @return Result Code
 */
fpc_result_t fpc_hal_init(void);


/**
 * @brief Data Transmit function.
 *
 * The data buffer is allowed to be overwritten by the implementation if that
 * is feasable.
 *
 * @param data Buffer to transmit data from.
 * @param len Length of buffer to transfer
 * @param timeout Timeout value in milliseconds.
 * @param flush Set to 1 to flush data to host (needed for SPI transfers).
 *
 * @return Result Code
 */
fpc_result_t fpc_hal_tx(uint8_t *data, size_t len, uint32_t timeout, int flush);


/**
 * @brief Data Receive function.
 *
 * Sending NULL/0 as data and len will do a CS restore.
 *
 * @param data buffer to receive data to.
 * @param len length of buffer to transfer
 * @param timeout timout value in ms.
 * @param keep_cs_low Set to 1 to keep chip select pin low (needed for SPI transfers).
 *
 * @return Result Code
 */
fpc_result_t fpc_hal_rx(uint8_t *data, size_t len, uint32_t timeout, int keep_cs_low);


/**
 * @brief Check if the FPS Module has its IRQ signal active or data in rx buffer
 *
 * Active IRQ means Data Available on the FPS Module.
 *
 * @return non-zero if IRQ is high. Zero otherwise.
 */
int fpc_hal_data_available(void);


/**
 * @brief Wait For Interrupt
 *
 * This function is meant to be blocking until there is a system interrupt,
 * including the FPS Module interrupt.
 *
 * @return Result Code
 */
fpc_result_t fpc_hal_wfi(void);


/**
 * @brief Blocking wait function
 *
 * @param ms Time in milliseconds to wait
 */
void fpc_hal_delay_ms(uint32_t ms);


/** Crypto section */

#define FPC_GMAC_VALID              0x21e0f4a6


/**
 * @brief Generate random byte array.
 *
 * @param data Buffer to be filled with random data.
 * @param size Number of bytes to be filled in data buffer
 * @return ::fpc_result_t
 */
fpc_result_t fpc_hal_crypto_gen_random(uint8_t *data, uint32_t size);


/**
 * @brief Get the AES key.
 *
 * This function is for sample code purposes.
 *
 * @param key pointer to the key buffer.
 * @param len length of the key buffer (16 or 32).
 * @return ::fpc_result_t
 */
fpc_result_t fpc_hal_crypto_get_aes_key(uint8_t **key, uint32_t *len);


/**
 * @brief Performs AES GCM encryption.
 *
 * @param iv_12b IV, 12 bytes of random data.
 * @param aad Additional authenticated data (header info). Optional.
 * @param aad_len Length in bytes of aad. Any length fine.
 * @param pt_in Plain Text Input buffer
 * @param pt_len Plain Text Input buffer length, in bytes.
 * @param ct_out Cipher Text output buffer, Must be at least pt_len
 * @param gmac_tag GMAC tag. OUTPUT. Must be a 16-byte buffer.
 * @return ::fpc_result_t
 */
fpc_result_t fpc_hal_crypto_encrypt_aes_gcm(
    const uint8_t *iv_12b,
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *pt_in, uint32_t pt_len,
    uint8_t *ct_out,
    uint8_t *gmac_tag);


/**
 * @brief Performs AES GCM decryption and GMAC validation.
 *
 * @param iv_12b IV, 12 bytes. Same as used in encryption
 * @param aad Additional authenticated data (header info)
 * @param aad_len Length in bytes of aad
 * @param ct_in Cipher Text input buffer
 * @param ct_len Cipher Text input buffer length.
 * @param pt_out Plain Text output buffer. Must be at least ct_len.
 * @param gmac_tag GMAC tag. INPUT. Must be a 16-byte buffer.
 * @param gmac_validation Output. If validated successful => FPC_GMAC_VALID.
 * @return ::fpc_result_t
 */
fpc_result_t fpc_hal_crypto_decrypt_and_verify_aes_gcm(
    const uint8_t *iv_12b,
    const uint8_t *aad, uint32_t aad_len,
    const uint8_t *ct_in, uint32_t ct_len,
    uint8_t *pt_out,
    const uint8_t *gmac_tag,
    uint32_t *gmac_validation);

#endif /* FPC_HAL_H_ */
