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
#if defined(HOST_IF_I2C)
/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "i2c_host.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "bsp_hal.h"

extern I2C_HandleTypeDef hi2c1;
#define hi2c_fpc2530 hi2c1

#define FPC2530_I2C_ADDRESS (0x24 << 1)
#define MAX_HOST_PACKET_SIZE_I2C 2048

extern volatile bool fpc2530_irq_active;
volatile bool fpc2530_i2c_rx_done = false;

void i2c_host_init(void)
{
    /* MX_I2C1_Init(); */
}

uint32_t i2c_host_rx_data_available()
{
    uint32_t active = fpc2530_irq_active;
    fpc2530_irq_active = false;
    return active;
}

int i2c_host_transmit(uint8_t *data, size_t size, uint32_t timeout, int flush)
{
    HAL_StatusTypeDef status = HAL_ERROR;
    uint32_t total_size = size + 2; /* Add 2 byte size before data */
    uint8_t *size_and_data = malloc(total_size);

    if (size_and_data == NULL) {
        status = HAL_ERROR;
        goto exit;

    }

    HAL_Delay(1);

    size_and_data[0] = size & 0xff;
    size_and_data[1] = (size >> 8) & 0xff;
    memcpy(size_and_data + 2, data, size);
    /* Send size and data */
    status = HAL_I2C_Master_Transmit(&hi2c_fpc2530, FPC2530_I2C_ADDRESS, size_and_data,
        total_size, timeout);
    if (status == HAL_ERROR) {
        goto cleanup;
    }

cleanup:
    free(size_and_data);
exit:

    return (status == HAL_OK) ? 0 : -1;
}

static int i2c_read(uint8_t addr, uint8_t *data, uint16_t *size, uint32_t timeout)
{
    HAL_StatusTypeDef status = HAL_ERROR;

    /* Read size of transfer */
    fpc2530_i2c_rx_done = false;
    status = HAL_I2C_Master_Seq_Receive_IT(&hi2c_fpc2530, addr, (uint8_t*)size, 2, I2C_NEXT_FRAME);
    if (status != HAL_OK) {
        goto exit;
    }

    while(!fpc2530_i2c_rx_done) {}

    fpc2530_i2c_rx_done = false;
    status = HAL_I2C_Master_Seq_Receive_IT(&hi2c_fpc2530, addr, data, *size, I2C_LAST_FRAME);
    if (status != HAL_OK) {
        goto exit;
    }

    while(!fpc2530_i2c_rx_done) {}

exit:
    return status;
}


int i2c_host_receive(uint8_t *data, size_t size, uint32_t timeout)
{
    HAL_StatusTypeDef status = HAL_ERROR;
    static uint8_t rx_buffer[MAX_HOST_PACKET_SIZE_I2C];
    static uint16_t rx_buf_size = 0;
    static uint16_t rx_buf_read_offset = 0;

    if (rx_buf_size == 0) {
        // Read from device
        status = i2c_read(FPC2530_I2C_ADDRESS, rx_buffer, &rx_buf_size, timeout);
        rx_buf_read_offset = 0;
    }
    if (rx_buf_size >= size) {
        memcpy(data, rx_buffer + rx_buf_read_offset, size);
        rx_buf_read_offset += size;
        rx_buf_size -= size;
        status = HAL_OK;
    }
    else {
        //printf("Missaligned size read from rx buffer (line=%d)\n",  __LINE__);
    }

    return (status == HAL_OK) ? 0 : -1;
}

void HAL_I2C_MasterRxCpltCallback(I2C_HandleTypeDef *hi2c)
{
    fpc2530_i2c_rx_done = true;
}
#endif /* HOST_IF_I2C */

#endif /* EVT2_ENABLE_BIOMETRIC */
