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
 * @file    fpc_hal.c
 * @brief   Implementation of the fpc_hal API.
 */

/* Fingerprint (FPC2530/FPC5234) stack: compiled only with EVT2_ENABLE_BIOMETRIC=1 (see Core/Src/main.c). */
#if EVT2_ENABLE_BIOMETRIC

#include "fpc_hal.h"

#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include "platform.h"

#include "fpc_api.h"
#include "hal_common.h"
#include "i2c_host.h"
#include "spi_host.h"
#include "uart_debug.h"
#include "uart_host.h"

extern void SystemClock_Config(void);

fpc_result_t fpc_hal_init(void)
{
    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    /* HAL_Init(); */

    /* Configure the system clock */
    /* SystemClock_Config(); */

    /* Configure the System Power */
/*    (void)HAL_PWREx_ConfigSupply(PWR_SMPS_SUPPLY);

    MX_GPIO_Init();

    MX_DCACHE1_Init();
    MX_ICACHE_Init();

    MX_GPDMA1_Init();
*/
    hal_common_init(); /* wires fpc2530_irq_active (and the user button, if
                         * EVT2_DIAGNOSTICS) up to their EXTI interrupts via
                         * platform_gpio_register_exti_callback() */
#if defined(HOST_IF_UART)
    uart_host_init();
    hal_set_if_config(HAL_IF_CONFIG_UART);
#elif defined(HOST_IF_SPI)
    spi_host_init();
    hal_set_if_config(HAL_IF_CONFIG_SPI);
#elif defined(HOST_IF_I2C)
    i2c_host_init();
    hal_set_if_config(HAL_IF_CONFIG_I2C);
#endif
    return FPC_RESULT_OK;
}

fpc_result_t fpc_hal_tx(uint8_t *data, size_t len, uint32_t timeout, int flush)
{
#if defined(HOST_IF_UART)
    int rc = uart_host_transmit(data, len, timeout, flush);
#elif defined(HOST_IF_SPI)
    int rc = spi_host_transmit(data, len, timeout, flush);
#elif defined(HOST_IF_I2C)
    int rc = i2c_host_transmit(data, len, timeout, flush);
#endif
    return rc == 0 ? FPC_RESULT_OK : FPC_RESULT_FAILURE;
}

fpc_result_t fpc_hal_rx(uint8_t *data, size_t len, uint32_t timeout, int keep_cs_low)
{
#if defined(HOST_IF_UART)
    int rc = uart_host_receive(data, len, timeout);
#elif defined(HOST_IF_SPI)
    int rc = spi_host_receive(data, len, timeout, keep_cs_low);
#elif defined(HOST_IF_I2C)
    int rc = i2c_host_receive(data, len, timeout);
#endif
    return rc == 0 ? FPC_RESULT_OK : FPC_RESULT_FAILURE;}

int fpc_hal_data_available(void)
{
#if defined(HOST_IF_UART)
    return uart_host_rx_data_available();
#elif defined(HOST_IF_SPI)
    return spi_host_rx_data_available();
#elif defined(HOST_IF_I2C)
    return i2c_host_rx_data_available();
#endif
}

fpc_result_t fpc_hal_wfi(void)
{
    platform_wait_for_interrupt();
    return FPC_RESULT_OK;
}

void fpc_hal_delay_ms(uint32_t ms)
{
    platform_delay_ms(ms);
}

#if EVT2_DIAGNOSTICS /* otherwise fpc_hal.h turns fpc_sample_logf() into an empty macro */
void fpc_sample_logf(const char *format, ...)
{
    va_list arglist;

    va_start(arglist, format);
    uart_debug_vprintf(format, arglist);
    va_end(arglist);
}
#endif

#endif /* EVT2_ENABLE_BIOMETRIC */
