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

#ifndef I2C_HOST_H
#define I2C_HOST_H

#if defined(HOST_IF_I2C)
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


/**
 * @brief Init I2C interface to FPC2530.
 */
void i2c_host_init(void);

uint32_t i2c_host_rx_data_available();

void i2c_host_rx_data_clear();

void i2c_check_status();

int i2c_host_transmit(uint8_t *data, size_t size, uint32_t timeout, int flush);

int i2c_host_receive(uint8_t *data, size_t size, uint32_t timeout);
#endif /* HOST_IF_I2C */
#endif /* I2C_HOST_H */
