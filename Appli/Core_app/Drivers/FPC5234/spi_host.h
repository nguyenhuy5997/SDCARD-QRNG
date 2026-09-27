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

#ifndef SPI_HOST_H
#define SPI_HOST_H
#ifdef HOST_IF_SPI
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @brief Init SPI interface to FPC2530.
 */
void spi_host_init(void);

uint32_t spi_host_rx_data_available();

void spi_host_rx_data_clear();

void spi_check_status();

int spi_host_transmit(uint8_t *data, size_t size, uint32_t timeout, int flush);

int spi_host_receive(uint8_t *data, size_t size, uint32_t timeout, int keep_cs_low);
#endif /* HOST_IF_SPI */
#endif /* SPI_HOST_H */
