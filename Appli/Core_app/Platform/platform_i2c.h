/**
 * @file    platform_i2c.h
 * @brief   MCU-agnostic I2C (master) interface of the Platform HAL.
 *
 * Bus timing/clock/pin configuration is the code generator's job (e.g.
 * STM32CubeMX's MX_I2C1_Init() in main.c) and is not part of this API.
 * platform_i2c_init() only attaches to a bus that code already brought up.
 */
#ifndef PLATFORM_I2C_H
#define PLATFORM_I2C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "platform.h"

/** Logical I2C instances exposed by the board. */
typedef enum {
    PLATFORM_I2C_1 = 0,
    PLATFORM_I2C_COUNT,
} platform_i2c_id_t;

/** Width of the internal register/memory address used by *_mem_* calls. */
typedef enum {
    PLATFORM_I2C_MEMADD_SIZE_8BIT = 1,
    PLATFORM_I2C_MEMADD_SIZE_16BIT = 2,
} platform_i2c_memadd_size_t;

/** Attach to a bus already brought up by generated init code. Returns
 *  PLATFORM_ERROR if that init has not run yet. Safe to call more than
 *  once (e.g. from several drivers sharing the bus). */
platform_status_t platform_i2c_init(platform_i2c_id_t id);

/** Detach from the bus. Does not touch clocks/GPIO/HAL peripheral state
 *  -- those stay owned by generated init code, since other users may
 *  still depend on them. */
platform_status_t platform_i2c_deinit(platform_i2c_id_t id);

/** `dev_addr` is the 7-bit device address left-shifted by 1 (as read off a
 *  datasheet timing diagram / typical HAL convention), e.g. 0x50 << 1. */
platform_status_t platform_i2c_master_transmit(platform_i2c_id_t id, uint16_t dev_addr,
                                                const uint8_t *data, uint16_t len, uint32_t timeout_ms);
platform_status_t platform_i2c_master_receive(platform_i2c_id_t id, uint16_t dev_addr,
                                               uint8_t *data, uint16_t len, uint32_t timeout_ms);

/** Read/write a device's internal memory/register map (EEPROM, sensor regs, ...). */
platform_status_t platform_i2c_mem_write(platform_i2c_id_t id, uint16_t dev_addr, uint16_t mem_addr,
                                          platform_i2c_memadd_size_t mem_addr_size,
                                          const uint8_t *data, uint16_t len, uint32_t timeout_ms);
platform_status_t platform_i2c_mem_read(platform_i2c_id_t id, uint16_t dev_addr, uint16_t mem_addr,
                                         platform_i2c_memadd_size_t mem_addr_size,
                                         uint8_t *data, uint16_t len, uint32_t timeout_ms);

/** Probe the bus (ACK polling) to check whether a device answers its address. */
bool platform_i2c_is_device_ready(platform_i2c_id_t id, uint16_t dev_addr, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_I2C_H */
