/**
 * @file    platform_i2c.c
 * @brief   STM32H7xx implementation of the Platform I2C interface.
 *
 * Clock, GPIO (PB8=SCL, PB9=SDA) and HAL_I2C_Init() are done by the
 * CubeMX-generated MX_I2C1_Init() in bsp_h7s3.c (EVT2: Src/main.c), called from main()
 * before any application code runs. This file only implements the
 * runtime business operations (transmit/receive/mem access) on the
 * `hi2c1` handle that generated code already initialized -- it never
 * calls HAL_I2C_Init()/HAL_I2C_DeInit() itself (HAL_I2C_DeInit() would
 * run the generated HAL_I2C_MspDeInit() and disable the clock/GPIO out
 * from under every other user of this bus).
 */
#include "platform.h"
#include "bsp_hal.h"

extern I2C_HandleTypeDef hi2c1;

static I2C_HandleTypeDef *const s_i2c_handle[PLATFORM_I2C_COUNT] = {
    [PLATFORM_I2C_1] = &hi2c1,
};

static bool s_i2c_ready[PLATFORM_I2C_COUNT];

static bool i2c_id_valid(platform_i2c_id_t id)
{
    return id < PLATFORM_I2C_COUNT && s_i2c_ready[id];
}

static platform_status_t hal_to_platform_status(HAL_StatusTypeDef status)
{
    switch (status) {
    case HAL_OK:      return PLATFORM_OK;
    case HAL_BUSY:    return PLATFORM_BUSY;
    case HAL_TIMEOUT: return PLATFORM_TIMEOUT;
    case HAL_ERROR:
    default:          return PLATFORM_ERROR;
    }
}

/* Trace hook (weak, no-op here): event 0 = transmit, 1 = receive (arg = address << 16 | length), 2 = done
 * (arg = platform_status_t). Core_app/App/app_trace.c overrides it for the post-mortem trace. */
__attribute__((weak)) void platform_i2c_trace_hook(uint32_t event, uint32_t arg)
{
    (void)event;
    (void)arg;
}

platform_status_t platform_i2c_init(platform_i2c_id_t id)
{
    if (id >= PLATFORM_I2C_COUNT) {
        return PLATFORM_INVALID_PARAM;
    }
    if (s_i2c_ready[id]) {
        return PLATFORM_OK;
    }
    if (HAL_I2C_GetState(s_i2c_handle[id]) == HAL_I2C_STATE_RESET) {
        /* MX_I2C1_Init() has not run yet -- this is a call-order bug in
         * the caller, not something Platform can fix by initializing
         * the bus itself. */
        return PLATFORM_ERROR;
    }

    s_i2c_ready[id] = true;
    return PLATFORM_OK;
}

platform_status_t platform_i2c_deinit(platform_i2c_id_t id)
{
    if (!i2c_id_valid(id)) {
        return PLATFORM_INVALID_PARAM;
    }

    s_i2c_ready[id] = false;
    return PLATFORM_OK;
}

platform_status_t platform_i2c_master_transmit(platform_i2c_id_t id, uint16_t dev_addr,
                                                const uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!i2c_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    platform_i2c_trace_hook(0U, ((uint32_t)dev_addr << 16) | (uint32_t)len);
    platform_status_t st = hal_to_platform_status(HAL_I2C_Master_Transmit(s_i2c_handle[id], dev_addr,
                                                            (uint8_t *)data, len, timeout_ms));
    platform_i2c_trace_hook(2U, (uint32_t)st);
    return st;
}

platform_status_t platform_i2c_master_receive(platform_i2c_id_t id, uint16_t dev_addr,
                                               uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!i2c_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    platform_i2c_trace_hook(1U, ((uint32_t)dev_addr << 16) | (uint32_t)len);
    platform_status_t st = hal_to_platform_status(HAL_I2C_Master_Receive(s_i2c_handle[id], dev_addr,
                                                           data, len, timeout_ms));
    platform_i2c_trace_hook(2U, (uint32_t)st);
    return st;
}

platform_status_t platform_i2c_mem_write(platform_i2c_id_t id, uint16_t dev_addr, uint16_t mem_addr,
                                          platform_i2c_memadd_size_t mem_addr_size,
                                          const uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!i2c_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    uint16_t hal_size = (mem_addr_size == PLATFORM_I2C_MEMADD_SIZE_16BIT)
                             ? I2C_MEMADD_SIZE_16BIT : I2C_MEMADD_SIZE_8BIT;

    return hal_to_platform_status(HAL_I2C_Mem_Write(s_i2c_handle[id], dev_addr, mem_addr,
                                                      hal_size, (uint8_t *)data, len, timeout_ms));
}

platform_status_t platform_i2c_mem_read(platform_i2c_id_t id, uint16_t dev_addr, uint16_t mem_addr,
                                         platform_i2c_memadd_size_t mem_addr_size,
                                         uint8_t *data, uint16_t len, uint32_t timeout_ms)
{
    if (!i2c_id_valid(id) || data == NULL) {
        return PLATFORM_INVALID_PARAM;
    }

    uint16_t hal_size = (mem_addr_size == PLATFORM_I2C_MEMADD_SIZE_16BIT)
                             ? I2C_MEMADD_SIZE_16BIT : I2C_MEMADD_SIZE_8BIT;

    return hal_to_platform_status(HAL_I2C_Mem_Read(s_i2c_handle[id], dev_addr, mem_addr,
                                                     hal_size, data, len, timeout_ms));
}

bool platform_i2c_is_device_ready(platform_i2c_id_t id, uint16_t dev_addr, uint32_t timeout_ms)
{
    if (!i2c_id_valid(id)) {
        return false;
    }

    return HAL_I2C_IsDeviceReady(s_i2c_handle[id], dev_addr, 2, timeout_ms) == HAL_OK;
}
