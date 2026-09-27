#include "plug_and_trust_stm32_config.h"
#include "i2c_a7.h"

static uint16_t pnt_stm32_normalize_address(unsigned char address)
{
    if (address == PLUG_AND_TRUST_STM32_I2C_ADDRESS_7BIT) {
        return (uint16_t)(address << 1);
    }
    return address;
}

static i2c_error_t pnt_stm32_map_status(platform_status_t status)
{
    switch (status) {
    case PLATFORM_OK:      return I2C_OK;
    case PLATFORM_BUSY:    return I2C_BUSY;
    case PLATFORM_TIMEOUT: return I2C_TIME_OUT;
    default:                return I2C_FAILED;
    }
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    (void)pDevName;
    if (conn_ctx == NULL) {
        return I2C_FAILED;
    }

    if (platform_i2c_init(BOARD_SE052_I2C) != PLATFORM_OK) {
        return I2C_FAILED;
    }

    /* The Platform I2C API is addressed by bus id, not by a handle
     * pointer, so any non-NULL sentinel satisfies callers that only
     * check conn_ctx for success. */
    *conn_ctx = (void *)1;
    return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode)
{
    (void)conn_ctx;
    (void)mode;
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr,
    unsigned char *pTx, unsigned short txLen)
{
    if (conn_ctx == NULL || pTx == NULL || txLen == 0U || bus != I2C_BUS_0) {
        return I2C_FAILED;
    }

    return pnt_stm32_map_status(platform_i2c_master_transmit(
        BOARD_SE052_I2C,
        pnt_stm32_normalize_address(addr),
        pTx,
        txLen,
        PLUG_AND_TRUST_STM32_I2C_TIMEOUT_MS));
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr,
    unsigned char *pRx, unsigned short rxLen)
{
    if (conn_ctx == NULL || pRx == NULL || rxLen == 0U || bus != I2C_BUS_0) {
        return I2C_FAILED;
    }

    return pnt_stm32_map_status(platform_i2c_master_receive(
        BOARD_SE052_I2C,
        pnt_stm32_normalize_address(addr),
        pRx,
        rxLen,
        PLUG_AND_TRUST_STM32_I2C_TIMEOUT_MS));
}
