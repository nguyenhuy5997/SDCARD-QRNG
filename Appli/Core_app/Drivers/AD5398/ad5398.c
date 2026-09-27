/**
 * @file    ad5398.c
 * @brief   AD5398 current-sink DAC driver -- see ad5398.h.
 */
#include "ad5398.h"

#include "board.h"

/* 7-bit address 0001100b, shifted left by 1 as platform_i2c expects. */
#define AD5398_I2C_ADDR        (0x0CU << 1)
#define AD5398_I2C_TIMEOUT_MS  100U

#define AD5398_PD_BIT          0x8000U
#define AD5398_CODE_SHIFT      4U
#define AD5398_CODE_MAX        0x3FFU
#define AD5398_CODE_MASK       (AD5398_CODE_MAX << AD5398_CODE_SHIFT)
#define AD5398_STEPS           1024U

static bool s_ready;

static platform_status_t ad5398_read_reg(uint16_t *value)
{
    uint8_t buf[2];
    platform_status_t st = platform_i2c_master_receive(BOARD_AD5398_I2C, AD5398_I2C_ADDR, buf, sizeof(buf),
                                                       AD5398_I2C_TIMEOUT_MS);
    if (st == PLATFORM_OK) {
        *value = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
    }
    return st;
}

static platform_status_t ad5398_write_reg(uint16_t value)
{
    uint8_t buf[2] = { (uint8_t)(value >> 8), (uint8_t)value };
    return platform_i2c_master_transmit(BOARD_AD5398_I2C, AD5398_I2C_ADDR, buf, sizeof(buf), AD5398_I2C_TIMEOUT_MS);
}

static uint32_t ad5398_code_to_ua(uint16_t reg)
{
    uint32_t code = ((uint32_t)reg & AD5398_CODE_MASK) >> AD5398_CODE_SHIFT;
    return (code * AD5398_FULL_SCALE_UA) / AD5398_STEPS;
}

platform_status_t ad5398_init(void)
{
    if (s_ready) {
        return PLATFORM_OK;
    }
    platform_status_t st = platform_i2c_init(BOARD_AD5398_I2C);
    if (st != PLATFORM_OK) {
        return st;
    }
    /* PD pin is active high. Keep it HIGH (output off) here: init must never switch the sink on by itself -- the V8Y
     * board's QRNG safety lock calls ad5398_init() only to power the chip down. ad5398_set_current_ua() releases the
     * pin when an output current is actually requested. PD only shuts the current sink down; if the chip did not
     * answer I2C while PD is high, init would fail and the output would simply stay off (fail-safe). Not yet checked
     * on hardware -- recheck when the analog block is enabled again. */
    st = platform_gpio_write(BOARD_AD5398_PD_GPIO, true);
    if (st != PLATFORM_OK) {
        return st;
    }
    if (!platform_i2c_is_device_ready(BOARD_AD5398_I2C, AD5398_I2C_ADDR, AD5398_I2C_TIMEOUT_MS)) {
        return PLATFORM_ERROR;
    }
    s_ready = true;
    return PLATFORM_OK;
}

platform_status_t ad5398_set_current_ua(uint32_t current_ua)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    if (current_ua > AD5398_FULL_SCALE_UA) {
        return PLATFORM_INVALID_PARAM;
    }
    /* Nearest step; full scale itself maps to the top code (1023), not to 1024. */
    uint32_t code = (current_ua * AD5398_STEPS + AD5398_FULL_SCALE_UA / 2U) / AD5398_FULL_SCALE_UA;
    if (code > AD5398_CODE_MAX) {
        code = AD5398_CODE_MAX;
    }
    uint16_t reg = (uint16_t)(code << AD5398_CODE_SHIFT); /* PD bit 0: output on */

    /* Release the PD pin too, in case ad5398_power_down() raised it earlier. */
    platform_status_t st = platform_gpio_write(BOARD_AD5398_PD_GPIO, false);
    if (st != PLATFORM_OK) {
        return st;
    }
    st = ad5398_write_reg(reg);
    if (st != PLATFORM_OK) {
        return st;
    }
    uint16_t readback = 0U;
    st = ad5398_read_reg(&readback);
    if (st != PLATFORM_OK) {
        return st;
    }
    return ((readback & (AD5398_PD_BIT | AD5398_CODE_MASK)) == reg) ? PLATFORM_OK : PLATFORM_ERROR;
}

platform_status_t ad5398_get_current_ua(uint32_t *current_ua, bool *enabled)
{
    if (!s_ready) {
        return PLATFORM_ERROR;
    }
    uint16_t reg = 0U;
    platform_status_t st = ad5398_read_reg(&reg);
    if (st != PLATFORM_OK) {
        return st;
    }
    if (current_ua != NULL) {
        *current_ua = ad5398_code_to_ua(reg);
    }
    if (enabled != NULL) {
        *enabled = (reg & AD5398_PD_BIT) == 0U;
    }
    return PLATFORM_OK;
}

platform_status_t ad5398_power_down(void)
{
    platform_status_t st = PLATFORM_OK;
    if (s_ready) {
        uint16_t reg = 0U;
        st = ad5398_read_reg(&reg);
        if (st == PLATFORM_OK) {
            st = ad5398_write_reg((uint16_t)(reg | AD5398_PD_BIT));
        }
    }
    /* Pin as well, so the output is off even if the bus write failed. */
    platform_status_t pin_st = platform_gpio_write(BOARD_AD5398_PD_GPIO, true);
    return (st != PLATFORM_OK) ? st : pin_st;
}
