/**
 * @file    app_trace.c
 * @brief   Post-mortem trace kept across IWDG/fault resets -- see app_trace.h.
 *
 * Layout of g_app_trace (0x24071800, all 32-bit words, little endian):
 *   +0x00 magic "TRCE"        +0x04 boot_count
 *   +0x08 rsr                 +0x0C bc (id << 24 | arg & 0xFFFFFF)  +0x10 bc_arg  +0x14 prev_bc
 *   +0x18 loop_count          +0x1C tick                            +0x20 usb_irqs +0x24 i2c_ops
 *   +0x28 fault_exc  +0x2C fault_pc  +0x30 fault_lr  +0x34 fault_xpsr  +0x38 fault_cfsr  +0x3C fault_hfsr
 *   +0x40 fault_bfar +0x44 fault_mmfar
 *   +0x48 history[8], 40 bytes each: rsr, last_bc, last_arg, prev_bc, loop_count, tick, usb_irqs, i2c_ops,
 *         fault_pc, fault_cfsr
 *   +0x188 temp_c (int32, deg C)  +0x18C temp_max_c  +0x190 sleep_permille  +0x194 sleep_count  (app_power.c)
 */
#include "app_trace.h"

#if EVT2_TRACE

#include <string.h>

#include "bsp_hal.h"

/* NOLOAD, fixed address inside the non-cacheable DMA window (MPU region 2) -- see the linker script. */
app_trace_t g_app_trace __attribute__((section(".trace_noinit")));

void app_trace_boot(void)
{
    const uint32_t rsr = RCC->RSR;
    SET_BIT(RCC->RSR, RCC_RSR_RMVF); /* clear the flags so the next run sees only its own cause */

    if (g_app_trace.magic != APP_TRACE_MAGIC || (rsr & (RCC_RSR_PORRSTF | RCC_RSR_BORRSTF)) != 0U) {
        /* first run after power-on (RAM content is garbage) */
        memset(&g_app_trace, 0, sizeof(g_app_trace));
        g_app_trace.magic = APP_TRACE_MAGIC;
        g_app_trace.temp_c = APP_TRACE_TEMP_NONE;
        g_app_trace.temp_max_c = APP_TRACE_TEMP_NONE;
    }
    else {
        /* file the run that just ended */
        memmove(&g_app_trace.history[1], &g_app_trace.history[0],
                sizeof(g_app_trace.history[0]) * (APP_TRACE_HISTORY - 1U));
        app_trace_run_t *r = &g_app_trace.history[0];
        r->rsr = g_app_trace.rsr;
        r->last_bc = g_app_trace.bc;
        r->last_arg = g_app_trace.bc_arg;
        r->prev_bc = g_app_trace.prev_bc;
        r->loop_count = g_app_trace.loop_count;
        r->tick = g_app_trace.tick;
        r->usb_irqs = g_app_trace.usb_irqs;
        r->i2c_ops = g_app_trace.i2c_ops;
        r->fault_pc = g_app_trace.fault_pc;
        r->fault_cfsr = g_app_trace.fault_cfsr;
        /* the reset cause of the run that ended is the RSR we see NOW */
        r->rsr = rsr;
    }
    g_app_trace.boot_count++;
    g_app_trace.rsr = rsr;
    g_app_trace.bc = 0U;
    g_app_trace.bc_arg = 0U;
    g_app_trace.prev_bc = 0U;
    g_app_trace.loop_count = 0U;
    g_app_trace.tick = 0U;
    g_app_trace.usb_irqs = 0U;
    g_app_trace.i2c_ops = 0U;
    g_app_trace.fault_exc = 0U;
    g_app_trace.fault_pc = 0U;
    g_app_trace.fault_lr = 0U;
    g_app_trace.fault_xpsr = 0U;
    g_app_trace.fault_cfsr = 0U;
    g_app_trace.fault_hfsr = 0U;
    g_app_trace.fault_bfar = 0U;
    g_app_trace.fault_mmfar = 0U;

    /* Keep the IWDG from resetting the chip while SWD holds the core halted (register reads etc.). */
    __HAL_DBGMCU_FREEZE_IWDG();

    app_trace_bc(TRC_BOOT, rsr);
}

void app_trace_loop(void)
{
    g_app_trace.loop_count++;
    g_app_trace.tick = HAL_GetTick();
    app_trace_bc(TRC_MAIN_LOOP, g_app_trace.loop_count);
}

/* Strong definitions of the weak hooks in command_protocol.c and platform_i2c.c. */
void command_protocol_trace_hook(uint8_t type, uint8_t sub_cmd, bool begin)
{
    app_trace_bc(begin ? TRC_CMD_BEGIN : TRC_CMD_END, ((uint32_t)type << 8) | sub_cmd);
}

void platform_i2c_trace_hook(uint32_t event, uint32_t arg)
{
    app_trace_i2c(event == 0U ? TRC_I2C_TX : (event == 1U ? TRC_I2C_RX : TRC_I2C_DONE), arg);
}

/* C part of the fault entry: sp = stacked exception frame (r0, r1, r2, r3, r12, lr, pc, xpsr). */
void app_trace_fault_c(const uint32_t *sp, uint32_t exc) __attribute__((used, noreturn));
void app_trace_fault_c(const uint32_t *sp, uint32_t exc)
{
    g_app_trace.fault_exc = exc;
    g_app_trace.fault_lr = sp[5];
    g_app_trace.fault_pc = sp[6];
    g_app_trace.fault_xpsr = sp[7];
    g_app_trace.fault_cfsr = SCB->CFSR;
    g_app_trace.fault_hfsr = SCB->HFSR;
    g_app_trace.fault_bfar = SCB->BFAR;
    g_app_trace.fault_mmfar = SCB->MMFAR;
    app_trace_bc(TRC_FAULT, exc);
    __DSB();
    NVIC_SystemReset();
    for (;;) {
    }
}

/* Entered with the exception's EXC_RETURN still in lr and the exception number in r1: pick the stack the frame is on
 * and hand it to the C part. */
void app_trace_fault_entry(void)
{
    __asm volatile(
        "tst lr, #4          \n"
        "ite eq              \n"
        "mrseq r0, msp       \n"
        "mrsne r0, psp       \n"
        "b app_trace_fault_c \n");
}

#endif /* EVT2_TRACE */
