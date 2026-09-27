/**
 * @file    app_trace.h
 * @brief   Post-mortem trace for a board without UART or NRST (STM32H7S3V8Y6TR, 2026-09-27).
 *
 * The board sometimes hangs so hard that SWD cannot reach the core and only a power cycle helps. The IWDG (in the
 * .ioc, ~32 s) now resets the chip instead. This module keeps a small record in RAM that survives that reset
 * (NOLOAD section at a FIXED address, non-cacheable, never cleared by the startup code):
 *   - where the firmware last was (breadcrumb id + argument, and the one before),
 *   - main-loop count, HAL tick, USB interrupt count, I2C transfer count at that moment,
 *   - the fault frame (PC, LR, xPSR, CFSR, HFSR, BFAR, MMFAR) if a fault handler ran,
 *   - a history of the last APP_TRACE_HISTORY runs with their reset cause (RCC_RSR).
 * Read it over SWD after the reset: g_app_trace at 0x24071800 (see app_trace.c for the layout).
 * Everything compiles away with EVT2_TRACE 0.
 */
#ifndef APP_TRACE_H
#define APP_TRACE_H

#include <stdint.h>
#include <stdbool.h>

#define EVT2_TRACE 1

/* IWDG refresh (Core/Src/main.c). Declared unconditionally: the watchdog exists with or without the trace. */
void app_watchdog_kick(void);

#define APP_TRACE_ADDR    0x24071800U
#define APP_TRACE_MAGIC   0x54524345U /* "TRCE" */
#define APP_TRACE_HISTORY 8U

/* Breadcrumb ids (8 bits); the argument is 32 bits. */
enum {
    TRC_BOOT          = 0x01, /* arg: RCC_RSR at boot */
    TRC_INIT_STEP     = 0x02, /* arg: step number inside main() init */
    TRC_MAIN_LOOP     = 0x03, /* arg: loop count */
    TRC_POLL_CMD      = 0x10, /* command_protocol_poll() */
    TRC_POLL_QRNG     = 0x11,
    TRC_POLL_MEDIA    = 0x12,
    TRC_CMD_BEGIN     = 0x20, /* arg: type << 8 | first payload byte (sub-command) */
    TRC_CMD_END       = 0x21, /* arg: same */
    TRC_I2C_TX        = 0x30, /* arg: address << 16 | length */
    TRC_I2C_RX        = 0x31,
    TRC_I2C_DONE      = 0x32, /* arg: platform status */
    TRC_USB_IRQ_IN    = 0x40, /* arg: USB interrupt count */
    TRC_USB_IRQ_OUT   = 0x41,
    TRC_FAULT         = 0xF0, /* arg: exception number */
};

#if EVT2_TRACE

typedef struct {
    uint32_t rsr;          /* RCC_RSR at the start of the run that ended */
    uint32_t last_bc;      /* last breadcrumb: id << 24 | (arg & 0xFFFFFF) */
    uint32_t last_arg;
    uint32_t prev_bc;
    uint32_t loop_count;
    uint32_t tick;
    uint32_t usb_irqs;
    uint32_t i2c_ops;
    uint32_t fault_pc;     /* 0 if no fault */
    uint32_t fault_cfsr;
} app_trace_run_t;

typedef struct {
    uint32_t magic;
    uint32_t boot_count;   /* runs since the last power-on */
    /* current run */
    volatile uint32_t rsr;
    volatile uint32_t bc;      /* id << 24 | (arg & 0xFFFFFF) */
    volatile uint32_t bc_arg;
    volatile uint32_t prev_bc;
    volatile uint32_t loop_count;
    volatile uint32_t tick;
    volatile uint32_t usb_irqs;
    volatile uint32_t i2c_ops;
    /* fault frame, current run */
    volatile uint32_t fault_exc;
    volatile uint32_t fault_pc;
    volatile uint32_t fault_lr;
    volatile uint32_t fault_xpsr;
    volatile uint32_t fault_cfsr;
    volatile uint32_t fault_hfsr;
    volatile uint32_t fault_bfar;
    volatile uint32_t fault_mmfar;
    /* previous runs, [0] = most recent */
    app_trace_run_t history[APP_TRACE_HISTORY];
} app_trace_t;

extern app_trace_t g_app_trace;

/** Call once, early in main() after MPU_Config() (the trace area must already be non-cacheable). Files the previous
 *  run into the history using RCC_RSR, clears the reset flags and freezes the IWDG while the core is halted by SWD. */
void app_trace_boot(void);

static inline void app_trace_bc(uint32_t id, uint32_t arg)
{
    g_app_trace.prev_bc = g_app_trace.bc;
    g_app_trace.bc_arg = arg;
    g_app_trace.bc = (id << 24) | (arg & 0x00FFFFFFU);
}

/** Main loop: count, tick, breadcrumb. The IWDG is refreshed by the caller (main.c). */
void app_trace_loop(void);

static inline void app_trace_usb_irq(bool enter)
{
    if (enter) {
        g_app_trace.usb_irqs++;
    }
    app_trace_bc(enter ? TRC_USB_IRQ_IN : TRC_USB_IRQ_OUT, g_app_trace.usb_irqs);
}

static inline void app_trace_i2c(uint32_t id, uint32_t arg)
{
    if (id != TRC_I2C_DONE) {
        g_app_trace.i2c_ops++;
    }
    app_trace_bc(id, arg);
}

/** IWDG refresh, implemented in Core/Src/main.c (the handle is CubeMX's). For the rare long, legitimate operations
 *  outside the main loop (e.g. the temporary SE05x probe at boot). */
void app_watchdog_kick(void);

/** Fault entry: branch here (not call) as the FIRST instruction of a fault handler, with r1 = exception number.
 *  Records the stacked frame and fault registers, then resets the chip. */
void app_trace_fault_entry(void) __attribute__((naked, noreturn));

#define APP_TRACE_BC(id, arg) app_trace_bc((id), (arg))

#else

#define APP_TRACE_BC(id, arg) do { (void)(id); (void)(arg); } while (0)
static inline void app_trace_boot(void) {}
static inline void app_trace_loop(void) {}
static inline void app_trace_usb_irq(bool enter) { (void)enter; }
static inline void app_trace_i2c(uint32_t id, uint32_t arg) { (void)id; (void)arg; }

#endif /* EVT2_TRACE */

#endif /* APP_TRACE_H */
