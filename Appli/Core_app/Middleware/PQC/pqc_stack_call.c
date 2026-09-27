/**
 * @file    pqc_stack_call.c
 * @brief   pqc_stack_call.h implementation -- see that header's doc comment for why this exists.
 */
#include "pqc_stack_call.h"

#include <stdint.h>

/* Sized off PQC_SIGN_MAX_ENABLED_LEVEL (pqc_stack_call.h), not hardcoded -- each tier is the worst measured
 * PQClean stack use for that tier's own highest enabled level (-fstack-usage: ML-DSA-44 ~50KB, -65 ~78KB, -87
 * ~121KB) plus margin for this file's own trampoline frame, pqc_sign.c's small per-call context structs, and any
 * interrupt that fires while executing on this stack (Cortex-M pushes its exception frame onto whatever MSP
 * currently points at -- this project runs everything on MSP, no RTOS/PSP split, so an ISR firing during a
 * PQClean call lands here too, same as it would on the normal stack). The margin-over-measured ratio matches the
 * original 176KB/121KB (~1.45x) pick for the two smaller tiers as well, rounded up for round numbers. RAM_D2 is
 * 288KB total with only .dma_noncache's 8KB otherwise claimed (STM32H753ZITX_FLASH.ld) -- even the largest tier
 * leaves ~104KB still free there on THIS board; a leaner target (see PQC_SIGN_MAX_ENABLED_LEVEL's own doc
 * comment) picks a smaller tier to free the difference for everything else it needs to fit. */
#if PQC_SIGN_MAX_ENABLED_LEVEL >= 2
#define PQC_SIGN_ALT_STACK_BYTES (176U * 1024U) /* covers ML-DSA-87, ~121KB measured */
#elif PQC_SIGN_MAX_ENABLED_LEVEL == 1
#define PQC_SIGN_ALT_STACK_BYTES (128U * 1024U) /* covers ML-DSA-65, ~78KB measured */
#else
#define PQC_SIGN_ALT_STACK_BYTES (80U * 1024U)  /* covers ML-DSA-44, ~50KB measured */
#endif

/* Placed in RAM_D2 (STM32H753ZITX_FLASH.ld's .pqc_sign_stack section, right after .dma_noncache's own 8KB) --
 * NEVER accessed by name after boot, only through its address; the `aligned(8)` matches AAPCS's stack-alignment
 * requirement (a public interface's SP must be 8-byte aligned at a function call boundary). */
__attribute__((section(".pqc_sign_stack"), aligned(8))) static uint8_t s_alt_stack[PQC_SIGN_ALT_STACK_BYTES];

/* Pure register-shuffling primitive: switches sp to `new_sp`, calls fn(arg), switches sp back, returns -- see
 * pqc_stack_call.h's doc comment for the full rationale. `naked` means GCC generates NO prologue/epilogue of its
 * own (no automatic push/frame setup that would run on the OLD stack before we get a chance to switch) -- the
 * function body below is the ENTIRE assembly this compiles to, hand-written for exactly this reason.
 *
 * Register use (AAPCS: r0/r1/r2 = this function's 3 arguments; r4/r5/lr must be preserved across calls, hence the
 * explicit push/pop):
 *   entry:  r0 = fn, r1 = arg, r2 = new_sp (already computed by the C caller below -- no address arithmetic
 *           happens in this asm at all, deliberately, to keep this primitive as simple and reviewable as possible)
 *   r4 <- old sp (saved so it can be restored after fn returns)
 *   r5 <- fn (saved before r0 is reused to pass `arg`)
 *   sp <- new_sp (r2)                          -- NOW running on the alternate stack
 *   r0 <- arg (r1)                             -- set up fn's own single argument
 *   blx r5                                     -- call fn(arg); fn must preserve r4/r5/lr per AAPCS, and does,
 *                                                  being ordinary compiled C
 *   sp <- r4 (restore the original stack)      -- back on the normal stack
 *   pop {r4, r5, pc}                           -- restore caller's r4/r5, return (pop into pc = return branch)
 */
__attribute__((naked)) static void pqc_stack_switch_call(pqc_stack_call_fn_t fn, void *arg, void *new_sp)
{
    __asm volatile("push {r4, r5, lr}\n"
                   "mov  r4, sp\n"
                   "mov  r5, r0\n"
                   "mov  sp, r2\n"
                   "mov  r0, r1\n"
                   "blx  r5\n"
                   "mov  sp, r4\n"
                   "pop  {r4, r5, pc}\n");
}

void pqc_call_on_alt_stack(pqc_stack_call_fn_t fn, void *arg)
{
    /* Top of the buffer (stack grows down), 8-byte-aligned -- sizeof() is a compile-time constant multiple of 8
     * here (176*1024), so this alignment is already exact, but computed defensively rather than assumed. */
    uintptr_t base = (uintptr_t)s_alt_stack;
    uintptr_t top = base + sizeof(s_alt_stack);
    top &= ~(uintptr_t)7U;

    /* Re-entrancy guard (H7S3 port): ML-KEM now runs on this stack too (pqc_kem.c), so a caller already executing
     * on the alternate stack must NOT be switched to `top` again -- that would put the new frame on top of the
     * live one. Already here -> just call through on the current stack. */
    uintptr_t sp;
    __asm volatile("mov %0, sp" : "=r"(sp));
    if (sp > base && sp <= top) {
        fn(arg);
        return;
    }
    pqc_stack_switch_call(fn, arg, (void *)top);
}
