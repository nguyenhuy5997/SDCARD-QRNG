/**
 * @file    pqc_stack_call.h
 * @brief   Call a function on a dedicated alternate CPU stack in RAM_D2 -- Giai đoạn 4, see CLAUDE.md.
 *
 * WHY THIS EXISTS: PQClean's "clean" (portable, no ASM) reference implementation of ML-DSA keeps its working
 * polynomial matrices on the C call stack rather than statically allocated -- measured via `-fstack-usage`, a
 * single call to e.g. PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx() needs ~121KB of stack. This firmware's
 * normal stack lives at the top of RAM_D1 (STM32H753ZITX_FLASH.ld's `_estack`), and only has roughly 58KB of
 * actual headroom above the firmware's existing .data/.bss -- nowhere near enough for even ML-DSA-44's ~50KB
 * signing path with any safety margin, let alone ML-DSA-65/87. A stack overflow here would not necessarily crash
 * cleanly: RAM_D1 is shared with .bss (all of this project's other static state, including security-sensitive
 * session data), so an overflow could silently corrupt it instead.
 *
 * FIX: RAM_D2 (288KB) is otherwise almost entirely unused by this project (only .dma_noncache's own 8KB, see
 * STM32H753ZITX_FLASH.ld) -- pqc_call_on_alt_stack() temporarily points the CPU's stack pointer at a dedicated
 * ~176KB buffer there (the .pqc_sign_stack linker section) before calling into PQClean, and restores the normal
 * stack pointer immediately afterward. This is the standard embedded technique for isolating one unusually
 * stack-hungry call from the rest of an application's stack budget, without modifying the vendored library at
 * all (PQClean's own source is untouched -- only Core_app/Middleware/PQC/pqc_sign.c's own wrapper functions route
 * their calls through this).
 *
 * Cortex-M / ARMv7-M (Thumb-2) specific -- see pqc_stack_call.c's hand-written assembly. Not a general-purpose
 * coroutine/fiber mechanism: `fn` runs to completion, synchronously, on the caller's own thread of execution (no
 * RTOS involved, this project is a bare-metal superloop) -- this only relocates WHERE its stack frame lives, not
 * when it runs.
 */
#ifndef PQC_STACK_CALL_H
#define PQC_STACK_CALL_H

#ifdef __cplusplus
extern "C" {
#endif

/** Signature of the function pqc_call_on_alt_stack() invokes on the alternate stack. `arg` is passed through
 *  unchanged -- the usual way to hand it more than one value (a small context struct on the CALLER's own stack;
 *  `fn` only ever dereferences it, so it does not need to live on the alternate stack itself). */
typedef void (*pqc_stack_call_fn_t)(void *arg);

/** Highest pqc_sign_level_t (pqc_sign.h: 0=ML-DSA-44, 1=ML-DSA-65, 2=ML-DSA-87) this build's alternate stack is
 *  actually SIZED for -- see pqc_stack_call.c's PQC_SIGN_ALT_STACK_BYTES, which is picked off this number. This
 *  does NOT remove any level's code: all three PQClean parameter sets (Core_app/Middleware/PQC/pqclean/
 *  ml-dsa-{44,65,87}-clean/) always compile in, every level's pqc_sign_publickey_bytes()/etc. still answer
 *  correctly, and pqc_sign.c's dispatch switches still have all three cases -- only pqc_sign_keygen_from_seed()/
 *  _sign()/_verify() refuse (return false) for a level above this, BEFORE ever switching onto the (now
 *  too-small-for-it) alternate stack, so a leaner build cannot silently overflow it. Raising this back up again
 *  later (more RAM available, e.g. a bigger H7S3 variant, or simply back on this H753 board) needs no code
 *  un-deleted -- just rebuild with a higher value.
 *
 *  Overridable via a build's own compiler flags (e.g. -DPQC_SIGN_MAX_ENABLED_LEVEL=1), same pattern as
 *  command_protocol.h's CMD_PROTO_MAX_PAYLOAD override -- added while sizing a future STM32H7S3 port, whose
 *  AXI-SRAM (456KB total) cannot fit this buffer at its current 176KB alongside everything else this project
 *  already keeps in RAM_D1+RAM_D2 today. Default (2) keeps this H753 board's current behavior -- every level
 *  available -- unchanged. */
#ifndef PQC_SIGN_MAX_ENABLED_LEVEL
#define PQC_SIGN_MAX_ENABLED_LEVEL 2
#endif

/** Calls `fn(arg)` with the CPU stack pointer temporarily switched to the dedicated RAM_D2 buffer (see this
 *  header's own doc comment), restoring the normal stack pointer the moment `fn` returns -- safe to call
 *  re-entrantly in the sense that nothing is left switched afterward, but NOT reentrant/concurrent with itself:
 *  this project has no RTOS/interrupts that would call back into ML-DSA signing, so exactly one call is ever in
 *  flight at a time. Must not be called from an interrupt handler (the alternate stack is sized for the deepest
 *  known PQClean call from ordinary code, not for stacking an ISR on top of it as well). */
void pqc_call_on_alt_stack(pqc_stack_call_fn_t fn, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* PQC_STACK_CALL_H */
