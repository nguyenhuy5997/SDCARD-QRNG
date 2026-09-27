/**
 * @file    pqc_sign.c
 * @brief   pqc_sign.h implementation -- dispatches to one of the three vendored PQClean ML-DSA parameter sets.
 *
 * Every PQClean call below runs via pqc_call_on_alt_stack() (pqc_stack_call.h), not a direct call -- PQClean's
 * "clean" ML-DSA implementation needs far more stack than this firmware's normal RAM_D1 stack has headroom for
 * (measured up to ~121KB for a single ML-DSA-87 signature, see pqc_stack_call.h's doc comment). Each operation
 * gets a small context struct (on THIS function's own, normal-stack frame -- tiny, just a handful of pointers/
 * enums) that the trampoline running on the alternate stack reads its arguments from and writes its result into.
 */
#include "pqc_sign.h"

#include "pqc_stack_call.h"
#include "randombytes.h"

/* Each level's api.h declares its own PQCLEAN_MLDSA{44,65,87}_CLEAN_* symbols -- no name collisions, so all three
 * headers can be included together in this one dispatch file (same reason ca_protocol.c can freely mix multiple
 * SE05x curve constants: distinct namespaces, not a runtime multiplexer over one shared implementation). */
#include "ml-dsa-44-clean/api.h"
#include "ml-dsa-65-clean/api.h"
#include "ml-dsa-87-clean/api.h"

size_t pqc_sign_publickey_bytes(pqc_sign_level_t level)
{
    switch (level) {
        case PQC_SIGN_MLDSA44: return PQC_SIGN_MLDSA44_PUBLICKEY_BYTES;
        case PQC_SIGN_MLDSA65: return PQC_SIGN_MLDSA65_PUBLICKEY_BYTES;
        case PQC_SIGN_MLDSA87: return PQC_SIGN_MLDSA87_PUBLICKEY_BYTES;
        default: return 0U;
    }
}

size_t pqc_sign_secretkey_bytes(pqc_sign_level_t level)
{
    switch (level) {
        case PQC_SIGN_MLDSA44: return PQC_SIGN_MLDSA44_SECRETKEY_BYTES;
        case PQC_SIGN_MLDSA65: return PQC_SIGN_MLDSA65_SECRETKEY_BYTES;
        case PQC_SIGN_MLDSA87: return PQC_SIGN_MLDSA87_SECRETKEY_BYTES;
        default: return 0U;
    }
}

size_t pqc_sign_max_signature_bytes(pqc_sign_level_t level)
{
    switch (level) {
        case PQC_SIGN_MLDSA44: return PQC_SIGN_MLDSA44_BYTES;
        case PQC_SIGN_MLDSA65: return PQC_SIGN_MLDSA65_BYTES;
        case PQC_SIGN_MLDSA87: return PQC_SIGN_MLDSA87_BYTES;
        default: return 0U;
    }
}

/* ---- keygen_from_seed ------------------------------------------------------------------------------------- */

typedef struct {
    pqc_sign_level_t level;
    const uint8_t *seed;
    uint8_t *pk;
    uint8_t *sk;
    bool ok;
} keygen_ctx_t;

static void keygen_trampoline(void *arg)
{
    keygen_ctx_t *ctx = (keygen_ctx_t *)arg;
    /* Armed for exactly the one randombytes() call crypto_sign_keypair() below makes -- see randombytes.h's
     * pqc_randombytes_pin_next() doc comment for why this single call is sufficient to make the whole keypair a
     * deterministic function of the seed. */
    pqc_randombytes_pin_next(ctx->seed, PQC_SIGN_SEED_BYTES);
    switch (ctx->level) {
        case PQC_SIGN_MLDSA44: ctx->ok = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(ctx->pk, ctx->sk) == 0; break;
        case PQC_SIGN_MLDSA65: ctx->ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(ctx->pk, ctx->sk) == 0; break;
        case PQC_SIGN_MLDSA87: ctx->ok = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(ctx->pk, ctx->sk) == 0; break;
        default: ctx->ok = false; break;
    }
}

bool pqc_sign_keygen_from_seed(pqc_sign_level_t level, const uint8_t seed[PQC_SIGN_SEED_BYTES], uint8_t *pk, uint8_t *sk)
{
    /* Refuse BEFORE pqc_call_on_alt_stack() -- see pqc_stack_call.h's PQC_SIGN_MAX_ENABLED_LEVEL doc comment: on a
     * build that sized the alternate stack for a lower tier, actually switching onto it for this level would
     * overflow it. */
    if ((int)level > PQC_SIGN_MAX_ENABLED_LEVEL) {
        return false;
    }
    keygen_ctx_t ctx = {level, seed, pk, sk, false};
    pqc_call_on_alt_stack(keygen_trampoline, &ctx);
    return ctx.ok;
}

/* ---- sign --------------------------------------------------------------------------------------------------- */

typedef struct {
    pqc_sign_level_t level;
    const uint8_t *sk;
    const uint8_t *msg;
    size_t msg_len;
    uint8_t *sig;
    size_t sig_len;
    bool ok;
} sign_ctx_t;

static void sign_trampoline(void *arg)
{
    sign_ctx_t *ctx = (sign_ctx_t *)arg;
    switch (ctx->level) {
        case PQC_SIGN_MLDSA44:
            ctx->ok = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(ctx->sig, &ctx->sig_len, ctx->msg, ctx->msg_len,
                                                                  ctx->sk) == 0;
            break;
        case PQC_SIGN_MLDSA65:
            ctx->ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(ctx->sig, &ctx->sig_len, ctx->msg, ctx->msg_len,
                                                                  ctx->sk) == 0;
            break;
        case PQC_SIGN_MLDSA87:
            ctx->ok = PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(ctx->sig, &ctx->sig_len, ctx->msg, ctx->msg_len,
                                                                  ctx->sk) == 0;
            break;
        default: ctx->ok = false; break;
    }
}

bool pqc_sign_sign(pqc_sign_level_t level, const uint8_t *sk, const uint8_t *msg, size_t msg_len, uint8_t *sig,
                    size_t *sig_len)
{
    if ((int)level > PQC_SIGN_MAX_ENABLED_LEVEL) {
        *sig_len = 0U;
        return false;
    }
    sign_ctx_t ctx = {level, sk, msg, msg_len, sig, 0U, false};
    pqc_call_on_alt_stack(sign_trampoline, &ctx);
    *sig_len = ctx.sig_len;
    return ctx.ok;
}

/* ---- verify ------------------------------------------------------------------------------------------------- */

typedef struct {
    pqc_sign_level_t level;
    const uint8_t *pk;
    const uint8_t *msg;
    size_t msg_len;
    const uint8_t *sig;
    size_t sig_len;
    bool ok;
} verify_ctx_t;

static void verify_trampoline(void *arg)
{
    verify_ctx_t *ctx = (verify_ctx_t *)arg;
    switch (ctx->level) {
        case PQC_SIGN_MLDSA44:
            ctx->ok = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(ctx->sig, ctx->sig_len, ctx->msg, ctx->msg_len,
                                                               ctx->pk) == 0;
            break;
        case PQC_SIGN_MLDSA65:
            ctx->ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(ctx->sig, ctx->sig_len, ctx->msg, ctx->msg_len,
                                                               ctx->pk) == 0;
            break;
        case PQC_SIGN_MLDSA87:
            ctx->ok = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(ctx->sig, ctx->sig_len, ctx->msg, ctx->msg_len,
                                                               ctx->pk) == 0;
            break;
        default: ctx->ok = false; break;
    }
}

bool pqc_sign_verify(pqc_sign_level_t level, const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len)
{
    /* Verify's own stack use is smaller than sign's (no rejection-sampling loop), but this file has never
     * measured it separately per level -- gated the same as keygen/sign rather than assumed safe, so a leaner
     * build's guarantee ("nothing above PQC_SIGN_MAX_ENABLED_LEVEL touches the alternate stack") stays absolute
     * instead of case-by-case. */
    if ((int)level > PQC_SIGN_MAX_ENABLED_LEVEL) {
        return false;
    }
    verify_ctx_t ctx = {level, pk, msg, msg_len, sig, sig_len, false};
    pqc_call_on_alt_stack(verify_trampoline, &ctx);
    return ctx.ok;
}
