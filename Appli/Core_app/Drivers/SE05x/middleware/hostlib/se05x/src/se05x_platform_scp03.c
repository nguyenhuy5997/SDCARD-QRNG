#include "se05x_platform_scp03.h"
#include "fsl_sss_se05x_scp03.h"
#include "fsl_sss_user_apis.h"
#include <string.h>

/* This whole file only has something to do when the host-crypto backend
 * Se05x_Scp03_Authenticate() is written against (sss_host_*, from
 * fsl_sss_user_apis.h) is actually selected. That only happens when
 * PLUG_AND_TRUST_STM32_ENABLE_SCP03 is defined (see
 * config/fsl_sss_ftr.h). Guarding here -- rather than relying on the
 * CubeIDE project to add/remove this file -- means toggling that one
 * define is enough to turn Platform SCP03 on or off; the stub below
 * keeps Se05x_Scp03_Authenticate() linkable either way. */
#if SSS_HAVE_HOSTCRYPTO_USER

/* Host-crypto session/keystore backing every sss_object_t used for SCP03
 * (both the static pre-shared keys and the derived session keys). The
 * derived-key objects living in *pDynCtx keep a pointer back into this
 * keystore/session and are read on every subsequent Se05x_API_* call, so
 * this must outlive the SCP03 session -- kept as file-static storage
 * rather than a stack variable. This port only ever drives one SE052F
 * channel at a time. */
static sss_session_t s_hostSession;
static sss_key_store_t s_hostKeyStore;
static uint8_t s_hostCryptoReady;

static sss_status_t pnt_scp03_ensure_host_crypto(void)
{
    sss_status_t status;

    if (s_hostCryptoReady) {
        return kStatus_SSS_Success;
    }

    status = sss_host_session_open(&s_hostSession, kType_SSS_Software, 0, kSSS_ConnectionType_Plain, NULL);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_store_context_init(&s_hostKeyStore, &s_hostSession);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    s_hostCryptoReady = 1U;
    return kStatus_SSS_Success;
}

static sss_status_t pnt_scp03_make_key_object(sss_object_t *keyObj, uint32_t keyId)
{
    sss_status_t status = sss_host_key_object_init(keyObj, &s_hostKeyStore);

    if (status != kStatus_SSS_Success) {
        return status;
    }
    return sss_host_key_object_allocate_handle(
        keyObj, keyId, kSSS_KeyPart_Default, kSSS_CipherType_AES, 16, kKeyObject_Mode_Transient);
}

sss_status_t Se05x_Scp03_Authenticate(
    Se05xSession_t *session, const Se05x_Scp03StaticKeys_t *staticKeys, NXSCP03_DynCtx_t *pDynCtx)
{
    sss_status_t status;
    NXSCP03_StaticCtx_t staticCtx;
    NXSCP03_AuthCtx_t authCtx;

    memset(&staticCtx, 0, sizeof(staticCtx));
    memset(pDynCtx, 0, sizeof(*pDynCtx));

    status = pnt_scp03_ensure_host_crypto();
    if (status != kStatus_SSS_Success) {
        return status;
    }

    staticCtx.keyVerNo = staticKeys->keyVerNo;
    staticCtx.key_len = 16;

    status = pnt_scp03_make_key_object(&staticCtx.Enc, 1);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    status = sss_host_key_store_set_key(&s_hostKeyStore, &staticCtx.Enc, staticKeys->encKey, 16, 128, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = pnt_scp03_make_key_object(&staticCtx.Mac, 2);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    status = sss_host_key_store_set_key(&s_hostKeyStore, &staticCtx.Mac, staticKeys->macKey, 16, 128, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = pnt_scp03_make_key_object(&pDynCtx->Enc, 3);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    status = pnt_scp03_make_key_object(&pDynCtx->Mac, 4);
    if (status != kStatus_SSS_Success) {
        return status;
    }
    status = pnt_scp03_make_key_object(&pDynCtx->Rmac, 5);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    authCtx.pStatic_ctx = &staticCtx;
    authCtx.pDyn_ctx = pDynCtx;

    /* nxScp03_GP_InitializeUpdate() (fsl_sss_se05x_scp03.c) reads
     * session->authType == kSSS_AuthType_SCP03 to pick up keyVerNo, then
     * itself resets authType to kSSS_AuthType_None for the duration of
     * the handshake: INITIALIZE UPDATE / EXTERNAL AUTHENTICATE travel
     * unencrypted (there are no session keys yet to encrypt them with),
     * so fp_Transform must be the plain se05x_Transform here, not
     * se05x_Transform_scp -- mirrors sss/src/se05x/fsl_sss_se05x_apis.c's
     * kSSS_AuthType_SCP03 branch. */
    session->fp_Transform = &se05x_Transform;
    session->fp_DeCrypt = &se05x_DeCrypt;
    session->authType = kSSS_AuthType_SCP03;

    status = nxScp03_AuthenticateChannel(session, &authCtx);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Platform SCP03 counter model, as in sss/src/se05x/fsl_sss_se05x_apis.c ("There is a different behaviour of
     * Platform SCP between SE050 and future applet"), which decides it from the applet version at run time:
     *   applet >= 4.3 (SE05X_VER_07_02: SE052F, SE050E, SE051): kSSS_AuthType_AESKey -> every command advances the
     *     encryption counter;
     *   older applets (SE05X_VER_03_XX: SE050A/B/C/F): kSSS_AuthType_SCP03 -> commands without a data field do not,
     *     and their response ICV uses counter - 1 (nxScp03_Com.c).
     * This port decides it from the build flag, which must match the chip anyway. It used to be hard-wired to AESKey
     * (SE052F only): on the SE050F2 of the STM32H7S3V8Y6TR board (applet 3.6.0) the first command without data (e.g.
     * GetVersion, ReadECCurveList) then desynchronised the channel and every later command failed with 6982/6985
     * (found and verified on the board 2026-09-27). */
#if SSS_HAVE_SE05X_VER_GTE_07_02
    pDynCtx->authType = kSSS_AuthType_AESKey;
#else
    pDynCtx->authType = kSSS_AuthType_SCP03;
#endif

    /* nxScp03_AuthenticateChannel() left authType at kSSS_AuthType_None
     * (see above) -- restore it now that the channel is authenticated. */
    session->authType = kSSS_AuthType_SCP03;
    session->pdynScp03Ctx = pDynCtx;
    session->fp_Transform = &se05x_Transform_scp;

    return kStatus_SSS_Success;
}

#else /* !SSS_HAVE_HOSTCRYPTO_USER */

sss_status_t Se05x_Scp03_Authenticate(
    Se05xSession_t *session, const Se05x_Scp03StaticKeys_t *staticKeys, NXSCP03_DynCtx_t *pDynCtx)
{
    (void)session;
    (void)staticKeys;
    (void)pDynCtx;
    /* Built without PLUG_AND_TRUST_STM32_ENABLE_SCP03 -- see README.md
     * "Enabling Platform SCP03". */
    return kStatus_SSS_Fail;
}

#endif /* SSS_HAVE_HOSTCRYPTO_USER */
