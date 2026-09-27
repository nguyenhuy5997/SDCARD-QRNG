#ifndef SE05X_PLATFORM_SCP03_H
#define SE05X_PLATFORM_SCP03_H

#include "nxScp03_Apis.h"
#include "se05x_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Static (pre-shared) Platform SCP03 keys to authenticate the channel
 * with. These must match what is actually provisioned on the SE052F --
 * see README.md "Enabling Platform SCP03" before using this on anything
 * other than a throwaway/eval part. */
typedef struct
{
    const uint8_t *encKey; /* 16-byte AES-128 static ENC key */
    const uint8_t *macKey; /* 16-byte AES-128 static MAC key */
    uint8_t keyVerNo;       /* GlobalPlatform key version number */
} Se05x_Scp03StaticKeys_t;

/* Runs the Platform SCP03 handshake (GP INITIALIZE UPDATE, session-key
 * derivation, GP EXTERNAL AUTHENTICATE) over a session already opened
 * with Se05x_SessionInit() (se05x_session_none.h), and on success rewires
 * that session's fp_Transform/fp_DeCrypt/authType/pdynScp03Ctx so every
 * subsequent Se05x_API_* call on it is transparently SCP03-encrypted and
 * MAC'd.
 *
 * pDynCtx must stay valid for as long as the session is used afterwards
 * (its address is stored in session->pdynScp03Ctx and read on every
 * following APDU) -- do not put it on a stack frame that returns before
 * the session is closed.
 *
 * Only usable when built against config/scp03/fsl_sss_ftr.h (HOSTCRYPTO_USER
 * + SCP_SCP03_SSS); see README.md. Returns kStatus_SSS_Success on success. */
sss_status_t Se05x_Scp03_Authenticate(
    Se05xSession_t *session, const Se05x_Scp03StaticKeys_t *staticKeys, NXSCP03_DynCtx_t *pDynCtx);

#ifdef __cplusplus
}
#endif

#endif /* SE05X_PLATFORM_SCP03_H */
