#include "se052_scp03_example.h"

/* Vendor example/test code, dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS

#include <string.h>

#include "ax_reset.h"
#include "se05x_APDU.h"
#include "se05x_platform_scp03.h"
#include "se05x_reset_apis.h"
#include "se05x_session_none.h"
#include "sm_api.h"
#include "sm_printf.h"
#include "sm_timer.h"
#include "sm_types.h"

/* NXP factory-default Platform SCP03 ENC/MAC keys for the SE052_B501 OEF
 * variant, copied verbatim from
 * simw-top/sss/ex/inc/ex_sss_tp_scp03_keys.h (SSS_PFSCP_ENABLE_SE052_B501
 * block; that file cites AN12436 as the source and is itself a
 * NXP-generated, "DO NOT MODIFY" table -- these are not fabricated).
 *
 * This is a FACTORY DEFAULT: it only authenticates if this exact SE052F
 * (a) is genuinely the B501 OEF variant and (b) has never had its
 * Platform SCP03 keys rotated/provisioned to something else. If
 * Se05x_Scp03_Authenticate() below fails against a unit that HAS been
 * re-keyed, you need the actual provisioned ENC/MAC keys from whoever
 * did that, not these. */
static const uint8_t s_scp03EncKey[16] = {
    0x3A, 0xE4, 0x41, 0xC7, 0x47, 0xE3, 0x2E, 0xBC, 0x16, 0xB3, 0xBB, 0x2D, 0x84, 0x3C, 0x6D, 0xD8};
static const uint8_t s_scp03MacKey[16] = {
    0x6C, 0x18, 0xF3, 0xD0, 0x8F, 0xEE, 0x1C, 0xB9, 0x6A, 0x3C, 0x8D, 0xE5, 0xD3, 0x53, 0x8A, 0xAA};

/* 0x0B is the key version number NXP's own SE05x example boot code
 * (sss/ex/inc/ex_sss_auth.h, EX_SSS_AUTH_SE05X_KEY_VERSION_NO) uses for
 * these OEF default keys; change it to match your actual provisioning. */
#define SE052_SCP03_KEY_VERSION_NO 0x0B

int se052_scp03_example_run(void)
{
    SmCommState_t commState;
    U8 atr[64];
    U16 atrLen = sizeof(atr);
    U16 status;
    Se05xSession_t session;
    NXSCP03_DynCtx_t scp03DynCtx;
    Se05x_Scp03StaticKeys_t staticKeys;
    sss_status_t scpStatus;
    smStatus_t apduStatus;
    uint8_t version[16];
    size_t versionLen = sizeof(version);
    size_t i;

    axReset_HostConfigure();
    axReset_ResetPulseDUT(SE_RESET_LOGIC);
    sm_sleep(5);

    memset(&commState, 0, sizeof(commState));
    commState.select = SELECT_APPLET;

    status = SM_Connect(NULL, &commState, atr, &atrLen);
    if (status != SW_OK) {
        PRINTF("SM_Connect failed: 0x%04X\r\n", status);
        return 1;
    }

    Se05x_SessionInit(&session, NULL);

    staticKeys.encKey = s_scp03EncKey;
    staticKeys.macKey = s_scp03MacKey;
    staticKeys.keyVerNo = SE052_SCP03_KEY_VERSION_NO;

    scpStatus = Se05x_Scp03_Authenticate(&session, &staticKeys, &scp03DynCtx);
    if (scpStatus != kStatus_SSS_Success) {
        PRINTF("Platform SCP03 authentication failed: 0x%X\r\n", (unsigned int)scpStatus);
        SM_Close(NULL, 0);
        return 2;
    }
    PRINTF("Platform SCP03 channel authenticated\r\n");

    apduStatus = Se05x_API_GetVersion(&session, version, &versionLen);
    if (apduStatus != SM_OK) {
        PRINTF("Se05x_API_GetVersion (over SCP03) failed: 0x%04X\r\n", (unsigned int)apduStatus);
        SM_Close(NULL, 0);
        return 3;
    }

    PRINTF("GetVersion over SCP03 (%u bytes):", (unsigned int)versionLen);
    for (i = 0; i < versionLen; i++) {
        PRINTF(" %02X", version[i]);
    }
    PRINTF("\r\n");

    SM_Close(NULL, 0);
    return 0;
}

#endif /* EVT2_DIAGNOSTICS */
