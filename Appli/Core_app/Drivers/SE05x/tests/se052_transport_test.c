#include "se052_transport_test.h"

/* Vendor example/test code, dev/QA only: compiled out unless EVT2_DIAGNOSTICS=1 (see Core/Src/main.c). */
#if EVT2_DIAGNOSTICS

#include <string.h>

#include "ax_reset.h"
#include "se05x_APDU.h"
#include "se05x_reset_apis.h"
#include "se05x_session_none.h"
#include "sm_api.h"
#include "sm_printf.h"
#include "sm_timer.h"
#include "sm_types.h"

int se052_transport_test_run(void)
{
    SmCommState_t commState;
    U8 atr[64];
    U16 atrLen = sizeof(atr);
    U16 status;
    Se05xSession_t session;
    uint8_t version[16];
    size_t versionLen = sizeof(version);
    smStatus_t apduStatus;

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
    PRINTF("SM_Connect OK, applet version 0x%08lX\r\n", (unsigned long)commState.appletVersion);

    Se05x_SessionInit(&session, NULL);

    apduStatus = Se05x_API_GetVersion(&session, version, &versionLen);
    if (apduStatus != SM_OK) {
        PRINTF("Se05x_API_GetVersion failed: 0x%04X\r\n", (unsigned int)apduStatus);
        SM_Close(NULL, 0);
        return 2;
    }

    PRINTF("GetVersion (%u bytes):", (unsigned int)versionLen);
    for (size_t i = 0; i < versionLen; i++) {
        PRINTF(" %02X", version[i]);
    }
    PRINTF("\r\n");

    SM_Close(NULL, 0);
    return 0;
}

#endif /* EVT2_DIAGNOSTICS */
