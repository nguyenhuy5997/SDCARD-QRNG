#include "se052_sign_example.h"

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

/* This SE052F rejects Se05x_API_CheckObjectExists/WriteECKey (Secure
 * Object management) on a plain session-less connection with
 * SW=0x6985 (SM_ERR_CONDITIONS_NOT_SATISFIED) -- confirmed by running
 * se052_transport_test.c (plain Se05x_API_GetVersion succeeds) against
 * se052_scp03_example.c (object management over an authenticated
 * channel succeeds). So this example requires
 * PLUG_AND_TRUST_STM32_ENABLE_SCP03; see README.md "Enabling Platform
 * SCP03" for what that pulls in, and the same factory-default-key
 * caveat as se052_scp03_example.c applies to the keys below. */
static const uint8_t s_scp03EncKey[16] = {
    0x3A, 0xE4, 0x41, 0xC7, 0x47, 0xE3, 0x2E, 0xBC, 0x16, 0xB3, 0xBB, 0x2D, 0x84, 0x3C, 0x6D, 0xD8};
static const uint8_t s_scp03MacKey[16] = {
    0x6C, 0x18, 0xF3, 0xD0, 0x8F, 0xEE, 0x1C, 0xB9, 0x6A, 0x3C, 0x8D, 0xE5, 0xD3, 0x53, 0x8A, 0xAA};
#define SE052_SIGN_EXAMPLE_KEY_VERSION_NO 0x0B

/* Demo object ID for the EC key pair used by this example.
 *
 * Must be in the "customer" object ID range (0x00000001-0x7BFFFFFF per
 * simw-top/sss/ex/inc/ex_sss_objid.h). Ranges from 0x7C000000 upward are
 * reserved by NXP for their own AKM/demo/cloud/applet-internal objects
 * (e.g. 0x7DC00000-0x7DCFFFFF is "DEMO_CLOUD") -- on an SE052F that has
 * ever run one of NXP's own demos, an ID in those ranges can already
 * exist with a restrictive policy, and even a read-only
 * Se05x_API_CheckObjectExists on it comes back SW=0x6985
 * (SM_ERR_CONDITIONS_NOT_SATISFIED) instead of a plain "no". Pick a value
 * that does not collide with anything already provisioned on your
 * SE052F if you change this. */
#define SE052_SIGN_EXAMPLE_KEY_ID 0x00223344U

static smStatus_t pnt_ensure_demo_key(Se05xSession_t *session, uint32_t keyId)
{
    SE05x_Result_t exists = kSE05x_Result_NA;
    smStatus_t status = Se05x_API_CheckObjectExists(session, keyId, &exists);

    if (status != SM_OK) {
        return status;
    }
    if (exists == kSE05x_Result_SUCCESS) {
        return SM_OK;
    }

    /* NULL priv/pub key value + P1_KEY_PAIR => key pair is generated
     * inside the SE052F; the private key never leaves the chip. */
    return Se05x_API_WriteECKey(session,
        NULL,
        0,
        keyId,
        kSE05x_ECCurve_NIST_P256,
        NULL,
        0,
        NULL,
        0,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
}

int se052_sign_example_run(void)
{
    static const uint8_t message[] = "Hello from STM32H753 + SE052F";
    SmCommState_t commState;
    U8 atr[64];
    U16 atrLen = sizeof(atr);
    U16 status;
    Se05xSession_t session;
    NXSCP03_DynCtx_t scp03DynCtx;
    Se05x_Scp03StaticKeys_t scp03Keys;
    sss_status_t scpStatus;
    smStatus_t apduStatus;
    uint8_t digest[32];
    size_t digestLen = sizeof(digest);
    uint8_t signature[80];
    size_t signatureLen = sizeof(signature);
    SE05x_Result_t verifyResult = kSE05x_Result_NA;
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

    scp03Keys.encKey = s_scp03EncKey;
    scp03Keys.macKey = s_scp03MacKey;
    scp03Keys.keyVerNo = SE052_SIGN_EXAMPLE_KEY_VERSION_NO;

    scpStatus = Se05x_Scp03_Authenticate(&session, &scp03Keys, &scp03DynCtx);
    if (scpStatus != kStatus_SSS_Success) {
        PRINTF("Platform SCP03 authentication failed: 0x%X\r\n", (unsigned int)scpStatus);
        PRINTF("(Built without PLUG_AND_TRUST_STM32_ENABLE_SCP03? This example needs it.)\r\n");
        SM_Close(NULL, 0);
        return 6;
    }

    apduStatus = pnt_ensure_demo_key(&session, SE052_SIGN_EXAMPLE_KEY_ID);
    if (apduStatus != SM_OK) {
        PRINTF("Ensure demo key failed: 0x%04X\r\n", (unsigned int)apduStatus);
        SM_Close(NULL, 0);
        return 2;
    }

    apduStatus = Se05x_API_DigestOneShot(
        &session, kSE05x_DigestMode_SHA256, message, sizeof(message) - 1U, digest, &digestLen);
    if (apduStatus != SM_OK) {
        PRINTF("DigestOneShot failed: 0x%04X\r\n", (unsigned int)apduStatus);
        SM_Close(NULL, 0);
        return 3;
    }

    apduStatus = Se05x_API_ECDSASign(&session,
        SE052_SIGN_EXAMPLE_KEY_ID,
        kSE05x_ECSignatureAlgo_SHA_256,
        digest,
        digestLen,
        signature,
        &signatureLen);
    if (apduStatus != SM_OK) {
        PRINTF("ECDSASign failed: 0x%04X\r\n", (unsigned int)apduStatus);
        SM_Close(NULL, 0);
        return 4;
    }

    PRINTF("Signature (%u bytes, ASN.1 DER):", (unsigned int)signatureLen);
    for (i = 0; i < signatureLen; i++) {
        PRINTF(" %02X", signature[i]);
    }
    PRINTF("\r\n");

    apduStatus = Se05x_API_ECDSAVerify(&session,
        SE052_SIGN_EXAMPLE_KEY_ID,
        kSE05x_ECSignatureAlgo_SHA_256,
        digest,
        digestLen,
        signature,
        signatureLen,
        &verifyResult);
    if (apduStatus != SM_OK || verifyResult != kSE05x_Result_SUCCESS) {
        PRINTF("ECDSAVerify failed: status=0x%04X result=%d\r\n", (unsigned int)apduStatus, (int)verifyResult);
        SM_Close(NULL, 0);
        return 5;
    }

    PRINTF("Signature verified OK\r\n");

    SM_Close(NULL, 0);
    return 0;
}

#endif /* EVT2_DIAGNOSTICS */
