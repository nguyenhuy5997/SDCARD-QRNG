#include "se05x_session_none.h"
#include "se05x_const.h"
#include "smCom.h"
#include <string.h>

/* Mirrors sss_se05x_channel_txnRaw() in sss/src/se05x/fsl_sss_se05x_apis.c,
 * minus the SCP03/tunnel-context branches that do not apply session-less. */
static smStatus_t pnt_se05x_RawTXn(void *conn_ctx,
    struct _sss_se05x_tunnel_context *pChannelCtx,
    SE_AuthType_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    uint8_t txBuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t i = 0;
    U32 u32RspLen;
    smStatus_t ret;

    (void)pChannelCtx;
    (void)currAuth;

    memcpy(&txBuf[i], hdr, sizeof(*hdr));
    i += sizeof(*hdr);

    if (cmdBufLen > 0) {
        if ((cmdBufLen < 0xFFu) && !hasle) {
            txBuf[i++] = (uint8_t)cmdBufLen;
        }
        else {
            txBuf[i++] = 0x00;
            txBuf[i++] = (uint8_t)(0xFFu & (cmdBufLen >> 8));
            txBuf[i++] = (uint8_t)(0xFFu & cmdBufLen);
        }
        memcpy(&txBuf[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    else {
        txBuf[i++] = 0x00;
    }

    if (hasle) {
        txBuf[i++] = 0x00;
        txBuf[i++] = 0x00;
    }

    u32RspLen = (U32)*rspLen;
    ret = (smStatus_t)smCom_TransceiveRaw(conn_ctx, txBuf, (U16)i, rsp, &u32RspLen);
    *rspLen = u32RspLen;
    return ret;
}

/* Mirrors sss_se05x_TXn() in sss/src/se05x/fsl_sss_se05x_apis.c: apply
 * fp_Transform (if set) before the wire, fp_DeCrypt (if set) after. With
 * fp_Transform/fp_DeCrypt left NULL (the plain, session-less case set up
 * by Se05x_SessionInit()) this is a straight passthrough to fp_RawTXn.
 * Wiring fp_Transform to se05x_Transform_scp (see se05x_platform_scp03.c)
 * makes the exact same dispatch also carry Platform SCP03 encryption. */
static smStatus_t pnt_se05x_TXn(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    smStatus_t ret;
    tlvHeader_t outHdr = {{0}};
    uint8_t txBuf[SE05X_MAX_BUF_SIZE_CMD];
    size_t txBufLen = sizeof(txBuf);
    const tlvHeader_t *sendHdr = hdr;
    uint8_t *sendBuf = cmdBuf;
    size_t sendBufLen = cmdBufLen;
#if SSS_HAVE_SCP_SCP03_SSS
    uint8_t alreadyFramed = 0;
#endif

    if (pSession->fp_Transform != NULL) {
        ret = pSession->fp_Transform(pSession, hdr, cmdBuf, cmdBufLen, &outHdr, txBuf, &txBufLen, hasle);
        if (ret != SM_OK) {
            return ret;
        }
        sendHdr = &outHdr;
        sendBuf = txBuf;
        sendBufLen = txBufLen;

#if SSS_HAVE_SCP_SCP03_SSS
        /* se05x_Transform_scp()'s session-less branch (se05x_tlv.c) builds
         * the complete wire APDU -- header with the SCP CLA bit already
         * OR'd in, Lc, encrypted data, MAC -- directly into txBuf and
         * never touches outHdr (unlike the plain se05x_Transform, which
         * always fills outHdr with the original header and leaves
         * fp_RawTXn to prepend Lc + data around it). Routing that
         * already-complete buffer through the normal RawTXn header-prepend
         * path would double-wrap it with a bogus all-zero header. */
        if (pSession->fp_Transform == &se05x_Transform_scp && !pSession->hasSession) {
            alreadyFramed = 1;
        }
#endif
    }

#if SSS_HAVE_SCP_SCP03_SSS
    if (alreadyFramed) {
        U32 u32RspLen = (U32)*rspLen;
        ret = (smStatus_t)smCom_TransceiveRaw(pSession->conn_ctx, sendBuf, (U16)sendBufLen, rsp, &u32RspLen);
        *rspLen = u32RspLen;
    }
    else
#endif
    {
        ret = pSession->fp_RawTXn(pSession->conn_ctx,
            pSession->pChannelCtx,
            pSession->authType,
            sendHdr,
            sendBuf,
            sendBufLen,
            rsp,
            rspLen,
            hasle);
    }

    if (pSession->fp_DeCrypt != NULL) {
        ret = pSession->fp_DeCrypt(pSession, cmdBufLen, rsp, rspLen, hasle);
    }

    return ret;
}

void Se05x_SessionInit(Se05xSession_t *pSession, void *conn_ctx)
{
    memset(pSession, 0, sizeof(*pSession));
    pSession->fp_TXn = &pnt_se05x_TXn;
    pSession->fp_RawTXn = &pnt_se05x_RawTXn;
    pSession->fp_Transform = NULL;
    pSession->fp_DeCrypt = NULL;
    pSession->authType = kSSS_AuthType_None;
    pSession->conn_ctx = conn_ctx;
    pSession->hasSession = 0;
}
