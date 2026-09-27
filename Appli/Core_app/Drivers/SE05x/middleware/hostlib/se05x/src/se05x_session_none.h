#ifndef SE05X_SESSION_NONE_H
#define SE05X_SESSION_NONE_H

#include "se05x_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wires Se05xSession_t::fp_TXn/fp_RawTXn (declared in se05x_tlv.h) so that
 * every generated Se05x_API_* call reaches smCom_TransceiveRaw(). The full
 * SSS layer (sss/src/se05x/fsl_sss_se05x_apis.c, not part of this reduced
 * port) is normally what assigns these function pointers; without it any
 * Se05x_API_* call dereferences a NULL fp_TXn.
 *
 * fp_TXn's dispatch (fp_Transform -> fp_RawTXn -> fp_DeCrypt) is generic:
 * this leaves fp_Transform/fp_DeCrypt NULL for a plain session-less
 * connection (HOSTCRYPTO_NONE / SCP_NONE). To add Platform SCP03 transport
 * encryption on top of an already-initialized session, call
 * Se05x_Scp03_Authenticate() (se05x_platform_scp03.h) afterwards -- it
 * reassigns fp_Transform/fp_DeCrypt/authType itself and reuses this same
 * dispatcher. */
void Se05x_SessionInit(Se05xSession_t *pSession, void *conn_ctx);

#ifdef __cplusplus
}
#endif

#endif /* SE05X_SESSION_NONE_H */
