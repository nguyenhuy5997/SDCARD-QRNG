/**
 * @file    security_service_se052f.c
 * @brief   SE052F backend of the chip-agnostic security_service interface.
 *
 * Wraps Core_app/Drivers/SE05x's NXP Plug & Trust host library (T=1 over
 * I2C, session-less APDU transport) behind security_service.h so App
 * never touches Se05x_API_* calls or Se05xSession_t directly.
 *
 * This board's SE052F rejects Secure-Object-management commands
 * (CheckObjectExists, WriteECKey, ...) on a plain session-less
 * connection with SW=0x6985 -- confirmed by
 * Core_app/Drivers/SE05x/tests/se052_transport_test.c (plain
 * Se05x_API_GetVersion succeeds) vs. se052_scp03_example.c (object
 * management over an authenticated channel succeeds). So
 * security_service_init() below always authenticates Platform SCP03;
 * this REQUIRES the project-wide `PLUG_AND_TRUST_STM32_ENABLE_SCP03`
 * preprocessor symbol (and RNG enabled in CubeMX) -- see
 * Core_app/Drivers/SE05x/README.md "Enabling Platform SCP03". Without
 * it, Se05x_Scp03_Authenticate() compiles to a stub that always fails,
 * so security_service_init() will cleanly return SEC_ERROR rather than
 * silently running unauthenticated.
 */
#include "security_service.h"
#include "scp03_keys_cfg.h"
#include "platform_rng.h"

#include <string.h>

#include "ax_reset.h"
#include "se05x_APDU.h"
#include "se05x_ecc_curves.h"
#include "se05x_platform_scp03.h"
#include "se05x_reset_apis.h"
#include "se05x_session_none.h"
#include "sm_api.h"
#include "sm_timer.h"
#include "sm_types.h"

/* NXP factory-default Platform SCP03 keys for the SSS_PFSCP_ENABLE_SE052_B501
 * OEF variant, copied verbatim from Core_app/Drivers/SE05x's own
 * se052_scp03_example.c/se052_sign_example.c (sourced from AN12436, not a
 * placeholder). Only authenticates if this SE052F (a) is genuinely that
 * OEF variant and (b) has never had its Platform SCP03 keys
 * rotated/provisioned to something else -- replace these two arrays
 * with the actual provisioned keys if that is not the case; there is no
 * way to recover the real keys from the chip afterwards. */
#if EVT2_SCP03_SE050F2_A92A
/* NXP factory Platform SCP03 keys, SE050F2 OEF 0x0001A92A (see scp03_keys_cfg.h). */
static const uint8_t s_scp03EncKey[16] = {
    0xB5, 0x0E, 0x1F, 0x12, 0xB8, 0x1F, 0xE5, 0x3B, 0x6C, 0x3B, 0x53, 0x87, 0x91, 0x2A, 0x1A, 0x5A};
static const uint8_t s_scp03MacKey[16] = {
    0x71, 0x93, 0x69, 0x59, 0xD3, 0x7F, 0x2B, 0x22, 0xC5, 0xA0, 0xC3, 0x49, 0x19, 0xA2, 0xBC, 0x1F};
#elif EVT2_SCP03_USE_TEST_KEYS
/* The chip was moved OFF the NXP defaults onto the demo's PUBLIC test key (ENC = MAC = DEK = 0x40..0x4F) by factory mode 7.
 * Development state only: this key is published in NXP's own demo, so it protects nothing. */
static const uint8_t s_scp03EncKey[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
static const uint8_t s_scp03MacKey[16] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
#else
static const uint8_t s_scp03EncKey[16] = {
    0x3A, 0xE4, 0x41, 0xC7, 0x47, 0xE3, 0x2E, 0xBC, 0x16, 0xB3, 0xBB, 0x2D, 0x84, 0x3C, 0x6D, 0xD8};
static const uint8_t s_scp03MacKey[16] = {
    0x6C, 0x18, 0xF3, 0xD0, 0x8F, 0xEE, 0x1C, 0xB9, 0x6A, 0x3C, 0x8D, 0xE5, 0xD3, 0x53, 0x8A, 0xAA};
#endif
#define SECURITY_SERVICE_SCP03_KEY_VERSION_NO 0x0B

#if defined(EVT2_SE05X_IDENTIFY) && EVT2_SE05X_IDENTIFY
/* TEMPORARY DIAGNOSTIC (2026-09-26): which SE05x variant/OEF is on the board. security_service_init() connects,
 * reads the JCOP "IDENTIFY" data (GET DATA 80 CA 00 FE [DF 28], same as NXP's se05x_GetInfo demo) from the ISD and
 * returns WITHOUT any SCP03 authentication attempt. Read the result over SWD: OEF ID = g_se05x_identify[?] --
 * configuration ID bytes 2..3. No UART on this board, hence RAM. */
#include "global_platf.h"
#include "smCom.h"
volatile uint8_t g_se05x_identify[96];
volatile uint32_t g_se05x_identify_len;
volatile uint32_t g_se05x_identify_status;
volatile uint32_t g_se05x_applet_version; /* commState.appletVersion from SM_Connect: 0xMMmmpp00 */ /* 0x11 = connected, 0x22 = ISD selected, 0x9000.. = GET DATA SM status */
#endif

static Se05xSession_t s_session;

/* ---- Host-side random source -- see security_service_set_random_source() ---------------------------------------- */
static sec_random_source_t s_random_source;

void security_service_set_random_source(sec_random_source_t source)
{
    s_random_source = source;
}

static bool host_random(uint8_t *buf, size_t len)
{
    if (len == 0U) {
        return true;
    }
    if (s_random_source != NULL) {
        return s_random_source(buf, len);
    }
    return platform_rng_get_bytes(buf, len) == PLATFORM_OK; /* nothing registered: MCU TRNG */
}

/* Strong definition of the SE05x port's weak hook (Drivers/SE05x ... fsl_sss_user_impl.c): the SCP03 host challenge
 * drawn while security_service_init() authenticates takes the same random source as everything else here. */
bool se05x_port_host_random(uint8_t *buf, size_t len)
{
    return host_random(buf, len);
}

#if !SSS_HAVE_SE05X_VER_GTE_07_02
/* ---- Software ECDH (applet 3.x, e.g. the SE050F2 in FIPS mode) ---------------------------------------------------
 *
 * The SE050F2's applet refuses ECDH in every form (6985, AN12413 3.10 -- FIPS mode, fixed by NXP) and has no "ECDH into
 * an object" command at all, so an ephemeral EC key generated INSIDE the chip would be useless for key agreement. On this
 * applet the backend therefore keeps the per-call ephemeral ECDH key in MCU RAM instead and computes ECDH in software with
 * p256-m (Middleware/Security/p256-m, vendored verbatim, constant time). Only these calls are affected, and only for ids
 * that currently hold such a software key (see soft_ec_find()):
 *   security_service_generate_ephemeral_ec_keypair()  -> p256-m keypair in s_soft_ec[] (P-256 only)
 *   security_service_read_ec_public_key()             -> 0x04||X||Y from RAM
 *   security_service_ecdh_to_host()                   -> p256-m ECDH
 *   security_service_delete_key() / key_exists()      -> wipe / report the RAM slot
 * Everything else -- identity key, ECDSA, verify, HMAC, stored secrets -- still runs in the chip. The private scalar never
 * leaves s_soft_ec[] and is wiped on delete or when the slot is reused. security_service_derives_in_chip() reports false,
 * so callers know to derive on the host (see security_service.h).
 *
 * Randomness: the registered host random source (host_random(): QRNG first, MCU TRNG fallback -- see
 * security_service_set_random_source()). */
#include "p256-m/p256-m.h"

#define SOFT_EC_SLOTS 2U /* ca_protocol.c's ephemeral key + one more (app_self_test.c's simulated peer uses a second id) */

typedef struct {
    bool used;
    uint32_t id;
    uint8_t priv[32];
    uint8_t pub[64]; /* X||Y, big endian */
} soft_ec_slot_t;

static soft_ec_slot_t s_soft_ec[SOFT_EC_SLOTS];
static bool s_soft_ecdh_ok; /* set by soft_ecdh_self_test() at init; nothing software-ECDH runs unless it passed */

static void soft_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- != 0U) {
        *v++ = 0U;
    }
}

static soft_ec_slot_t *soft_ec_find(uint32_t id)
{
    for (size_t i = 0; i < SOFT_EC_SLOTS; i++) {
        if (s_soft_ec[i].used && s_soft_ec[i].id == id) {
            return &s_soft_ec[i];
        }
    }
    return NULL;
}

static void soft_ec_release(soft_ec_slot_t *slot)
{
    soft_wipe(slot, sizeof(*slot)); /* also clears `used` */
}

/* Required by p256-m (p256-m.h): cryptographically secure bytes. */
int p256_generate_random(uint8_t *output, unsigned output_size)
{
    return host_random(output, output_size) ? 0 : -1;
}

/* Known-answer test, RFC 5903 section 8.1 (P-256): both directions must give the published shared secret. Run once at
 * init; a failure keeps every software-ECDH call refusing (fail closed). Checked independently with Python's
 * `cryptography` before being written here. */
static bool soft_ecdh_self_test(void)
{
    static const uint8_t i_priv[32] = {
        0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31, 0x6D, 0xE5,
        0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57, 0x86, 0x2D, 0x14, 0x33};
    static const uint8_t i_pub[64] = {
        0xDA, 0xD0, 0xB6, 0x53, 0x94, 0x22, 0x1C, 0xF9, 0xB0, 0x51, 0xE1, 0xFE, 0xCA, 0x57, 0x87, 0xD0,
        0x98, 0xDF, 0xE6, 0x37, 0xFC, 0x90, 0xB9, 0xEF, 0x94, 0x5D, 0x0C, 0x37, 0x72, 0x58, 0x11, 0x80,
        0x52, 0x71, 0xA0, 0x46, 0x1C, 0xDB, 0x82, 0x52, 0xD6, 0x1F, 0x1C, 0x45, 0x6F, 0xA3, 0xE5, 0x9A,
        0xB1, 0xF4, 0x5B, 0x33, 0xAC, 0xCF, 0x5F, 0x58, 0x38, 0x9E, 0x05, 0x77, 0xB8, 0x99, 0x0B, 0xB3};
    static const uint8_t r_priv[32] = {
        0xC6, 0xEF, 0x9C, 0x5D, 0x78, 0xAE, 0x01, 0x2A, 0x01, 0x11, 0x64, 0xAC, 0xB3, 0x97, 0xCE, 0x20,
        0x88, 0x68, 0x5D, 0x8F, 0x06, 0xBF, 0x9B, 0xE0, 0xB2, 0x83, 0xAB, 0x46, 0x47, 0x6B, 0xEE, 0x53};
    static const uint8_t r_pub[64] = {
        0xD1, 0x2D, 0xFB, 0x52, 0x89, 0xC8, 0xD4, 0xF8, 0x12, 0x08, 0xB7, 0x02, 0x70, 0x39, 0x8C, 0x34,
        0x22, 0x96, 0x97, 0x0A, 0x0B, 0xCC, 0xB7, 0x4C, 0x73, 0x6F, 0xC7, 0x55, 0x44, 0x94, 0xBF, 0x63,
        0x56, 0xFB, 0xF3, 0xCA, 0x36, 0x6C, 0xC2, 0x3E, 0x81, 0x57, 0x85, 0x4C, 0x13, 0xC5, 0x8D, 0x6A,
        0xAC, 0x23, 0xF0, 0x46, 0xAD, 0xA3, 0x0F, 0x83, 0x53, 0xE7, 0x4F, 0x33, 0x03, 0x98, 0x72, 0xAB};
    static const uint8_t z_expected[32] = {
        0xD6, 0x84, 0x0F, 0x6B, 0x42, 0xF6, 0xED, 0xAF, 0xD1, 0x31, 0x16, 0xE0, 0xE1, 0x25, 0x65, 0x20,
        0x2F, 0xEF, 0x8E, 0x9E, 0xCE, 0x7D, 0xCE, 0x03, 0x81, 0x24, 0x64, 0xD0, 0x4B, 0x94, 0x42, 0xDE};
    uint8_t z1[32];
    uint8_t z2[32];
    bool ok = p256_ecdh_shared_secret(z1, i_priv, r_pub) == P256_SUCCESS &&
              p256_ecdh_shared_secret(z2, r_priv, i_pub) == P256_SUCCESS &&
              memcmp(z1, z_expected, 32U) == 0 && memcmp(z2, z_expected, 32U) == 0;
    /* A point that is not on the curve (i_pub with its last byte changed) must be refused. */
    uint8_t bad_pub[64];
    memcpy(bad_pub, i_pub, sizeof(bad_pub));
    bad_pub[63] ^= 0x01U;
    ok = ok && p256_ecdh_shared_secret(z1, r_priv, bad_pub) == P256_INVALID_PUBKEY;
    soft_wipe(z1, sizeof(z1));
    soft_wipe(z2, sizeof(z2));
    return ok;
}
#endif /* !SSS_HAVE_SE05X_VER_GTE_07_02 */

#if defined(EVT2_SE05X_STATE_DIAG) && EVT2_SE05X_STATE_DIAG
/* TEMPORARY DIAGNOSTIC (2026-09-27): why does the SE050F2 answer 6985 to every object creation? AN14028 table 1:
 * on SE050F a full memory ALSO returns 6985. Run once inside the authenticated session, results in RAM (read over
 * SWD, no UART on this board):
 *   g_d_mem[0..2]/g_d_mem_sw[0..2] = GetFreeMemory persistent / transient-reset / transient-deselect
 *   g_d_ver[..]/g_d_ver_len/g_d_ver_sw = raw GetVersion response (VersionInfo + SW)
 *   g_d_idl[..]/g_d_idl_len/g_d_idl_more/g_d_idl_sw = ReadIDList(filter = all): 4-byte ID + 1-byte type per entry
 *   g_d_write_sw/g_d_delete_sw = WriteBinary(16 B at 0x00000100) + delete, only tried if persistent free >= 512 B
 *   g_d_done = 0x600D0000 when finished */
#include "se05x_tlv.h"
volatile uint32_t g_d_mem[3];
volatile uint32_t g_d_mem_sw[3];
volatile uint8_t g_d_ver[16];
volatile uint32_t g_d_ver_len;
volatile uint32_t g_d_ver_sw;
volatile uint8_t g_d_idl[256];
volatile uint32_t g_d_idl_len;
volatile uint32_t g_d_idl_more;
volatile uint32_t g_d_idl_sw;
volatile uint32_t g_d_write_sw = 0xEEEEU;
volatile uint32_t g_d_delete_sw = 0xEEEEU;
volatile uint32_t g_d_done;

static void se05x_state_diag(void)
{
    /* Sequence test (2026-09-27): does a command WITHOUT a data field (GetVersion) break the commands after it?
     * g_d_mem_sw[0] = write #1 (before any no-data command), g_d_mem_sw[1] = delete #1,
     * g_d_mem_sw[2] = GetFreeMemory before, g_d_ver_sw = GetVersion (no data),
     * g_d_idl_sw = GetFreeMemory after, g_d_write_sw = write #2, g_d_delete_sw = delete #2 */
    static const uint8_t data[16] = {0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
                                     0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A};
    uint32_t free_mem = 0U;

    g_d_mem_sw[0] = Se05x_API_WriteBinary(&s_session, NULL, 0x00000100U, 0U, sizeof(data), data, sizeof(data));
    g_d_mem_sw[1] = (g_d_mem_sw[0] == SM_OK) ? Se05x_API_DeleteSecureObject(&s_session, 0x00000100U) : 0xEEEEU;

    g_d_mem_sw[2] = Se05x_API_GetFreeMemory(&s_session, kSE05x_MemoryType_PERSISTENT, &free_mem);
    g_d_mem[0] = free_mem;

    {
        tlvHeader_t hdr = {{kSE05x_CLA, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, kSE05x_P2_VERSION}};
        uint8_t cmd[4] = {0};
        uint8_t rsp[32] = {0};
        size_t rsp_len = sizeof(rsp);
        g_d_ver_sw = DoAPDUTxRx_s_Case2(&s_session, &hdr, cmd, 0, rsp, &rsp_len);
        g_d_ver_len = rsp_len;
        for (size_t i = 0; i < rsp_len && i < sizeof(g_d_ver); i++) {
            g_d_ver[i] = rsp[i];
        }
    }

    free_mem = 0U;
    g_d_idl_sw = Se05x_API_GetFreeMemory(&s_session, kSE05x_MemoryType_PERSISTENT, &free_mem);
    g_d_mem[1] = free_mem;

    g_d_write_sw = Se05x_API_WriteBinary(&s_session, NULL, 0x00000101U, 0U, sizeof(data), data, sizeof(data));
    g_d_delete_sw = (g_d_write_sw == SM_OK) ? Se05x_API_DeleteSecureObject(&s_session, 0x00000101U) : 0xEEEEU;

    g_d_done = 0x600D0000U;
}
#endif
static NXSCP03_DynCtx_t s_scp03DynCtx;
static bool s_ready;

static sec_status_t map_status(smStatus_t status)
{
    return (status == SM_OK) ? SEC_OK : SEC_ERROR;
}

static bool map_ec_curve(sec_ec_curve_t curve, SE05x_ECCurve_t *out)
{
    switch (curve) {
        case SEC_EC_CURVE_P256: *out = kSE05x_ECCurve_NIST_P256; return true;
        case SEC_EC_CURVE_P384: *out = kSE05x_ECCurve_NIST_P384; return true;
        case SEC_EC_CURVE_P521: *out = kSE05x_ECCurve_NIST_P521; return true;
        case SEC_EC_CURVE_BRAINPOOL256: *out = kSE05x_ECCurve_Brainpool256; return true;
        case SEC_EC_CURVE_BRAINPOOL384: *out = kSE05x_ECCurve_Brainpool384; return true;
        case SEC_EC_CURVE_BRAINPOOL512: *out = kSE05x_ECCurve_Brainpool512; return true;
        case SEC_EC_CURVE_SECP256K1: *out = kSE05x_ECCurve_Secp256k1; return true;
        default: return false;
    }
}

static bool map_rsa_bits(sec_rsa_key_bits_t key_bits, uint16_t *out_bits)
{
    switch (key_bits) {
        case SEC_RSA_2048: *out_bits = 2048; return true;
        case SEC_RSA_3072: *out_bits = 3072; return true;
        case SEC_RSA_4096: *out_bits = 4096; return true;
        default: return false;
    }
}

/* Uncompressed EC point length (0x04 || X || Y) for `curve`, 0 if unsupported. */
static size_t ec_point_len(SE05x_ECCurve_t curve)
{
    switch (curve) {
        case kSE05x_ECCurve_NIST_P256:
        case kSE05x_ECCurve_Brainpool256:
        case kSE05x_ECCurve_Secp256k1:
            return 65U;
        case kSE05x_ECCurve_NIST_P384:
        case kSE05x_ECCurve_Brainpool384:
            return 97U;
        case kSE05x_ECCurve_NIST_P521:
            return 133U;
        case kSE05x_ECCurve_Brainpool512:
            return 129U;
        default:
            return 0U;
    }
}

/* A Weierstrass curve must exist as an object on the chip before a key on
 * it can be written -- the chip keeps a per-curve "is set" list. NXP's own
 * sss_se05x_create_curve_if_needed() (fsl_sss_se05x_apis.c, read in full)
 * reads that list and creates the curve if missing; it also tolerates
 * SM_ERR_CONDITIONS_NOT_SATISFIED from the create call, mirrored here.
 * NIST P-256 is already set on this board, which is why P-256 key
 * generation always worked without this; the curves below (used to fail
 * with SW=0x6985) were never created. */
static bool ensure_ec_curve(SE05x_ECCurve_t curve)
{
    uint8_t list[kSE05x_ECCurve_Total_Weierstrass_Curves] = {0};
    size_t list_len = sizeof(list);

    if (Se05x_API_ReadECCurveList(&s_session, list, &list_len) != SM_OK) {
        return false;
    }
    size_t idx = (size_t)curve;
    if (idx == 0U || idx > list_len) {
        return false;
    }
    if (list[idx - 1U] == kSE05x_SetIndicator_SET) {
        return true;
    }

    smStatus_t status;
    switch (curve) {
        case kSE05x_ECCurve_NIST_P256: status = Se05x_API_CreateCurve_prime256v1(&s_session, curve); break;
        case kSE05x_ECCurve_NIST_P384: status = Se05x_API_CreateCurve_secp384r1(&s_session, curve); break;
        case kSE05x_ECCurve_NIST_P521: status = Se05x_API_CreateCurve_secp521r1(&s_session, curve); break;
        case kSE05x_ECCurve_Brainpool256: status = Se05x_API_CreateCurve_brainpoolP256r1(&s_session, curve); break;
        case kSE05x_ECCurve_Brainpool384: status = Se05x_API_CreateCurve_brainpoolP384r1(&s_session, curve); break;
        case kSE05x_ECCurve_Brainpool512: status = Se05x_API_CreateCurve_brainpoolP512r1(&s_session, curve); break;
        case kSE05x_ECCurve_Secp256k1: status = Se05x_API_CreateCurve_secp256k1(&s_session, curve); break;
        default: return false;
    }
    return status == SM_OK || status == SM_ERR_CONDITIONS_NOT_SATISFIED;
}

static bool is_public_key_type(SE05x_SecureObjectType_t type)
{
    unsigned t = (unsigned)type;
    /* Generic EC/RSA public-key types, plus the per-curve EC public-key
     * types (0x23, 0x27, ... 0x63 -- every one is == 3 mod 4 in
     * se05x_enums.h's SE05x_SecureObjectType_t). */
    return t == (unsigned)kSE05x_SecObjTyp_EC_PUB_KEY || t == (unsigned)kSE05x_SecObjTyp_RSA_PUB_KEY ||
           (t >= 0x23U && t <= 0x63U && (t & 0x03U) == 0x03U);
}

/* Make `key_id` ready for a public-key import: free slot is fine; an
 * existing PUBLIC key is replaced (deleted); anything else -- above all a
 * private key or key pair -- is refused, so a stray import can never wipe
 * this device's own signing key. */
static sec_status_t prepare_public_key_slot(uint32_t key_id)
{
    SE05x_Result_t exists = kSE05x_Result_NA;
    if (Se05x_API_CheckObjectExists(&s_session, key_id, &exists) != SM_OK) {
        return SEC_ERROR;
    }
    if (exists != kSE05x_Result_SUCCESS) {
        return SEC_OK;
    }

    SE05x_SecureObjectType_t type = kSE05x_SecObjTyp_NA;
    uint8_t is_transient = 0;
    if (Se05x_API_ReadType(&s_session, key_id, &type, &is_transient, kSE05x_AttestationType_None) != SM_OK) {
        return SEC_ERROR;
    }
    if (!is_public_key_type(type)) {
        return SEC_INVALID_PARAM;
    }
    return map_status(Se05x_API_DeleteSecureObject(&s_session, key_id));
}

/* digest_len: hash's raw output size. ec_algo: SE05x_API_ECDSASign/Verify's
 * algorithm selector for that hash. rsa_oid_last_byte: the one
 * hash-dependent byte of the RFC 8017 DigestInfo AlgorithmIdentifier OID
 * (1.2.840.113549.1.1.<...> at the ASN.1 level is SHA-2's actual OID
 * 2.16.840.1.101.3.4.2.<n> -- the shared 8-byte prefix is in
 * pkcs1_v15_encode() below); values cross-checked against NXP's own
 * pkcs1_v15_encode() in fsl_sss_util_rsa_sign_utils.c (oid[8] there), not
 * guessed. SHA-1 is deliberately not offered (deprecated, and its OID
 * prefix has a different shape/length than SHA-2's, which would complicate
 * pkcs1_v15_encode()'s fixed oid_size=9 assumption below for no real
 * benefit). */
/* digest_mode: SE05x_API_DigestOneShot()'s algorithm selector for that
 * hash -- only needed by RSA-PSS below (PKCS1_V15/ECDSA never hash on the
 * chip, they only take a caller-supplied digest). NOTE real-hardware
 * caveat found while adding PSS: se05x_enums.h marks
 * kSE05x_DigestMode_SHA224 "Not supported" in the vendor header's own
 * comment -- PSS with SEC_HASH_SHA224 may therefore fail on this chip
 * (surfaces as a plain SEC_ERROR from the DigestOneShot call inside
 * emsa_pss_encode/verify below, not a crash); not yet exercised on real
 * hardware since the stated requirement only calls for SHA-256. */
static bool hash_digest_info(sec_hash_t hash, size_t *digest_len, SE05x_ECSignatureAlgo_t *ec_algo,
    uint8_t *rsa_oid_last_byte, SE05x_DigestMode_t *digest_mode)
{
    switch (hash) {
        case SEC_HASH_SHA224:
            *digest_len = 28;
            *ec_algo = kSE05x_ECSignatureAlgo_SHA_224;
            *rsa_oid_last_byte = 0x04;
            *digest_mode = kSE05x_DigestMode_SHA224;
            return true;
        case SEC_HASH_SHA256:
            *digest_len = 32;
            *ec_algo = kSE05x_ECSignatureAlgo_SHA_256;
            *rsa_oid_last_byte = 0x01;
            *digest_mode = kSE05x_DigestMode_SHA256;
            return true;
        case SEC_HASH_SHA384:
            *digest_len = 48;
            *ec_algo = kSE05x_ECSignatureAlgo_SHA_384;
            *rsa_oid_last_byte = 0x02;
            *digest_mode = kSE05x_DigestMode_SHA384;
            return true;
        case SEC_HASH_SHA512:
            *digest_len = 64;
            *ec_algo = kSE05x_ECSignatureAlgo_SHA_512;
            *rsa_oid_last_byte = 0x03;
            *digest_mode = kSE05x_DigestMode_SHA512;
            return true;
        default:
            return false;
    }
}

/* Largest RSA modulus this backend supports (SEC_RSA_4096 = 4096/8 bytes) --
 * sizes the on-stack scratch buffers below. */
#define SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES 512U

/* RFC 8017 EMSA-PKCS1-v1_5-ENCODE: em = 0x00 || 0x01 || PS(0xFF..) || 0x00
 * || T, where T is the DER-encoded DigestInfo. Re-derives the exact same
 * byte shape as NXP's own pkcs1_v15_encode() (fsl_sss_util_rsa_sign_utils.c,
 * read in full before writing this) for SHA-224/256/384/512 (oid_size == 9
 * for all four, confirmed there), but built directly against RFC 8017
 * rather than sharing code with a file this project doesn't vendor. */
static bool pkcs1_v15_encode(uint8_t rsa_oid_last_byte, const uint8_t *digest, size_t digest_len, uint8_t *em,
    size_t em_len)
{
    static const uint8_t oid_prefix[8] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02};
    const size_t oid_size = sizeof(oid_prefix) + 1U; /* +1 hash-specific byte */
    const size_t t_len = 10U + oid_size + digest_len; /* DigestInfo, incl. its own SEQUENCE header */

    if (em_len < t_len + 3U + 8U) { /* +3 header/separator bytes, +>=8 padding bytes (RFC 8017 minimum) */
        return false;
    }
    size_t pad_len = em_len - t_len - 3U;

    uint8_t *p = em;
    *p++ = 0x00;
    *p++ = 0x01;
    memset(p, 0xFF, pad_len);
    p += pad_len;
    *p++ = 0x00;
    *p++ = 0x30; /* DigestInfo SEQUENCE */
    *p++ = (uint8_t)(0x08U + oid_size + digest_len);
    *p++ = 0x30; /* AlgorithmIdentifier SEQUENCE */
    *p++ = (uint8_t)(0x04U + oid_size);
    *p++ = 0x06; /* OID */
    *p++ = (uint8_t)oid_size;
    memcpy(p, oid_prefix, sizeof(oid_prefix));
    p += sizeof(oid_prefix);
    *p++ = rsa_oid_last_byte;
    *p++ = 0x05; /* NULL */
    *p++ = 0x00;
    *p++ = 0x04; /* OCTET STRING */
    *p++ = (uint8_t)digest_len;
    memcpy(p, digest, digest_len);
    p += digest_len;

    return (size_t)(p - em) == em_len;
}

/* Largest hash this backend offers (SHA-512) -- also PSS's salt length,
 * since this backend fixes saltLen == hLen (RFC 8017's common default,
 * matching NXP's own emsa_encode() below). */
#define SECURITY_SERVICE_HASH_MAX_LEN 64U

/* RFC 8017 MGF1, XORing `dlen` mask bytes into `dst` in place. Mirrors
 * NXP's sss_mgf_mask_func() (fsl_sss_util_rsa_sign_utils.c, read in full
 * before writing this) byte-for-byte: a 4-byte big-endian counter
 * appended to `seed` (of `hash_len` bytes) is hashed once per
 * hash_len-sized mask block (the last block may be partial), each block
 * XORed into `dst` as it's produced -- except the reference computes each
 * block via a *streaming* host hash context (its `sss_digest_update()`
 * calls), which this firmware has no equivalent for; a small stack
 * buffer holding `seed || counter` and one Se05x_API_DigestOneShot() call
 * per block produces the identical result (the reference's own one-shot
 * RSA-sign path, pkcs1_v15_encode(), makes the same host/chip split, just
 * for a different hash call). */
static bool mgf1_mask(uint8_t *dst, size_t dlen, const uint8_t *seed, size_t hash_len, SE05x_DigestMode_t mode)
{
    uint8_t counter[4] = {0, 0, 0, 0};
    uint8_t seed_buf[SECURITY_SERVICE_HASH_MAX_LEN + 4U];
    uint8_t mask[SECURITY_SERVICE_HASH_MAX_LEN];

    memcpy(seed_buf, seed, hash_len);

    while (dlen > 0U) {
        size_t use_len = (dlen < hash_len) ? dlen : hash_len;
        memcpy(seed_buf + hash_len, counter, 4U);

        size_t mask_len = sizeof(mask);
        smStatus_t status =
            Se05x_API_DigestOneShot(&s_session, (uint8_t)mode, seed_buf, hash_len + 4U, mask, &mask_len);
        if (status != SM_OK || mask_len < use_len) {
            return false;
        }

        for (size_t i = 0; i < use_len; i++) {
            dst[i] ^= mask[i];
        }
        dst += use_len;
        dlen -= use_len;

        for (int i = 3; i >= 0; i--) {
            if (++counter[i] != 0U) {
                break;
            }
        }
    }
    return true;
}

/* RFC 8017 EMSA-PSS-ENCODE (Section 9.1.1), saltLen == hash_len. Mirrors
 * NXP's emsa_encode() (same source file, read in full before writing
 * this) field-for-field: `em` (the caller's zeroed, key-size-length
 * output buffer) doubles as DB = PS || 0x01 || salt while it's being
 * built -- the leading PS zero run is never written because the caller
 * already zeroed `em`, exactly like the reference relies on its own
 * pre-zeroed output buffer. `em_len` must equal the RSA modulus size in
 * bytes (a byte-aligned quantity for every key size this backend offers,
 * so only em[0]'s single top bit ever needs clearing below -- the
 * general RFC formula degrades to that for any byte-aligned modulus). */
static bool emsa_pss_encode(
    SE05x_DigestMode_t mode, size_t hash_len, const uint8_t *mhash, uint8_t *em, size_t em_len)
{
    if (em_len < 2U * hash_len + 2U || hash_len > SECURITY_SERVICE_HASH_MAX_LEN) {
        return false;
    }

    uint8_t salt[SECURITY_SERVICE_HASH_MAX_LEN];
    if (!host_random(salt, hash_len)) {
        return false;
    }

    size_t db_len = em_len - hash_len - 1U; /* PS || 0x01 || salt */
    size_t ps_len = db_len - hash_len - 1U;

    /* em[0 .. ps_len-1] is PS -- already 0 (caller-zeroed). */
    em[ps_len] = 0x01;
    memcpy(em + ps_len + 1U, salt, hash_len);

    uint8_t m_prime[8U + 2U * SECURITY_SERVICE_HASH_MAX_LEN]; /* 0x00*8 || mHash || salt */
    memset(m_prime, 0, 8U);
    memcpy(m_prime + 8U, mhash, hash_len);
    memcpy(m_prime + 8U + hash_len, salt, hash_len);

    uint8_t *h_out = em + db_len; /* H goes immediately after DB */
    size_t h_len = hash_len;
    smStatus_t status = Se05x_API_DigestOneShot(&s_session, (uint8_t)mode, m_prime, 8U + 2U * hash_len, h_out, &h_len);
    if (status != SM_OK || h_len != hash_len) {
        return false;
    }

    if (!mgf1_mask(em, db_len, h_out, hash_len, mode)) {
        return false;
    }
    em[0] &= 0x7FU; /* clear the top bit (byte-aligned modulus, see doc comment above) */

    em[em_len - 1U] = 0xBC;
    return true;
}

/* RFC 8017 EMSA-PSS-VERIFY (Section 9.1.2), saltLen == hash_len. Mirrors
 * NXP's emsa_decode_and_compare() field-for-field, including its
 * tolerant scan for the PS/0x01 boundary rather than assuming a fixed
 * position. `em` is the recovered block (Se05x_API_RSAEncrypt's NO_PAD
 * output on the signature, i.e. the raw public-key primitive undoing the
 * signature) -- it is modified in place (unmasked) as scratch space, same
 * as the reference's own `buf`. */
static bool emsa_pss_verify(SE05x_DigestMode_t mode, size_t hash_len, const uint8_t *mhash, uint8_t *em,
    size_t em_len)
{
    if (em_len < hash_len + 2U || hash_len > SECURITY_SERVICE_HASH_MAX_LEN || em[em_len - 1U] != 0xBC) {
        return false;
    }
    if ((em[0] & 0x80U) != 0U) {
        return false;
    }

    size_t db_len = em_len - hash_len - 1U;
    uint8_t *h_in_em = em + db_len;

    if (!mgf1_mask(em, db_len, h_in_em, hash_len, mode)) {
        return false;
    }
    em[0] &= 0x7FU;

    size_t i = 0;
    while (i < db_len - 1U && em[i] == 0U) {
        i++;
    }
    if (em[i] != 0x01U) {
        return false;
    }
    i++;
    size_t salt_len = db_len - i;
    if (salt_len > SECURITY_SERVICE_HASH_MAX_LEN) {
        return false;
    }
    const uint8_t *salt = em + i;

    uint8_t m_prime[8U + 2U * SECURITY_SERVICE_HASH_MAX_LEN];
    memset(m_prime, 0, 8U);
    memcpy(m_prime + 8U, mhash, hash_len);
    memcpy(m_prime + 8U + hash_len, salt, salt_len);

    uint8_t h_computed[SECURITY_SERVICE_HASH_MAX_LEN];
    size_t h_computed_len = sizeof(h_computed);
    smStatus_t status = Se05x_API_DigestOneShot(
        &s_session, (uint8_t)mode, m_prime, 8U + hash_len + salt_len, h_computed, &h_computed_len);
    if (status != SM_OK || h_computed_len != hash_len) {
        return false;
    }

    return memcmp(h_in_em, h_computed, hash_len) == 0;
}

sec_status_t security_service_init(void)
{
    if (s_ready) {
        return SEC_OK;
    }

    SmCommState_t commState;
    U8 atr[64];
    U16 atrLen = sizeof(atr);
    U16 status;
    Se05x_Scp03StaticKeys_t scp03Keys;
    sss_status_t scpStatus;

    axReset_HostConfigure();
    axReset_ResetPulseDUT(SE_RESET_LOGIC);
    sm_sleep(5);

    memset(&commState, 0, sizeof(commState));
    commState.select = SELECT_APPLET;

    status = SM_Connect(NULL, &commState, atr, &atrLen);
    if (status != SW_OK) {
        return SEC_ERROR;
    }

#if defined(EVT2_SE05X_IDENTIFY) && EVT2_SE05X_IDENTIFY
    {
        static const uint8_t get_identify[] = { 0x80, 0xCA, 0x00, 0xFE, 0x02, 0xDF, 0x28, 0x00 };
        uint8_t rsp[96] = { 0 };
        U16 sel_len = sizeof(rsp);
        U32 rsp_len = sizeof(rsp);
        g_se05x_identify_status = 0x11U;
        g_se05x_applet_version = commState.appletVersion;
        if (GP_Select(NULL, rsp, 0, rsp, &sel_len) == SM_OK) {
            g_se05x_identify_status = 0x22U;
            memset(rsp, 0, sizeof(rsp));
            U32 st = smCom_TransceiveRaw(NULL, (U8 *)get_identify, sizeof(get_identify), rsp, &rsp_len);
            g_se05x_identify_status = st;
            if (st == SM_OK) {
                for (U32 i = 0; i < rsp_len && i < sizeof(g_se05x_identify); i++) {
                    g_se05x_identify[i] = rsp[i];
                }
                g_se05x_identify_len = rsp_len;
            }
        }
        SM_Close(NULL, 0);
        return SEC_ERROR; /* never try SCP03 in this build */
    }
#endif
    Se05x_SessionInit(&s_session, NULL);

    scp03Keys.encKey = s_scp03EncKey;
    scp03Keys.macKey = s_scp03MacKey;
    scp03Keys.keyVerNo = SECURITY_SERVICE_SCP03_KEY_VERSION_NO;

    scpStatus = Se05x_Scp03_Authenticate(&s_session, &scp03Keys, &s_scp03DynCtx);
    if (scpStatus != kStatus_SSS_Success) {
        SM_Close(NULL, 0);
        return SEC_ERROR;
    }

    s_ready = true;
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    s_soft_ecdh_ok = soft_ecdh_self_test();
#endif
#if defined(EVT2_SE05X_STATE_DIAG) && EVT2_SE05X_STATE_DIAG
    se05x_state_diag();
#endif
    return SEC_OK;
}

sec_status_t security_service_deinit(void)
{
    if (!s_ready) {
        return SEC_OK;
    }

    SM_Close(NULL, 0);
    s_ready = false;
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    for (size_t i = 0; i < SOFT_EC_SLOTS; i++) {
        soft_ec_release(&s_soft_ec[i]);
    }
#endif
    return SEC_OK;
}

bool security_service_is_ready(void)
{
    return s_ready;
}

sec_status_t security_service_get_random(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0 || len > 0xFFFFU) {
        return SEC_INVALID_PARAM;
    }
    /* No chip needed: the registered random source (QRNG first, MCU TRNG fallback), not the secure element's DRBG. */
    return host_random(buf, len) ? SEC_OK : SEC_ERROR;
}

sec_status_t security_service_ensure_ec_keypair(uint32_t key_id)
{
    return security_service_ensure_ec_keypair_ex(key_id, SEC_EC_CURVE_P256);
}

sec_status_t security_service_ensure_ec_keypair_ex(uint32_t key_id, sec_ec_curve_t curve)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }

    SE05x_ECCurve_t se_curve;
    if (!map_ec_curve(curve, &se_curve)) {
        return SEC_INVALID_PARAM;
    }

    SE05x_Result_t exists = kSE05x_Result_NA;
    smStatus_t status = Se05x_API_CheckObjectExists(&s_session, key_id, &exists);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    if (exists == kSE05x_Result_SUCCESS) {
        return SEC_OK;
    }

    if (!ensure_ec_curve(se_curve)) {
        return SEC_ERROR;
    }

    /* NULL priv/pub key value + P1_KEY_PAIR => key pair is generated
     * inside the SE052F; the private key never leaves the chip.
     *
     * History worth keeping: an earlier version called WriteECKey without
     * ensure_ec_curve() above, so every curve except P-256 (already set on
     * this board) failed with SW=0x6985, and that was WRONGLY written up as
     * an SE052F SKU restriction. The real cause was that the curve object
     * did not exist on the chip yet. With ensure_ec_curve(), all seven
     * offered curves (P-256/384/521, Brainpool 256/384/512, secp256k1)
     * generate keys on this board -- verified on real hardware. */
    status = Se05x_API_WriteECKey(&s_session,
        NULL,
        0,
        key_id,
        se_curve,
        NULL,
        0,
        NULL,
        0,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
    return map_status(status);
}

sec_status_t security_service_ensure_rsa_keypair(uint32_t key_id, sec_rsa_key_bits_t key_bits)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }

    uint16_t bits;
    if (!map_rsa_bits(key_bits, &bits)) {
        return SEC_INVALID_PARAM;
    }

    SE05x_Result_t exists = kSE05x_Result_NA;
    smStatus_t status = Se05x_API_CheckObjectExists(&s_session, key_id, &exists);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    if (exists == kSE05x_Result_SUCCESS) {
        return SEC_OK;
    }

    /* All key-component args NULL/0 (SE05X_RSA_NO_*) + P1_KEY_PAIR => key
     * pair generated inside the SE052F, same on-chip-generation pattern as
     * security_service_ensure_ec_keypair_ex() above -- shape verified
     * against NXP's own sss_se05x_key_store_generate_key() RSA branch in
     * fsl_sss_se05x_apis.c before writing this.
     *
     * Verified on real hardware for 2048 AND 4096 bits (SW=0x9000 both
     * times, unlike the EC curve restriction above -- RSA is NOT
     * similarly gated on this chip instance). This call BLOCKS the
     * firmware's single main loop for its entire duration -- measured
     * ~20s for a 4096-bit key on real hardware (RSA prime search timing
     * varies run to run) -- during which no other USB command gets a
     * reply. Callers must budget a generous timeout, and this is not
     * something to call from any latency-sensitive path (e.g. mid video
     * call); it's a one-time provisioning operation. */
    status = Se05x_API_WriteRSAKey(&s_session,
        NULL,
        key_id,
        bits,
        SE05X_RSA_NO_p,
        SE05X_RSA_NO_q,
        SE05X_RSA_NO_dp,
        SE05X_RSA_NO_dq,
        SE05X_RSA_NO_qInv,
        SE05X_RSA_NO_pubExp,
        SE05X_RSA_NO_priv,
        SE05X_RSA_NO_pubMod,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair,
        kSE05x_RSAKeyFormat_CRT);
    return map_status(status);
}

sec_status_t security_service_read_ec_public_key(uint32_t key_id, uint8_t *point, size_t *point_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (point == NULL || point_len == NULL) {
        return SEC_INVALID_PARAM;
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    const soft_ec_slot_t *slot = soft_ec_find(key_id);
    if (slot != NULL) { /* software ephemeral key -- see "Software ECDH" */
        if (*point_len < 65U) {
            return SEC_INVALID_PARAM;
        }
        point[0] = 0x04U;
        memcpy(&point[1], slot->pub, sizeof(slot->pub));
        *point_len = 65U;
        return SEC_OK;
    }
#endif

    /* offset=0, length=0 => whole object, same convention as
     * security_service_load_secret() above. On an EC key the chip returns
     * only the public point, never the private scalar (NXP's own
     * sss_se05x_key_store_get_key() reads EC keys exactly this way). */
    return map_status(Se05x_API_ReadObject(&s_session, key_id, 0, 0, point, point_len));
}

sec_status_t security_service_import_ec_public_key(
    uint32_t key_id, sec_ec_curve_t curve, const uint8_t *point, size_t point_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (point == NULL) {
        return SEC_INVALID_PARAM;
    }

    SE05x_ECCurve_t se_curve;
    if (!map_ec_curve(curve, &se_curve)) {
        return SEC_INVALID_PARAM;
    }
    if (point_len != ec_point_len(se_curve) || point[0] != 0x04U) {
        return SEC_INVALID_PARAM; /* only the uncompressed 0x04||X||Y form, exactly the curve's size */
    }

    if (!ensure_ec_curve(se_curve)) {
        return SEC_ERROR;
    }
    sec_status_t prep = prepare_public_key_slot(key_id);
    if (prep != SEC_OK) {
        return prep;
    }

    return map_status(Se05x_API_WriteECKey(&s_session,
        NULL,
        0,
        key_id,
        se_curve,
        NULL,
        0,
        point,
        point_len,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Public));
}

sec_status_t security_service_import_ec_keypair(
    uint32_t key_id, sec_ec_curve_t curve, const uint8_t *priv, size_t priv_len, const uint8_t *pub, size_t pub_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (priv == NULL || pub == NULL) {
        return SEC_INVALID_PARAM;
    }

    SE05x_ECCurve_t se_curve;
    if (!map_ec_curve(curve, &se_curve)) {
        return SEC_INVALID_PARAM;
    }
    /* Private scalar is half of the uncompressed point minus the 0x04 tag: (pub_len - 1) / 2 bytes. */
    if (pub_len != ec_point_len(se_curve) || pub[0] != 0x04U || priv_len != (pub_len - 1U) / 2U) {
        return SEC_INVALID_PARAM;
    }

    if (security_service_key_exists(key_id)) {
        return SEC_ERROR; /* never overwrite by accident -- the caller deletes deliberately */
    }
    if (!ensure_ec_curve(se_curve)) {
        return SEC_ERROR;
    }

    /* P1 = KEY_PAIR with BOTH halves supplied. (KEY_PAIR with only the private half is rejected, SW=0x6985 -- see
     * docs/qrng_identity_key_import_experiment.md.) */
    return map_status(Se05x_API_WriteECKey(&s_session,
        NULL,
        0,
        key_id,
        se_curve,
        priv,
        priv_len,
        pub,
        pub_len,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair));
}

sec_status_t security_service_read_unique_id(uint8_t uid[SEC_UNIQUE_ID_LEN])
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (uid == NULL) {
        return SEC_INVALID_PARAM;
    }
    size_t len = SEC_UNIQUE_ID_LEN;
    sec_status_t st = map_status(Se05x_API_ReadObject(&s_session, kSE05x_AppletResID_UNIQUE_ID, 0, 0, uid, &len));
    return (st == SEC_OK && len != SEC_UNIQUE_ID_LEN) ? SEC_ERROR : st;
}

bool security_service_derives_in_chip(void)
{
#if SSS_HAVE_SE05X_VER_GTE_07_02
    return true;
#else
    return false;
#endif
}

sec_status_t security_service_generate_ephemeral_ec_keypair(uint32_t key_id, sec_ec_curve_t curve)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    /* Software key in MCU RAM -- see "Software ECDH" above. */
    if (curve != SEC_EC_CURVE_P256) {
        return SEC_INVALID_PARAM;
    }
    if (!s_soft_ecdh_ok) {
        return SEC_ERROR;
    }
    soft_ec_slot_t *slot = soft_ec_find(key_id);
    if (slot == NULL) {
        for (size_t i = 0; i < SOFT_EC_SLOTS && slot == NULL; i++) {
            if (!s_soft_ec[i].used) {
                slot = &s_soft_ec[i];
            }
        }
        if (slot == NULL) {
            return SEC_ERROR; /* all slots taken: a caller forgot to delete its ephemeral key */
        }
    }
    soft_ec_release(slot);
    if (p256_gen_keypair(slot->priv, slot->pub) != P256_SUCCESS) {
        soft_ec_release(slot);
        return SEC_ERROR;
    }
    slot->id = key_id;
    slot->used = true;
    return SEC_OK;
#else
    SE05x_ECCurve_t se_curve;
    if (!map_ec_curve(curve, &se_curve)) {
        return SEC_INVALID_PARAM;
    }
    if (security_service_key_exists(key_id) && Se05x_API_DeleteSecureObject(&s_session, key_id) != SM_OK) {
        return SEC_ERROR;
    }
    if (!ensure_ec_curve(se_curve)) {
        return SEC_ERROR;
    }
    /* NULL priv/pub + KEY_PAIR = generate on chip; INS_TRANSIENT = RAM-only object, no NVM write. */
    return map_status(Se05x_API_WriteECKey(&s_session, NULL, 0, key_id, se_curve, NULL, 0, NULL, 0, kSE05x_INS_TRANSIENT,
                                           kSE05x_KeyPart_Pair));
#endif
}

#if SSS_HAVE_SE05X_VER_GTE_07_02 /* only the in-chip ECDH/HKDF variants use it; applet 3.x has neither */
/* Create an empty transient HMAC-key object of exactly `len` bytes at `id` (deleting whatever was there): ECDH/HKDF can only
 * store their result into an object that already exists with the exact output size. The placeholder value is overwritten
 * inside the chip by the operation that fills it. */
static sec_status_t create_transient_secret_object(uint32_t id, size_t len)
{
    static const uint8_t placeholder[64] = {0};
    if (len == 0U || len > sizeof(placeholder)) {
        return SEC_INVALID_PARAM;
    }
    if (security_service_key_exists(id) && Se05x_API_DeleteSecureObject(&s_session, id) != SM_OK) {
        return SEC_ERROR;
    }
    return map_status(Se05x_API_WriteSymmKey(&s_session, NULL, 0, id, SE05x_KeyID_KEK_NONE, placeholder, len,
                                             kSE05x_INS_TRANSIENT, kSE05x_SymmKeyType_HMAC));
}
#endif

sec_status_t security_service_ecdh_to_secret(uint32_t ec_key_id, const uint8_t *peer_point, size_t peer_len,
                                             uint32_t secret_id)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (peer_point == NULL || peer_len != 65U || peer_point[0] != 0x04U) {
        return SEC_INVALID_PARAM; /* P-256 only for now */
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    /* Applet 3.x (e.g. the SE050F2 on the STM32H7S3V8Y6TR board) has no "ECDH into a secure object" command (and
     * refuses ECDH altogether in FIPS mode). security_service_derives_in_chip() is false here: callers compute ECDH
     * with security_service_ecdh_to_host() (software, see "Software ECDH") and derive on the host instead. */
    (void)ec_key_id;
    (void)secret_id;
    return SEC_ERROR;
#else
    sec_status_t st = create_transient_secret_object(secret_id, 32U);
    if (st != SEC_OK) {
        return st;
    }
    st = map_status(Se05x_API_ECDHGenerateSharedSecret_InObject(&s_session, ec_key_id, peer_point, peer_len, secret_id, 0));
    if (st != SEC_OK) {
        (void)Se05x_API_DeleteSecureObject(&s_session, secret_id); /* do not leave an all-zero "secret" behind */
    }
    return st;
#endif
}

static bool hkdf_args_ok(const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len)
{
    return info != NULL && info_len >= 1U && info_len <= 80U && salt_len <= 64U && (salt != NULL || salt_len == 0U);
}

sec_status_t security_service_hkdf_to_secret(uint32_t ikm_id, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                                             size_t info_len, uint32_t out_id, size_t out_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (!hkdf_args_ok(salt, salt_len, info, info_len)) {
        return SEC_INVALID_PARAM;
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    /* Applet 3.x (SE050F2): its HKDF (AN12413 4.14.1) only returns the output to the host -- there is no "derive into
     * a secure object" form -- so this in-chip variant is not available. security_service_hkdf_export() works. */
    (void)out_id;
    (void)out_len;
    return SEC_ERROR;
#else
    sec_status_t st = create_transient_secret_object(out_id, out_len);
    if (st != SEC_OK) {
        return st;
    }
    st = map_status(Se05x_API_HKDF_Extended(&s_session, ikm_id, kSE05x_DigestMode_SHA256, kSE05x_HkdfMode_ExtractExpand, salt,
                                            salt_len, 0, info, info_len, out_id, (uint16_t)out_len, NULL, NULL));
    if (st != SEC_OK) {
        (void)Se05x_API_DeleteSecureObject(&s_session, out_id);
    }
    return st;
#endif
}

sec_status_t security_service_hkdf_export(uint32_t ikm_id, const uint8_t *salt, size_t salt_len, const uint8_t *info,
                                          size_t info_len, uint8_t *out, size_t out_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (out == NULL || out_len == 0U || out_len > 128U || !hkdf_args_ok(salt, salt_len, info, info_len)) {
        return SEC_INVALID_PARAM;
    }
    size_t got = out_len;
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    /* Applet 3.x HKDF (AN12413 4.14.1): extract-and-expand only, output returned to the host. HKDF_Extended (applet
     * 7.x, extra mode/salt-object/target TLVs) is answered with 6A80 there. */
    sec_status_t st = map_status(Se05x_API_HKDF(&s_session, ikm_id, kSE05x_DigestMode_SHA256, salt, salt_len, info, info_len,
                                                (uint16_t)out_len, out, &got));
#else
    sec_status_t st = map_status(Se05x_API_HKDF_Extended(&s_session, ikm_id, kSE05x_DigestMode_SHA256,
                                                         kSE05x_HkdfMode_ExtractExpand, salt, salt_len, 0, info, info_len, 0,
                                                         (uint16_t)out_len, out, &got));
#endif
    return (st == SEC_OK && got != out_len) ? SEC_ERROR : st;
}

sec_status_t security_service_hmac_sha256_with_secret(uint32_t key_id, const uint8_t *data, size_t data_len, uint8_t mac[32])
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (data == NULL || data_len == 0U || mac == NULL) {
        return SEC_INVALID_PARAM;
    }
    size_t mac_len = 32U;
    sec_status_t st = map_status(Se05x_API_MACOneShot_G(&s_session, key_id, kSE05x_MACAlgo_HMAC_SHA256, data, data_len, mac, &mac_len));
    return (st == SEC_OK && mac_len != 32U) ? SEC_ERROR : st;
}

sec_status_t security_service_ecdh_to_host(uint32_t ec_key_id, const uint8_t *peer_point, size_t peer_len, uint8_t z_out[32])
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (peer_point == NULL || peer_len != 65U || peer_point[0] != 0x04U || z_out == NULL) {
        return SEC_INVALID_PARAM; /* P-256 only, same restriction as security_service_ecdh_to_secret() */
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    /* The chip refuses ECDH (6985): only software ephemeral keys can do it -- see "Software ECDH". */
    const soft_ec_slot_t *slot = soft_ec_find(ec_key_id);
    if (slot == NULL || !s_soft_ecdh_ok) {
        return SEC_ERROR;
    }
    int r = p256_ecdh_shared_secret(z_out, slot->priv, &peer_point[1]);
    if (r != P256_SUCCESS) {
        soft_wipe(z_out, 32U);
        return (r == P256_INVALID_PUBKEY) ? SEC_INVALID_PARAM : SEC_ERROR;
    }
    return SEC_OK;
#else
    size_t got = 32U;
    sec_status_t st = map_status(Se05x_API_ECDHGenerateSharedSecret(&s_session, ec_key_id, peer_point, peer_len, z_out, &got));
    return (st == SEC_OK && got != 32U) ? SEC_ERROR : st;
#endif
}

#if defined(EVT2_SE05X_HKDF_CASES) && EVT2_SE05X_HKDF_CASES
/* TEMPORARY (2026-09-27): which condition makes the SE050F2 answer 6985 to HKDF (AN14028 says applet 3.6 has HKDF).
 * Runs 8 cases on scratch object 0x7E000070 and records the raw SW (Se05x_API_HKDF returns it directly):
 *   g_hkdf_case_sw[c], g_hkdf_case_wr[c] (SW of the key write), g_hkdf_case_out[c][0..63], g_hkdf_free_transient. */
#include "se05x_const.h"
volatile uint32_t g_hkdf_case_sw[8];
volatile uint32_t g_hkdf_case_wr[8];
volatile uint8_t g_hkdf_case_out[8][64];
volatile uint32_t g_hkdf_free_transient;
volatile uint32_t g_hkdf_cases_done;

void security_service_debug_hkdf_cases(void)
{
    static const struct {
        uint8_t transient, policy, key_len;
        SE05x_DigestMode_t digest;
        uint8_t salt, info_len, out_len;
    } c[8] = {
        {1, 0, 32, kSE05x_DigestMode_SHA256, 0, 4, 32},  /* c0 baseline, like the earlier probe */
        {1, 1, 32, kSE05x_DigestMode_SHA256, 0, 4, 32},  /* c1 explicit policy incl. ALLOW_KDF */
        {0, 1, 32, kSE05x_DigestMode_SHA256, 0, 4, 32},  /* c2 persistent + policy */
        {1, 0, 16, kSE05x_DigestMode_SHA256, 0, 4, 32},  /* c3 16-byte key */
        {1, 0, 64, kSE05x_DigestMode_SHA256, 0, 4, 32},  /* c4 64-byte key */
        {1, 0, 32, kSE05x_DigestMode_SHA384, 0, 4, 48},  /* c5 SHA-384 */
        {1, 0, 32, kSE05x_DigestMode_SHA512, 0, 4, 64},  /* c6 SHA-512 */
        {1, 0, 32, kSE05x_DigestMode_SHA256, 1, 32, 64}, /* c7 32-byte salt, 32-byte info, L = 64 */
    };
    const uint32_t id = 0x7E000070U;
    uint8_t key[64], salt[32], info[32], out[64];
    for (size_t i = 0; i < 64U; i++) {
        key[i] = (uint8_t)(0xA0U + i);
    }
    for (size_t i = 0; i < 32U; i++) {
        salt[i] = (uint8_t)i;
        info[i] = (uint8_t)(0x40U + i);
    }
    memcpy(info, "info", 4);
    uint32_t free_mem = 0U;
    (void)Se05x_API_GetFreeMemory(&s_session, kSE05x_MemoryType_TRANSIENT_RESET, &free_mem);
    g_hkdf_free_transient = free_mem;
    /* policy: [len 8][auth object 0 = default session][access rules] */
    const uint32_t ar = POLICY_OBJ_ALLOW_KDF | POLICY_OBJ_ALLOW_SIGN | POLICY_OBJ_ALLOW_VERIFY | POLICY_OBJ_ALLOW_DELETE;
    uint8_t pol[9] = {8, 0, 0, 0, 0, (uint8_t)(ar >> 24), (uint8_t)(ar >> 16), (uint8_t)(ar >> 8), (uint8_t)ar};
    Se05xPolicy_t policy = {pol, sizeof(pol)};
    for (size_t k = 0; k < 8U; k++) {
        if (security_service_key_exists(id)) {
            (void)Se05x_API_DeleteSecureObject(&s_session, id);
        }
        g_hkdf_case_wr[k] = Se05x_API_WriteSymmKey(&s_session, c[k].policy ? &policy : NULL, 0, id, SE05x_KeyID_KEK_NONE,
                                                   key, c[k].key_len,
                                                   c[k].transient ? kSE05x_INS_TRANSIENT : kSE05x_INS_NA,
                                                   kSE05x_SymmKeyType_HMAC);
        memset(out, 0, sizeof(out));
        size_t got = sizeof(out);
        g_hkdf_case_sw[k] = Se05x_API_HKDF(&s_session, id, c[k].digest, c[k].salt ? salt : NULL, c[k].salt ? 32U : 0U,
                                           info, c[k].info_len, c[k].out_len, out, &got);
        for (size_t i = 0; i < 64U; i++) {
            g_hkdf_case_out[k][i] = out[i];
        }
    }
    if (security_service_key_exists(id)) {
        (void)Se05x_API_DeleteSecureObject(&s_session, id);
    }
    g_hkdf_cases_done = 0x600DCA5EU;
}
#endif

#if defined(EVT2_SE05X_HKDF_PERSIST_TEST) && EVT2_SE05X_HKDF_PERSIST_TEST
/* TEMPORARY (2026-09-27): persistent (NVM) HMAC key, to check whether the SE050F2's HKDF refusal (6985) depends on
 * the key being transient. Used only by app_se05x_probe.c's HKDF probe. */
sec_status_t security_service_debug_write_persistent_hmac_key(uint32_t key_id, const uint8_t *key, size_t key_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (security_service_key_exists(key_id) && Se05x_API_DeleteSecureObject(&s_session, key_id) != SM_OK) {
        return SEC_ERROR;
    }
    return map_status(Se05x_API_WriteSymmKey(&s_session, NULL, 0, key_id, SE05x_KeyID_KEK_NONE, key, key_len,
                                             kSE05x_INS_NA, kSE05x_SymmKeyType_HMAC));
}
#endif

sec_status_t security_service_write_transient_hmac_key(uint32_t key_id, const uint8_t *key, size_t key_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (key == NULL || key_len == 0U || key_len > 64U) {
        return SEC_INVALID_PARAM;
    }
    if (security_service_key_exists(key_id) && Se05x_API_DeleteSecureObject(&s_session, key_id) != SM_OK) {
        return SEC_ERROR;
    }
    return map_status(Se05x_API_WriteSymmKey(&s_session, NULL, 0, key_id, SE05x_KeyID_KEK_NONE, key, key_len,
                                             kSE05x_INS_TRANSIENT, kSE05x_SymmKeyType_HMAC));
}

sec_status_t security_service_import_rsa_public_key(
    uint32_t key_id, const uint8_t *modulus, size_t modulus_len, const uint8_t *exponent, size_t exponent_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (modulus == NULL || exponent == NULL) {
        return SEC_INVALID_PARAM;
    }
    if ((modulus_len != 256U && modulus_len != 384U && modulus_len != 512U) || exponent_len == 0U ||
        exponent_len > 4U) {
        return SEC_INVALID_PARAM;
    }

    sec_status_t prep = prepare_public_key_slot(key_id);
    if (prep != SEC_OK) {
        return prep;
    }

    /* Two writes, exactly like NXP's sss_se05x_key_store_set_key() RSA
     * public-key path (fsl_sss_se05x_apis.c, read in full): first the key
     * size + public exponent (creates the object), then the modulus into
     * that same object (a separate APDU -- the modulus alone is too big to
     * share one with the header on the larger key sizes). */
    smStatus_t status = Se05x_API_WriteRSAKey(&s_session,
        NULL,
        key_id,
        (uint16_t)(modulus_len * 8U),
        SE05X_RSA_NO_p,
        SE05X_RSA_NO_q,
        SE05X_RSA_NO_dp,
        SE05X_RSA_NO_dq,
        SE05X_RSA_NO_qInv,
        exponent,
        exponent_len,
        SE05X_RSA_NO_priv,
        SE05X_RSA_NO_pubMod,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Public,
        kSE05x_RSAKeyFormat_RAW);
    if (status != SM_OK) {
        return SEC_ERROR;
    }

    status = Se05x_API_WriteRSAKey(&s_session,
        NULL,
        key_id,
        0,
        SE05X_RSA_NO_p,
        SE05X_RSA_NO_q,
        SE05X_RSA_NO_dp,
        SE05X_RSA_NO_dq,
        SE05X_RSA_NO_qInv,
        SE05X_RSA_NO_pubExp,
        SE05X_RSA_NO_priv,
        modulus,
        modulus_len,
        kSE05x_INS_NA,
        kSE05x_KeyPart_NA,
        kSE05x_RSAKeyFormat_RAW);
    if (status != SM_OK) {
        (void)Se05x_API_DeleteSecureObject(&s_session, key_id); /* don't leave a half-written key behind */
        return SEC_ERROR;
    }
    return SEC_OK;
}

sec_status_t security_service_read_rsa_public_key(uint32_t key_id, uint8_t *modulus, size_t *modulus_len,
    uint8_t *exponent, size_t *exponent_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (modulus == NULL || modulus_len == NULL || exponent == NULL || exponent_len == NULL) {
        return SEC_INVALID_PARAM;
    }

    /* offset=0, length=0 reads the whole component, same "whole object"
     * convention as Se05x_API_ReadObject (already relied on by
     * security_service_load_secret() above). */
    smStatus_t status =
        Se05x_API_ReadRSA(&s_session, key_id, 0, 0, kSE05x_RSAPubKeyComp_MOD, modulus, modulus_len);
    if (status != SM_OK) {
        return SEC_ERROR;
    }

    status = Se05x_API_ReadRSA(&s_session, key_id, 0, 0, kSE05x_RSAPubKeyComp_PUB_EXP, exponent, exponent_len);
    if (status != SM_OK) {
        return SEC_ERROR;
    }

    return SEC_OK;
}

sec_status_t security_service_delete_key(uint32_t key_id)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    soft_ec_slot_t *slot = soft_ec_find(key_id);
    if (slot != NULL) { /* software ephemeral key: wipe it, nothing to send to the chip */
        soft_ec_release(slot);
        return SEC_OK;
    }
#endif

    return map_status(Se05x_API_DeleteSecureObject(&s_session, key_id));
}

bool security_service_key_exists(uint32_t key_id)
{
    if (!s_ready) {
        return false;
    }
#if !SSS_HAVE_SE05X_VER_GTE_07_02
    if (soft_ec_find(key_id) != NULL) {
        return true;
    }
#endif

    SE05x_Result_t exists = kSE05x_Result_NA;
    smStatus_t status = Se05x_API_CheckObjectExists(&s_session, key_id, &exists);
    return (status == SM_OK) && (exists == kSE05x_Result_SUCCESS);
}

sec_status_t security_service_store_secret(uint32_t key_id, const uint8_t *data, size_t len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (data == NULL || len == 0 || len > 0xFFFFU) {
        return SEC_INVALID_PARAM;
    }

    /* offset=0, length=len writes the whole BinaryFile object in one
     * shot (no partial/append update -- see Se05x_API_WriteBinary). */
    smStatus_t status = Se05x_API_WriteBinary(&s_session, NULL, key_id, 0, (uint16_t)len, data, len);
    return map_status(status);
}

sec_status_t security_service_load_secret(uint32_t key_id, uint8_t *data, size_t *len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (data == NULL || len == NULL) {
        return SEC_INVALID_PARAM;
    }

    /* offset=0, length=0 reads the whole BinaryFile object (both are
     * documented as defaulting to "whole object" -- see
     * Se05x_API_ReadObject); *len still bounds the output buffer. */
    smStatus_t status = Se05x_API_ReadObject(&s_session, key_id, 0, 0, data, len);
    return map_status(status);
}

sec_status_t security_service_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (data == NULL || digest == NULL) {
        return SEC_INVALID_PARAM;
    }

    size_t digestLen = 32;
    smStatus_t status = Se05x_API_DigestOneShot(&s_session, kSE05x_DigestMode_SHA256, data, len, digest, &digestLen);
    if (status == SM_OK && digestLen != 32) {
        return SEC_ERROR;
    }
    return map_status(status);
}

sec_status_t security_service_ecdsa_sign(uint32_t key_id, const uint8_t digest[32], uint8_t *sig, size_t *sig_len)
{
    return security_service_ecdsa_sign_ex(key_id, SEC_HASH_SHA256, digest, 32, sig, sig_len);
}

sec_status_t security_service_ecdsa_verify(
    uint32_t key_id, const uint8_t digest[32], const uint8_t *sig, size_t sig_len, bool *valid)
{
    return security_service_ecdsa_verify_ex(key_id, SEC_HASH_SHA256, digest, 32, sig, sig_len, valid);
}

sec_status_t security_service_ecdsa_sign_ex(
    uint32_t key_id, sec_hash_t hash, const uint8_t *digest, size_t digest_len, uint8_t *sig, size_t *sig_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (digest == NULL || sig == NULL || sig_len == NULL) {
        return SEC_INVALID_PARAM;
    }

    size_t expect_len;
    SE05x_ECSignatureAlgo_t ec_algo;
    uint8_t rsa_oid_unused;
    SE05x_DigestMode_t digest_mode_unused;
    if (!hash_digest_info(hash, &expect_len, &ec_algo, &rsa_oid_unused, &digest_mode_unused) ||
        digest_len != expect_len) {
        return SEC_INVALID_PARAM;
    }

    smStatus_t status = Se05x_API_ECDSASign(&s_session, key_id, ec_algo, digest, digest_len, sig, sig_len);
    return map_status(status);
}

sec_status_t security_service_ecdsa_verify_ex(uint32_t key_id, sec_hash_t hash, const uint8_t *digest,
    size_t digest_len, const uint8_t *sig, size_t sig_len, bool *valid)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (digest == NULL || sig == NULL || valid == NULL) {
        return SEC_INVALID_PARAM;
    }
    *valid = false;

    size_t expect_len;
    SE05x_ECSignatureAlgo_t ec_algo;
    uint8_t rsa_oid_unused;
    SE05x_DigestMode_t digest_mode_unused;
    if (!hash_digest_info(hash, &expect_len, &ec_algo, &rsa_oid_unused, &digest_mode_unused) ||
        digest_len != expect_len) {
        return SEC_INVALID_PARAM;
    }

    SE05x_Result_t result = kSE05x_Result_NA;
    smStatus_t status = Se05x_API_ECDSAVerify(&s_session, key_id, ec_algo, digest, digest_len, sig, sig_len, &result);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    *valid = (result == kSE05x_Result_SUCCESS);
    return SEC_OK;
}

sec_status_t security_service_rsa_sign_digest(uint32_t key_id, sec_rsa_padding_t padding, sec_hash_t hash,
    const uint8_t *digest, size_t digest_len, uint8_t *sig, size_t *sig_len)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (digest == NULL || sig == NULL || sig_len == NULL) {
        return SEC_INVALID_PARAM;
    }

    size_t expect_len;
    SE05x_ECSignatureAlgo_t ec_algo_unused;
    uint8_t rsa_oid_last_byte;
    SE05x_DigestMode_t digest_mode;
    if (!hash_digest_info(hash, &expect_len, &ec_algo_unused, &rsa_oid_last_byte, &digest_mode) ||
        digest_len != expect_len) {
        return SEC_INVALID_PARAM;
    }

    uint16_t key_size_bytes = 0;
    smStatus_t status = Se05x_API_ReadSize(&s_session, key_id, &key_size_bytes);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    if (key_size_bytes == 0U || key_size_bytes > SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES) {
        return SEC_ERROR;
    }
    if (*sig_len < key_size_bytes) {
        return SEC_INVALID_PARAM;
    }

    uint8_t em[SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES];
    if (padding == SEC_RSA_PADDING_PSS) {
        memset(em, 0, key_size_bytes); /* emsa_pss_encode() relies on a zeroed buffer, see its doc comment */
        if (!emsa_pss_encode(digest_mode, expect_len, digest, em, key_size_bytes)) {
            return SEC_ERROR;
        }
    } else {
        if (!pkcs1_v15_encode(rsa_oid_last_byte, digest, digest_len, em, key_size_bytes)) {
            return SEC_ERROR;
        }
    }

    /* Raw RSA private-key primitive (textbook modexp, no chip-side padding)
     * applied to the host-padded block -- see security_service_rsa_sign_digest()'s
     * doc comment in security_service.h for why this replaces
     * Se05x_API_RSASign. */
    size_t out_len = key_size_bytes;
    status = Se05x_API_RSADecrypt(
        &s_session, key_id, kSE05x_RSAEncryptionAlgo_NO_PAD, em, key_size_bytes, sig, &out_len);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    *sig_len = out_len;
    return SEC_OK;
}

sec_status_t security_service_rsa_verify_digest(uint32_t key_id, sec_rsa_padding_t padding, sec_hash_t hash,
    const uint8_t *digest, size_t digest_len, const uint8_t *sig, size_t sig_len, bool *valid)
{
    if (!s_ready) {
        return SEC_NOT_READY;
    }
    if (digest == NULL || sig == NULL || valid == NULL) {
        return SEC_INVALID_PARAM;
    }
    *valid = false;

    size_t expect_len;
    SE05x_ECSignatureAlgo_t ec_algo_unused;
    uint8_t rsa_oid_last_byte;
    SE05x_DigestMode_t digest_mode;
    if (!hash_digest_info(hash, &expect_len, &ec_algo_unused, &rsa_oid_last_byte, &digest_mode) ||
        digest_len != expect_len) {
        return SEC_INVALID_PARAM;
    }

    uint16_t key_size_bytes = 0;
    smStatus_t status = Se05x_API_ReadSize(&s_session, key_id, &key_size_bytes);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    if (key_size_bytes == 0U || key_size_bytes > SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES) {
        return SEC_ERROR;
    }
    if (sig_len != key_size_bytes) {
        /* Wrong-length signature can't possibly be valid for this key --
         * not a transport/chip error, so report it the same way a
         * decoded-but-mismatched signature would be. */
        return SEC_OK;
    }

    /* Raw RSA public-key primitive undoes the signature; the recovered
     * block is then checked against `padding`'s expected encoding rather
     * than trusting any parsing the chip itself might do. */
    uint8_t recovered[SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES];
    size_t recovered_len = key_size_bytes;
    status = Se05x_API_RSAEncrypt(
        &s_session, key_id, kSE05x_RSAEncryptionAlgo_NO_PAD, sig, sig_len, recovered, &recovered_len);
    if (status != SM_OK) {
        return SEC_ERROR;
    }
    if (recovered_len != key_size_bytes) {
        return SEC_OK;
    }

    if (padding == SEC_RSA_PADDING_PSS) {
        *valid = emsa_pss_verify(digest_mode, expect_len, digest, recovered, key_size_bytes);
    } else {
        uint8_t expected_em[SECURITY_SERVICE_RSA_MAX_MODULUS_BYTES];
        if (!pkcs1_v15_encode(rsa_oid_last_byte, digest, digest_len, expected_em, key_size_bytes)) {
            return SEC_ERROR;
        }
        *valid = (memcmp(recovered, expected_em, key_size_bytes) == 0);
    }
    return SEC_OK;
}

sec_status_t security_service_sign_message(
    uint32_t key_id, const uint8_t *data, size_t len, uint8_t *sig, size_t *sig_len)
{
    uint8_t digest[32];
    sec_status_t status = security_service_sha256(data, len, digest);
    if (status != SEC_OK) {
        return status;
    }

    return security_service_ecdsa_sign(key_id, digest, sig, sig_len);
}

sec_status_t security_service_verify_message(
    uint32_t key_id, const uint8_t *data, size_t len, const uint8_t *sig, size_t sig_len, bool *valid)
{
    uint8_t digest[32];
    sec_status_t status = security_service_sha256(data, len, digest);
    if (status != SEC_OK) {
        return status;
    }

    return security_service_ecdsa_verify(key_id, digest, sig, sig_len, valid);
}
