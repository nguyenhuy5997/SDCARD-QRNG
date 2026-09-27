/**
 * @file    ca_protocol.c
 * @brief   App-layer command_protocol.h adapter for the CA-based key exchange handshake (CMD_TYPE_CA).
 *
 * Lives under Core_app/App, not Core_app/Middleware/CA -- same reason as security_protocol.c/qrng_protocol.c: this file
 * depends on command_protocol.h, Middleware/CA/ca_service.h and ca_x509.h, Middleware/Security/security_service.h and
 * Middleware/QRNG/qrng_service.h at once, and App is the only layer allowed to depend on more than one Middleware module.
 *
 * WHAT THIS FILE DOES NOT DO: it does not talk to the network, and it does not run the 3-message handshake itself. Each
 * sub-command below is one CRYPTOGRAPHIC PRIMITIVE (generate my ephemeral key, sign the transcript, verify the peer,
 * derive session keys, confirm) -- the phone app (or, for testing, a PC peer tool) calls them in order and carries the
 * bytes to/from the network peer, exactly the way tools/sign_app.py's Peer class already orchestrates SE05x sign/verify
 * over a relay for digital signatures. This mirrors security_protocol.c's shape (many sub_cmd under one CMD_TYPE) rather
 * than media_protocol.c's shape (a whole packet range owned by one stateful session): the handshake has no per-chunk
 * traffic, so the simple request/response idiom already used for Security/Biometric/QRNG fits it directly.
 *
 * Wire format, transcript and message layouts: docs/key_exchange_ca_profile.md section 6. Read that before touching this
 * file -- the byte layouts here must match it exactly (both sides of a call assemble the transcript/confirm message
 * independently and must land on the identical bytes for the signature/MAC to verify).
 *
 * SESSION STATE: one active handshake at a time (this device has one active call). CA_CMD_BEGIN resets it. The ephemeral
 * EC key pair and the two derived secret objects (ECDH result, confirmation key) are TRANSIENT SE052F objects (RAM-only,
 * gone at reset) at fixed ids in a range (0x00690001..0x00690003) not used by any other service -- see CLAUDE.md's
 * 2026-09-22 object-policy TODO: ids are kept out of any range a USB client can pick, since the delete-then-recreate
 * calls in security_service.h do not yet refuse to touch a non-transient object at a colliding id.
 *
 * THE DERIVED AES-256-GCM SESSION KEYS NEVER CROSS USB. CA_CMD_DERIVE_KEYS's response carries no key material at all --
 * the two keys are held in this file's own static RAM (s_send_key/s_recv_key) for the App layer to wire into
 * media_protocol.c's encrypt/decrypt path (not done yet -- see CLAUDE.md's CA handoff notes, "step 8"). This is the one
 * exception the design allows to "every secret stays in the SE052F": the STM32's own CRYP hardware needs the raw key, but
 * it still never leaves this device's RAM, let alone the wire.
 *
 * SE050F2 (applet 3.x, FIPS mode -- 2026-09-27): the chip refuses ECDH and HKDF, so security_service_derives_in_chip()
 * is false there. The ephemeral ECDH key then lives in MCU RAM (the Security backend does that transparently behind
 * security_service_generate_ephemeral_ec_keypair()/ecdh_to_host(), in software), and CA_CMD_DERIVE_KEYS takes its
 * host-side derivation branch for the classical suite too. The identity key, transcript signing, peer verification and
 * the confirmation HMAC stay in the chip exactly as on the SE052F, and the wire format does not change.
 *
 * HYBRID PQC (2026-09-24, Giai đoạn 1, see CLAUDE.md): every quad-carrying sub-command below (SIGN_TRANSCRIPT,
 * VERIFY_PEER, DERIVE_KEYS, CONFIRM, VERIFY_CONFIRM) additionally carries an optional ML-KEM-768 extension (see
 * ca_kem_ext_t/read_kem_ext()) bound into the same signature/MAC as the rest of the transcript -- there is no build
 * flag: whether a given call is hybrid or classical-only is decided per-call purely by whether that extension is
 * present, exactly the "capability shows through the payload" design the user asked for. See
 * docs/key_exchange_ca_profile.md section 6.5 for the wire format and CLAUDE.md's Giai đoạn 1 entry for the exact
 * key-combining rule (SecP256r1MLKEM768, `Z_ecdh || Z_kem` -> one HKDF).
 */
#include "command_protocol.h"
#include "ca_service.h"
#include "ca_x509.h"
#include "security_service.h"
#include "qrng_service.h"
#include "pqc_kem.h"
#include "platform_hash.h"

#include <string.h>

typedef enum {
    CA_CMD_GET_IDENTITY    = 0x01, /* -> [sub][status][id_len:1B][id][cert_len:2B LE][cert][issuing_len:2B LE][issuing]
                                     *    [root_pt:65B][root_subj_len:1B][root_subj] */
    CA_CMD_GET_STATUS_TOKEN = 0x02, /* -> [sub][status][token_len:1B][token] */
    CA_CMD_BEGIN            = 0x03, /* -> [sub][status][n_mine:32B][epk_mine:65B][pk_kem_len:2B LE][pk_kem]
                                      * pk_kem_len is always CA_KEM_PK_LEN (1184) unless the on-chip ML-KEM-768
                                      * keygen itself failed (best-effort -- see the handler), in which case it is 0
                                      * and this call still offers a fully usable classical-only key exchange. */
    /* payload (after sub_cmd): [role:1B][nA:32B][epkA:65B][nB:32B][epkB:65B][ext] -- CA_QUAD_LEN = 195 bytes, `ext`
     * = ca_kem_ext_t's wire form (read_kem_ext()'s doc comment), ALWAYS present (2+2 = 4 bytes minimum, zero-length
     * on both slots for a classical-only call). role = 1: I signed/am signing as A (initiator, epkA is mine); role
     * = 2: as B (responder, epkB is mine). Same shape for SIGN_TRANSCRIPT/DERIVE_KEYS/CONFIRM below. */
    CA_CMD_SIGN_TRANSCRIPT  = 0x04, /* -> [sub][status][sig_len:1B][sig][ct_kem_b_len:2B LE][ct_kem_b] -- role B's
                                      * ct_kem_b_len/ct_kem_b are this device's freshly-computed encapsulation
                                      * (ext.pk_kem_a offered valid), NOT an echo of whatever the host passed in
                                      * (which is unknown before this call, see the handler); role A's are simply
                                      * the ext.ct_kem_b this call was given, echoed back for a uniform response
                                      * shape regardless of role. */
    /* payload: [peer_role:1B][nA:32B][epkA:65B][nB:32B][epkB:65B][ext][issuing_len:2B LE][issuing][leaf_len:2B LE]
     *          [leaf][token_len:1B][token][sig_len:1B][sig]
     * peer_role: the ROLE THE PEER SIGNED AS (1 or 2). -> [sub][result:1B][ca_x509_status:1B][id_len:1B][peer_id]
     * result: 0 OK, 1 chain/token invalid (see ca_x509_status), 2 transcript signature invalid, 3 peer id == own id
     * (reflection guard), 4 bad parameter. id_len/peer_id present only when result == 0. */
    CA_CMD_VERIFY_PEER      = 0x05,
    CA_CMD_DERIVE_KEYS      = 0x06, /* payload: [role:1B][nA:32B][epkA:65B][nB:32B][epkB:65B][ext] -> [sub][status]
                                      * (no keys). Hybrid iff ext's two slots are BOTH non-empty (suite_of()). */
    CA_CMD_CONFIRM          = 0x07, /* payload: [role:1B][nA:32B][epkA:65B][nB:32B][epkB:65B][ext]
                                      * -> [sub][status][mac:32B] */
    /* payload: [peer_role:1B][nA:32B][epkA:65B][nB:32B][epkB:65B][ext][mac:32B]
     * -> [sub][result:1B]  0 = matches, 1 = mismatch, 2 = no confirmation key held (DERIVE_KEYS not done) */
    CA_CMD_VERIFY_CONFIRM   = 0x08,
    CA_CMD_END_SESSION      = 0x09, /* -> [sub][status] */
} ca_cmd_t;

#define CA_EPHEMERAL_KEY_ID  0x00690001U
#define CA_ECDH_SECRET_ID    0x00690002U
#define CA_CONFIRM_SECRET_ID 0x00690003U
#define CA_PEER_VERIFY_SLOT  0x00690004U /* scratch EC public-key slot for ca_x509's verify callback, see se052f_verify() */

#define CA_NONCE_LEN 32U
#define CA_POINT_LEN CA_X509_POINT_LEN /* 65 */
#define CA_QUAD_LEN (1U + CA_NONCE_LEN + CA_POINT_LEN + CA_NONCE_LEN + CA_POINT_LEN) /* role + nA + epkA + nB + epkB = 195 */
#define CA_ID_MAX 64U /* hex-text device id, generous over the dev PKI's actual 18B raw -> 36 hex chars, see s_peer_id */

#define CA_ROLE_A 1U
#define CA_ROLE_B 2U

/* Explicit protocol/suite descriptor, prepended (as raw bytes, not text) to every signed/MAC'd message below -- see
 * build_msg()'s doc comment and CLAUDE.md's transcript-binding review point ("cần định nghĩa chính xác byte nào
 * được ký... đưa vào transcript: phiên bản giao thức, thuật toán"). Bump CA_PROTO_VERSION whenever the quad layout,
 * context strings, or KDF info strings below change in a way that must not silently interop with an older board --
 * two boards signing/verifying with different values here simply fail the handshake (safe failure), never a
 * silent mismatch. Bumped to 2 for Giai đoạn 1 (2026-09-24): every quad-carrying message now mandatorily carries the
 * ML-KEM-768 extension trailer (read_kem_ext()), even when both its slots are empty -- a v1 peer's 195-byte-exact
 * quad no longer parses (payload_len check fails cleanly), which is exactly the safe-failure this doc comment
 * already calls for, not a silent mismatch.
 *
 * CA_SUITE_ID is no longer a single fixed value: it is written dynamically into each message by suite_of(), which
 * derives it from whether THAT message's own ca_kem_ext_t actually carries a complete hybrid exchange -- so the
 * negotiated mode (classical vs. hybrid) is itself part of what gets signed/MAC'd, the same anti-downgrade binding
 * TLS 1.3 gets from including its negotiated group in the transcript hash under the Finished MAC. */
#define CA_PROTO_VERSION 2U
#define CA_SUITE_CLASSICAL_P256        1U /* P256 + SHA256 + HKDF-SHA256 + AES-256-GCM, unchanged since v1 */
#define CA_SUITE_HYBRID_P256_MLKEM768  2U /* above, plus ML-KEM-768 combined in per SecP256r1MLKEM768 (draft-ietf-tls-ecdhe-mlkem) */

/* ML-KEM-768 sizes this file cares about, aliased from pqc_kem.h under the CA_ naming convention used everywhere
 * else in this file (CA_NONCE_LEN, CA_POINT_LEN, ...). */
#define CA_KEM_PK_LEN PQC_KEM_PUBLICKEY_BYTES     /* 1184 -- role A's ML-KEM-768 public key */
#define CA_KEM_CT_LEN PQC_KEM_CIPHERTEXT_BYTES    /* 1088 -- role B's ML-KEM-768 ciphertext */
#define CA_KEM_SS_LEN PQC_KEM_SHARED_SECRET_BYTES /* 32   -- Z_kem, both sides, never appears on the wire */
#define CA_KEM_DIGEST_LEN 32U                     /* SHA-256(pk_kem_a) / SHA-256(ct_kem_b) -- see build_msg() */

/* Domain-separation prefixes, same convention as ca_x509.c's TOKEN_CONTEXT (trailing 0x00, via the string literal's own
 * NUL terminator) -- distinct contexts so a transcript signature and a confirmation MAC can never be confused with each
 * other or with a status token, even though all three end up as "sign/MAC this byte string" underneath. */
static const uint8_t CA_TRANSCRIPT_CONTEXT[] = "EVT2-KEX-v1";
static const uint8_t CA_CONFIRM_MSG_CONTEXT[] = "EVT2-KEX-confirm-v1";
static const uint8_t CA_INFO_A_TO_B[] = "EVT2-KEX-AtoB-v1";
static const uint8_t CA_INFO_B_TO_A[] = "EVT2-KEX-BtoA-v1";
static const uint8_t CA_INFO_CONFIRM_KEY[] = "EVT2-KEX-confirm-key-v1";

/* Largest message built by build_msg()+append_ids(): 2 (version+suite) + the longer context (CONFIRM's) + the quad
 * + the largest possible ML-KEM-768 extension (both slots full -- but see build_msg()'s doc comment: it embeds each
 * slot's SHA-256 DIGEST, not the raw CA_KEM_PK_LEN/CA_KEM_CT_LEN bytes, so this is 2+CA_KEM_DIGEST_LEN twice, not
 * 2+CA_KEM_PK_LEN+2+CA_KEM_CT_LEN), plus append_ids()'s own [len][id]*2 for the CONFIRM/VERIFY_CONFIRM message (see
 * those handlers) -- transcript messages use the same buffer but never call append_ids(), so they just use a
 * prefix of it. */
#define CA_MSG_BUF_LEN (2U + sizeof(CA_CONFIRM_MSG_CONTEXT) + CA_QUAD_LEN + 2U + CA_KEM_DIGEST_LEN + 2U + \
                        CA_KEM_DIGEST_LEN + 1U + CA_ID_MAX + 1U + CA_ID_MAX)

/* Session state -- see CLAUDE.md's "CA_CMD_BEGIN không ràng buộc với các sub-command sau" finding: earlier, every
 * sub-command after BEGIN trusted whatever quad/role the host handed it, with no check that DERIVE_KEYS/CONFIRM ran
 * only after a real VERIFY_PEER, or that START_STREAM (media_protocol.c) could only pick up session keys after a
 * FULL mutual handshake (both VERIFY_CONFIRM calls, not just DERIVE_KEYS) completed. This enum is that missing
 * ordering, enforced state-by-state below; CA_SESSION_ESTABLISHED is the only state
 * ca_protocol_get_session_keys() will hand out keys in. */
typedef enum {
    CA_SESSION_IDLE = 0,     /* no BEGIN yet this session, or END_SESSION/a fresh BEGIN reset everything */
    CA_SESSION_BEGUN,        /* BEGIN done: have an ephemeral key + my own nonce/epk (s_my_nonce/s_my_epk) */
    CA_SESSION_PEER_VERIFIED,/* VERIFY_PEER succeeded at least once (CA_PEER_OK) */
    CA_SESSION_KEYS_DERIVED, /* DERIVE_KEYS succeeded -- session keys computed and held, but NOT yet handed to media */
    CA_SESSION_ESTABLISHED,  /* VERIFY_CONFIRM matched -- both sides proven to hold the same session keys */
} ca_session_state_t;

static ca_session_state_t s_state = CA_SESSION_IDLE;
static uint8_t s_my_nonce[CA_NONCE_LEN]; /* what BEGIN actually generated -- see quad_slot_matches_mine() */
static uint8_t s_my_epk[CA_POINT_LEN];
static uint8_t s_peer_id[CA_ID_MAX];     /* peer's cert CN (hex text), captured on a successful VERIFY_PEER */
static size_t s_peer_id_len;

static uint8_t s_send_key[32]; /* zeroed when absent -- see s_state */
static uint8_t s_recv_key[32];

/* Hybrid PQC state (Giai đoạn 1, see CLAUDE.md), all reset by end_session() like everything else above.
 *
 * s_kem_pk/s_kem_sk: this device's own ML-KEM-768 keypair, generated unconditionally by every BEGIN (role is not
 * decided yet at BEGIN time -- see docs/key_exchange_ca_profile.md 6.3 -- so both roles generate one; whichever
 * role this device turns out NOT to be simply never uses it). s_have_kem_keypair is false only if the on-chip
 * keygen itself failed (best-effort, see CA_CMD_BEGIN) -- BEGIN still succeeds classically in that case.
 *
 * s_kem_ct_b/s_kem_z_b/s_have_kem_ct_b: role B ONLY. ML-KEM encapsulation is RANDOMIZED (pqc_kem_encapsulate()
 * draws fresh QRNG entropy each call, see pqc_randombytes.c) -- unlike the classical ECDH secret (deterministic,
 * safely recomputable on a retry), a second encapsulation against the same pk_kem_a would produce a DIFFERENT
 * ct_kem_b/Z_kem pair that no longer matches whatever ct_kem_b was already sent to the peer in M2. So this is
 * computed exactly ONCE per session -- at SIGN_TRANSCRIPT time, the earliest point a role-B call actually has the
 * peer's pk_kem_a in hand (see that handler) -- cached here, and reused verbatim by every later call this session
 * (DERIVE_KEYS, CONFIRM) that needs "my" ct_kem_b/Z_kem, exactly the same ownership pattern
 * quad_slot_matches_mine() already applies to s_my_nonce/s_my_epk for the classical fields. */
static uint8_t s_kem_pk[CA_KEM_PK_LEN];
static uint8_t s_kem_sk[PQC_KEM_SECRETKEY_BYTES];
static bool s_have_kem_keypair;
static uint8_t s_kem_ct_b[CA_KEM_CT_LEN];
static uint8_t s_kem_z_b[CA_KEM_SS_LEN];
static bool s_have_kem_ct_b;

static void wipe_session_keys(void)
{
    memset(s_send_key, 0, sizeof(s_send_key));
    memset(s_recv_key, 0, sizeof(s_recv_key));
}

static void wipe_kem_state(void)
{
    memset(s_kem_pk, 0, sizeof(s_kem_pk));
    memset(s_kem_sk, 0, sizeof(s_kem_sk));
    s_have_kem_keypair = false;
    memset(s_kem_ct_b, 0, sizeof(s_kem_ct_b));
    memset(s_kem_z_b, 0, sizeof(s_kem_z_b));
    s_have_kem_ct_b = false;
}

/** Not part of the wire protocol -- for media_protocol.c's handle_start_stream() to pick up the keys CA_CMD_DERIVE_KEYS
 *  derived, without ever sending them over USB. `send_key`/`recv_key` each receive 32 bytes. Returns false (leaves the
 *  buffers untouched) unless the handshake reached CA_SESSION_ESTABLISHED -- i.e. VERIFY_CONFIRM actually matched, not
 *  merely DERIVE_KEYS having run. Handing out keys any earlier would let a session start encrypting media before either
 *  side has proven it derived the SAME keys as its peer (see CLAUDE.md's review point on this). */
bool ca_protocol_get_session_keys(uint8_t send_key[32], uint8_t recv_key[32])
{
    if (s_state != CA_SESSION_ESTABLISHED) {
        return false;
    }
    memcpy(send_key, s_send_key, 32U);
    memcpy(recv_key, s_recv_key, 32U);
    return true;
}

#if EVT2_DIAGNOSTICS /* self-test hook only -- a product build must not be able to set s_peer_id without VERIFY_PEER */
/** TEST ONLY -- no USB command reaches this; not declared in any shared header, extern'd directly where used, same
 *  convention as this file's other non-wire entry points. app_main.c's app_ca_protocol_self_test() uses this to
 *  populate s_peer_id the way a successful VERIFY_PEER normally would, since it cannot produce a real CA_PEER_OK
 *  itself (no second identity exists on one board -- every VERIFY_PEER call it makes is expected to hit
 *  CA_PEER_SELF or CA_PEER_BAD_PARAM instead, see that test's own comments and quad_slot_matches_mine()'s doc
 *  comment). Without this, CONFIRM/VERIFY_CONFIRM's id-binding (see append_ids()) has nothing to work with:
 *  s_peer_id would stay empty, and the CONFIRM/VERIFY_CONFIRM formulas -- deliberately asymmetric so a REAL two
 *  different-board exchange lands on identical bytes from both sides, see those handlers' own comments -- are
 *  mirror images of each other for a single q.role value, so they can only ever produce the SAME message when
 *  own_id_hex and s_peer_id happen to be equal (swapping two equal things changes nothing). That equality is
 *  exactly what a genuine self-dial would look like -- CA_PEER_SELF exists to refuse ever reaching CONFIRM in that
 *  real scenario, so this setter is the only way to exercise CONFIRM/VERIFY_CONFIRM's matching path on hardware
 *  with just one identity provisioned. Returns false (does nothing) if `len` would not fit s_peer_id. */
bool ca_protocol_test_set_peer_id(const uint8_t *id, size_t len)
{
    if (len > sizeof(s_peer_id)) {
        return false;
    }
    memcpy(s_peer_id, id, len);
    s_peer_id_len = len;
    return true;
}
#endif /* EVT2_DIAGNOSTICS */

static void end_session(void)
{
    if (s_state >= CA_SESSION_BEGUN) {
        (void)security_service_delete_key(CA_EPHEMERAL_KEY_ID);
    }
    (void)security_service_delete_key(CA_ECDH_SECRET_ID); /* harmless if absent (delete_key on a missing id just fails) */
    if (s_state >= CA_SESSION_KEYS_DERIVED) {
        (void)security_service_delete_key(CA_CONFIRM_SECRET_ID);
    }
    wipe_session_keys();
    wipe_kem_state();
    memset(s_my_nonce, 0, sizeof(s_my_nonce));
    memset(s_my_epk, 0, sizeof(s_my_epk));
    memset(s_peer_id, 0, sizeof(s_peer_id));
    s_peer_id_len = 0U;
    s_state = CA_SESSION_IDLE;
}

/* role/nA/epkA/nB/epkB, read from a CA_QUAD_LEN-byte block (payload[1..1+CA_QUAD_LEN)). */
typedef struct {
    uint8_t role;
    const uint8_t *nA;
    const uint8_t *epkA;
    const uint8_t *nB;
    const uint8_t *epkB;
} ca_quad_t;

static void read_quad(const uint8_t *p, ca_quad_t *q)
{
    q->role = p[0];
    q->nA = &p[1];
    q->epkA = &p[1U + CA_NONCE_LEN];
    q->nB = &p[1U + CA_NONCE_LEN + CA_POINT_LEN];
    q->epkB = &p[1U + CA_NONCE_LEN + CA_POINT_LEN + CA_NONCE_LEN];
}

static uint16_t read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Optional ML-KEM-768 material appended after the fixed 195-byte quad in every quad-carrying sub-command (see
 * ca_cmd_t's doc comments) -- symmetric with how the quad itself always carries both epkA and epkB regardless of
 * who is building the message:
 *   pk_kem_a: role A's ML-KEM-768 public key (CA_KEM_PK_LEN bytes), published unconditionally in BEGIN's response.
 *   ct_kem_b: role B's ML-KEM-768 ciphertext (CA_KEM_CT_LEN bytes), produced by B's SIGN_TRANSCRIPT-time
 *             encapsulation (see s_kem_ct_b's doc comment) -- never supplied by the host for role B's own calls.
 * Either slot may be zero-length ("not offered/not available this call") -- see suite_of(): that is how a call
 * falls back to the classical-only suite, not an error. Both slots are always present in the byte stream (a 2-byte
 * length prefix, possibly followed by zero bytes) -- never omitted outright -- so every message's shape is
 * unambiguous without needing a separate "extension present" flag. */
typedef struct {
    const uint8_t *pk_kem_a; /* NULL iff pk_kem_a_len == 0 */
    size_t pk_kem_a_len;     /* 0 or CA_KEM_PK_LEN -- read_kem_ext() rejects any other value */
    const uint8_t *ct_kem_b; /* NULL iff ct_kem_b_len == 0 */
    size_t ct_kem_b_len;     /* 0 or CA_KEM_CT_LEN -- read_kem_ext() rejects any other value */
} ca_kem_ext_t;

/* Reads [pk_kem_a_len:2B LE][pk_kem_a][ct_kem_b_len:2B LE][ct_kem_b] out of `payload` starting at `*o`, advancing
 * `*o` past it -- callers with more fields after the extension (VERIFY_PEER's chain data, VERIFY_CONFIRM's mac)
 * keep parsing from the new `*o`, same incremental-offset style those handlers already use for everything else.
 * Returns false, leaving `*o` unspecified, if a length field does not fit what remains of `payload_len`, or is
 * nonzero but not exactly CA_KEM_PK_LEN / CA_KEM_CT_LEN -- same strict-or-nothing rule ca_x509.c applies to every
 * field it parses; this file's own dispatcher never trusts an odd-sized "public key" or "ciphertext" any more than
 * ca_x509.c trusts an odd-sized certificate field. */
static bool read_kem_ext(const uint8_t *payload, size_t payload_len, size_t *o, ca_kem_ext_t *ext)
{
    if (*o + 2U > payload_len) {
        return false;
    }
    uint16_t pk_len = read_u16le(&payload[*o]);
    *o += 2U;
    if ((pk_len != 0U && pk_len != CA_KEM_PK_LEN) || *o + pk_len > payload_len) {
        return false;
    }
    ext->pk_kem_a = (pk_len != 0U) ? &payload[*o] : NULL;
    ext->pk_kem_a_len = pk_len;
    *o += pk_len;

    if (*o + 2U > payload_len) {
        return false;
    }
    uint16_t ct_len = read_u16le(&payload[*o]);
    *o += 2U;
    if ((ct_len != 0U && ct_len != CA_KEM_CT_LEN) || *o + ct_len > payload_len) {
        return false;
    }
    ext->ct_kem_b = (ct_len != 0U) ? &payload[*o] : NULL;
    ext->ct_kem_b_len = ct_len;
    *o += ct_len;
    return true;
}

/* The suite this ONE message negotiates: hybrid only when BOTH ML-KEM slots are actually present (a "half-hybrid"
 * extension -- one slot filled, the other empty -- never reaches this function; every call site that builds or
 * accepts an ext rejects that shape outright as CA_INVALID_PARAM before getting here, see e.g. CA_CMD_DERIVE_KEYS).
 * Written into the message itself by build_msg() -- see this file's CA_SUITE_* doc comment for why binding the
 * negotiated mode into the signed/MAC'd bytes matters. */
static uint8_t suite_of(const ca_kem_ext_t *ext)
{
    return (ext->pk_kem_a_len == CA_KEM_PK_LEN && ext->ct_kem_b_len == CA_KEM_CT_LEN) ? CA_SUITE_HYBRID_P256_MLKEM768
                                                                                       : CA_SUITE_CLASSICAL_P256;
}

/* True if `ext`'s pk_kem_a slot is either absent (a legitimate classical-fallback choice, e.g. this call's peer does
 * not support PQC -- see ca_cmd_t's doc comments) or exactly the public key THIS device's own BEGIN generated.
 * Applied only where `ext`'s pk_kem_a slot is "mine" (role == CA_ROLE_A in SIGN_TRANSCRIPT/DERIVE_KEYS/CONFIRM,
 * exactly the calls quad_slot_matches_mine() already guards) -- same rationale as that function's own doc comment:
 * without this, a confused or malicious host could make this device sign/derive/confirm a transcript vouching for
 * an ML-KEM public key it does not actually hold the matching secret key for. */
static bool kem_pk_matches_mine(const ca_kem_ext_t *ext)
{
    return ext->pk_kem_a_len == 0U ||
           (s_have_kem_keypair && ext->pk_kem_a_len == CA_KEM_PK_LEN &&
            memcmp(ext->pk_kem_a, s_kem_pk, CA_KEM_PK_LEN) == 0);
}

/* RFC 5869 HKDF-SHA256, Extract then Expand for exactly 32 bytes of output (a single Expand block, since 32 equals
 * SHA-256's output size: T(1) = HMAC(PRK, info || 0x01), no T(0) needed). Software-only, used by CA_CMD_DERIVE_KEYS's
 * host-side derivation: the hybrid path, and the classical path on a chip that cannot derive in-chip (SE050F2 --
 * security_service_derives_in_chip()). For the hybrid path: the combined input keying material (Z_ecdh || Z_kem)
 * cannot live in an SE052F secret object the way the classical path's Z can (security_service_hkdf_to_secret()/hkdf_export()), because
 * Z_kem never touches the chip at all (ML-KEM runs entirely in MCU software, see pqc_kem.h) -- so this whole
 * derivation has to run in MCU RAM instead. It computes exactly what Se05x_API_HKDF_Extended(..., kSE05x_HkdfMode_
 * ExtractExpand, ...) computes on-chip for the classical path -- same standard (RFC 5869), different execution
 * engine. `info_len` is bounded the same way the chip path's own hkdf_args_ok() bounds it (1..80), even though
 * platform_hmac_sha256() itself has no such limit -- kept for symmetry and to catch a caller bug early. */
static bool hkdf_sha256_extract_expand_32(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                                          const uint8_t *info, size_t info_len, uint8_t out[32])
{
    if (info_len == 0U || info_len > 80U) {
        return false;
    }
    uint8_t prk[32];
    if (platform_hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != PLATFORM_OK) {
        return false;
    }
    uint8_t t_input[80U + 1U];
    memcpy(t_input, info, info_len);
    t_input[info_len] = 0x01U;
    bool ok = platform_hmac_sha256(prk, sizeof(prk), t_input, info_len + 1U, out) == PLATFORM_OK;
    memset(prk, 0, sizeof(prk));
    memset(t_input, 0, sizeof(t_input));
    return ok;
}

/* out must hold CA_MSG_BUF_LEN bytes; returns the actual length written, or 0 on failure (see below -- every field
 * this function itself writes is a fixed, non-empty size, so 0 can never be a genuine length and is safe to use as
 * an error sentinel; callers must check for it). Always starts with the fixed [CA_PROTO_VERSION][suite_id]
 * descriptor (see CA_SUITE_*'s doc comment) before the caller's own context string and the quad, then the
 * ML-KEM-768 extension -- every signature/MAC below is therefore bound to a specific protocol version, negotiated
 * suite, and (when hybrid) the exact PQC material, not just to the nonces/keys themselves.
 *
 * The extension embeds SHA-256(pk_kem_a)/SHA-256(ct_kem_b) (CA_KEM_DIGEST_LEN bytes each), NOT the raw
 * CA_KEM_PK_LEN/CA_KEM_CT_LEN bytes -- found necessary on real hardware (2026-09-24): security_service_sha256(),
 * used below to hash this whole message before signing/MAC'ing it, goes through the SE052F's Se05x_API_DigestOneShot,
 * which builds its command APDU into a SE05X_MAX_BUF_SIZE_CMD-sized buffer (892 or 1024 bytes, see se05x_const.h)
 * -- far smaller than a message that inlined the full ~1184+1088-byte ML-KEM material (confirmed failing:
 * "SIGN_TRANSCRIPT: FAIL -- status=7 (CA_ERR_SIGN_TEST)" the first time this was tried). Hashing each blob down to
 * 32 bytes here, on the STM32's OWN hardware HASH peripheral (platform_sha256() -- no SE05x one-shot size limit,
 * same reasoning media_protocol.c's END_STREAM digest already relies on for large H.264 frames) before it ever
 * reaches security_service_sha256(), keeps every message this function builds small regardless of the PQC blobs'
 * real size, while still binding them just as strongly (a SHA-256 commitment is exactly as tamper-evident as the
 * bytes themselves, under the same collision-resistance assumption this whole file already depends on everywhere
 * else). `ext` is never NULL -- callers with nothing to offer pass a zeroed ca_kem_ext_t (both slots empty), which
 * still gets its two zero-length prefixes written here (and no digest computed), same as any other classical-only
 * call. */
static size_t build_msg(uint8_t *out, const uint8_t *context, size_t context_len, const ca_quad_t *q,
                         const ca_kem_ext_t *ext)
{
    size_t o = 0;
    out[o++] = CA_PROTO_VERSION;
    out[o++] = suite_of(ext);
    memcpy(&out[o], context, context_len);
    o += context_len;
    out[o++] = q->role;
    memcpy(&out[o], q->nA, CA_NONCE_LEN);
    o += CA_NONCE_LEN;
    memcpy(&out[o], q->epkA, CA_POINT_LEN);
    o += CA_POINT_LEN;
    memcpy(&out[o], q->nB, CA_NONCE_LEN);
    o += CA_NONCE_LEN;
    memcpy(&out[o], q->epkB, CA_POINT_LEN);
    o += CA_POINT_LEN;
    out[o++] = (uint8_t)(ext->pk_kem_a_len & 0xFFU);
    out[o++] = (uint8_t)((ext->pk_kem_a_len >> 8) & 0xFFU);
    if (ext->pk_kem_a_len != 0U) {
        if (platform_sha256(ext->pk_kem_a, ext->pk_kem_a_len, &out[o]) != PLATFORM_OK) {
            return 0U;
        }
        o += CA_KEM_DIGEST_LEN;
    }
    out[o++] = (uint8_t)(ext->ct_kem_b_len & 0xFFU);
    out[o++] = (uint8_t)((ext->ct_kem_b_len >> 8) & 0xFFU);
    if (ext->ct_kem_b_len != 0U) {
        if (platform_sha256(ext->ct_kem_b, ext->ct_kem_b_len, &out[o]) != PLATFORM_OK) {
            return 0U;
        }
        o += CA_KEM_DIGEST_LEN;
    }
    return o;
}

/* Appends [id_a_len:1][id_a][id_b_len:1][id_b] after build_msg()'s own output -- CONFIRM/VERIFY_CONFIRM only (see
 * those handlers), never the transcript signature: at SIGN_TRANSCRIPT time the signer does not yet know the peer's
 * id (certs are exchanged AFTER the transcript is signed, see docs/key_exchange_ca_profile.md section 6.3's message
 * order), so binding both ids is only possible once both sides have already verified each other -- exactly the
 * CONFIRM/VERIFY_CONFIRM step. `id_a`/`id_b` are always in canonical A-then-B order regardless of which one is
 * "me" -- see the two call sites for how each resolves that from its own point of view. Returns the new length. */
static size_t append_ids(uint8_t *out, size_t o, const uint8_t *id_a, size_t id_a_len, const uint8_t *id_b,
                          size_t id_b_len)
{
    out[o++] = (uint8_t)id_a_len;
    memcpy(&out[o], id_a, id_a_len);
    o += id_a_len;
    out[o++] = (uint8_t)id_b_len;
    memcpy(&out[o], id_b, id_b_len);
    o += id_b_len;
    return o;
}

static const uint8_t *peer_epk_of(const ca_quad_t *q)
{
    return (q->role == CA_ROLE_A) ? q->epkB : q->epkA; /* my role is A => the peer's point is epkB, and vice versa */
}

/* True if the (nonce, epk) pair at quad slot `role` matches what THIS device's own BEGIN actually generated
 * (s_my_nonce/s_my_epk). Applied ONLY to SIGN_TRANSCRIPT/DERIVE_KEYS/CONFIRM below, always with `role` = the
 * quad's own `role` field -- for those three, `role` unambiguously means "my role" (see ca_cmd_t's doc comments),
 * so there is exactly one slot that could legitimately be mine, and this checks it is.
 *
 * Deliberately NOT applied to VERIFY_PEER/VERIFY_CONFIRM (their quad's `role` field means the PEER's role
 * instead): a strict "my slot = other_role(peer_role)" version was tried and reverted -- it rejects a completely
 * legitimate case, a genuine same-identity self-dial (two different boards that happen to carry the same identity,
 * e.g. from a shared factory image -- see CLAUDE.md's identity-provisioning notes), whenever peer_role happens to
 * equal my own declared role, which is exactly the scenario CA_PEER_SELF exists to catch -- app_main.c's
 * app_ca_protocol_self_test() exercises precisely that on real hardware (no second board available, so it
 * presents this device's own cert as "the peer" and must still reach the CA_PEER_SELF check, not be rejected one
 * layer earlier by a slot-assignment mismatch). Skipping the check there is safe: VERIFY_PEER/VERIFY_CONFIRM never
 * sign anything or derive any key material with MY ephemeral -- the operations that actually do (SIGN_TRANSCRIPT,
 * DERIVE_KEYS, CONFIRM) each independently check their own quad against s_my_nonce/s_my_epk, so a quad that never
 * really involved this device's real ephemeral key still can't be signed, ECDH'd, or HMAC'd, regardless of what
 * VERIFY_PEER/VERIFY_CONFIRM did or didn't check.
 *
 * Why this exists at all: without it, SIGN_TRANSCRIPT/DERIVE_KEYS/CONFIRM used to trust whatever quad the host
 * handed them, with no check that "my" half of it was the ephemeral key/nonce this device actually generated
 * on-chip -- turning the identity key into a signing oracle for any quad-shaped bytes, not just the ones
 * belonging to a real ECDH this device is actually part of (see CLAUDE.md's review point on this). */
static bool quad_slot_matches_mine(const ca_quad_t *q, uint8_t role)
{
    const uint8_t *n = (role == CA_ROLE_A) ? q->nA : q->nB;
    const uint8_t *epk = (role == CA_ROLE_A) ? q->epkA : q->epkB;
    return memcmp(n, s_my_nonce, CA_NONCE_LEN) == 0 && memcmp(epk, s_my_epk, CA_POINT_LEN) == 0;
}

static void write_blob(uint8_t *out, size_t *o, ca_blob_t b)
{
    out[(*o)++] = (uint8_t)b.len;
    memcpy(&out[*o], b.data, b.len);
    *o += b.len;
}

/* ca_verify_fn for ca_x509.c's chain check (docs/key_exchange_ca_profile.md section 4): verify one ECDSA-SHA256 signature
 * under a bare 65-byte point. The SE052F can only verify against a key it already holds as an object, so this imports
 * `point` into a scratch slot first -- skipping the (flash-writing) import when the slot already holds the exact same
 * point, since ca_chain_verify() calls this twice per chain (issuing-under-root, then leaf-under-issuing) and this
 * handshake calls it a third time for the transcript signature (leaf key again) -- see CLAUDE.md's object-policy TODO
 * point about avoiding needless SE052F flash writes on the verify path. `ctx` is unused (no per-call state needed). */
static bool se052f_verify(void *ctx, const uint8_t point[CA_X509_POINT_LEN], const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len)
{
    static uint8_t s_last_point[CA_X509_POINT_LEN];
    static bool s_have_last;
    (void)ctx;
    if (!s_have_last || memcmp(s_last_point, point, CA_X509_POINT_LEN) != 0) {
        (void)security_service_delete_key(CA_PEER_VERIFY_SLOT);
        if (security_service_import_ec_public_key(CA_PEER_VERIFY_SLOT, SEC_EC_CURVE_P256, point, CA_X509_POINT_LEN) !=
            SEC_OK) {
            s_have_last = false;
            return false;
        }
        memcpy(s_last_point, point, CA_X509_POINT_LEN);
        s_have_last = true;
    }
    bool valid = false;
    return security_service_verify_message(CA_PEER_VERIFY_SLOT, msg, msg_len, sig, sig_len, &valid) == SEC_OK && valid;
}

static void hex_upper(const uint8_t *in, size_t len, uint8_t *out)
{
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[2U * i] = (uint8_t)digits[in[i] >> 4];
        out[2U * i + 1U] = (uint8_t)digits[in[i] & 0x0FU];
    }
}

/* Result codes for CA_CMD_VERIFY_PEER's response[1] (see the sub-command's doc comment above). */
#define CA_PEER_OK          0U
#define CA_PEER_CHAIN_FAIL  1U
#define CA_PEER_SIG_FAIL    2U
#define CA_PEER_SELF        3U
#define CA_PEER_BAD_PARAM   4U

bool ca_protocol_handler(const uint8_t *payload, uint16_t payload_len, uint8_t *response, uint16_t *response_len,
                          uint16_t max_response_len)
{
    uint8_t sub_cmd = payload[0];
    response[0] = sub_cmd;

    switch (sub_cmd) {
        case CA_CMD_GET_IDENTITY: {
            ca_blob_t id = ca_service_get_device_id();
            ca_blob_t cert = ca_service_get_device_cert();
            ca_blob_t issuing = ca_service_get_issuing_cert();
            ca_blob_t root_pt = ca_service_get_root_pubkey();
            ca_blob_t root_subj = ca_service_get_root_subject_der();
            size_t need = 2U + 1U + id.len + 2U + cert.len + 2U + issuing.len + root_pt.len + 1U + root_subj.len;
            if (max_response_len < need) {
                return false;
            }
            response[1] = (uint8_t)(ca_service_is_ready() ? CA_OK : CA_NOT_READY);
            size_t o = 2U;
            write_blob(response, &o, id);
            response[o++] = (uint8_t)(cert.len & 0xFFU);
            response[o++] = (uint8_t)((cert.len >> 8) & 0xFFU);
            memcpy(&response[o], cert.data, cert.len);
            o += cert.len;
            response[o++] = (uint8_t)(issuing.len & 0xFFU);
            response[o++] = (uint8_t)((issuing.len >> 8) & 0xFFU);
            memcpy(&response[o], issuing.data, issuing.len);
            o += issuing.len;
            memcpy(&response[o], root_pt.data, root_pt.len);
            o += root_pt.len;
            write_blob(response, &o, root_subj);
            *response_len = (uint16_t)o;
            return true;
        }
        case CA_CMD_GET_STATUS_TOKEN: {
            ca_blob_t tok = ca_service_get_status_token();
            if (max_response_len < 2U + 1U + tok.len) {
                return false;
            }
            response[1] = (uint8_t)(ca_service_is_ready() ? CA_OK : CA_NOT_READY);
            size_t o = 2U;
            write_blob(response, &o, tok);
            *response_len = (uint16_t)o;
            return true;
        }
        case CA_CMD_BEGIN: {
            if (max_response_len < 2U + CA_NONCE_LEN + CA_POINT_LEN + 2U + CA_KEM_PK_LEN) {
                return false;
            }
            end_session(); /* idempotent: a fresh BEGIN always starts a brand new session */
            if (!ca_service_is_ready()) {
                response[1] = (uint8_t)CA_NOT_READY;
                *response_len = 2U;
                return true;
            }
            uint8_t n_mine[CA_NONCE_LEN];
            /* QRNG first, MCU TRNG fallback (e.g. the V8Y board's analog safety lock) -- qrng_service_random_bytes(). */
            if (qrng_service_random_bytes(n_mine, CA_NONCE_LEN, NULL) != QRNG_OK) {
                response[1] = (uint8_t)CA_ERR_PROVISION; /* reused: "could not produce what BEGIN needs" */
                *response_len = 2U;
                return true;
            }
            sec_status_t gk = security_service_generate_ephemeral_ec_keypair(CA_EPHEMERAL_KEY_ID, SEC_EC_CURVE_P256);
            if (gk != SEC_OK) {
                memset(n_mine, 0, sizeof(n_mine));
                response[1] = (uint8_t)CA_ERR_PROVISION;
                *response_len = 2U;
                return true;
            }
            /* Set BEFORE the read-back below so a failure there still routes through end_session() knowing there is
             * a real ephemeral key object to delete (end_session() keys its cleanup off s_state >= CA_SESSION_BEGUN,
             * not a separate flag anymore). */
            s_state = CA_SESSION_BEGUN;
            uint8_t epk_mine[80];
            size_t epk_len = sizeof(epk_mine);
            if (security_service_read_ec_public_key(CA_EPHEMERAL_KEY_ID, epk_mine, &epk_len) != SEC_OK ||
                epk_len != CA_POINT_LEN) {
                memset(n_mine, 0, sizeof(n_mine));
                end_session();
                response[1] = (uint8_t)CA_ERR_READBACK;
                *response_len = 2U;
                return true;
            }
            /* Remember exactly what was generated -- every later sub-command's quad_slot_matches_mine() check is
             * only as good as this being the real source of truth, not whatever the host claims afterward. */
            memcpy(s_my_nonce, n_mine, CA_NONCE_LEN);
            memcpy(s_my_epk, epk_mine, CA_POINT_LEN);

            /* Best-effort ML-KEM-768 keypair, Giai đoạn 1 hybrid PQC (see CLAUDE.md and this file's top comment).
             * Unlike the ECDH keypair above, a failure here does NOT fail BEGIN -- it only means this call offers a
             * classical-only key exchange (pk_kem_len = 0 below); the ECDH keypair, already generated successfully,
             * is still fully usable on its own, exactly as before this feature existed. Both roles generate one
             * here because BEGIN runs before either side's role is decided (see s_kem_ct_b's doc comment) --
             * whichever role this device turns out NOT to be simply never uses it. */
            s_have_kem_keypair = pqc_kem_keygen(s_kem_pk, s_kem_sk);
            if (!s_have_kem_keypair) {
                memset(s_kem_sk, 0, sizeof(s_kem_sk));
                memset(s_kem_pk, 0, sizeof(s_kem_pk));
            }

            response[1] = (uint8_t)CA_OK;
            memcpy(&response[2], n_mine, CA_NONCE_LEN);
            memcpy(&response[2U + CA_NONCE_LEN], epk_mine, CA_POINT_LEN);
            memset(n_mine, 0, sizeof(n_mine)); /* handed to the caller in the response; this copy is done with it */
            size_t begin_o = 2U + CA_NONCE_LEN + CA_POINT_LEN;
            uint16_t pk_len = s_have_kem_keypair ? (uint16_t)CA_KEM_PK_LEN : 0U;
            response[begin_o++] = (uint8_t)(pk_len & 0xFFU);
            response[begin_o++] = (uint8_t)((pk_len >> 8) & 0xFFU);
            if (pk_len != 0U) {
                memcpy(&response[begin_o], s_kem_pk, CA_KEM_PK_LEN);
                begin_o += CA_KEM_PK_LEN;
            }
            *response_len = (uint16_t)begin_o;
            return true;
        }
        case CA_CMD_SIGN_TRANSCRIPT: {
            if (payload_len < 1U + CA_QUAD_LEN + 4U || max_response_len < 3U) {
                return false;
            }
            if (s_state < CA_SESSION_BEGUN) {
                response[1] = (uint8_t)CA_NOT_READY;
                *response_len = 2U;
                return true;
            }
            ca_quad_t q;
            read_quad(&payload[1], &q);
            size_t o = 1U + CA_QUAD_LEN;
            ca_kem_ext_t ext;
            if (!read_kem_ext(payload, (size_t)payload_len, &o, &ext) || o != (size_t)payload_len) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            if (!quad_slot_matches_mine(&q, q.role)) {
                /* q.role is asserted to be MY role for this sub-command -- see quad_slot_matches_mine()'s doc
                 * comment. A mismatch here means the host is asking the identity key to sign a quad that does not
                 * contain the ephemeral key/nonce this device actually generated in BEGIN -- refuse rather than
                 * sign an arbitrary quad-shaped statement. */
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            static uint8_t s_kem_ct_scratch[CA_KEM_CT_LEN]; /* only filled/used on the role-B hybrid path below */
            if (q.role == CA_ROLE_A) {
                if (!kem_pk_matches_mine(&ext)) {
                    response[1] = (uint8_t)CA_INVALID_PARAM;
                    *response_len = 2U;
                    return true;
                }
            }
            else if (ext.pk_kem_a_len == CA_KEM_PK_LEN) {
                /* My slot (ct_kem_b) is never taken from the host -- see s_kem_ct_b's doc comment for why it must
                 * be computed exactly once and then reused verbatim by every later call this session. A repeated
                 * SIGN_TRANSCRIPT call (host retry) reuses what is already cached instead of encapsulating again,
                 * which would silently desynchronize from whatever ct_kem_b M2 already sent the peer. */
                if (!s_have_kem_ct_b) {
                    uint8_t z[CA_KEM_SS_LEN];
                    if (!pqc_kem_encapsulate(ext.pk_kem_a, s_kem_ct_b, z)) {
                        response[1] = (uint8_t)CA_ERR_PROVISION;
                        *response_len = 2U;
                        return true;
                    }
                    memcpy(s_kem_z_b, z, sizeof(z));
                    memset(z, 0, sizeof(z));
                    s_have_kem_ct_b = true;
                }
                memcpy(s_kem_ct_scratch, s_kem_ct_b, CA_KEM_CT_LEN);
                ext.ct_kem_b = s_kem_ct_scratch;
                ext.ct_kem_b_len = CA_KEM_CT_LEN;
            }
            /* else: no valid pk_kem_a offered (classical-only, or an old/non-hybrid peer) -- ext.ct_kem_b is left
             * as whatever the host passed (must be empty too, see the half-hybrid check right below). */
            if ((ext.pk_kem_a_len == 0U) != (ext.ct_kem_b_len == 0U)) {
                /* Half-hybrid is never valid for a message actually being signed -- suite_of() only recognizes
                 * "both present" (hybrid) or "both empty" (classical). Reject rather than silently pick one. */
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            uint8_t msg[CA_MSG_BUF_LEN];
            size_t msg_len = build_msg(msg, CA_TRANSCRIPT_CONTEXT, sizeof(CA_TRANSCRIPT_CONTEXT), &q, &ext);
            if (msg_len == 0U) { /* platform_sha256() failure hashing the PQC extension -- see build_msg()'s doc comment */
                response[1] = (uint8_t)CA_ERR_PROVISION;
                *response_len = 2U;
                return true;
            }
            uint8_t digest[32];
            uint8_t sig[72];
            size_t sig_len = sizeof(sig);
            ca_status_t st = (security_service_sha256(msg, msg_len, digest) == SEC_OK)
                                  ? ca_service_sign_identity(digest, sig, &sig_len)
                                  : CA_ERR_SIGN_TEST;
            response[1] = (uint8_t)st;
            size_t need = 3U + sig_len + 2U + ext.ct_kem_b_len;
            if (st != CA_OK || max_response_len < need) {
                response[2] = 0U;
                *response_len = 3U;
                return true;
            }
            response[2] = (uint8_t)sig_len;
            memcpy(&response[3], sig, sig_len);
            size_t ro = 3U + sig_len;
            response[ro++] = (uint8_t)(ext.ct_kem_b_len & 0xFFU);
            response[ro++] = (uint8_t)((ext.ct_kem_b_len >> 8) & 0xFFU);
            if (ext.ct_kem_b_len != 0U) {
                memcpy(&response[ro], ext.ct_kem_b, ext.ct_kem_b_len);
                ro += ext.ct_kem_b_len;
            }
            *response_len = (uint16_t)ro;
            return true;
        }
        case CA_CMD_VERIFY_PEER: {
            if (payload_len < 1U + CA_QUAD_LEN + 4U || max_response_len < 3U) {
                return false;
            }
            ca_quad_t q;
            read_quad(&payload[1], &q);
            if (s_state < CA_SESSION_BEGUN) {
                /* Hygiene, not a security boundary: verifying a peer only makes sense inside an active handshake
                 * session. See quad_slot_matches_mine()'s doc comment for why this sub-command does NOT also check
                 * that a slot of `q` matches s_my_nonce/s_my_epk -- q.role here is the PEER's role, and requiring
                 * "my" slot to match would reject a legitimate same-identity self-dial (CA_PEER_SELF's own job). */
                response[1] = CA_PEER_BAD_PARAM;
                response[2] = (uint8_t)CA_X509_ERR_PARAM;
                *response_len = 3U;
                return true;
            }
            size_t o = 1U + CA_QUAD_LEN;
            ca_kem_ext_t ext;
            /* Whatever this device's own view of pk_kem_a/ct_kem_b is (if any) is irrelevant here -- this rebuilds
             * the message exactly as the PEER claims to have signed it (same as epkA/epkB above, never checked
             * against s_my_nonce/s_my_epk for this sub-command); a lie in either slot just means se052f_verify()
             * below fails, since it would no longer be verifying against what the peer actually signed. */
            if (!read_kem_ext(payload, (size_t)payload_len, &o, &ext) ||
                (ext.pk_kem_a_len == 0U) != (ext.ct_kem_b_len == 0U)) {
                response[1] = CA_PEER_BAD_PARAM;
                response[2] = (uint8_t)CA_X509_ERR_PARAM;
                *response_len = 3U;
                return true;
            }
            if ((size_t)payload_len < o + 2U + 2U + 1U + 1U) {
                return false;
            }
            uint16_t issuing_len = read_u16le(&payload[o]);
            o += 2U;
            if ((size_t)payload_len < o + issuing_len + 2U) {
                return false;
            }
            const uint8_t *issuing = &payload[o];
            o += issuing_len;
            uint16_t leaf_len = read_u16le(&payload[o]);
            o += 2U;
            if ((size_t)payload_len < o + leaf_len + 1U) {
                return false;
            }
            const uint8_t *leaf = &payload[o];
            o += leaf_len;
            uint8_t token_len = payload[o];
            o += 1U;
            if ((size_t)payload_len < o + token_len + 1U) {
                return false;
            }
            const uint8_t *token = &payload[o];
            o += token_len;
            uint8_t sig_len = payload[o];
            o += 1U;
            if ((size_t)payload_len != o + sig_len) {
                return false;
            }
            const uint8_t *sig = &payload[o];
            if (token_len == 0U) {
                /* the whole point of this handshake is revocation-checked auth -- unlike ca_x509's generic API, a token
                 * is not optional here */
                response[1] = CA_PEER_BAD_PARAM;
                response[2] = (uint8_t)CA_X509_ERR_PARAM;
                *response_len = 3U;
                return true;
            }

            ca_token_t tok_peek;
            if (ca_token_parse(token, token_len, &tok_peek) != CA_X509_OK) {
                response[1] = CA_PEER_CHAIN_FAIL;
                response[2] = (uint8_t)CA_X509_ERR_TOKEN;
                *response_len = 3U;
                return true;
            }
            ca_blob_t root_pt = ca_service_get_root_pubkey();
            ca_blob_t root_subj = ca_service_get_root_subject_der();
            ca_trust_anchor_t anchor;
            anchor.root_point = root_pt.data;
            anchor.root_subject.p = root_subj.data;
            anchor.root_subject.len = root_subj.len;
            ca_span_t issuing_span = {issuing, issuing_len};
            ca_span_t leaf_span = {leaf, leaf_len};
            ca_span_t token_span = {token, token_len};
            ca_chain_t out;
            ca_x509_status_t chain_status =
                ca_chain_verify(&anchor, issuing_span, leaf_span, token_span, (int64_t)tok_peek.this_update,
                                se052f_verify, NULL, &out);
            if (chain_status != CA_X509_OK) {
                response[1] = CA_PEER_CHAIN_FAIL;
                response[2] = (uint8_t)chain_status;
                *response_len = 3U;
                return true;
            }

            uint8_t msg[CA_MSG_BUF_LEN];
            size_t msg_len = build_msg(msg, CA_TRANSCRIPT_CONTEXT, sizeof(CA_TRANSCRIPT_CONTEXT), &q, &ext);
            if (msg_len == 0U) { /* platform_sha256() failure hashing the PQC extension -- see build_msg()'s doc comment */
                response[1] = CA_PEER_SIG_FAIL;
                response[2] = (uint8_t)CA_X509_OK;
                *response_len = 3U;
                return true;
            }
            if (!se052f_verify(NULL, out.leaf.point, msg, msg_len, sig, sig_len)) {
                response[1] = CA_PEER_SIG_FAIL;
                response[2] = (uint8_t)CA_X509_OK;
                *response_len = 3U;
                return true;
            }

            ca_blob_t own_id = ca_service_get_device_id();
            uint8_t own_id_hex[64];
            if (own_id.len * 2U <= sizeof(own_id_hex)) {
                hex_upper(own_id.data, own_id.len, own_id_hex);
                if (out.leaf.subject_cn.len == own_id.len * 2U &&
                    memcmp(out.leaf.subject_cn.p, own_id_hex, out.leaf.subject_cn.len) == 0) {
                    response[1] = CA_PEER_SELF;
                    response[2] = (uint8_t)CA_X509_OK;
                    *response_len = 3U;
                    return true;
                }
            }

            /* Remember the verified peer's identity (cert CN, hex text) for CONFIRM/VERIFY_CONFIRM's id-binding
             * (see append_ids()'s doc comment), and only now advance the session state -- DERIVE_KEYS below refuses
             * to run until this has actually happened once. */
            size_t id_len = out.leaf.subject_cn.len;
            if (id_len > sizeof(s_peer_id)) {
                response[1] = CA_PEER_BAD_PARAM;
                response[2] = (uint8_t)CA_X509_ERR_PROFILE;
                *response_len = 3U;
                return true;
            }
            memcpy(s_peer_id, out.leaf.subject_cn.p, id_len);
            s_peer_id_len = id_len;
            s_state = CA_SESSION_PEER_VERIFIED;

            response[1] = CA_PEER_OK;
            response[2] = (uint8_t)CA_X509_OK;
            if (max_response_len < (uint16_t)(4U + id_len)) {
                *response_len = 3U;
                return true;
            }
            response[3] = (uint8_t)id_len;
            memcpy(&response[4], out.leaf.subject_cn.p, id_len);
            *response_len = (uint16_t)(4U + id_len);
            return true;
        }
        case CA_CMD_DERIVE_KEYS: {
            if (payload_len < 1U + CA_QUAD_LEN + 4U || max_response_len < 2U) {
                return false;
            }
            /* Requires BEGIN to have run (same as the original !s_have_ephemeral check) -- NOT a successful
             * VERIFY_PEER, even though a real call's own message order always does VERIFY_PEER first (see
             * docs/key_exchange_ca_profile.md section 6.3). Deliberately not required here: media_protocol.c never
             * gets these keys anyway until CA_SESSION_ESTABLISHED (ca_protocol_get_session_keys(), which requires a
             * matching VERIFY_CONFIRM -- see that function's doc comment), and requiring PEER_VERIFIED here was
             * found to conflict with app_main.c's app_ca_protocol_self_test(), which (having no second board)
             * cannot make its own VERIFY_PEER call return CA_PEER_OK -- see quad_slot_matches_mine()'s doc comment
             * for the same reasoning applied to VERIFY_PEER itself. An attacker who calls DERIVE_KEYS without a
             * real VERIFY_PEER gains nothing: the resulting keys simply won't match whatever a genuine peer
             * independently derived, so VERIFY_CONFIRM still won't match and ESTABLISHED is still never reached. */
            if (s_state < CA_SESSION_BEGUN) {
                response[1] = (uint8_t)CA_NOT_READY;
                *response_len = 2U;
                return true;
            }
            ca_quad_t q;
            read_quad(&payload[1], &q);
            size_t o = 1U + CA_QUAD_LEN;
            ca_kem_ext_t ext;
            if (!read_kem_ext(payload, (size_t)payload_len, &o, &ext) || o != (size_t)payload_len ||
                (ext.pk_kem_a_len == 0U) != (ext.ct_kem_b_len == 0U)) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            if (!quad_slot_matches_mine(&q, q.role)) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            const uint8_t *peer_epk = peer_epk_of(&q);
            if (!ca_x509_point_on_curve(peer_epk)) {
                /* The peer's ephemeral key comes straight off the wire with no certificate around it (unlike
                 * VERIFY_PEER's leaf/issuing points, which ca_x509_parse_cert() already validates) -- check it here
                 * explicitly instead of relying solely on the SE052F rejecting an invalid point inside
                 * security_service_ecdh_to_secret() below. Real-hardware behavior of that rejection was verified
                 * separately (see CLAUDE.md's "Test 1"), but that was a one-off manual test, not something this
                 * file enforced itself. */
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }

            bool hybrid = suite_of(&ext) == CA_SUITE_HYBRID_P256_MLKEM768;
            if (hybrid && q.role == CA_ROLE_A && !kem_pk_matches_mine(&ext)) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            if (hybrid && q.role == CA_ROLE_B &&
                (!s_have_kem_ct_b || memcmp(ext.ct_kem_b, s_kem_ct_b, CA_KEM_CT_LEN) != 0)) {
                /* My own ct_kem_b is authoritative (computed once at SIGN_TRANSCRIPT time, see its doc comment) --
                 * a DERIVE_KEYS call quoting a DIFFERENT ct_kem_b than what was actually sent to the peer in M2
                 * would derive keys the peer can never match, so refuse outright instead of silently deriving
                 * something useless. */
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }

            uint8_t salt[CA_NONCE_LEN * 2U];
            memcpy(salt, q.nA, CA_NONCE_LEN);
            memcpy(&salt[CA_NONCE_LEN], q.nB, CA_NONCE_LEN);
            uint8_t k_a_to_b[32], k_b_to_a[32];
            sec_status_t st;

            if (!hybrid && security_service_derives_in_chip()) {
                /* Classical path on a chip that can derive in-chip (SE052F) -- Z never leaves it, exactly as before
                 * Giai đoạn 1. */
                st = security_service_ecdh_to_secret(CA_EPHEMERAL_KEY_ID, peer_epk, CA_POINT_LEN, CA_ECDH_SECRET_ID);
                if (st == SEC_OK) {
                    sec_status_t r1 = security_service_hkdf_export(CA_ECDH_SECRET_ID, salt, sizeof(salt),
                                                                    CA_INFO_A_TO_B, sizeof(CA_INFO_A_TO_B), k_a_to_b,
                                                                    sizeof(k_a_to_b));
                    sec_status_t r2 = (r1 == SEC_OK) ? security_service_hkdf_export(CA_ECDH_SECRET_ID, salt,
                                                                                    sizeof(salt), CA_INFO_B_TO_A,
                                                                                    sizeof(CA_INFO_B_TO_A), k_b_to_a,
                                                                                    sizeof(k_b_to_a))
                                                     : r1;
                    st = (r2 == SEC_OK) ? security_service_hkdf_to_secret(CA_ECDH_SECRET_ID, salt, sizeof(salt),
                                                                          CA_INFO_CONFIRM_KEY,
                                                                          sizeof(CA_INFO_CONFIRM_KEY),
                                                                          CA_CONFIRM_SECRET_ID, 32U)
                                        : r2;
                }
                (void)security_service_delete_key(CA_ECDH_SECRET_ID); /* Z is single-use: never needed again after this */
            }
            else {
                /* Host-side derivation, in MCU RAM. Taken for:
                 *  - the hybrid path -- exactly SecP256r1MLKEM768 (draft-ietf-tls-ecdhe-mlkem): IKM = Z_ecdh || Z_kem
                 *    (ECDH first, per NIST SP 800-56Cr2's "first value must be FIPS-approved"). Z_kem can never be a
                 *    chip secret object (ML-KEM runs in MCU software), so the combine has to happen here;
                 *  - the classical path on a chip that cannot derive in-chip (security_service_derives_in_chip()
                 *    false: the SE050F2, whose FIPS-mode applet refuses ECDH and HKDF) -- IKM = Z_ecdh alone, where
                 *    security_service_ecdh_to_host() is software ECDH on the backend's RAM ephemeral key.
                 * One HKDF-Extract+Expand per key (hkdf_sha256_extract_expand_32(), RFC 5869, the same salt/info as the
                 * in-chip path, so the keys are byte-identical to what an SE052F peer or the PC/Android tools derive).
                 * Z_ecdh, Z_kem and the IKM are wiped the moment this block is done with them; the derived confirm key
                 * is written back into the chip (security_service_write_transient_hmac_key()) so CONFIRM/
                 * VERIFY_CONFIRM's HMAC keeps running on-chip afterward, unchanged. */
                uint8_t z_ecdh[32];
                uint8_t z_kem[CA_KEM_SS_LEN];
                bool have_ikm = false;
                st = security_service_ecdh_to_host(CA_EPHEMERAL_KEY_ID, peer_epk, CA_POINT_LEN, z_ecdh);
                if (st == SEC_OK && hybrid) {
                    if (q.role == CA_ROLE_A) {
                        have_ikm = pqc_kem_decapsulate(s_kem_sk, ext.ct_kem_b, z_kem);
                    }
                    else {
                        memcpy(z_kem, s_kem_z_b, sizeof(z_kem));
                        have_ikm = true;
                    }
                }
                else if (st == SEC_OK) {
                    have_ikm = true;
                }
                if (st == SEC_OK && !have_ikm) {
                    st = SEC_ERROR;
                }
                if (st == SEC_OK) {
                    uint8_t ikm[32U + CA_KEM_SS_LEN];
                    size_t ikm_len = 32U;
                    memcpy(ikm, z_ecdh, 32U);
                    if (hybrid) {
                        memcpy(&ikm[32], z_kem, CA_KEM_SS_LEN);
                        ikm_len += CA_KEM_SS_LEN;
                    }
                    uint8_t confirm_key[32];
                    bool ok = hkdf_sha256_extract_expand_32(salt, sizeof(salt), ikm, ikm_len, CA_INFO_A_TO_B,
                                                            sizeof(CA_INFO_A_TO_B), k_a_to_b) &&
                              hkdf_sha256_extract_expand_32(salt, sizeof(salt), ikm, ikm_len, CA_INFO_B_TO_A,
                                                            sizeof(CA_INFO_B_TO_A), k_b_to_a) &&
                              hkdf_sha256_extract_expand_32(salt, sizeof(salt), ikm, ikm_len, CA_INFO_CONFIRM_KEY,
                                                            sizeof(CA_INFO_CONFIRM_KEY), confirm_key);
                    st = ok ? security_service_write_transient_hmac_key(CA_CONFIRM_SECRET_ID, confirm_key,
                                                                        sizeof(confirm_key))
                            : SEC_ERROR;
                    memset(ikm, 0, sizeof(ikm));
                    memset(confirm_key, 0, sizeof(confirm_key));
                }
                memset(z_kem, 0, sizeof(z_kem));
                memset(z_ecdh, 0, sizeof(z_ecdh));
            }
            memset(salt, 0, sizeof(salt));
            if (st != SEC_OK) {
                memset(k_a_to_b, 0, sizeof(k_a_to_b));
                memset(k_b_to_a, 0, sizeof(k_b_to_a));
                response[1] = (uint8_t)CA_ERR_PROVISION;
                *response_len = 2U;
                return true;
            }
            if (q.role == CA_ROLE_A) {
                memcpy(s_send_key, k_a_to_b, 32U);
                memcpy(s_recv_key, k_b_to_a, 32U);
            }
            else {
                memcpy(s_send_key, k_b_to_a, 32U);
                memcpy(s_recv_key, k_a_to_b, 32U);
            }
            /* Keys are computed and held from here on, but ca_protocol_get_session_keys() still won't hand them out
             * until CA_SESSION_ESTABLISHED (VERIFY_CONFIRM matches) -- see that function's doc comment. */
            s_state = CA_SESSION_KEYS_DERIVED;
            memset(k_a_to_b, 0, sizeof(k_a_to_b));
            memset(k_b_to_a, 0, sizeof(k_b_to_a));
            response[1] = (uint8_t)CA_OK;
            *response_len = 2U;
            return true;
        }
        case CA_CMD_CONFIRM: {
            if (payload_len < 1U + CA_QUAD_LEN + 4U || max_response_len < 2U + 32U) {
                return false;
            }
            if (s_state != CA_SESSION_KEYS_DERIVED) {
                response[1] = (uint8_t)CA_NOT_READY;
                *response_len = 2U;
                return true;
            }
            ca_quad_t q;
            read_quad(&payload[1], &q);
            size_t o = 1U + CA_QUAD_LEN;
            ca_kem_ext_t ext;
            if (!read_kem_ext(payload, (size_t)payload_len, &o, &ext) || o != (size_t)payload_len) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            if (!quad_slot_matches_mine(&q, q.role)) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            if (q.role == CA_ROLE_A) {
                if (!kem_pk_matches_mine(&ext)) {
                    response[1] = (uint8_t)CA_INVALID_PARAM;
                    *response_len = 2U;
                    return true;
                }
            }
            else {
                /* My slot (ct_kem_b) is authoritative here too, same as SIGN_TRANSCRIPT -- see s_kem_ct_b's doc
                 * comment. By CONFIRM time it must already be cached (set at SIGN_TRANSCRIPT), never recomputed --
                 * a host-supplied ct_kem_b that does not match is refused outright (same reasoning as DERIVE_KEYS's
                 * own check), rather than silently building a message whose suite_id/PQC bytes disagree with what
                 * DERIVE_KEYS actually used to compute CA_CONFIRM_SECRET_ID. */
                if (ext.ct_kem_b_len != 0U &&
                    (!s_have_kem_ct_b || memcmp(ext.ct_kem_b, s_kem_ct_b, CA_KEM_CT_LEN) != 0)) {
                    response[1] = (uint8_t)CA_INVALID_PARAM;
                    *response_len = 2U;
                    return true;
                }
                if (s_have_kem_ct_b) {
                    ext.ct_kem_b = s_kem_ct_b;
                    ext.ct_kem_b_len = CA_KEM_CT_LEN;
                }
            }
            if ((ext.pk_kem_a_len == 0U) != (ext.ct_kem_b_len == 0U)) {
                response[1] = (uint8_t)CA_INVALID_PARAM;
                *response_len = 2U;
                return true;
            }
            /* Bind the confirmation MAC to both parties' VERIFIED identities (not just their ephemeral keys/nonces)
             * -- see append_ids()'s doc comment. Canonical A-then-B order: q.role is MY role here, so if I am A my
             * own id goes in the A slot and s_peer_id (captured by VERIFY_PEER) goes in the B slot, and vice versa. */
            ca_blob_t own_id = ca_service_get_device_id();
            uint8_t own_id_hex[CA_ID_MAX];
            size_t own_id_hex_len = own_id.len * 2U;
            if (own_id_hex_len > sizeof(own_id_hex)) {
                response[1] = (uint8_t)CA_ERR_READBACK;
                *response_len = 2U;
                return true;
            }
            hex_upper(own_id.data, own_id.len, own_id_hex);
            const uint8_t *id_a = (q.role == CA_ROLE_A) ? own_id_hex : s_peer_id;
            size_t id_a_len = (q.role == CA_ROLE_A) ? own_id_hex_len : s_peer_id_len;
            const uint8_t *id_b = (q.role == CA_ROLE_A) ? s_peer_id : own_id_hex;
            size_t id_b_len = (q.role == CA_ROLE_A) ? s_peer_id_len : own_id_hex_len;

            uint8_t msg[CA_MSG_BUF_LEN];
            size_t msg_len = build_msg(msg, CA_CONFIRM_MSG_CONTEXT, sizeof(CA_CONFIRM_MSG_CONTEXT), &q, &ext);
            if (msg_len == 0U) { /* platform_sha256() failure hashing the PQC extension -- see build_msg()'s doc comment */
                response[1] = (uint8_t)SEC_ERROR;
                *response_len = 2U;
                return true;
            }
            msg_len = append_ids(msg, msg_len, id_a, id_a_len, id_b, id_b_len);
            uint8_t mac[32];
            sec_status_t st = security_service_hmac_sha256_with_secret(CA_CONFIRM_SECRET_ID, msg, msg_len, mac);
            response[1] = (uint8_t)st;
            if (st != SEC_OK) {
                *response_len = 2U;
                return true;
            }
            memcpy(&response[2], mac, sizeof(mac));
            *response_len = (uint16_t)(2U + sizeof(mac));
            return true;
        }
        case CA_CMD_VERIFY_CONFIRM: {
            if (payload_len < 1U + CA_QUAD_LEN + 4U + 32U || max_response_len < 2U) {
                return false;
            }
            /* `< CA_SESSION_KEYS_DERIVED` (not `!=`) so this can be called again after a PRIOR successful call
             * already advanced s_state to CA_SESSION_ESTABLISHED -- e.g. a legitimate retry of a lost/duplicate M4
             * message, or (found on real hardware, 2026-09-24) app_ca_protocol_self_test()'s own tamper-detection
             * check, which deliberately calls VERIFY_CONFIRM a second time (correct MAC, then a 1-bit-flipped one)
             * to prove mismatches are still caught post-establishment. The original `!=` version incorrectly
             * short-circuited that second call with "no confirm key held" (result=2) instead of actually checking
             * the MAC, because by then s_state had already moved past CA_SESSION_KEYS_DERIVED to ESTABLISHED --
             * confirmed on real hardware: "VERIFY_CONFIRM (tampered): FAIL -- expected mismatch(1), got 2" every
             * boot. The confirm key itself (CA_CONFIRM_SECRET_ID) is still held in both states, so re-checking a
             * MAC against it here is always safe. */
            if (s_state < CA_SESSION_KEYS_DERIVED) {
                response[1] = 2U;
                *response_len = 2U;
                return true;
            }
            ca_quad_t q;
            read_quad(&payload[1], &q);
            size_t o = 1U + CA_QUAD_LEN;
            ca_kem_ext_t ext;
            /* No quad_slot_matches_mine() / kem_pk_matches_mine() check here -- q.role is the PEER's role (see this
             * sub-command's own doc comment), and the same reasoning as VERIFY_PEER applies: requiring "my" slot to
             * be the OTHER one would reject a legitimate same-identity self-dial. The MAC comparison below is
             * itself the real check -- it can only match if this device's own CONFIRM (using its own real
             * quad/ext/keys) produced the same bytes, which already depends on quad_slot_matches_mine()/
             * kem_pk_matches_mine() having passed back in DERIVE_KEYS/CONFIRM. */
            if (!read_kem_ext(payload, (size_t)payload_len, &o, &ext) || (size_t)payload_len != o + 32U) {
                response[1] = 2U;
                *response_len = 2U;
                return true;
            }
            const uint8_t *given_mac = &payload[o];

            /* Same canonical A/B id resolution as CONFIRM, but q.role is the PEER's role here -- see that
             * handler's own comment for the mirrored (and equivalent) logic. */
            ca_blob_t own_id = ca_service_get_device_id();
            uint8_t own_id_hex[CA_ID_MAX];
            size_t own_id_hex_len = own_id.len * 2U;
            if (own_id_hex_len > sizeof(own_id_hex)) {
                response[1] = 2U;
                *response_len = 2U;
                return true;
            }
            hex_upper(own_id.data, own_id.len, own_id_hex);
            const uint8_t *id_a = (q.role == CA_ROLE_A) ? s_peer_id : own_id_hex;
            size_t id_a_len = (q.role == CA_ROLE_A) ? s_peer_id_len : own_id_hex_len;
            const uint8_t *id_b = (q.role == CA_ROLE_A) ? own_id_hex : s_peer_id;
            size_t id_b_len = (q.role == CA_ROLE_A) ? own_id_hex_len : s_peer_id_len;

            uint8_t msg[CA_MSG_BUF_LEN];
            size_t msg_len = build_msg(msg, CA_CONFIRM_MSG_CONTEXT, sizeof(CA_CONFIRM_MSG_CONTEXT), &q, &ext);
            if (msg_len == 0U) { /* platform_sha256() failure hashing the PQC extension -- see build_msg()'s doc comment */
                response[1] = 2U;
                *response_len = 2U;
                return true;
            }
            msg_len = append_ids(msg, msg_len, id_a, id_a_len, id_b, id_b_len);
            uint8_t mac[32];
            if (security_service_hmac_sha256_with_secret(CA_CONFIRM_SECRET_ID, msg, msg_len, mac) != SEC_OK) {
                response[1] = 2U;
                *response_len = 2U;
                return true;
            }
            /* Constant-time-ish compare: XOR-accumulate rather than an early-exit memcmp. A timing side channel here would
             * only help an attacker who already broke HMAC-SHA256 (no such attack is known), but it costs nothing to avoid. */
            uint8_t diff = 0U;
            for (size_t i = 0; i < sizeof(mac); i++) {
                diff |= (uint8_t)(mac[i] ^ given_mac[i]);
            }
            if (diff == 0U) {
                /* Both sides now provably hold the same session keys -- only now is it safe for
                 * ca_protocol_get_session_keys() to hand them to media_protocol.c. */
                s_state = CA_SESSION_ESTABLISHED;
            }
            response[1] = (diff == 0U) ? 0U : 1U;
            *response_len = 2U;
            return true;
        }
        case CA_CMD_END_SESSION: {
            if (max_response_len < 2U) {
                return false;
            }
            end_session();
            response[1] = (uint8_t)CA_OK;
            *response_len = 2U;
            return true;
        }
        default:
            return false;
    }
}
