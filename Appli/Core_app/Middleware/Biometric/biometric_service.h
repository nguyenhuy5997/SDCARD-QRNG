/**
 * @file    biometric_service.h
 * @brief   Chip-agnostic fingerprint sensor service interface.
 *
 * App code that needs fingerprint enrollment/identification calls only
 * this header -- never Core_app/Drivers/FPC5234's FPC host library
 * directly. Swapping the sensor (a different chip, e.g. going from the
 * FPC5234 to an FPC2530/FPC2534 variant or another vendor entirely) means
 * adding another backend under Core_app/Middleware/Biometric/<chip>/ that
 * implements this same interface; App does not change. This mirrors
 * exactly how Core_app/Middleware/Security/security_service.h decouples
 * App from the SE052F, and how Core_app/Platform decouples App from the
 * specific MCU family.
 *
 * Scope: this is deliberately a small, commonly-needed subset of what the
 * sensor can do -- init, enroll, identify, list/delete templates. The
 * FPC5234 backend alone speaks 15+ raw commands (navigation, GPIO
 * control, system config, BIST, raw template data get/put, factory
 * reset, ...) -- see Core_app/Drivers/FPC5234/fpc_host_sample.h. Extend
 * this header (and every backend) the same way if App needs one of
 * those; do not reach past this header from App.
 *
 * Unlike security_service.h's backend (a synchronous request/response
 * chip), the FPC5234 protocol is asynchronous (frames arrive as
 * interrupt-driven events) -- every call below is still a normal
 * blocking function from App's point of view, bounded by its own
 * `timeout_ms`; the backend does the event pumping internally.
 */
#ifndef BIOMETRIC_SERVICE_H
#define BIOMETRIC_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    BIO_OK = 0,
    BIO_ERROR,          /* transport/sensor error -- see backend logs */
    BIO_NOT_READY,       /* biometric_service_init() was not called, or failed */
    BIO_INVALID_PARAM,
    BIO_TIMEOUT,
    BIO_NO_MATCH,        /* biometric_service_identify() completed normally
                           * but the touch did not match any template --
                           * distinct from a transport/sensor error */
    BIO_WRONG_STATE,     /* e.g. biometric_service_navigation_poll() called
                           * without an active biometric_service_navigation_start() */
} bio_status_t;

/** Pass to biometric_service_delete_template() to delete every enrolled
 *  template instead of one specific id. No real template uses this value
 *  (ids come back from biometric_service_list_templates()). */
#define BIO_TEMPLATE_ID_ALL 0xFFFFU

/** Bring the fingerprint sensor up: reset it, bring up its transport, and
 *  wait for it to report ready. Safe to call more than once. */
bio_status_t biometric_service_init(void);

/** Tear down. biometric_service_init() must be called again before using
 *  any other function. */
bio_status_t biometric_service_deinit(void);

/** True once biometric_service_init() has succeeded and not been
 *  followed by biometric_service_deinit(). */
bool biometric_service_is_ready(void);

/** List every enrolled template id. `*count` is the capacity of `ids` on
 *  call (0 is valid, just to learn the count -- pass ids as NULL then),
 *  the actual number of templates on success (may be less than the
 *  number stored if `ids` was too small; call again with a bigger buffer
 *  if `*count` came back equal to the capacity you passed in). */
bio_status_t biometric_service_list_templates(uint16_t *ids, size_t *count);

/** True if a template with this id exists. Unlike
 *  security_service_key_exists() (a single direct "does this id exist"
 *  query on the SE052F), the FPC5234 backend has to list every template
 *  and search it -- the underlying protocol has no per-id existence
 *  check. O(template count), not O(1); avoid calling this in a loop over
 *  many ids, use biometric_service_list_templates() once instead. */
bool biometric_service_template_exists(uint16_t template_id);

/** Optional per-touch progress callback for biometric_service_enroll(),
 *  invoked once per touch with the sensor's feedback for that touch (one
 *  of ENROLL_FEEDBACK_* in Core_app/Drivers/FPC5234/fpc_api.h -- that
 *  header is safe for a backend-specific callback signature like this
 *  one to depend on, unlike App) and how many more touches it expects.
 *  Called from inside biometric_service_enroll()'s blocking call, not
 *  from an ISR -- keep it quick regardless. */
typedef void (*bio_enroll_progress_cb_t)(uint8_t feedback, uint8_t samples_remaining);

/** Enroll a new fingerprint (blocking): walks the sensor through however
 *  many touches it needs (device-configured, typically 12-20),
 *  invoking `progress_cb` after each one if non-NULL. `timeout_ms`
 *  bounds the whole operation, all touches included (0 = no timeout --
 *  not recommended, this blocks until a human finishes touching the
 *  sensor). The new template's id is not returned directly -- the
 *  underlying protocol doesn't surface it here (see
 *  Core_app/Middleware/Biometric/FPC5234/biometric_service_fpc5234.c's
 *  doc comment on biometric_service_enroll()) -- call
 *  biometric_service_list_templates() before and after to find it if
 *  needed. */
bio_status_t biometric_service_enroll(bio_enroll_progress_cb_t progress_cb, uint32_t timeout_ms);

/** Identify a touch against every enrolled template (blocking): waits
 *  for a finger, matches it, and reports the result. Returns BIO_OK with
 *  `*matched_template_id` set on a match, BIO_NO_MATCH (not an error,
 *  `*matched_template_id` is left untouched) if the touch matched
 *  nothing, or BIO_TIMEOUT/BIO_ERROR otherwise. */
bio_status_t biometric_service_identify(uint16_t *matched_template_id, uint32_t timeout_ms);

/** Delete one template (`template_id`), or every template
 *  (BIO_TEMPLATE_ID_ALL). */
bio_status_t biometric_service_delete_template(uint16_t template_id);

/** Gesture reported by biometric_service_navigation_poll(). Mirrors
 *  CMD_NAV_EVENT_* in Core_app/Drivers/FPC5234/fpc_api.h -- kept as its
 *  own enum (rather than reusing that one) so App never needs to include
 *  a Core_app/Drivers/FPC5234 header, same reasoning as
 *  bio_enroll_progress_cb_t's feedback byte. */
typedef enum {
    BIO_NAV_NONE = 0,
    BIO_NAV_UP,
    BIO_NAV_DOWN,
    BIO_NAV_RIGHT,
    BIO_NAV_LEFT,
    BIO_NAV_PRESS,
    BIO_NAV_LONG_PRESS,
} bio_nav_gesture_t;

/** Orientation for biometric_service_navigation_start(), in 90-degree
 *  clockwise steps from the sensor's default mounting orientation. */
typedef enum {
    BIO_NAV_ORIENTATION_0 = 0,
    BIO_NAV_ORIENTATION_90,
    BIO_NAV_ORIENTATION_180,
    BIO_NAV_ORIENTATION_270,
} bio_nav_orientation_t;

/** Reset the sensor and wait for it to report ready again, as if
 *  biometric_service_init() had just brought it up for the first time.
 *  The sensor firmware only accepts CMD_NAVIGATION right after boot --
 *  call this immediately before biometric_service_navigation_start() if
 *  enroll/identify/list/delete_template already ran earlier in this
 *  session, or the sensor rejects it with BIO_ERROR (FPC_RESULT_WRONG_STATE)
 *  once a touch arrives. Requires biometric_service_init() to have
 *  already succeeded once; leaves every enrolled template untouched
 *  (this is a device reset, not a factory reset). */
bio_status_t biometric_service_reset(void);

/** Put the sensor into navigation (trackpad) mode: every touch/gesture on
 *  it from here on is reported by biometric_service_navigation_poll().
 *  Stays in this mode until biometric_service_navigation_stop() is
 *  called -- biometric_service_enroll()/identify() both return
 *  BIO_WRONG_STATE while it is active; stop navigation first. See
 *  biometric_service_reset()'s doc comment before calling this after
 *  any other sensor operation in the same session. */
bio_status_t biometric_service_navigation_start(bio_nav_orientation_t orientation);

/** Non-blocking: reports whether a new navigation gesture has arrived
 *  since the last call, without waiting. On BIO_OK, `*gesture` is the
 *  new gesture, or BIO_NAV_NONE if nothing new has shown up yet -- both
 *  are a normal, successful check, not an error or a timeout. Navigation
 *  is a continuous stream of gesture events for as long as the sensor
 *  reports finger movement, not a single request/response, so this call
 *  never blocks: call it on every iteration of the App's own loop while
 *  navigation mode is active (e.g. alongside whatever else the main loop
 *  polls) to track gestures as they happen in real time. Only valid
 *  between biometric_service_navigation_start() and
 *  biometric_service_navigation_stop() -- returns BIO_WRONG_STATE
 *  otherwise. */
bio_status_t biometric_service_navigation_poll(bio_nav_gesture_t *gesture);

/** Leave navigation mode (aborts it on the sensor). Safe to call even if
 *  navigation was never started. */
bio_status_t biometric_service_navigation_stop(void);

/** Optional per-gesture subscriber, invoked from inside
 *  biometric_service_navigation_poll() whenever it detects a new
 *  gesture (i.e. it fires with the same value poll() also returns
 *  through its `*gesture` out-param, as a convenience for App code that
 *  is not the one calling poll() itself -- a menu/UI module elsewhere in
 *  App, for example). Called synchronously from inside poll(), on
 *  whatever context poll() is called from -- never from an interrupt,
 *  and never on its own; something still has to call
 *  biometric_service_navigation_poll() regularly (e.g. from the main
 *  loop) to pump events at all. Keep it quick, same as
 *  bio_enroll_progress_cb_t. */
typedef void (*bio_nav_gesture_cb_t)(bio_nav_gesture_t gesture);

/** Register `callback` to be invoked by every future
 *  biometric_service_navigation_poll() call that detects a new gesture.
 *  Pass NULL to unregister. Only one subscriber at a time -- registering
 *  again replaces the previous callback. Persists across
 *  navigation_start()/stop() cycles; call with NULL when the subscriber
 *  no longer needs updates. */
void biometric_service_navigation_set_callback(bio_nav_gesture_cb_t callback);

#ifdef __cplusplus
}
#endif

#endif /* BIOMETRIC_SERVICE_H */
