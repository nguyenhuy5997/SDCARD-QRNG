"""
qrng_health.py -- the firmware's online health test (RCT + APT) for raw 12-bit QRNG blocks, on the PC.

A line-by-line copy of Core_app/Drivers/QRNG/entropy.c (entropy_run_health_checks(), entropy_run_rct(),
entropy_run_apt()) with the thresholds of qrng_constant.h. The state is reset for every 1024-sample buffer, like
entropy_reset() does. Used by adc_stream.py (live PASS/FAIL), raw_capture.py (statistics) and
toeplitz_condition.py (--drop-health-fail). Keep it in step with the firmware if the thresholds change.
"""
RCT_CUTOFF = 3       # QRNG_ENTROPY_RCT_CUTOFF_VALUE: fail when one value repeats this many times in a row
APT_WINDOW = 512     # QRNG_ENTROPY_APT_WINDOW_SIZE
APT_CUTOFF = 4       # QRNG_ENTROPY_APT_CUTOFF_VALUE: fail when a window's first value occurs this many times in it


def health_check(block):
    """One block through the firmware's RCT + APT test. Returns ("PASS", None), ("RCT", index) or ("APT", index)
    -- index = the sample where it failed."""
    s = [int(v) for v in block]
    if not s:
        return "PASS", None
    rct_a = apt_a = s[0]
    rct_b = apt_b = 1
    apt_n = 1
    for i in range(1, len(s)):
        v = s[i]
        if v == rct_a:                      # entropy_run_rct()
            rct_b += 1
            if rct_b >= RCT_CUTOFF:
                return "RCT", i
        else:
            rct_a, rct_b = v, 1
        if apt_n < APT_WINDOW:              # entropy_run_apt()
            apt_n += 1
            if v == apt_a:
                apt_b += 1
                if apt_b >= APT_CUTOFF:
                    return "APT", i
        else:
            apt_n, apt_b, apt_a = 1, 1, v
    return "PASS", None
