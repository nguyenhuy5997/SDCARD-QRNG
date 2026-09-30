#!/usr/bin/env python3
"""
entropy_estimate.py -- min-entropy estimate of raw 12-bit QRNG samples (uint16 LE .bin from raw_capture.py), to pick
the Toeplitz output ratio (toeplitz_condition.py --out-bits-per-sample).

Reports:
  - Most Common Value estimate, NIST SP 800-90B section 6.3.1: p_u = min(1, p + 2.576 sqrt(p (1-p) / (N-1))),
    H = -log2(p_u) bits per sample (an IID estimate: it does not see correlation between samples);
  - autocorrelation at lags 1..8 inside the 1024-sample blocks (0 for independent samples; |r| > ~3/sqrt(N) is
    significant) -- correlation lowers the real entropy below the MCV value;
  - a conservative suggestion: MCV estimate x --margin (default 0.75), rounded down to 1/8 bit.
For a full assessment run NIST's ea_non_iid on the same file (12-bit samples: `ea_non_iid -v file 12` after
converting to one sample per byte pair as the tool expects).

    python Tools/entropy_estimate.py --in captures/pilot.bin
"""
import argparse
import math

import numpy as np

BLOCK = 1024


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--margin", type=float, default=0.75, help="fraction of the MCV estimate to suggest (0.75)")
    args = ap.parse_args()

    x = np.fromfile(args.inp, dtype="<u2")
    n = len(x)
    if n < BLOCK:
        raise SystemExit("need at least one block")
    counts = np.bincount(x, minlength=4096)
    p = counts.max() / n
    pu = min(1.0, p + 2.576 * math.sqrt(p * (1 - p) / (n - 1)))
    h_mcv = -math.log2(pu)
    xb = x[: n // BLOCK * BLOCK].reshape(-1, BLOCK).astype(np.float64)
    # Global mean, not per block: removing each block's own mean biases every lag by -1/(BLOCK-1) (~ -0.001) and
    # would flag independent samples as correlated. A drifting mean shows up as positive correlation -- rightly.
    xb -= xb.mean()
    var = float(np.mean(xb * xb))
    print(f"{args.inp}: {n:,} samples, {len(xb):,} blocks, values {x.min()}..{x.max()}, {np.count_nonzero(counts)} "
          f"distinct")
    print(f"  most common value {counts.argmax()} ({counts.max():,}x, p = {p:.6f}, upper bound {pu:.6f})")
    print(f"  MCV min-entropy (SP 800-90B 6.3.1): {h_mcv:.3f} bits per sample (of 12)")
    sig = 3 / math.sqrt(xb.size)
    print(f"  autocorrelation inside blocks (significant if |r| > {sig:.4f}):")
    for lag in range(1, 9):
        r = float(np.mean(xb[:, :-lag] * xb[:, lag:])) / var
        print(f"    lag {lag}: r = {r:+.4f}{'   <- correlated' if abs(r) > sig else ''}")
    sugg = math.floor(h_mcv * args.margin * 8) / 8
    print(f"  suggested Toeplitz output: {sugg:.3f} bits per sample ({args.margin:.0%} of the MCV estimate); "
          f"lower it further if the samples are correlated")


if __name__ == "__main__":
    main()
