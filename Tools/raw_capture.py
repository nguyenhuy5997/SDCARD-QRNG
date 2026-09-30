#!/usr/bin/env python3
"""
raw_capture.py -- long headless capture of raw QRNG ADC samples to a binary file (for entropy estimation and
Toeplitz conditioning). No plot, nothing kept in memory: blocks go straight to disk.

Output FILE.bin: little-endian uint16 per sample, 12 bits used (0..4095), blocks of 1024 contiguous samples (the
blocks are NOT contiguous with each other), exactly --samples samples (rounded down to whole blocks unless the last
block is cut). FILE.bin.json: capture conditions (sample rate, front-end state, AD5398 current, health stats, ...).

The board sends the samples packed (12-bit stream, 1536 bytes per block) when its firmware supports it
(RAW_CAPTURE flag bit 1); adc_stream.read_capture() unpacks. Ctrl+C stops early and keeps what was written.

    python Tools/raw_capture.py --port COM25 --samples 20000000 --out captures/pilot.bin
    python Tools/raw_capture.py --port COM25 --samples 1400000000 --out D:/captures/raw_1p4G.bin
    python Tools/raw_capture.py --port COM25 --samples 20000000 --out captures/pilot.bin --manual   # front end as is

Needs: pip install pyserial numpy
"""
import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adc_stream as a  # noqa: E402
import evt2_cli as c  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    ap.add_argument("--samples", type=int, required=True, help="samples to capture")
    ap.add_argument("--out", required=True, metavar="FILE.bin")
    ap.add_argument("--depth", type=int, default=2, choices=[1, 2, 3, 4], help="requests in flight (default 2)")
    ap.add_argument("--manual", action="store_true",
                    help="start the ADC WITHOUT powering the analog front end: capture it as it is now (e.g. parts "
                         "switched on with adc_stream.py's buttons / ANALOG_CTRL)")
    ap.add_argument("--keep-on", action="store_true", help="leave the ADC/analog front end running afterwards")
    ap.add_argument("--reconnect-wait", type=int, default=600,
                    help="after a USB drop, wait this many seconds for the port to come back (default 600)")
    ap.add_argument("--max-reconnects", type=int, default=20, help="give up after this many link problems")
    ap.add_argument("--session-id", type=lambda x: int(x, 0), default=0x0001)
    args = ap.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    sid = args.session_id
    import serial

    def open_dev():
        """Open the port, waiting up to --reconnect-wait s for it to (re)appear after a USB drop."""
        deadline = time.time() + args.reconnect_wait
        while True:
            try:
                d = a.FastDevice(args.port)
            except serial.SerialException:
                if time.time() > deadline:
                    raise
                time.sleep(2)
                continue
            st = a.analog_ctrl(d, sid)
            if st is not None and st[1] & a.QRNG_SERVICE_OWNS_BIT:
                print("QRNG service owns the front end -> releasing it (QRNG off until reset)")
                a.analog_ctrl(d, sid, a.ANALOG_RELEASE)
            return d

    dev = open_dev()
    need_blocks = -(-args.samples // a.BLOCK)
    health = {"PASS": 0, "RCT": 0, "APT": 0}
    written = blocks = sent = inflight = 0
    reconnects = 0
    resync = True           # the next reply may take seconds (front-end power-up + settle)
    sum_var = 0.0
    fs = None
    front = None
    stop = None
    t_start = t_last = None
    print(f"capturing {args.samples:,} samples to {args.out} (first block ~3 s: front-end power-up + settle)")
    with open(args.out, "wb", buffering=1 << 22) as f:
        try:
            while blocks < need_blocks:
                try:
                    depth = 1 if resync else args.depth
                    while inflight < depth and sent < need_blocks:
                        a.send_capture(dev, sid, args.manual)
                        sent += 1
                        inflight += 1
                    blk = a.read_capture(dev, sid, resync)
                    inflight -= 1
                except (serial.SerialException, OSError, RuntimeError) as e:
                    # USB dropped (the port vanishes, e.g. ClearCommError) or a reply was lost: reopen and go on
                    # appending to the same file. Blocks are independent, so the gap does not matter.
                    reconnects += 1
                    print(f"  !! link problem at {written:,} samples ({type(e).__name__}: {e}); reconnect "
                          f"{reconnects}/{args.max_reconnects} -- waiting up to {args.reconnect_wait} s for "
                          f"{args.port}", flush=True)
                    f.flush()
                    try:
                        dev.close()
                    except Exception:  # noqa: BLE001 -- the port may already be gone
                        pass
                    if reconnects > args.max_reconnects:
                        stop = f"too many link problems, last: {e}"
                        break
                    dev = open_dev()
                    inflight = 0
                    sent = blocks
                    resync = True
                    print("  reconnected, continuing", flush=True)
                    continue
                if resync:
                    resync = False
                    if fs is None:
                        fs = a.measure_rate(dev, sid) or a.DEFAULT_FS
                        front = a.analog_ctrl(dev, sid)
                        t_start = t_last = time.time()
                        print(f"ADC {fs / 1e6:.4f} MS/s, front end: "
                              f"{a.state_name(front[1], front[2]) if front else '?'}")
                part = blk[:args.samples - written]
                f.write(part.astype("<u2").tobytes())
                written += len(part)
                blocks += 1
                if len(blk) == a.BLOCK:
                    health[a.health_check(blk)[0]] += 1
                x = blk.astype(np.float64)
                sum_var += float(np.var(x)) * len(x)
                now = time.time()
                if now - t_last >= 5.0:
                    t_last = now
                    rate = (blocks - 1) * a.BLOCK / (now - t_start)
                    eta = (args.samples - written) / rate if rate else 0
                    n_h = sum(health.values())
                    print(f"  {written:,}/{args.samples:,} ({100.0 * written / args.samples:.1f} %)  "
                          f"{rate / 1e3:.0f} kS/s  ETA {eta / 60:.1f} min  health PASS "
                          f"{100.0 * health['PASS'] / max(n_h, 1):.1f} %  RMS(AC) "
                          f"{(sum_var / written) ** 0.5 * a.LSB_MV:.2f} mV", flush=True)
        except KeyboardInterrupt:
            stop = "Ctrl+C"
        except Exception as e:  # noqa: BLE001 -- keep the file and write the metadata whatever happened
            stop = f"{type(e).__name__}: {e}"
        finally:
            try:
                while inflight > 0 and dev.read_frame(3.0, session_id=sid) is not None:
                    inflight -= 1
                if not args.keep_on:
                    c.request(dev, c.CMD_TYPE_QRNG, sid, a.QRNG_CMD_RAW_STOP)
                dev.close()
            except Exception:  # noqa: BLE001 -- port gone: nothing more to tell the board
                pass

    el = (time.time() - t_start) if t_start else 0.0
    n_h = sum(health.values())
    meta = {
        "file": Path(args.out).name, "samples": written, "dtype": "uint16 little-endian, 12 bits used",
        "block_samples": a.BLOCK, "blocks_contiguous": False, "fs_hz": fs, "vref_v": a.VREF,
        "front_end": a.state_name(front[1], front[2]) if front else None,
        "ad5398_programmed_ua": front[2] if front else None,
        "manual_front_end": args.manual,
        "capture_seconds": round(el, 1), "transfer_sps": round(written / el) if el else None,
        "rms_ac_mv": round((sum_var / written) ** 0.5 * a.LSB_MV, 3) if written else None,
        "health_firmware_rct_apt": {**health, "blocks": n_h}, "stopped_early": stop, "reconnects": reconnects,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(args.out + ".json", "w", encoding="utf-8") as fj:
        json.dump(meta, fj, indent=2)
    if stop:
        print(f"stopped early: {stop}")
    print(f"wrote {written:,} samples ({written * 2 / 1e6:,.1f} MB) in {el / 60:.1f} min "
          f"({written / el / 1e3 if el else 0:.0f} kS/s); health PASS {health['PASS']}/{n_h}; meta {args.out}.json")
    sys.exit(0 if written == args.samples else 1)


if __name__ == "__main__":
    main()
