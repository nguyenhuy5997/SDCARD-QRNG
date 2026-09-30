#!/usr/bin/env python3
"""
adc_histogram.py -- count how many raw QRNG ADC samples fall on every level 0..4095 (12-bit ADC2, PA5).

Reads blocks of 1024 samples with QRNG_CMD_RAW_CAPTURE (0x13) over USB (packed 12-bit when the firmware supports
it; adc_stream.read_capture() unpacks), accumulates a 4096-bin histogram and writes it to CSV with ALL 4096 levels,
including the ones that never occurred (count 0):

    level,volts,count,fraction

Default: runs until Ctrl+C (overnight). The CSV is rewritten every --save-every s (atomic: temp file + rename, so
the last saved counts survive a crash or power loss); a USB drop or lost reply is handled by reopening the port
(waits up to --reconnect-wait s) and counting on. --resume continues from the counts already in --out.
Note: USB Full Speed carries only ~25-30 % of the 2 MS/s, so the counts come from blocks of 1024 contiguous samples
with gaps between the blocks -- every received sample is counted.

Instead of the board it can also read a file written by raw_capture.py (--from-bin, uint16 LE per sample).

    python Tools/adc_histogram.py --port COM25 --out captures/hist_night.csv --plot      (until Ctrl+C)
    python Tools/adc_histogram.py --port COM25 --out captures/hist_night.csv --resume    (continue those counts)
    python Tools/adc_histogram.py --port COM25 --out captures/hist_night.csv --skip-ad5398  (AD5398 not used)
    python Tools/adc_histogram.py --port COM25 --samples 10000000 --out captures/hist.csv
    python Tools/adc_histogram.py --port COM25 --samples 2000000 --manual --out captures/hist_off.csv
    python Tools/adc_histogram.py --from-bin captures/raw_part2.bin --out captures/hist_part2.csv --plot

Needs: pip install pyserial numpy   (matplotlib only for --plot)
"""
import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adc_stream as a  # noqa: E402
import evt2_cli as c  # noqa: E402

LEVELS = a.ADC_MAX + 1  # 4096


def draw(ax1, ax2, hist, title):
    ax1.bar(np.arange(LEVELS), hist, width=1.0)
    ax1.set_xlim(-1, LEVELS)
    ax1.set_xlabel("ADC level")
    ax1.set_ylabel("count")
    ax1.set_title(title)
    nz = np.flatnonzero(hist)
    if nz.size:
        lo, hi = max(int(nz[0]) - 5, 0), min(int(nz[-1]) + 5, a.ADC_MAX)
        ax2.bar(np.arange(lo, hi + 1), hist[lo:hi + 1], width=1.0)
        ax2.set_xlim(lo - 0.5, hi + 0.5)
    ax2.set_xlabel("ADC level (used range)")
    ax2.set_ylabel("count")


class LiveHist:
    """Live histogram window, redrawn from the capture loop every --plot-every s (~50 ms per redraw)."""

    def __init__(self):
        import matplotlib.pyplot as plt
        self.plt = plt
        plt.ion()
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(11, 7))
        self.closed = False
        self.fig.canvas.mpl_connect("close_event", lambda _e: setattr(self, "closed", True))

    def update(self, hist, title):
        if self.closed:          # closing the window only stops the plot, counting goes on
            return
        self.ax1.cla()
        self.ax2.cla()
        draw(self.ax1, self.ax2, hist, title)
        self.fig.tight_layout()
        self.plt.pause(0.001)


def count_from_board(args, hist):
    """Adds RAW_CAPTURE samples to hist until --samples are counted (0 = forever, until Ctrl+C)."""
    import serial
    sid = args.session_id
    forever = args.samples <= 0

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

    def power_without_ad5398(d):
        """--skip-ad5398: PS_FIRST -> PS_SECOND -> LED_EN with ANALOG_CTRL (the AD5398 is never touched and stays
        powered down), then wait --settle s. RAW_CAPTURE is then sent with bit 0 = do not power the front end."""
        for i in range(a.AD5398_IDX):
            st = a.analog_ctrl(d, sid, i, True)
            if st is None or st[0] != "QRNG_OK":
                raise RuntimeError(f"status {st[0] if st else 'no reply'} switching {a.ANALOG_ELEMENTS[i]} on")
            time.sleep(0.01)
        print(f"front end on without AD5398, settling {args.settle:.0f} s", flush=True)
        time.sleep(args.settle)

    live = LiveHist() if args.plot else None
    dev = open_dev()
    need_power = args.skip_ad5398          # switch the three enables on before the next capture
    start_total = int(hist.sum())
    done = inflight = blocks = reconnects = board_errors = 0
    first = True
    t_start = t_last = t_save = t_plot = time.time()
    print(("counting until Ctrl+C" if forever else f"counting {args.samples:,} samples")
          + (f", CSV saved every {args.save_every:.0f} s to {args.out}" if args.out else "")
          + " (first block ~3 s: front-end power-up + settle)", flush=True)
    try:
        while forever or done < args.samples:
            try:
                if need_power:
                    power_without_ad5398(dev)
                    need_power = False
                depth = 1 if first else args.depth
                while inflight < depth:
                    a.send_capture(dev, sid, args.manual or args.skip_ad5398)
                    inflight += 1
                blk = a.read_capture(dev, sid, first)
                inflight -= 1
                err = None
            except (serial.SerialException, OSError, RuntimeError) as e:
                err = e
            if isinstance(err, RuntimeError) and str(err).startswith("status"):
                # the board answered with an error (e.g. analog power-up or ADC start failed): stop what RAW_CAPTURE
                # started, wait and try again on the same port -- no tight retry loop overnight
                board_errors += 1
                print(f"  !! {time.strftime('%H:%M:%S')} board error after {done:,} samples ({err}); "
                      f"error {board_errors}, RAW_STOP + retry in {args.error_wait:.0f} s", flush=True)
                if board_errors == 1 and not (args.skip_ad5398 or args.manual):
                    print("     (the firmware power-up includes the AD5398 -- if the AD5398 does not answer, run with "
                          "--skip-ad5398)", flush=True)
                try:
                    while inflight > 1 and dev.read_frame(3.0, session_id=sid) is not None:
                        inflight -= 1
                    c.request(dev, c.CMD_TYPE_QRNG, sid, a.QRNG_CMD_RAW_STOP)
                except Exception:  # noqa: BLE001 -- a dead port shows up as a link problem on the next request
                    pass
                inflight = 0
                first = True
                need_power = args.skip_ad5398      # RAW_STOP switched the front end off
                time.sleep(args.error_wait)
                continue
            if err is not None:
                # USB dropped (the port vanishes) or a reply was lost: save, reopen and count on
                reconnects += 1
                print(f"  !! {time.strftime('%H:%M:%S')} link problem after {done:,} samples "
                      f"({type(err).__name__}: {err}); reconnect {reconnects} -- waiting up to "
                      f"{args.reconnect_wait} s for {args.port}", flush=True)
                if args.out:
                    write_csv(args.out, hist, quiet=True)
                try:
                    dev.close()
                except Exception:  # noqa: BLE001 -- the port may already be gone
                    pass
                if args.max_reconnects and reconnects > args.max_reconnects:
                    print("too many link problems, stopping")
                    break
                dev = open_dev()
                inflight = 0
                first = True
                need_power = args.skip_ad5398
                print("  reconnected, counting on", flush=True)
                continue
            if first:
                first = False
                if blocks == 0:
                    front = a.analog_ctrl(dev, sid)
                    print(f"front end: {a.state_name(front[1], front[2]) if front else '?'}", flush=True)
                    t_start = t_last = time.time()
            part = blk if forever else blk[:args.samples - done]
            if part.size and int(part.max()) > a.ADC_MAX:
                raise RuntimeError(f"sample {int(part.max())} > {a.ADC_MAX}: not a 12-bit capture?")
            hist += np.bincount(part[part != a.ADC_MAX], minlength=LEVELS)   # 4095 is not counted
            done += len(part)
            blocks += 1
            now = time.time()
            if now - t_last >= args.print_every:
                t_last = now
                el = max(now - t_start, 1e-9)
                n = int(hist.sum())
                nz = np.flatnonzero(hist)
                mean = float((np.arange(LEVELS) * hist).sum()) / n
                print(f"  {time.strftime('%H:%M:%S')}  +{done:,} (total {n:,})  {done / el / 1e3:.0f} kS/s  "
                      f"run {el / 3600:.2f} h  min {nz[0]} max {nz[-1]} mean {mean:.1f}  "
                      f"levels hit {nz.size}  reconnects {reconnects}  board errors {board_errors}", flush=True)
            if args.out and now - t_save >= args.save_every:
                t_save = now
                write_csv(args.out, hist, quiet=True)
            if live and now - t_plot >= args.plot_every:
                t_plot = now
                live.update(hist, f"{int(hist.sum()):,} samples  ({time.strftime('%H:%M:%S')})")
    except KeyboardInterrupt:
        print("Ctrl+C -- keeping what was counted")
    finally:
        try:
            while inflight > 0 and dev.read_frame(3.0, session_id=sid) is not None:
                inflight -= 1
            if not args.keep_on:
                c.request(dev, c.CMD_TYPE_QRNG, sid, a.QRNG_CMD_RAW_STOP)
            dev.close()
        except Exception:  # noqa: BLE001 -- port gone: nothing more to tell the board
            pass
    print(f"counted {done:,} new samples (total {start_total + done:,}) in "
          f"{(time.time() - t_start) / 3600:.2f} h, {reconnects} reconnects, {board_errors} board errors")
    return hist


def count_from_bin(path, chunk=1 << 24):
    """Histogram of a raw_capture.py file (uint16 LE), read in chunks so any size fits in memory."""
    hist = np.zeros(LEVELS, dtype=np.int64)
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk * 2)
            if not buf:
                break
            x = np.frombuffer(buf[:len(buf) // 2 * 2], dtype="<u2")
            if x.size and int(x.max()) > a.ADC_MAX:
                raise RuntimeError(f"{path}: sample {int(x.max())} > {a.ADC_MAX}: not a 12-bit capture?")
            hist += np.bincount(x[x != a.ADC_MAX], minlength=LEVELS)   # 4095 is not counted
    return hist


def load_csv(path):
    """Counts from an earlier adc_histogram.py CSV (--resume)."""
    hist = np.zeros(LEVELS, dtype=np.int64)
    with open(path, encoding="utf-8") as f:
        next(f)
        for line in f:
            k, _volts, cnt = line.split(",")[:3]
            hist[int(k)] = int(cnt)
    return hist


def summary(hist):
    n = int(hist.sum())
    if n == 0:
        print("no samples")
        return
    lv = np.arange(LEVELS)
    nz = np.flatnonzero(hist)
    lo, hi = int(nz[0]), int(nz[-1])
    mean = float((lv * hist).sum()) / n
    std = (float(((lv - mean) ** 2 * hist).sum()) / n) ** 0.5
    missing = [int(k) for k in range(lo, hi + 1) if hist[k] == 0]   # empty codes INSIDE the used range
    print(f"samples {n:,}  min {lo}  max {hi}  mean {mean:.2f} ({mean * a.LSB_MV:.2f} mV)  "
          f"std {std:.2f} LSB ({std * a.LSB_MV:.3f} mV)")
    print(f"levels hit {len(nz)}/{LEVELS}; empty levels inside {lo}..{hi}: {len(missing)}"
          + (f" -> {missing[:32]}{' ...' if len(missing) > 32 else ''}" if missing else ""))
    print(f"at the rails: level 0 = {int(hist[0]):,}, level {a.ADC_MAX} = {int(hist[a.ADC_MAX]):,}")
    top = np.argsort(hist)[::-1][:5]
    print("most frequent: " + ", ".join(f"{int(k)} x{int(hist[k]):,}" for k in top))
    # odd/even imbalance is a quick look at the ADC's LSB (DNL) behaviour
    odd = int(hist[1::2].sum())
    print(f"odd/even levels: {odd / n * 100:.2f} % / {(n - odd) / n * 100:.2f} %")


def write_csv(path, hist, quiet=False):
    """All 4096 levels; written to a temp file and renamed, so a crash never leaves half a CSV."""
    n = max(int(hist.sum()), 1)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write("level,volts,count,fraction\n")
        for k in range(LEVELS):
            f.write(f"{k},{k * a.VREF / LEVELS:.6f},{int(hist[k])},{hist[k] / n:.9g}\n")
    os.replace(tmp, path)
    if not quiet:
        print(f"wrote {path} ({LEVELS} levels, {int(hist.sum()):,} samples)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--port", help="board COM port (RAW_CAPTURE over USB)")
    src.add_argument("--from-bin", metavar="FILE.bin", help="count a raw_capture.py file instead")
    ap.add_argument("--samples", type=int, default=0,
                    help="samples to count from the board; 0 (default) = until Ctrl+C")
    ap.add_argument("--out", metavar="FILE.csv", help="CSV with all 4096 levels (level,volts,count,fraction)")
    ap.add_argument("--resume", action="store_true", help="start from the counts already in --out")
    ap.add_argument("--save-every", type=float, default=60.0, help="save the CSV every N s (default 60)")
    ap.add_argument("--print-every", type=float, default=10.0, help="status line every N s (default 10)")
    ap.add_argument("--manual", action="store_true",
                    help="start the ADC WITHOUT powering the front end (RAW_CAPTURE flag bit 0)")
    ap.add_argument("--skip-ad5398", action="store_true",
                    help="power PS_FIRST, PS_SECOND, LED_EN with ANALOG_CTRL and never touch the AD5398 (stays off); "
                         "RAW_CAPTURE then only starts the ADC")
    ap.add_argument("--settle", type=float, default=3.0,
                    help="--skip-ad5398: wait after switching the front end on (default 3 s, as the firmware)")
    ap.add_argument("--depth", type=int, default=2, choices=[1, 2, 3, 4], help="requests in flight (default 2)")
    ap.add_argument("--keep-on", action="store_true", help="leave the ADC/analog front end running afterwards")
    ap.add_argument("--reconnect-wait", type=int, default=600,
                    help="after a USB drop, wait this many seconds for the port to come back (default 600)")
    ap.add_argument("--error-wait", type=float, default=5.0,
                    help="after an error status from the board, RAW_STOP and retry after N s (default 5)")
    ap.add_argument("--max-reconnects", type=int, default=0, help="stop after this many link problems (0 = never)")
    ap.add_argument("--plot", action="store_true", help="histogram plot (live while counting from the board)")
    ap.add_argument("--plot-every", type=float, default=3.0, help="live plot redraw period in s (default 3)")
    ap.add_argument("--session-id", type=lambda x: int(x, 0), default=0x0001)
    args = ap.parse_args()

    hist = np.zeros(LEVELS, dtype=np.int64)
    if args.resume:
        if not args.out or not Path(args.out).exists():
            ap.error("--resume needs an existing --out CSV")
        hist = load_csv(args.out)
        print(f"resuming from {args.out}: {int(hist.sum()):,} samples already counted")
    if args.from_bin:
        hist += count_from_bin(args.from_bin)
    else:
        count_from_board(args, hist)
    summary(hist)
    if args.out:
        write_csv(args.out, hist)
    if args.plot:
        import matplotlib.pyplot as plt
        plt.ioff()
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7))
        draw(ax1, ax2, hist, f"{int(hist.sum()):,} samples ({args.from_bin or args.port}) -- final")
        fig.tight_layout()
        plt.show()


if __name__ == "__main__":
    main()
