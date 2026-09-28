"""Read the running board's temperature and sleep share over SWD (ST-Link), without resetting it.

The Appli publishes them once a second in the trace record g_app_trace (0x24071800, non-cacheable RAM, see
Appli/Core_app/App/app_trace.c and app_power.c). SWD is independent of the target's USB port, so this works while a
phone owns the USB link (e.g. during a call).

    python Tools/board_status.py            # one reading
    python Tools/board_status.py --watch 5  # every 5 s until Ctrl+C

STM32_Programmer_CLI: $PROGRAMMER_CLI, else the one inside STM32CubeIDE (same search as find_tools.bat), else PATH.
"""
import argparse
import glob
import os
import re
import shutil
import struct
import subprocess
import sys
import time

TRACE_ADDR = 0x24071800
TRACE_SIZE = 0x198
MAGIC = 0x54524345
TEMP_NONE = -0x80000000


def find_programmer():
    env = os.environ.get("PROGRAMMER_CLI")
    if env and os.path.isfile(env):
        return env
    roots = [r"C:\ST", r"D:\ST", r"C:\Tools", r"D:\Tools", os.environ.get("ProgramFiles", r"C:\Program Files")]
    hits = []
    for r in roots:
        hits += glob.glob(os.path.join(r, "STM32CubeIDE_*", "STM32CubeIDE", "plugins",
                                       "com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.*", "tools", "bin",
                                       "STM32_Programmer_CLI.exe"))
    if hits:
        return sorted(hits)[-1]
    standalone = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "STMicroelectronics", "STM32Cube",
                              "STM32CubeProgrammer", "bin", "STM32_Programmer_CLI.exe")
    if os.path.isfile(standalone):
        return standalone
    return shutil.which("STM32_Programmer_CLI.exe") or shutil.which("STM32_Programmer_CLI")


def read_trace(cli):
    out = subprocess.run([cli, "-c", "port=SWD", "mode=HOTPLUG", "-r32", hex(TRACE_ADDR), str(TRACE_SIZE)],
                         capture_output=True, text=True, timeout=60).stdout
    words = {}
    for m in re.finditer(r"^\s*0x([0-9A-Fa-f]{8})\s*:\s*((?:[0-9A-Fa-f]{8}\s*)+)$", out, re.M):
        addr = int(m.group(1), 16)
        for i, w in enumerate(m.group(2).split()):
            words[addr + 4 * i] = int(w, 16)
    if len(words) < TRACE_SIZE // 4:
        raise RuntimeError("SWD read failed:\n" + out[-800:])
    raw = b"".join(struct.pack("<I", words[TRACE_ADDR + 4 * i]) for i in range(TRACE_SIZE // 4))
    return raw


def show(raw):
    u = lambda off: struct.unpack_from("<I", raw, off)[0]
    s = lambda off: struct.unpack_from("<i", raw, off)[0]
    if u(0x00) != MAGIC:
        print("no trace record (magic %08X) -- is the Appli running?" % u(0x00))
        return
    temp, tmax = s(0x188), s(0x18C)
    fmt = lambda t: "--" if t == TEMP_NONE else "%d C" % t
    print("%s  temp %s (max since power-on %s)  asleep %.1f%% (%d WFI/s)  uptime %.0f s  loops %d  boots %d" % (
        time.strftime("%H:%M:%S"), fmt(temp), fmt(tmax), u(0x190) / 10.0, u(0x194), u(0x1C) / 1000.0, u(0x18),
        u(0x04)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--watch", type=float, metavar="S", help="repeat every S seconds")
    args = ap.parse_args()
    cli = find_programmer()
    if not cli:
        sys.exit("STM32_Programmer_CLI not found -- set PROGRAMMER_CLI")
    while True:
        show(read_trace(cli))
        if not args.watch:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
