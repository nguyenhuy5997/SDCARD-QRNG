"""factory_flag.py on|off -- add/remove EVT2_FACTORY_PROVISION=1 in the Appli Release C compiler defines (V8Y)."""
import re, sys
p = r"D:\Workspace\SDQRNG_V8Y\Appli\.cproject"
t = open(p, "rb").read().decode()
line = '<listOptionValue builtIn="false" value="EVT2_FACTORY_PROVISION=1"/>'
t = re.sub(r'\s*' + re.escape(line), "", t)
if sys.argv[1] == "on":
    rel = t.index('name="Release"')
    anchor = '<listOptionValue builtIn="false" value="USE_HAL_DRIVER"/>'
    i = t.index(anchor, rel)
    ls = t.rfind("\n", 0, i) + 1
    indent = t[ls:i]
    t = t[:ls] + indent + line + "\r\n" + t[ls:]
open(p, "wb").write(t.encode())
print(sys.argv[1], t.count(line))
