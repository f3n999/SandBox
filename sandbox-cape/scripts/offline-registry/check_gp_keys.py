#!/usr/bin/env python3
import hivex
import struct

HIVE_PATH = "/mnt/winc/Windows/System32/config/SOFTWARE"
h = hivex.Hivex(HIVE_PATH)
root = h.root()

def find_node(start, *path):
    node = start
    for name in path:
        child = h.node_get_child(node, name)
        if not child:
            print(f"  [!] missing: {name}")
            return None
        node = child
    return node

def dump_node(node, indent=0):
    prefix = "  " * indent
    for v in (h.node_values(node) or []):
        key = h.value_key(v)
        t, raw = h.value_type(v)[0], h.value_value(v)[1]
        if t == 1:  # REG_SZ
            val = raw.decode("utf-16-le").rstrip("\x00")
        elif t == 4:  # REG_DWORD
            val = struct.unpack("<I", raw)[0]
        elif t in (3, 11):  # BINARY / QWORD
            val = f"[{t}] {raw.hex()}"
        else:
            val = f"[type={t}] {raw[:20].hex()}"
        print(f"{prefix}  {key} = {val}")
    for child in (h.node_children(node) or []):
        child_name = h.node_name(child)
        print(f"{prefix}\\{child_name}\\")
        dump_node(child, indent + 1)

# Check GP Scripts Startup\0
print("=== GP Scripts Startup\\0 ===")
node_0 = find_node(root,
    "Microsoft", "Windows", "CurrentVersion",
    "Group Policy", "Scripts", "Startup", "0"
)
if node_0:
    dump_node(node_0)

# Also check Run key
print("\n=== Run Key ===")
run = find_node(root, "Microsoft", "Windows", "CurrentVersion", "Run")
if run:
    dump_node(run)

# Check AutoAdminLogon area
print("\n=== Winlogon ===")
wl = find_node(root, "Microsoft", "Windows NT", "CurrentVersion", "Winlogon")
if wl:
    for vname in ["AutoAdminLogon", "DefaultUserName", "DefaultPassword", "DefaultDomainName", "Userinit"]:
        try:
            v = h.node_get_value(wl, vname)
            t, raw = h.value_type(v)[0], h.value_value(v)[1]
            val = raw.decode("utf-16-le").rstrip("\x00") if t == 1 else raw.hex()
            print(f"  {vname} = {repr(val)}")
        except:
            print(f"  {vname} = [NOT SET]")
