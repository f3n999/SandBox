#!/usr/bin/env python3
"""Investigate luafv and UserManager in SYSTEM hive."""
import hivex
import struct

SYSTEM_PATH = "/mnt/winc/Windows/System32/config/SYSTEM"

h = hivex.Hivex(SYSTEM_PATH)
root = h.root()

# Find current control set
def find_node(start, *path):
    node = start
    for name in path:
        child = h.node_get_child(node, name)
        if not child: return None
        node = child
    return node

def get_val(node, name, default=None):
    try:
        v = h.node_get_value(node, name)
        t, raw = h.value_type(v)[0], h.value_value(v)[1]
        if t == 1: return raw.decode("utf-16-le").rstrip("\x00")
        if t == 4: return struct.unpack("<I", raw)[0]
        if t == 7:  # REG_MULTI_SZ
            return raw.decode("utf-16-le").split("\x00")
        return (t, raw.hex())
    except:
        return default

def dump_service(h, root, ccs, svc_name):
    svc = find_node(root, f"ControlSet00{ccs}", "Services", svc_name)
    if not svc:
        print(f"  [!] {svc_name} NOT FOUND")
        return
    start = get_val(svc, "Start", "?")
    type_ = get_val(svc, "Type", "?")
    err = get_val(svc, "ErrorControl", "?")
    img = get_val(svc, "ImagePath", "?")
    desc = get_val(svc, "Description", "")
    depends = get_val(svc, "DependOnService", [])
    group = get_val(svc, "Group", "")
    print(f"  {svc_name}: Start={start} Type={type_} ErrorControl={err}")
    print(f"    ImagePath: {img}")
    print(f"    Group: {group}")
    print(f"    Depends: {depends}")

# Find current control set
select = find_node(root, "Select")
if select:
    current_ccs = get_val(select, "Current", 1)
    print(f"Current Control Set: ControlSet00{current_ccs}")
else:
    current_ccs = 1
    print("Using ControlSet001")

ccs = current_ccs
print()

# Check luafv
print("=== luafv service ===")
dump_service(h, root, ccs, "luafv")

# Check FltMgr
print("\n=== FltMgr service ===")
dump_service(h, root, ccs, "FltMgr")

# Check UserManager
print("\n=== UserManager service ===")
dump_service(h, root, ccs, "UserManager")

# Check ProfileService (ProfSvc)
print("\n=== ProfSvc (User Profile Service) ===")
dump_service(h, root, ccs, "ProfSvc")

# Check WinLogon dependencies
print("\n=== Winlogon ===")
wl = find_node(root, f"ControlSet00{ccs}", "Services", "Winlogon")
if wl:
    dump_service(h, root, ccs, "Winlogon")

# Check if anything depends on luafv
print("\n=== Services depending on luafv ===")
services_node = find_node(root, f"ControlSet00{ccs}", "Services")
if services_node:
    count = 0
    for svc_child in (h.node_children(services_node) or []):
        svc_name = h.node_name(svc_child)
        depends = get_val(svc_child, "DependOnGroup", [])
        depends2 = get_val(svc_child, "DependOnService", [])
        all_deps = (depends if isinstance(depends, list) else []) + (depends2 if isinstance(depends2, list) else [])
        if any("luafv" in str(d).lower() for d in all_deps):
            print(f"  {svc_name} depends on luafv")
            count += 1
    if count == 0:
        print("  (none found)")

# Check luafv ImagePath (driver path)
print("\n=== luafv driver file check ===")
import os
luafv_path = "/mnt/winc/Windows/System32/drivers/luafv.sys"
if os.path.exists(luafv_path):
    size = os.path.getsize(luafv_path)
    print(f"  luafv.sys: {size} bytes, exists")
else:
    print("  luafv.sys: MISSING!")
