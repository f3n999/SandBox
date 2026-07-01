#!/usr/bin/env python3
"""Ensure ExecTime is REG_BINARY (8 null bytes) not REG_DWORD."""
import hivex
import struct

HIVE_PATH = "/mnt/winc/Windows/System32/config/SOFTWARE"
h = hivex.Hivex(HIVE_PATH, write=True)
root = h.root()

REG_BINARY = 3

def find_node(start, *path):
    node = start
    for name in path:
        child = h.node_get_child(node, name)
        if not child:
            return None
        node = child
    return node

gp_script_00 = find_node(root,
    "Microsoft", "Windows", "CurrentVersion",
    "Group Policy", "Scripts", "Startup", "0", "0"
)

if gp_script_00:
    try:
        v = h.node_get_value(gp_script_00, "ExecTime")
        t, raw = h.value_type(v)[0], h.value_value(v)[1]
        print(f"ExecTime type={t} value={raw.hex()} len={len(raw)}")
        if t != REG_BINARY or raw != b'\x00' * 8:
            print("Fixing ExecTime to REG_BINARY 8 null bytes...")
            h.node_set_value(gp_script_00, {
                "key": "ExecTime",
                "t": REG_BINARY,
                "value": b"\x00" * 8
            })
            h.commit(None)
            print("Done")
        else:
            print("ExecTime already correct REG_BINARY 8 null bytes")
    except Exception as e:
        print(f"ExecTime not found or error: {e}")
        print("Setting ExecTime as REG_BINARY 8 null bytes...")
        h.node_set_value(gp_script_00, {
            "key": "ExecTime",
            "t": REG_BINARY,
            "value": b"\x00" * 8
        })
        h.commit(None)
        print("Done")
else:
    print("[!] GP Script\\0\\0 key not found")
