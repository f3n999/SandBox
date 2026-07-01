#!/usr/bin/env python3
"""
Remove the CAPEAgent task from TaskCache (Tasks + Tree).
This was added with a null hash which likely causes Schedule service
instability → UserManager exits with code 0 → autologin fails.
"""
import hivex
import sys

HIVE_PATH = "/mnt/winc/Windows/System32/config/SOFTWARE"

def find_node(h, start, path):
    node = start
    for name in path:
        child = h.node_get_child(node, name)
        if not child:
            print(f"  [!] Node not found: {name}")
            return None
        node = child
    return node

h = hivex.Hivex(HIVE_PATH, write=True)
root = h.root()

TASK_GUID = "{2449155E-764A-43C1-AFCB-3467131A424E}"

# 1. Delete from TaskCache\Tasks
print(f"[*] Removing TaskCache\\Tasks\\{TASK_GUID}")
task_node = find_node(h, root, [
    "Microsoft", "Windows NT", "CurrentVersion",
    "Schedule", "TaskCache", "Tasks", TASK_GUID
])
if task_node:
    h.node_delete_child(task_node)
    print("  [+] Deleted")
else:
    print("  [-] Not found (already gone?)")

# 2. Delete from TaskCache\Tree
print("[*] Removing TaskCache\\Tree\\CAPEAgent")
tree_node = find_node(h, root, [
    "Microsoft", "Windows NT", "CurrentVersion",
    "Schedule", "TaskCache", "Tree", "CAPEAgent"
])
if tree_node:
    h.node_delete_child(tree_node)
    print("  [+] Deleted")
else:
    print("  [-] Not found (already gone?)")

h.commit(None)
print("[+] SOFTWARE hive committed")
