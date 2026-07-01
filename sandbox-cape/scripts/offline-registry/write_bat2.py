#!/usr/bin/env python3
"""Write enhanced start_agent_gp.bat with registry diagnostics."""

# This batch:
# 1. Writes to registry (proves cmd.exe runs as SYSTEM even if NTFS writes fail)
# 2. Writes to C:\Windows\Temp (file system test)
# 3. Tries to start agent.py
# Uses CRLF line endings
content = (
    "@echo off\r\n"
    "reg add HKLM\\Software\\GPTest /v Stage1 /t REG_SZ /d \"ran_%TIME%\" /f\r\n"
    "echo STAGE1 > C:\\Windows\\Temp\\gp_cape.txt\r\n"
    "C:\\Python310\\python.exe -c \"f=open('C:/Windows/Temp/gp_py.txt','w');f.write('ok');f.close()\"\r\n"
    "reg add HKLM\\Software\\GPTest /v Stage3 /t REG_SZ /d \"python_done_%ERRORLEVEL%\" /f\r\n"
    "echo STAGE3 >> C:\\Windows\\Temp\\gp_cape.txt\r\n"
    "C:\\Python310\\python.exe C:\\Users\\Public\\agent.py\r\n"
    "reg add HKLM\\Software\\GPTest /v Exited /t REG_SZ /d \"exit_%ERRORLEVEL%_%TIME%\" /f\r\n"
)

with open("/mnt/winc/Users/Public/start_agent_gp.bat", "wb") as f:
    f.write(content.encode("ascii"))

print(f"Written: {len(content)} bytes")
with open("/mnt/winc/Users/Public/start_agent_gp.bat", "rb") as f:
    data = f.read()
print("CRLF lines:")
for i, line in enumerate(data.split(b"\r\n")):
    if line:
        print(f"  [{i}] {line[:70]}")
