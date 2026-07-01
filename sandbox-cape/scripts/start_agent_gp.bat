@echo off
reg add HKLM\Software\GPTest /v Stage1 /t REG_SZ /d "ran_%TIME%" /f
echo STAGE1 > C:\Windows\Temp\gp_cape.txt
C:\Python310\python.exe -c "f=open('C:/Windows/Temp/gp_py.txt','w');f.write('ok');f.close()"
reg add HKLM\Software\GPTest /v Stage3 /t REG_SZ /d "python_done_%ERRORLEVEL%" /f
echo STAGE3 >> C:\Windows\Temp\gp_cape.txt
C:\Python310\python.exe C:\Users\Public\agent.py
reg add HKLM\Software\GPTest /v Exited /t REG_SZ /d "exit_%ERRORLEVEL%_%TIME%" /f
