@echo off
setlocal
cd /d "%~dp0"
set "NF_PYW="
set "NF_ARG="
set "NF_TMP="

rem ========== 1) 优先 py 启动器：pyw.exe -3 自动挑最新的 Python 3 ==========
for %%P in (pyw.exe) do if not defined NF_TMP set "NF_TMP=%%~$PATH:P"
if defined NF_TMP (
  echo "%NF_TMP%" | findstr /i "windowsapps" >nul
  if errorlevel 1 (
    set "NF_PYW=%NF_TMP%"
    set "NF_ARG=-3"
  )
)

rem ========== 2) PATH 里的 pythonw.exe（排掉微软商店的占位别名）==========
if not defined NF_PYW (
  set "NF_TMP="
  for %%P in (pythonw.exe) do if not defined NF_TMP set "NF_TMP=%%~$PATH:P"
)
if not defined NF_PYW if defined NF_TMP (
  echo "%NF_TMP%" | findstr /i "windowsapps" >nul
  if errorlevel 1 set "NF_PYW=%NF_TMP%"
)

rem ========== 3) 扫常见安装目录，版本号从新到旧 ==========
if not defined NF_PYW (
  for %%V in (315 314 313 312 311 310 39 38) do if not defined NF_PYW (
    if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe" set "NF_PYW=%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe"
  )
)
if not defined NF_PYW (
  for %%V in (315 314 313 312 311 310 39 38) do if not defined NF_PYW (
    if exist "%ProgramFiles%\Python\Python%%V\pythonw.exe" set "NF_PYW=%ProgramFiles%\Python\Python%%V\pythonw.exe"
  )
)
if not defined NF_PYW (
  for %%V in (315 314 313 312 311 310 39 38) do if not defined NF_PYW (
    if exist "C:\Python%%V\pythonw.exe" set "NF_PYW=C:\Python%%V\pythonw.exe"
  )
)

rem ========== 都没有就说清楚 ==========
if not defined NF_PYW (
  echo.
  echo   [X] 没有找到 Python。
  echo.
  echo   请到 python.org 下载安装 Python 3，
  echo   安装时记得勾选 Add python.exe to PATH，然后再双击本文件。
  echo.
  echo   装好后如果还是这样，双击「启动.vbs」也可以，它找得更全。
  echo.
  pause
  exit /b 1
)

start "" "%NF_PYW%" %NF_ARG% "%~dp0neepu_flow.py"
