@echo off
rem ============================================================
rem  NeepuFlow 启动器（备用版，能看到报错）
rem  和 启动.vbs 一样：先确认这个 Python 真的带 tkinter，
rem  否则 pythonw 没有控制台，起不来也看不到任何提示。
rem ============================================================
setlocal
cd /d "%~dp0"

set "NF_PYW="
set "NF_ARG="
set "NF_TMP="
set "NF_ANY="

rem ---------- 1) py 启动器：pyw.exe -3 ----------
call :TRY_LAUNCHER
if defined NF_PYW goto RUN

rem ---------- 2) PATH 里的 pythonw.exe ----------
call :TRY_PATH
if defined NF_PYW goto RUN

rem ---------- 3) 扫常见安装目录，版本从新到旧 ----------
for %%V in (315 314 313 312 311 310 39 38) do call :TRY_FILE "%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe"
if defined NF_PYW goto RUN
for %%V in (315 314 313 312 311 310 39 38) do call :TRY_FILE "%ProgramFiles%\Python\Python%%V\pythonw.exe"
if defined NF_PYW goto RUN
for %%V in (315 314 313 312 311 310 39 38) do call :TRY_FILE "%ProgramFiles(x86)%\Python\Python%%V\pythonw.exe"
if defined NF_PYW goto RUN
for %%V in (315 314 313 312 311 310 39 38) do call :TRY_FILE "C:\Python%%V\pythonw.exe"
if defined NF_PYW goto RUN

rem ---------- 都没有：说清楚为什么 ----------
echo.
if defined NF_ANY (
  echo   [X] 找到 Python 了，但它没带图形界面库 tkinter，程序起不来。
  echo.
  echo   请到 python.org 重新装一次 Python 3，
  echo   安装时把 "tcl/tk and IDLE" 也勾上（默认就勾着）。
  echo.
  echo   或者直接双击「启动.vbs」，两个文件找法一样。
) else (
  echo   [X] 没有找到 Python。
  echo.
  echo   请到 python.org 下载安装 Python 3，
  echo   安装时记得勾选 Add python.exe to PATH，然后再双击本文件。
  echo.
  echo   装好后如果还是这样，双击「启动.vbs」也可以，它找得更全。
)
echo.
pause
exit /b 1

:RUN
start "" "%NF_PYW%" %NF_ARG% "%~dp0neepu_flow.py"
exit /b 0


rem ============================================================
rem  子过程
rem ============================================================

:TRY_LAUNCHER
for %%P in (pyw.exe) do if not defined NF_TMP set "NF_TMP=%%~$PATH:P"
if not defined NF_TMP goto :eof
echo "%NF_TMP%" | findstr /i "windowsapps" >nul
if not errorlevel 1 goto :eof
for %%P in (py.exe) do set "NF_PY=%%~$PATH:P"
if not defined NF_PY goto :eof
"%NF_PY%" -3 -c "import tkinter" >nul 2>&1
if errorlevel 1 goto :eof
set "NF_PYW=%NF_TMP%"
set "NF_ARG=-3"
goto :eof

:TRY_PATH
set "NF_TMP="
for %%P in (pythonw.exe) do if not defined NF_TMP set "NF_TMP=%%~$PATH:P"
if not defined NF_TMP goto :eof
echo "%NF_TMP%" | findstr /i "windowsapps" >nul
if not errorlevel 1 goto :eof
call :TRY_FILE "%NF_TMP%"
goto :eof

:TRY_FILE
if defined NF_PYW goto :eof
if "%~1"=="" goto :eof
if not exist "%~1" goto :eof
set "NF_ANY=1"
call :HAS_TK "%~1"
if "%NF_TK%"=="1" set "NF_PYW=%~1"
goto :eof

:HAS_TK
rem 用同目录的 python.exe 试 import tkinter；没有 python.exe 就当能用
set "NF_TK=1"
set "NF_PY=%~1"
set "NF_PY=%NF_PY:pythonw.exe=python.exe%"
if /i "%NF_PY%"=="%~1" goto :eof
if not exist "%NF_PY%" goto :eof
"%NF_PY%" -c "import tkinter" >nul 2>&1
if errorlevel 1 (set "NF_TK=0") else (set "NF_TK=1")
goto :eof
