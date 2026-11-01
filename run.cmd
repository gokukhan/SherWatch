@echo off
rem NetMonitor Command Center launcher.
rem Starts the release build, requests administrator rights (UAC) and logs to data\logs.
setlocal
cd /d "%~dp0"
if not exist "target\release\netmon.exe" (
  echo Release binary not found. Building...
  cargo build --release || (echo Build failed. See docs\BUILDING.md & pause & exit /b 1)
)
if not exist "data\logs" mkdir "data\logs"
start "" "target\release\netmon.exe" %*
endlocal
