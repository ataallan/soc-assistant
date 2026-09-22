@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where powershell >nul 2>&1
if errorlevel 1 (
  echo Windows PowerShell was not found. AI-Powered SOC Assistant setup needs PowerShell.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_and_run.ps1" %*
set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" (
  echo.
  echo Setup exited with code %ERR%.
  pause
)
exit /b %ERR%
