@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title AI-Powered SOC Assistant

where powershell >nul 2>&1
if errorlevel 1 (
  echo Windows PowerShell was not found.
  echo AI-Powered SOC Assistant needs Windows PowerShell to start.
  echo.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\launch_app.ps1"
exit /b %ERRORLEVEL%
