@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title AI-Powered SOC Assistant

if not exist ".venv\Scripts\python.exe" (
  echo AI-Powered SOC Assistant needs setup before it can start.
  echo Double-click install_and_run.bat in this folder.
  echo That creates .venv, installs requirements, and adds the Desktop shortcut.
  echo.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -c "import flask, flask_mail, flask_wtf, pandas, dotenv, werkzeug, sqlalchemy, requests, yaml, joblib, numpy, scipy, sklearn, psycopg" >nul 2>&1
if errorlevel 1 (
  echo The local Python environment is missing core packages or is damaged.
  echo Double-click install_and_run.bat to repair .venv and refresh the Desktop shortcut.
  echo.
  pause
  exit /b 1
)

set "SOC_OPEN_BROWSER=1"
set "SOC_FLASK_DEBUG=0"
set "SOC_USE_RELOADER=0"
echo Starting AI-Powered SOC Assistant ...
echo Open http://127.0.0.1:5000/login if the browser does not appear.
echo Close this window to stop the dashboard.
echo.
".venv\Scripts\python.exe" "%~dp0dashboard.py"
set "ERR=%ERRORLEVEL%"
echo.
echo AI-Powered SOC Assistant stopped.
pause
exit /b %ERR%
