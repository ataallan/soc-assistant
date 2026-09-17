@echo off
title AI-Powered SOC Assistant
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment not found. Creating...
  py -3 -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)
echo.
echo Starting AI-Powered SOC Assistant on http://127.0.0.1:5000
echo Keep this window open. Press Ctrl+C to stop.
echo.
python dashboard.py
echo.
echo Dashboard stopped.
pause
