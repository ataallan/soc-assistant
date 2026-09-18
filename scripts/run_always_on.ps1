#Requires -Version 5.1
# Launched by scheduled task: no debug / no reloader.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "dashboard.py"))) { $Root = $PSScriptRoot }
$Python = Join-Path $Root ".venv\Scripts\python.exe"
Set-Location -LiteralPath $Root
$env:SOC_ALWAYS_ON = "1"
$env:SOC_FLASK_DEBUG = "false"
$env:SOC_USE_RELOADER = "false"
& $Python (Join-Path $Root "dashboard.py")
