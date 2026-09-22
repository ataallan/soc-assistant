# AI-Powered SOC Assistant launcher. Starts a healthy .venv without reinstalling.
# The Desktop shortcut points at "Start AI-Powered SOC Assistant.bat", which calls the same flow.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    Write-Host "AI-Powered SOC Assistant needs setup before it can start."
    Write-Host "Double-click install_and_run.bat in this folder."
    Write-Host "That creates .venv, installs requirements, and adds the Desktop shortcut."
    Read-Host "Press Enter to close" | Out-Null
    exit 1
}

& $python -c "import flask, flask_mail, flask_wtf, pandas, dotenv, werkzeug, sqlalchemy, requests, yaml, joblib, numpy, scipy, sklearn, psycopg"
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "The local Python environment is missing core packages or is damaged."
    Write-Host "Double-click install_and_run.bat to repair .venv and refresh the Desktop shortcut."
    Read-Host "Press Enter to close" | Out-Null
    exit 1
}

$env:SOC_OPEN_BROWSER = "1"
$env:SOC_FLASK_DEBUG = "0"
$env:SOC_USE_RELOADER = "0"
Write-Host "Starting AI-Powered SOC Assistant ..."
Write-Host "Open http://127.0.0.1:5000/login if the browser does not appear."
Write-Host "Close this window to stop the dashboard."
Write-Host ""
& $python (Join-Path $PSScriptRoot "dashboard.py")
$code = $LASTEXITCODE
Write-Host ""
Write-Host "AI-Powered SOC Assistant stopped."
Read-Host "Press Enter to close" | Out-Null
exit $code
