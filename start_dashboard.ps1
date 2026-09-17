$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
  Write-Host "Creating venv..."
  py -3 -m venv .venv
  & (Join-Path $PSScriptRoot ".venv\Scripts\pip.exe") install -r requirements.txt
}
Write-Host "Starting AI-Powered SOC Assistant at http://127.0.0.1:5000"
Write-Host "Keep this window open. Ctrl+C to stop."
& $py dashboard.py
