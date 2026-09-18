#Requires -Version 5.1
<#
.SYNOPSIS
  Active development: stop the always-on task and run Flask with auto-reload.
  Python file saves reload the app; refresh the browser for templates/static.
#>
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "dashboard.py"))) { $Root = $PSScriptRoot }
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$TaskName = "SOCAssistantDashboard"

if (-not (Test-Path $Python)) {
  Write-Error "Missing venv at $Python. Run start_dashboard.bat once first."
}

Write-Host "Stopping scheduled task (if present) so port 5000 is free..."
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -eq 5000 } |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

$env:SOC_ALWAYS_ON = "0"
$env:SOC_FLASK_DEBUG = "true"
$env:SOC_USE_RELOADER = "true"

Write-Host ""
Write-Host "Dev mode: Flask auto-reloads when you save .py files."
Write-Host "Refresh the browser for template/CSS changes."
Write-Host "When finished coding: .\scripts\stop_dev.ps1  (resumes always-on task)"
Write-Host "URL: http://127.0.0.1:5000"
Write-Host ""

Start-Process -FilePath $Python -ArgumentList "dashboard.py" -WorkingDirectory $Root
Start-Sleep -Seconds 4
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" -UseBasicParsing -TimeoutSec 10
  Write-Host "Ready. Login HTTP $($r.StatusCode)"
} catch {
  Write-Host "Started; if the page is not up yet, wait a few seconds."
}
