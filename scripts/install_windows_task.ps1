#Requires -Version 5.1
<#
.SYNOPSIS
  Install AI-Powered SOC Assistant to start automatically (Scheduled Task).
.DESCRIPTION
  Creates task "SOCAssistantDashboard" that runs the venv Python dashboard.py
  at user logon (and can be started now). Prefer this over a classic Windows
  Service for a local Flask app — no NSSM required.
#>
param(
  [switch]$StartNow,
  [switch]$AtStartup  # machine startup (needs admin); default is AtLogon
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "dashboard.py"))) {
  $Root = $PSScriptRoot
}
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$App = Join-Path $Root "dashboard.py"
$TaskName = "SOCAssistantDashboard"
$LogDir = Join-Path $Root "data\logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

if (-not (Test-Path $Python)) {
  Write-Error "Missing venv Python at $Python. Run start_dashboard.bat once first."
}

# Stop any existing listener on 5000 from a manual start
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -eq 5000 } |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$arg = "`"$App`""
$action = New-ScheduledTaskAction -Execute $Python -Argument $arg -WorkingDirectory $Root
if ($AtStartup) {
  $trigger = New-ScheduledTaskTrigger -AtStartup
} else {
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
}
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "AI-Powered SOC Assistant Flask dashboard (http://127.0.0.1:5000)" | Out-Null

Write-Host "Installed scheduled task: $TaskName"
Write-Host "App root: $Root"
Write-Host "URL: http://127.0.0.1:5000"

if ($StartNow -or $true) {
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 4
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" -UseBasicParsing -TimeoutSec 10
    Write-Host "Health check: login HTTP $($r.StatusCode)"
  } catch {
    Write-Host "Task started; if the site is not up yet, wait a few seconds and open http://127.0.0.1:5000"
  }
}

Write-Host ""
Write-Host "Manage: Task Scheduler -> $TaskName"
Write-Host "Remove:  .\scripts\uninstall_windows_task.ps1"
