#Requires -Version 5.1
param(
  [switch]$NoResumeTask  # leave always-on stopped
)
$ErrorActionPreference = "Continue"
$TaskName = "SOCAssistantDashboard"

Write-Host "Stopping any dashboard on port 5000..."
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -eq 5000 } |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

if (-not $NoResumeTask) {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 4
    Write-Host "Always-on task $TaskName started again."
  } else {
    Write-Host "No scheduled task found. Install with .\scripts\install_windows_task.ps1 if you want always-on."
  }
} else {
  Write-Host "Left always-on task stopped (-NoResumeTask)."
}

try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" -UseBasicParsing -TimeoutSec 8
  Write-Host "Login HTTP $($r.StatusCode) — http://127.0.0.1:5000"
} catch {
  Write-Host "Port 5000 not answering yet; check Task Scheduler if you expected always-on."
}
