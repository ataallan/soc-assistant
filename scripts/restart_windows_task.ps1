#Requires -Version 5.1
# After pulling/syncing code while always-on: one restart picks up changes.
$ErrorActionPreference = "Stop"
$TaskName = "SOCAssistantDashboard"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) { Write-Error "Task $TaskName not found. Run install_windows_task.ps1 first." }
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 4
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/login" -UseBasicParsing -TimeoutSec 10
  Write-Host "Restarted. Login HTTP $($r.StatusCode) — http://127.0.0.1:5000"
} catch {
  Write-Host "Task started; wait a few seconds then open http://127.0.0.1:5000"
}
