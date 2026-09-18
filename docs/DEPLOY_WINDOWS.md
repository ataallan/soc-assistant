# Deploy on Windows (keep the dashboard running)

The AI-Powered SOC Assistant is a Flask app. On Windows, the most reliable
"always on" option for a single workstation is a **Scheduled Task** (not a
classic Service). That avoids NSSM and keeps paths/venv simple.

## Quick install

1. Open PowerShell in the project folder (or right-click → Run with PowerShell):

```powershell
cd C:\Users\munyi\OneDrive\Desktop\Capstone\soc_assistant
powershell -ExecutionPolicy Bypass -File .\scripts\install_windows_task.ps1
```

2. Open http://127.0.0.1:5000

The task **SOCAssistantDashboard** starts at your user logon and auto-restarts
on failure (up to 3 times).

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall_windows_task.ps1
```

## Notes

- Do not also leave `start_dashboard.bat` running on port 5000 — one process only.
- Logs still appear in the Python process; for file logs later, we can add a
  RotatingFileHandler.
- Machine-wide start (before login) needs admin:  
  `.\scripts\install_windows_task.ps1 -AtStartup` (run elevated).
- Keep WSL/Wazuh running separately if you use live alerts.

## Manual start (no auto-start)

Use the Desktop shortcut **AI-Powered SOC Assistant** or `start_dashboard.bat`.
