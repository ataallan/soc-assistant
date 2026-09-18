# Deploy on Windows (keep the dashboard running)

The AI-Powered SOC Assistant is a Flask app. On Windows, the most reliable
"always on" option for a single workstation is a **Scheduled Task** (not a
classic Service). That avoids NSSM and keeps paths/venv simple.

## Two modes (pick one at a time)

| Mode | When | Script |
|------|------|--------|
| **Active development** | You (or an assistant) are editing code | `scripts/start_dev.ps1` |
| **Always-on** | Demo / daily use, not editing | Scheduled task via `install_windows_task.ps1` |

Only one process should listen on port 5000.

### Active development (auto-reload — no restart per edit)

While you are making changes, run **once**:

```powershell
cd C:\Users\munyi\OneDrive\Desktop\Capstone\soc_assistant
powershell -ExecutionPolicy Bypass -File .\scripts\start_dev.ps1
```

That stops the scheduled task and starts Flask with the **reloader**. Saving
`.py` files reloads the app automatically. Refresh the browser for
templates/CSS. When you are done coding:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop_dev.ps1
```

That stops the console app and starts the always-on task again (if installed).

### Always-on (scheduled task)

1. Install (once):

```powershell
cd C:\Users\munyi\OneDrive\Desktop\Capstone\soc_assistant
powershell -ExecutionPolicy Bypass -File .\scripts\install_windows_task.ps1
```

2. Open http://127.0.0.1:5000

The task **SOCAssistantDashboard** starts at your user logon and auto-restarts
on failure (up to 3 times). It runs **without** the Flask reloader
(`SOC_ALWAYS_ON=1`).

#### After you update code while always-on

One restart picks up the new files (not needed in start_dev mode):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\restart_windows_task.ps1
```

## Uninstall always-on

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall_windows_task.ps1
```

## Notes

- Do not leave both the task and `start_dev` / `start_dashboard.bat` on port 5000.
- Machine-wide start (before login) needs admin:  
  `.\scripts\install_windows_task.ps1 -AtStartup` (run elevated).
- Keep WSL/Wazuh running separately if you use live alerts.
- Manual start without auto-start: Desktop shortcut **AI-Powered SOC Assistant**
  or `start_dashboard.bat` (uses debug/reloader by default).
