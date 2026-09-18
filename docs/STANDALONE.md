# Standalone install (any Windows laptop)

Run **AI-Powered SOC Assistant** from a copied folder or zip — no Visual Studio
project required. Good for demos and local tests.

## What you need

- Windows 10/11
- [Python 3.10+](https://www.python.org/downloads/) (check **Add python.exe to PATH**)
- This project folder (from Downloads zip, Capstone copy, or GitHub clone)

Wazuh is **optional**. Without it, login, CSV triage, cases, and UI still work.

## Quick start

1. Unzip / copy the folder to the laptop (example: `Desktop\soc_assistant`).
2. Double-click **`install_and_run.bat`** — it **asks to confirm**, then installs Python packages from `requirements.txt` automatically.  
   or in PowerShell:

```powershell
cd path\to\soc_assistant
powershell -ExecutionPolicy Bypass -File .\install_and_run.ps1
```

3. Browser opens **http://127.0.0.1:5000/login**  
   Register an account, then set that email in `.env` as `SOC_ADMIN_EMAILS` if you need admin actions.

### Useful flags

```powershell
.\install_and_run.ps1 -NoStart          # install only
.\install_and_run.ps1 -ForceReinstall   # recreate .venv then start
```

## What the script does

1. Creates `.venv` if missing  
2. `pip install -r requirements.txt`  
3. Copies `.env.example` → `.env` (once) and sets a random `SECRET_KEY`  
4. Starts `dashboard.py`  
5. Opens the login page  

Later starts: use `start_dashboard.bat` / `start_dashboard.ps1` (faster; skips reinstall).

## Do not ship secrets

When copying to another laptop or sharing a zip:

- **Exclude** `.env`, `*.db`, credential text files, and `.venv` if you want a smaller zip  
- Recipients run `install_and_run` so they get a fresh `.env` and venv  

Your Downloads packages already omit `.env` for that reason.

## Optional: connect this laptop to Wazuh

Edit `.env` after install (see `docs/WAZUH_SETUP.md`):

- Manager API: `WAZUH_API`, `WAZUH_USER`, `WAZUH_PASS`  
- Indexer alerts: `WAZUH_INDEXER_*` (on Windows + WSL indexer, `WAZUH_INDEXER_VIA_WSL=true`)

## Always-on on this PC

After it runs once: `scripts\install_windows_task.ps1`  
While coding: `scripts\start_dev.ps1` (auto-reload).  
Details: `docs/DEPLOY_WINDOWS.md`.

## Public URL / domain

`127.0.0.1` is local only. For a shareable link, use a tunnel (Cloudflare Tunnel / ngrok)
or host on a VPS with HTTPS and your domain. Do not expose Flask debug mode to the internet.

## Branding

Login and navbar show the Mun Cyber company logo and **AI-Powered SOC Assistant**.
