# Standalone install (any Windows laptop)

Customers who received **AIPoweredSOCAssistantSetup.exe** should follow [INSTALLER.md](INSTALLER.md). That setup program installs the app, adds one Desktop icon, and does not ask you to unzip a project folder.

The steps below are the alternate folder install, for a copied project directory or zip. Unzip, install Python packages into `.venv`, start `dashboard.py`, and open a browser to the login page. There is no bundled password and no bundled mail or tunnel secret.

Account approval and email login codes stay as they are. The first **Create account** is the site admin and can sign in immediately. Later accounts stay pending until that admin approves them on **Accounts**. Approved users confirm a one-time code sent to their login email.

## What you need

- Windows 10/11
- [Python 3.10+](https://www.python.org/downloads/) (check **Add python.exe to PATH**)
- This project folder, or `AI-Powered-SOC-Assistant-standalone.zip`

Wazuh, outbound mail, and PostgreSQL are **optional**. Without them, login, CSV triage, cases, and the UI still work on local SQLite. Torch and ultralytics are not part of this install.

## Quick start

1. Unzip the folder. `C:\MunCyberSOC` is a reliable location. A Desktop folder, including one synced by OneDrive, can lock files while Python builds `.venv`.
2. Double-click **`install_and_run.bat`** (or right-click **`install_and_run.ps1`** → Run with PowerShell). The `.bat` starts the PowerShell installer with execution policy bypass.
3. Confirm the prompt. The installer creates `.venv`, installs `requirements.txt`, writes **`install.log`**, and creates `.env` from `.env.example` with a new `SECRET_KEY` when `.env` is missing.
4. It then creates two shortcuts named **AI-Powered SOC Assistant** (Desktop, and one inside the product folder) and starts the dashboard at **http://127.0.0.1:5000/login**.

Later, double-click the Desktop shortcut **AI-Powered SOC Assistant**. That runs `Start AI-Powered SOC Assistant.bat`, starts the dashboard, and opens the browser. It does not reinstall packages. A second double-click of `install_and_run.bat` sees a healthy `.venv` and offers **Start only** (press Enter) or **U** to upgrade packages.

Windows `.bat` files keep the default script icon. The clickable branded file is the **AI-Powered SOC Assistant** shortcut (`.lnk`). `start_dashboard.ps1` is the same launcher for a PowerShell window. `start_dashboard.bat` calls the Start launcher.

### Useful flags

```powershell
.\install_and_run.ps1 -NoStart          # install or refresh shortcuts, do not start
.\install_and_run.ps1 -ForceReinstall   # delete .venv, install again, then start
```

Set `SOC_INSTALL_ASSUME_YES=1` to skip the confirm prompt (and, when `.venv` is already healthy, start without asking).

## What the script does

1. Checks for Python 3.10+
2. Creates `.venv`, or deletes and recreates it when Python or a core package install is damaged
3. `pip install -r requirements.txt` (output is copied to `install.log`)
4. Removes optional torch / ultralytics leftovers when the core packages still import
5. Copies `.env.example` → `.env` once and sets a random `SECRET_KEY`
6. Creates the Desktop and folder shortcuts
7. Starts `dashboard.py` and opens the login page

## Icon and shortcuts

`static/img/ai-powered-soc-assistant.ico` is a multi-size icon (16, 24, 32, 48, 64, 128, and 256) built from `static/img/company-logo.png`, the Mun Cyber Technologies mark. The PNG already has a transparent background; the icon keeps that alpha and does not stretch the triangles. `scripts/build_icon.py` rebuilds the `.ico` when the artwork changes. The customer zip already contains the `.ico`.

When install finishes, `install_and_run.ps1` creates the shortcuts with `WScript.Shell`:

| Field | Value |
| --- | --- |
| Name | AI-Powered SOC Assistant |
| Target | `Start AI-Powered SOC Assistant.bat` in the install folder |
| WorkingDirectory | the install folder |
| IconLocation | `static\img\ai-powered-soc-assistant.ico,0` |

One shortcut is saved on the user Desktop (`[Environment]::GetFolderPath("Desktop")`, which follows a redirected Desktop). The other is saved in the product folder. Shortcuts store absolute paths, so they are created on the customer PC. The zip ships the `.ico` and the launcher scripts, not the `.lnk` files.

## If install fails

- **Python missing, or older than 3.10.** Install [Python 3.10+](https://www.python.org/downloads/) and check **Add python.exe to PATH**, then run `install_and_run.bat` again.
- **pip or package errors.** Read `install.log` in the install folder. The window also prints that path.
- **Damaged `.venv`.** Interrupted pip leftovers for a required package, or a `.dist-info` folder missing `METADATA`, make the installer delete `.venv` and install `requirements.txt` again. A healthy check imports Flask, Flask-Mail, Flask-WTF, pandas, python-dotenv, Werkzeug, SQLAlchemy, requests, PyYAML, joblib, NumPy, SciPy, scikit-learn, and psycopg.
- **Optional torch.** Torch and ultralytics are left out of `requirements.txt`. When those leftovers are the only damage and the core packages still import, the installer deletes the leftovers and continues. Existing `.env` values for Wazuh, mail, and PostgreSQL are left in place.
- **Desktop or OneDrive file locks.** If setup fails in a Desktop or OneDrive folder, copy the unzipped folder to `C:\MunCyberSOC` and run `install_and_run.bat` there.

## Do not ship secrets

When copying to another laptop or sharing a zip:

- The build script excludes `.env`, `users.csv`, `*.db`, credential files, `install.log`, `.venv`, and tunnel tokens or tunnel scripts
- Recipients run `install_and_run` so they get a fresh `.env` and venv

`127.0.0.1` is local only. The customer zip does not include a tunnel token or tunnel script. Do not expose Flask debug mode to the internet. The Start launcher runs with `SOC_FLASK_DEBUG=0`.

## Optional integrations

Edit `.env` after install (nothing here is required for the dashboard):

- Mail: `RESEND_API_KEY` / `RESEND_FROM`, or `MAIL_USERNAME` / `MAIL_PASSWORD`
- Wazuh: see [WAZUH_SETUP.md](WAZUH_SETUP.md)
- PostgreSQL: `SOC_DATABASE_URL` (psycopg is installed; SQLite is the default)

## Always-on on this PC

After it runs once: `scripts\install_windows_task.ps1`  
While coding: `scripts\start_dev.ps1` (auto-reload).  
Details: [DEPLOY_WINDOWS.md](DEPLOY_WINDOWS.md).

## Building `AI-Powered-SOC-Assistant-standalone.zip`

From a development checkout (not required for customers):

```powershell
python scripts/build_icon.py
python scripts/build_standalone_zip.py
```

`build_icon.py` needs Pillow (`pip install pillow`) and is only for regenerating the icon. The zip **includes** `.env.example`, `install_and_run.bat`, `install_and_run.ps1`, `Start AI-Powered SOC Assistant.bat`, `start_dashboard.ps1`, `static/img/ai-powered-soc-assistant.ico`, and `static/img/company-logo.png`. It **excludes** `.venv`, `__pycache__`, `.git`, a real `.env`, `install.log`, account and database files, machine-specific `.lnk` shortcuts, and tunnel tokens or scripts.

## Manual equivalent

```powershell
cd path\to\soc-assistant
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
$env:SOC_OPEN_BROWSER = "1"
$env:SOC_FLASK_DEBUG = "0"
python dashboard.py
```
