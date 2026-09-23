# Windows Setup installer

Customers install **AI-Powered SOC Assistant** from one setup program, `AIPoweredSOCAssistantSetup.exe`. They do not unzip a Python project or install Python themselves.

The setup program installs for the current user under `%LocalAppData%\AIPoweredSOCAssistant`. It creates one Desktop icon named **AI-Powered SOC Assistant**, using `static/img/ai-powered-soc-assistant.ico` (the Mun Cyber Technologies logo). It also adds a Start menu entry and an uninstaller.

The first launch starts the dashboard on **127.0.0.1 port 5000** and opens the sign-in page. Later launches use the Desktop icon. Close the application window to stop the dashboard.

Account approval and email login codes are unchanged. There is no default password. The first **Create account** is the site administrator and can sign in immediately. Later accounts stay pending until that administrator approves them on **Accounts**. Approved users confirm a one-time code sent to their login email. `SOC_EMAIL_2FA` stays at its default (on).

Wazuh, outbound mail, and PostgreSQL stay optional. Torch and ultralytics are not installed. The setup program does not include mail passwords, API keys, account files, or tunnel tokens. The PC needs internet access the first time, so setup can download the application runtime and Python packages.

The unzipped-folder install is still available for a copied project directory. See [STANDALONE.md](STANDALONE.md).

## Customer install

1. Download `AIPoweredSOCAssistantSetup.exe`.
2. Run it and finish the wizard. Windows may ask you to confirm an unrecognized app if the file is not signed.
3. Leave **Open AI-Powered SOC Assistant** checked. The dashboard starts and the sign-in page opens at http://127.0.0.1:5000/login.
4. Create the first account. That person is the administrator.
5. Next time, open the Desktop icon **AI-Powered SOC Assistant**. The Start menu has the same entry.
6. To remove the app, use **Uninstall AI-Powered SOC Assistant** in the Start menu, or Windows Settings. Uninstall removes the program files. Accounts and the local database under the install folder are left in place. Delete `%LocalAppData%\AIPoweredSOCAssistant` to remove those too.

Installing a newer setup program ends existing sign-ins. Open the dashboard and sign in again. Approval and the email code are unchanged.

The first preparation can take a few minutes. Details are written to `install.log` in the install folder.

## Build `AIPoweredSOCAssistantSetup.exe`

The setup program is compiled with [Inno Setup 6.3 or newer](https://jrsoftware.org/isdl.php) on 64-bit Windows. This repository cannot compile that executable on Linux. Use a Windows PC or the GitHub Actions workflow below.

On Windows, from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_installer.ps1
```

The script stages `dist\installer-payload` (application files, launcher, and icon, without secrets) and compiles `dist\AIPoweredSOCAssistantSetup.exe`. Staging writes a new `VERSION` stamp into that payload so sign-ins from the previous build cannot reopen the console after the upgrade.

Inno Setup 6.3 or newer must be installed. The compiler is usually `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`. Set `INNO_SETUP_ISCC` if it lives somewhere else.

To bundle the pinned embeddable Python zip inside the setup program (the customer PC still downloads Python packages on first setup):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows_installer.ps1 -VendorPython
```

What the pieces do:

| Path | Role |
| --- | --- |
| `installer/AIPoweredSOCAssistant.iss` | Inno Setup script: per-user folder, one Desktop icon, Start menu, uninstaller |
| `installer/bootstrap_embedded_python.ps1` | Downloads Python 3.12.10 embeddable (checked hash), installs components, creates `.env` |
| `installer/launch_app.ps1` | Starts the dashboard on port 5000 and opens the browser |
| `installer/Launch AI-Powered SOC Assistant.bat` | Shortcut target |
| `scripts/stage_installer_payload.py` | Builds the folder the setup program installs |
| `scripts/build_windows_installer.ps1` | Stages that folder and runs the Inno Setup compiler |
| `scripts/standalone_support.py` | Decides whether the runtime is ready, incomplete, or damaged |
| `static/img/ai-powered-soc-assistant.ico` | Desktop, Start menu, and setup icon |

### GitHub Actions

`.github/workflows/windows-installer.yml` runs the same build on `windows-latest` when installer files change, and when someone starts the **Windows installer** workflow by hand. Download `AIPoweredSOCAssistantSetup.exe` from that run's artifacts.

The workflow does not sign the executable.
