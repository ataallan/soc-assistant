# AI-Powered SOC Assistant - Windows standalone installer
# First run: create .venv, install requirements.txt, write install.log,
# create the Desktop and folder shortcuts, then start the dashboard.
# Later runs: when .venv is healthy, offer Start only (default) or Upgrade.
# Torch and ultralytics are optional and are not installed.
# Wazuh, mail, and PostgreSQL stay optional and are configured in .env.

#Requires -Version 5.1
param(
    [switch]$NoStart,
    [switch]$ForceReinstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$script:InstallLog = Join-Path $PSScriptRoot "install.log"
$script:Support = Join-Path $PSScriptRoot "scripts\standalone_support.py"
$script:VenvDir = Join-Path $PSScriptRoot ".venv"
$script:VenvPython = Join-Path $script:VenvDir "Scripts\python.exe"
$script:Requirements = Join-Path $PSScriptRoot "requirements.txt"
$script:Launcher = Join-Path $PSScriptRoot "Start AI-Powered SOC Assistant.bat"
# IconLocation = <install>\static\img\ai-powered-soc-assistant.ico,0
$script:Icon = Join-Path $PSScriptRoot "static\img\ai-powered-soc-assistant.ico"
$script:ShortcutName = "AI-Powered SOC Assistant.lnk"

function Write-InstallLog([string]$Message) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $script:InstallLog -Value $line -Encoding UTF8
}

function Pause-Close([string]$Prompt) {
    Read-Host $Prompt | Out-Null
}

function Get-PathRisk {
    param($Python)
    $desktop = [Environment]::GetFolderPath("Desktop")
    $supportArgs = @($script:Support, "path-risk", $PSScriptRoot)
    if ($desktop) {
        $supportArgs += @("--desktop", $desktop)
    }
    $raw = & $Python.Exe @($Python.Args + $supportArgs)
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    return ([string]$raw).Trim() -eq "risky"
}

function Show-Failure {
    param(
        [string]$Message,
        $Python
    )
    Write-Host ""
    Write-Host $Message
    if (Test-Path -LiteralPath $script:InstallLog) {
        Write-Host "Details were written to:"
        Write-Host "  $script:InstallLog"
    }
    $risky = $false
    if ($Python) {
        try { $risky = Get-PathRisk -Python $Python } catch { $risky = $false }
    }
    if ($risky) {
        Write-Host ""
        Write-Host "This folder is under Desktop or OneDrive. Those locations often lock files while Python builds .venv."
        Write-Host "Copy the unzipped folder to C:\MunCyberSOC and run install_and_run.bat from there."
    }
    Write-Host ""
    Pause-Close "Press Enter to close"
}

function Get-PythonLauncher {
    $candidates = @(
        @{ Exe = "py"; Args = @("-3") },
        @{ Exe = "python"; Args = @() },
        @{ Exe = "python3"; Args = @() }
    )
    $tooOld = $false
    foreach ($candidate in $candidates) {
        if (-not (Get-Command $candidate.Exe -ErrorAction SilentlyContinue)) {
            continue
        }
        & $candidate.Exe @($candidate.Args + @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 2)"))
        if ($LASTEXITCODE -eq 0) {
            return $candidate
        }
        if ($LASTEXITCODE -eq 2) {
            $tooOld = $true
        }
    }
    Write-Host ""
    if ($tooOld) {
        Write-Host "Python 3.10 or newer is required. A Python was found, but it is older than 3.10."
        Write-Host "Install a current Python from https://www.python.org/downloads/ and check Add python.exe to PATH."
    } else {
        Write-Host "Python 3 was not found on PATH."
        Write-Host "Install Python 3.10 or newer from https://www.python.org/downloads/"
        Write-Host "During setup, check Add python.exe to PATH, then run install_and_run.bat again."
    }
    Write-Host ""
    Pause-Close "Press Enter to close"
    exit 1
}

function Invoke-Support {
    param(
        $Python,
        [string[]]$SupportArgs
    )
    $raw = & $Python.Exe @($Python.Args + $SupportArgs)
    if ($LASTEXITCODE -ne 0) {
        throw "standalone_support.py failed: $($SupportArgs -join ' ')"
    }
    $text = (@($raw) -join "`n").Trim()
    if (-not $text) {
        throw "standalone_support.py returned no output."
    }
    return $text | ConvertFrom-Json
}

function Get-VenvAssessment {
    param($Python)
    return Invoke-Support -Python $Python -SupportArgs @($script:Support, "assess", $script:VenvDir)
}

function Invoke-Pip {
    param([string[]]$PipArgs)
    Write-InstallLog ("python -m pip " + ($PipArgs -join " "))
    # pip writes progress to stderr. Leave ErrorAction as Continue so those
    # lines are logged instead of stopping the installer.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $script:VenvPython -m pip @PipArgs 2>&1 | ForEach-Object {
            $line = $_.ToString()
            Add-Content -LiteralPath $script:InstallLog -Value $line -Encoding UTF8
            Write-Host $line
        }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Install-Requirements {
    param([switch]$UpgradePackages)
    Write-Host "Installing requirements.txt into .venv ..."
    Write-Host "A copy of the pip output is saved to install.log."
    Write-Host "Torch and ultralytics stay optional and are not installed."
    Write-InstallLog "begin requirements install"
    $pipUpgrade = Invoke-Pip -PipArgs @("install", "--upgrade", "pip")
    if ($pipUpgrade -ne 0) {
        Write-Host "pip could not upgrade itself. Continuing with the current pip."
        Write-InstallLog "pip self-upgrade exited $pipUpgrade; continuing with requirements.txt"
    }
    $pipArgs = @("install", "-r", $script:Requirements)
    if ($UpgradePackages) {
        $pipArgs = @("install", "--upgrade", "-r", $script:Requirements)
    }
    $reqCode = Invoke-Pip -PipArgs $pipArgs
    if ($reqCode -ne 0) {
        return $reqCode
    }
    Write-InstallLog "requirements install finished"
    return 0
}

function Remove-BrokenVenv {
    if (-not (Test-Path -LiteralPath $script:VenvDir)) {
        return
    }
    Write-Host "Removing the damaged .venv so it can be created cleanly ..."
    Write-InstallLog "removing $script:VenvDir"
    try {
        Remove-Item -LiteralPath $script:VenvDir -Recurse -Force -ErrorAction Stop
    } catch {
        Start-Sleep -Seconds 1
        Remove-Item -LiteralPath $script:VenvDir -Recurse -Force -ErrorAction Stop
    }
}

function New-Venv {
    param($Python)
    Write-Host "Creating .venv ..."
    Write-InstallLog "creating venv with $($Python.Exe)"
    & $Python.Exe @($Python.Args + @("-m", "venv", $script:VenvDir))
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $script:VenvPython)) {
        throw "venv creation failed"
    }
}

function Repair-OptionalLeftovers {
    param($Python)
    $result = Invoke-Support -Python $Python -SupportArgs @($script:Support, "scrub-optional", $script:VenvDir)
    $removed = [string]$result.removed
    if ($removed) {
        Write-Host "Removed optional torch/ultralytics leftovers: $removed"
        Write-Host "Core requirements stay installed. Wazuh, mail, and PostgreSQL settings in .env are unchanged."
        Write-InstallLog "scrubbed optional leftovers: $removed"
    }
}

function Install-SocShortcuts {
    if (-not (Test-Path -LiteralPath $script:Launcher)) {
        Write-Host "Launcher missing, so shortcuts were not created: $script:Launcher"
        return
    }
    $shell = New-Object -ComObject WScript.Shell
    $desktop = [Environment]::GetFolderPath("Desktop")
    if (-not $desktop) {
        $desktop = Join-Path $env:USERPROFILE "Desktop"
    }
    if (-not (Test-Path -LiteralPath $desktop)) {
        New-Item -ItemType Directory -Path $desktop | Out-Null
    }
    $iconLocation = ""
    if (Test-Path -LiteralPath $script:Icon) {
        $iconLocation = "$($script:Icon),0"
    } else {
        Write-Host "Icon file missing. Shortcuts will use the default icon: $script:Icon"
    }
    $shortcutPaths = @(
        (Join-Path $desktop $script:ShortcutName),
        (Join-Path $PSScriptRoot $script:ShortcutName)
    )
    foreach ($shortcutPath in $shortcutPaths) {
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $script:Launcher
        $shortcut.WorkingDirectory = $PSScriptRoot
        $shortcut.Description = "AI-Powered SOC Assistant"
        $shortcut.WindowStyle = 1
        if ($iconLocation) {
            $shortcut.IconLocation = $iconLocation
        }
        $shortcut.Save()
        Write-Host "Shortcut: $shortcutPath"
        Write-InstallLog "shortcut $shortcutPath -> $script:Launcher"
    }
    Write-Host "Next time, open AI-Powered SOC Assistant from the Desktop shortcut."
}

function Copy-EnvExample {
    $envPath = Join-Path $PSScriptRoot ".env"
    $examplePath = Join-Path $PSScriptRoot ".env.example"
    if ((Test-Path -LiteralPath $envPath) -or -not (Test-Path -LiteralPath $examplePath)) {
        if (Test-Path -LiteralPath $envPath) {
            Write-Host "Using existing .env"
        }
        return
    }
    Copy-Item -LiteralPath $examplePath -Destination $envPath
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $raw = Get-Content -LiteralPath $envPath -Raw
    $raw = $raw -replace "SECRET_KEY=change-me-to-a-long-random-string", "SECRET_KEY=$secret"
    Set-Content -LiteralPath $envPath -Value $raw -NoNewline
    Write-Host "Created .env from .env.example (new SECRET_KEY). Edit .env for Wazuh, mail, or PostgreSQL if needed."
    Write-InstallLog "created .env with a generated SECRET_KEY"
}

function Initialize-LocalConfig {
    Copy-EnvExample
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "data") -Force | Out-Null
    try {
        Install-SocShortcuts
    } catch {
        Write-Host "Could not create shortcuts: $($_.Exception.Message)"
        Write-Host "The dashboard can still start. You can run Start AI-Powered SOC Assistant.bat in this folder."
    }
}

function Start-SocAssistant {
    Initialize-LocalConfig
    if ($NoStart) {
        Write-Host ""
        Write-Host "Skipping start (-NoStart)."
        Write-Host "Double-click Start AI-Powered SOC Assistant.bat when you want the dashboard."
        exit 0
    }
    $env:SOC_OPEN_BROWSER = "1"
    $env:SOC_FLASK_DEBUG = "0"
    $env:SOC_USE_RELOADER = "0"
    Write-Host ""
    Write-Host "Starting AI-Powered SOC Assistant ..."
    Write-Host "Open http://127.0.0.1:5000/login if the browser does not appear."
    Write-Host "Create the first admin account. Close this window to stop the dashboard."
    Write-Host ""
    & $script:VenvPython (Join-Path $PSScriptRoot "dashboard.py")
    $code = $LASTEXITCODE
    Write-Host ""
    Pause-Close "Press Enter to close"
    exit $code
}

function Assert-CoreImports {
    param($Python)
    $afterInstall = Get-VenvAssessment -Python $Python
    $afterAction = [string]$afterInstall.action
    if ($afterAction -eq "scrub_optional") {
        Repair-OptionalLeftovers -Python $Python
        $afterAction = "ready"
    }
    if ($afterAction -ne "ready") {
        Show-Failure -Message "Packages were installed, but core imports still failed. $($afterInstall.detail)" -Python $Python
        exit 1
    }
}

Write-Host ""
Write-Host "AI-Powered SOC Assistant - Windows standalone"
Write-Host ""
Write-Host "This installer will:"
Write-Host "  1. Create or repair a local .venv"
Write-Host "  2. Install Python packages from requirements.txt when they are missing"
Write-Host "  3. Add a Desktop shortcut named AI-Powered SOC Assistant"
Write-Host "  4. Start the dashboard at http://127.0.0.1:5000 and open your browser"
Write-Host ""
Write-Host "Torch / ultralytics is optional and is not part of this install."
Write-Host "Wazuh, outbound mail, and PostgreSQL stay optional. Leave them blank in .env to skip them."
Write-Host "There is no default password. Create the first admin yourself."
Write-Host "Approved accounts confirm an email login code."
Write-Host ""

if (-not (Test-Path -LiteralPath $script:Support)) {
    Write-Host "Missing installer helper: $script:Support"
    Pause-Close "Press Enter to close"
    exit 1
}

try {
    Write-InstallLog "installer started in $PSScriptRoot"
    $python = Get-PythonLauncher

    if ($ForceReinstall) {
        $action = "recreate"
        $reason = "damaged"
        $detail = "-ForceReinstall will delete .venv and install requirements.txt again."
    } else {
        $assessment = Get-VenvAssessment -Python $python
        $action = [string]$assessment.action
        $reason = [string]$assessment.reason
        $detail = [string]$assessment.detail
        if ($action -eq "scrub_optional") {
            Repair-OptionalLeftovers -Python $python
            $action = "ready"
            $reason = "ready"
            $detail = "Core packages import."
        }
    }

    if ($action -eq "ready") {
        Write-Host "AI-Powered SOC Assistant is already installed in .venv."
        if ($NoStart) {
            Start-SocAssistant
        }
        if ($env:SOC_INSTALL_ASSUME_YES) {
            Start-SocAssistant
        }
        Write-Host "  [S] Start only"
        Write-Host "  [U] Upgrade packages from requirements.txt"
        Write-Host ""
        $choice = Read-Host "Press Enter to start, or type U to upgrade"
        if ($choice -match '^[Uu]') {
            $code = Install-Requirements -UpgradePackages
            if ($code -ne 0) {
                Show-Failure -Message "Upgrading requirements.txt failed." -Python $python
                exit 1
            }
            Assert-CoreImports -Python $python
        }
        Start-SocAssistant
    }

    Write-Host $detail
    if ($reason -eq "damaged") {
        Write-Host "The installer will delete .venv and install requirements.txt again."
        Write-Host "Optional torch/ultralytics leftovers are cleared with it. They are not required."
    } elseif ($reason -eq "missing") {
        Write-Host "A new .venv will be created and requirements.txt will be installed into it."
    } else {
        Write-Host "requirements.txt will be installed into the existing .venv."
    }
    Write-Host ""
    if (-not $env:SOC_INSTALL_ASSUME_YES) {
        $confirm = Read-Host "Continue and install from requirements.txt? [Y/n]"
        if ($confirm -match '^[Nn]') {
            Write-Host "Cancelled. Nothing was installed."
            exit 0
        }
    }

    try {
        if ($action -eq "recreate") {
            Remove-BrokenVenv
            New-Venv -Python $python
        } elseif (-not (Test-Path -LiteralPath $script:VenvPython)) {
            New-Venv -Python $python
        }
    } catch {
        Write-InstallLog "venv setup failed: $($_.Exception.Message)"
        Show-Failure -Message "Could not create a clean .venv. Close any Python window using this folder and try again." -Python $python
        exit 1
    }

    $installCode = Install-Requirements
    if ($installCode -ne 0) {
        Show-Failure -Message "Installing requirements.txt failed." -Python $python
        exit 1
    }

    Assert-CoreImports -Python $python
    Start-SocAssistant
} catch {
    Write-Host ""
    Write-Host "Setup stopped: $($_.Exception.Message)"
    if (Test-Path -LiteralPath $script:InstallLog) {
        Write-Host "Details were written to:"
        Write-Host "  $script:InstallLog"
    }
    Write-Host ""
    Pause-Close "Press Enter to close"
    exit 1
}
