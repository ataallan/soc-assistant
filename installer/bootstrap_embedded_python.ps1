# AI-Powered SOC Assistant
# First preparation: download embeddable Python, install application components,
# and create .env when it is missing. Later runs leave a healthy install in place.
# Torch and ultralytics are not installed.
# Keep the pinned URL and hash in sync with scripts/standalone_support.py.

#Requires -Version 5.1
param(
    [string]$InstallDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $InstallDir) {
    $InstallDir = Split-Path -Parent $PSScriptRoot
}

$script:PythonVersion = "3.12.10"
$script:EmbedName = "python-3.12.10-embeddable-amd64.zip"
$script:EmbedUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embeddable-amd64.zip"
$script:EmbedSha256 = "156c7eea90d58cd7e91a23f28a0056616b13e9f4cf4901b7b99b837b7848c6da"
$script:GetPipUrl = "https://bootstrap.pypa.io/get-pip.py"

function Write-InstallLog([string]$Message) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $script:InstallLog -Value $line -Encoding UTF8
}

function Pause-Close([string]$Prompt) {
    Read-Host $Prompt | Out-Null
}

function Get-Assessment {
    if (-not (Test-Path -LiteralPath $script:Python)) {
        return $null
    }
    $raw = & $script:Python $script:Support assess $script:Runtime
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    $text = (@($raw) -join "`n").Trim()
    if (-not $text) {
        return $null
    }
    return $text | ConvertFrom-Json
}

function Repair-OptionalLeftovers {
    $raw = & $script:Python $script:Support "scrub-optional" $script:Runtime
    if ($LASTEXITCODE -ne 0) {
        throw "Setup could not finish preparing AI-Powered SOC Assistant."
    }
    $text = (@($raw) -join "`n").Trim()
    if (-not $text) {
        return
    }
    $result = $text | ConvertFrom-Json
    $removed = [string]$result.removed
    if ($removed) {
        Write-InstallLog "removed optional leftovers: $removed"
    }
}

function Initialize-LocalConfig {
    $dataDir = Join-Path $InstallDir "data"
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

    $envPath = Join-Path $InstallDir ".env"
    $examplePath = Join-Path $InstallDir ".env.example"
    if (Test-Path -LiteralPath $envPath) {
        Write-Host "Using existing settings."
        return
    }
    if (-not (Test-Path -LiteralPath $examplePath)) {
        throw "Setup is missing a required settings file. Run AIPoweredSOCAssistantSetup.exe again."
    }
    Copy-Item -LiteralPath $examplePath -Destination $envPath
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $secret = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $raw = Get-Content -LiteralPath $envPath -Raw
    $raw = $raw -replace "SECRET_KEY=change-me-to-a-long-random-string", "SECRET_KEY=$secret"
    # UTF-8 without a BOM, so the dashboard can read .env.
    [System.IO.File]::WriteAllText($envPath, $raw)
    Write-Host "Saved local settings for this PC."
    Write-InstallLog "created .env with a generated SECRET_KEY"
}

function Enable-EmbeddedSite {
    $null = & $script:Python $script:Support "write-pth" $script:Runtime
    if ($LASTEXITCODE -ne 0) {
        throw "Setup could not finish preparing AI-Powered SOC Assistant."
    }
}

function Test-PipPresent {
    $null = & $script:Python -c "import pip" 2>&1
    return $LASTEXITCODE -eq 0
}

function Install-Pip {
    $getPip = Join-Path $env:TEMP "AIPoweredSOCAssistant-get-pip.py"
    Write-Host "Preparing application components ..."
    Write-InstallLog "download get-pip"
    try {
        Invoke-WebRequest -Uri $script:GetPipUrl -OutFile $getPip -UseBasicParsing
    } catch {
        Write-InstallLog $_.Exception.Message
        throw "Setup could not download required components. Check the internet connection and try again."
    }
    & $script:Python $getPip --no-warn-script-location
    if ($LASTEXITCODE -ne 0) {
        Write-InstallLog "get-pip exited $LASTEXITCODE"
        throw "Setup could not download required components. Check the internet connection and try again."
    }
}

function Invoke-Pip {
    param([string[]]$PipArgs)
    Write-InstallLog ("python -m pip " + ($PipArgs -join " "))
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Capture first so $LASTEXITCODE stays the Python process code.
        $output = & $script:Python -m pip @PipArgs 2>&1
        $code = $LASTEXITCODE
        foreach ($item in @($output)) {
            $line = $item.ToString()
            Add-Content -LiteralPath $script:InstallLog -Value $line -Encoding UTF8
            Write-Host $line
        }
        return $code
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Install-Components {
    Write-Host "Installing application components."
    Write-Host "This can take a few minutes the first time. Details are saved to install.log."
    Write-InstallLog "begin component install"
    $pipUpgrade = Invoke-Pip -PipArgs @("install", "--upgrade", "pip")
    if ($pipUpgrade -ne 0) {
        Write-InstallLog "pip self-upgrade exited $pipUpgrade; continuing"
    }
    $reqCode = Invoke-Pip -PipArgs @("install", "-r", $script:Requirements)
    if ($reqCode -ne 0) {
        throw "Setup could not install application components. Check the internet connection and try again."
    }
    Write-InstallLog "component install finished"
}

function Test-OfficialHash([string]$Path) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
    if ($hash -ne $script:EmbedSha256) {
        Write-InstallLog "runtime hash mismatch: $hash"
        throw "The application file did not match the expected copy. Setup stopped."
    }
}

function Install-EmbeddedPython {
    $cache = Join-Path $InstallDir "installer\cache\$script:EmbedName"
    $zipPath = Join-Path $env:TEMP "AIPoweredSOCAssistant-$script:EmbedName"
    if (Test-Path -LiteralPath $cache) {
        Write-Host "Using the included application files."
        Write-InstallLog "using cached $cache"
        Copy-Item -LiteralPath $cache -Destination $zipPath -Force
    } else {
        Write-Host "Downloading application files. This happens once."
        Write-InstallLog "download $script:EmbedUrl"
        try {
            Invoke-WebRequest -Uri $script:EmbedUrl -OutFile $zipPath -UseBasicParsing
        } catch {
            Write-InstallLog $_.Exception.Message
            throw "Setup could not download application files. Check the internet connection and try again."
        }
    }
    Test-OfficialHash $zipPath
    Unblock-File -LiteralPath $zipPath -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $script:Runtime) {
        Remove-Item -LiteralPath $script:Runtime -Recurse -Force
    }
    New-Item -ItemType Directory -Path $script:Runtime | Out-Null
    Expand-Archive -LiteralPath $zipPath -DestinationPath $script:Runtime
    if (-not (Test-Path -LiteralPath $script:Python)) {
        throw "Setup could not finish preparing AI-Powered SOC Assistant."
    }
    Write-InstallLog "extracted embeddable Python $script:PythonVersion"
}

function Assert-Ready {
    $report = Get-Assessment
    if (-not $report) {
        throw "Setup could not finish preparing AI-Powered SOC Assistant."
    }
    $action = [string]$report.action
    if ($action -eq "scrub_optional") {
        Repair-OptionalLeftovers
        $report = Get-Assessment
        if (-not $report) {
            throw "Setup could not finish preparing AI-Powered SOC Assistant."
        }
        $action = [string]$report.action
    }
    if ($action -ne "ready") {
        Write-InstallLog ([string]$report.detail)
        throw "Setup could not finish preparing AI-Powered SOC Assistant."
    }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Host "Continuing with the current security settings."
}
$ProgressPreference = "SilentlyContinue"

if (-not (Test-Path -LiteralPath $InstallDir)) {
    Write-Host "Setup could not find the install folder."
    Pause-Close "Press Enter to close"
    exit 1
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

$script:InstallLog = Join-Path $InstallDir "install.log"
$script:Runtime = Join-Path $InstallDir "runtime"
$script:Python = Join-Path $script:Runtime "python.exe"
$script:Support = Join-Path $InstallDir "scripts\standalone_support.py"
$script:Requirements = Join-Path $InstallDir "requirements.txt"

Write-Host ""
Write-Host "Preparing AI-Powered SOC Assistant."
Write-Host ""

if (-not (Test-Path -LiteralPath $script:Support)) {
    Write-Host "Setup is missing a required file. Run AIPoweredSOCAssistantSetup.exe again."
    Pause-Close "Press Enter to close"
    exit 1
}
if (-not (Test-Path -LiteralPath $script:Requirements)) {
    Write-Host "Setup is missing a required file. Run AIPoweredSOCAssistantSetup.exe again."
    Pause-Close "Press Enter to close"
    exit 1
}

try {
    Write-InstallLog "bootstrap started in $InstallDir"
    $assessment = Get-Assessment
    $action = "recreate"
    if ($assessment) {
        $action = [string]$assessment.action
    }

    if ($action -eq "scrub_optional") {
        Repair-OptionalLeftovers
        $action = "ready"
    }

    if ($action -eq "ready") {
        Initialize-LocalConfig
        Write-Host "AI-Powered SOC Assistant is ready."
        exit 0
    }

    if ($action -eq "recreate" -and (Test-Path -LiteralPath $script:Runtime)) {
        Write-Host "Replacing a damaged copy of the application files ..."
        Write-InstallLog "removing $script:Runtime"
        Remove-Item -LiteralPath $script:Runtime -Recurse -Force
    }

    if (-not (Test-Path -LiteralPath $script:Python)) {
        Install-EmbeddedPython
    }

    Enable-EmbeddedSite
    if (-not (Test-PipPresent)) {
        Install-Pip
    }
    Install-Components
    Assert-Ready
    Initialize-LocalConfig
    Write-Host "AI-Powered SOC Assistant is ready."
    exit 0
} catch {
    Write-Host ""
    Write-Host $_.Exception.Message
    if (Test-Path -LiteralPath $script:InstallLog) {
        Write-Host "Details were saved to:"
        Write-Host "  $script:InstallLog"
    }
    Write-Host ""
    Pause-Close "Press Enter to close"
    exit 1
}
