# AI-Powered SOC Assistant
# Desktop and Start menu shortcut target. Starts the dashboard on port 5000
# and opens the sign-in page. Does not reinstall when the app is already prepared.

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $InstallDir

function Test-SignInPage {
    $request = $null
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:5000/login")
        $request.Method = "GET"
        $request.Timeout = 1500
        $request.ReadWriteTimeout = 1500
        $request.AllowAutoRedirect = $true
        $response = $request.GetResponse()
        $code = [int]$response.StatusCode
        return ($code -ge 200 -and $code -lt 500)
    } catch {
        return $false
    } finally {
        if ($response) {
            $response.Close()
        }
    }
}

function Pause-Close([string]$Prompt) {
    Read-Host $Prompt | Out-Null
}

if (Test-SignInPage) {
    Write-Host "AI-Powered SOC Assistant is already running."
    Write-Host "The sign-in page was opened in your browser."
    Start-Process "http://127.0.0.1:5000/login"
    Write-Host ""
    Pause-Close "Press Enter to close"
    exit 0
}

$Python = Join-Path $InstallDir "runtime\python.exe"
$Support = Join-Path $InstallDir "scripts\standalone_support.py"
$ready = $false
if ((Test-Path -LiteralPath $Python) -and (Test-Path -LiteralPath $Support)) {
    $raw = & $Python $Support assess (Join-Path $InstallDir "runtime")
    if ($LASTEXITCODE -eq 0) {
        $text = (@($raw) -join "`n").Trim()
        if ($text) {
            $report = $text | ConvertFrom-Json
            if ([string]$report.action -eq "ready") {
                $ready = $true
            }
        }
    }
}

if (-not $ready) {
    Write-Host "Finishing setup for AI-Powered SOC Assistant."
    Write-Host "This can take a few minutes the first time."
    Write-Host ""
    $bootstrap = Join-Path $PSScriptRoot "bootstrap_embedded_python.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrap -InstallDir $InstallDir
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$env:SOC_OPEN_BROWSER = "1"
$env:SOC_FLASK_DEBUG = "0"
$env:SOC_USE_RELOADER = "0"
$env:SOC_FLASK_HOST = "127.0.0.1"
$env:SOC_FLASK_PORT = "5000"
Write-Host "Starting AI-Powered SOC Assistant ..."
Write-Host "Open http://127.0.0.1:5000/login if the browser does not appear."
Write-Host "Close this window to stop the dashboard."
Write-Host ""
& $Python (Join-Path $InstallDir "dashboard.py")
$code = $LASTEXITCODE
Write-Host ""
Write-Host "AI-Powered SOC Assistant stopped."
Pause-Close "Press Enter to close"
exit $code
