# Build dist\AIPoweredSOCAssistantSetup.exe with Inno Setup 6.
# Run this on 64-bit Windows from any directory:
#   powershell -ExecutionPolicy Bypass -File scripts\build_windows_installer.ps1
# Optional: -VendorPython downloads the pinned embeddable Python zip into the
# payload so the customer PC does not download that file again. Package
# installation still needs internet on first setup unless the PC already
# has the components.

#Requires -Version 5.1
param(
    [switch]$VendorPython
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location -LiteralPath $Root

$Payload = Join-Path $Root "dist\installer-payload"
$Setup = Join-Path $Root "dist\AIPoweredSOCAssistantSetup.exe"
$Iss = Join-Path $Root "installer\AIPoweredSOCAssistant.iss"

function Find-Iscc {
    if ($env:INNO_SETUP_ISCC -and (Test-Path -LiteralPath $env:INNO_SETUP_ISCC)) {
        return $env:INNO_SETUP_ISCC
    }
    $candidates = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) {
            $candidates += (Join-Path $base "Inno Setup 6\ISCC.exe")
        }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $null
}

Write-Host "Staging AI-Powered SOC Assistant files ..."
& python (Join-Path $Root "scripts\stage_installer_payload.py") --dest $Payload
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($VendorPython) {
    $scripts = Join-Path $Root "scripts"
    $raw = & python -c "import json,sys; sys.path.insert(0, sys.argv[1]); import standalone_support as s; print(json.dumps({'url': s.EMBEDDED_PYTHON_URL, 'name': s.EMBEDDED_PYTHON_FILENAME, 'sha256': s.EMBEDDED_PYTHON_SHA256}))" $scripts
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $spec = ($raw | Out-String).Trim() | ConvertFrom-Json
    $cacheDir = Join-Path $Payload "installer\cache"
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    $zipPath = Join-Path $cacheDir ([string]$spec.name)
    Write-Host "Downloading the pinned application runtime ..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri ([string]$spec.url) -OutFile $zipPath -UseBasicParsing
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLower()
    if ($hash -ne ([string]$spec.sha256).ToLower()) {
        Remove-Item -LiteralPath $zipPath -Force
        throw "The downloaded runtime did not match the expected copy."
    }
    Write-Host "Included the pinned runtime in the setup program."
}

$iscc = Find-Iscc
if (-not $iscc) {
    Write-Host ""
    Write-Host "Inno Setup 6.3 or newer was not found."
    Write-Host "Install it from https://jrsoftware.org/isdl.php and run this script again."
    Write-Host "The compiler is usually at:"
    Write-Host "  C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    Write-Host ""
    Write-Host "The staged files are in:"
    Write-Host "  $Payload"
    exit 1
}

Write-Host "Compiling AIPoweredSOCAssistantSetup.exe ..."
& $iscc "/DPayload=..\dist\installer-payload" $Iss
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
if (-not (Test-Path -LiteralPath $Setup)) {
    throw "Inno Setup did not write $Setup"
}
Write-Host ""
Write-Host "Wrote $Setup"
Write-Host "Give that file to the customer. They run it once, then use the Desktop icon."
