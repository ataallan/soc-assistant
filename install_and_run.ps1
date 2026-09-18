#Requires -Version 5.1
<#
.SYNOPSIS
  One-shot setup + start for AI-Powered SOC Assistant on any Windows laptop.
.DESCRIPTION
  Creates .venv, installs requirements, copies .env.example -> .env if missing,
  then starts the dashboard at http://127.0.0.1:5000
#>
param(
  [switch]$NoStart,          # only install
  [switch]$ForceReinstall    # recreate venv
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

Write-Host ""
Write-Host "AI-Powered SOC Assistant — standalone install"
Write-Host "Folder: $PSScriptRoot"
Write-Host ""

function Find-Python {
  foreach ($cmd in @("py", "python", "python3")) {
    try {
      $p = Get-Command $cmd -ErrorAction Stop
      if ($cmd -eq "py") {
        & $p.Source -3 -c "import sys; print(sys.version)" | Out-Null
        if ($LASTEXITCODE -eq 0) { return @{ Exe = $p.Source; Args = @("-3") } }
      } else {
        & $p.Source -c "import sys; print(sys.version)" | Out-Null
        if ($LASTEXITCODE -eq 0) { return @{ Exe = $p.Source; Args = @() } }
      }
    } catch { }
  }
  return $null
}

$pyInfo = Find-Python
if (-not $pyInfo) {
  Write-Host "Python 3 was not found."
  Write-Host "Install from https://www.python.org/downloads/ (check 'Add python.exe to PATH'), then re-run this script."
  exit 1
}

$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$venvPip = Join-Path $PSScriptRoot ".venv\Scripts\pip.exe"

if ($ForceReinstall -and (Test-Path (Join-Path $PSScriptRoot ".venv"))) {
  Write-Host "Removing existing .venv (-ForceReinstall)..."
  Remove-Item -Recurse -Force (Join-Path $PSScriptRoot ".venv")
}

if (-not (Test-Path $venvPy)) {
  Write-Host "Creating virtual environment (.venv)..."
  & $pyInfo.Exe @($pyInfo.Args + @("-m", "venv", ".venv"))
  if (-not (Test-Path $venvPy)) {
    Write-Error "Failed to create .venv. Is Python installed correctly?"
  }
}

Write-Host "Installing dependencies (requirements.txt)..."
& $venvPip install --upgrade pip | Out-Null
& $venvPip install -r (Join-Path $PSScriptRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) {
  Write-Error "pip install failed."
}

$envFile = Join-Path $PSScriptRoot ".env"
$envExample = Join-Path $PSScriptRoot ".env.example"
if (-not (Test-Path $envFile)) {
  if (Test-Path $envExample) {
    Copy-Item $envExample $envFile
    # Generate a random SECRET_KEY for this machine
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    $raw = Get-Content -LiteralPath $envFile -Raw
    $raw = $raw -replace "SECRET_KEY=change-me-to-a-long-random-string", "SECRET_KEY=$secret"
    Set-Content -LiteralPath $envFile -Value $raw -NoNewline
    Write-Host "Created .env from .env.example (new SECRET_KEY). Edit .env for Wazuh/mail if needed."
  } else {
    Write-Host "WARNING: No .env or .env.example found. Create .env before using auth/mail/Wazuh."
  }
} else {
  Write-Host "Using existing .env"
}

New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "data") -Force | Out-Null

Write-Host ""
Write-Host "Install complete."
Write-Host "Docs: docs\STANDALONE.md"
Write-Host ""

if ($NoStart) {
  Write-Host "Skipping start (-NoStart). Run .\start_dashboard.bat when ready."
  exit 0
}

Write-Host "Starting dashboard at http://127.0.0.1:5000"
Write-Host "Keep this window open. Ctrl+C to stop."
Write-Host ""
# Open browser shortly after start
Start-Process "http://127.0.0.1:5000/login"
& $venvPy (Join-Path $PSScriptRoot "dashboard.py")
