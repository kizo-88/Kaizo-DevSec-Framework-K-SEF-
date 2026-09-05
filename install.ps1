# ==============================================================================
# Kaizo DevSec Framework (K-SEF) - One-Line Global Installer for Windows
# Usage: irm https://raw.githubusercontent.com/kizo-88/Kaizo-DevSec-Framework-K-SEF-/main/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "🛡️ Installing Kaizo DevSec CLI (k-sef) on Windows..." -ForegroundColor Cyan

$InstallDir = "$env:USERPROFILE\.k-sef"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$CliFile = "$InstallDir\k-sef.js"
$CmdFile = "$InstallDir\k-sef.cmd"

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/kizo-88/Kaizo-DevSec-Framework-K-SEF-/main/bin/k-sef.js" -OutFile $CliFile

$CmdContent = "@echo off`r`nnode `"$CliFile`" %*"
Set-Content -Path $CmdFile -Value $CmdContent

# Add to User PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
    Write-Host "✔ Added $InstallDir to User PATH." -ForegroundColor Green
}

Write-Host "`n✅ Kaizo DevSec CLI installed successfully!" -ForegroundColor Green
Write-Host "👉 Open a new terminal and run: k-sef init (in any project directory)" -ForegroundColor Yellow
