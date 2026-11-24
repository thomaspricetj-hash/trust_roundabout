# Trust Roundabout - Windows Installer
# Run as Administrator
param(
    [string]$InstallDir = "C:\Program Files\TrustRoundabout"
)

Write-Host "Installing Trust Roundabout..." -ForegroundColor Green

# Check Rust
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust not found. Installing via rustup..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile $env:TEMP\rustup-init.exe
    Start-Process -FilePath $env:TEMP\rustup-init.exe -ArgumentList "-y" -Wait
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Recurse -Force ".\*" $InstallDir

Set-Location $InstallDir
cargo build --release

# Create Windows Service using NSSM or simple scheduled task
$serviceName = "TrustRoundabout"
$exePath = Join-Path $InstallDir "target\release\trust_roundabout.exe"
$configPath = Join-Path $InstallDir "config.toml"

# Create a scheduled task for auto-start
$action = New-ScheduledTaskAction -Execute $exePath -Argument "`"$configPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $serviceName -Action $action -Trigger $trigger -RunLevel Highest -Force

Write-Host "Installation complete. Service '$serviceName' created." -ForegroundColor Green
Write-Host "Edit $configPath to configure firewall and simulation." -ForegroundColor Cyan
