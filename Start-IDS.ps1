# Campus Cyber Intelligence Platform - PowerShell Startup
# Run this script as Administrator for packet capture

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CAMPUS CYBER INTELLIGENCE PLATFORM" -ForegroundColor White
Write-Host "  Adaptive Intrusion Detection System" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator!" -ForegroundColor Yellow
    Write-Host "Packet capture may not work. Run PowerShell as Admin." -ForegroundColor Yellow
    Write-Host ""
}

Set-Location "$PSScriptRoot\backend"
python start_ids.py
