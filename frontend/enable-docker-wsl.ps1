$ErrorActionPreference = "Stop"

Write-Host "Enabling Windows Subsystem for Linux..." -ForegroundColor Cyan
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
if ($LASTEXITCODE -ne 0) { throw "WSL feature could not be enabled." }

Write-Host "Enabling Virtual Machine Platform..." -ForegroundColor Cyan
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
if ($LASTEXITCODE -ne 0) { throw "Virtual Machine Platform could not be enabled." }

Write-Host "`nWindows features are enabled. Restart Windows to finish Docker setup." -ForegroundColor Green
exit 0
