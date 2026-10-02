$ErrorActionPreference = "Stop"

$frontendRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $frontendRoot
$nodeRoot = Join-Path $repoRoot ".tools\node\node-v24.18.1-win-x64"
$nodeExe = Join-Path $nodeRoot "node.exe"
$viteScript = Join-Path $frontendRoot "node_modules\vite\bin\vite.js"

if (-not (Test-Path -LiteralPath $nodeExe)) {
    throw "Portable Node.js is missing at $nodeExe"
}

if (-not (Test-Path -LiteralPath $viteScript)) {
    throw "Frontend dependencies are missing. Run npm ci from frontend first."
}

$env:PATH = "$nodeRoot;$env:PATH"
$env:VITE_DEV_HTTPS = "false"
Set-Location $frontendRoot
Write-Host "Starting Vite at http://127.0.0.1:5173/"
& $nodeExe $viteScript --host 127.0.0.1 --port 5173 --strictPort
