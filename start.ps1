$ErrorActionPreference = "Stop"

$backendRoot = Join-Path $PSScriptRoot "backend"
$frontendRoot = Join-Path $PSScriptRoot "frontend"
$envPath = Join-Path $PSScriptRoot ".env"
$pythonExe = Join-Path $backendRoot ".venv\Scripts\python.exe"
$npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
$backendHealthUrl = "http://127.0.0.1:3000/health"
$frontendUrl = "http://127.0.0.1:5173/"

function Test-ServiceEndpoint {
    param([Parameter(Mandatory)][string]$Uri)

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 400
    }
    catch {
        return $false
    }
}

function Wait-ForService {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-ServiceEndpoint -Uri $Uri) {
            Write-Host "$Name is ready." -ForegroundColor Green
            return
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "$Name did not become ready within $TimeoutSeconds seconds. Check its .err.log file."
}

if (-not (Test-Path -LiteralPath $envPath)) {
    throw "Local configuration is missing. Copy .env.example to .env and replace every replace_me value."
}

if ((Get-Content -LiteralPath $envPath -Raw) -match "(?m)^[A-Z0-9_]+=replace_me") {
    throw "The .env file still contains replace_me placeholders. Set local database and Admin credentials first."
}

if (-not (Test-Path -LiteralPath $pythonExe)) {
    throw "Backend environment is missing. Follow the one-time setup in README.md."
}

if (-not (Test-Path -LiteralPath (Join-Path $frontendRoot "node_modules"))) {
    throw "Frontend dependencies are missing. Run npm.cmd install from frontend/."
}

if (Test-ServiceEndpoint -Uri $backendHealthUrl) {
    Write-Host "FastAPI is already running." -ForegroundColor Green
}
else {
    $dockerExe = (Get-Command docker -ErrorAction Stop).Source

    Write-Host "Starting PostgreSQL..." -ForegroundColor Cyan
    & $dockerExe compose --project-directory $PSScriptRoot up -d --wait database
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL did not start successfully." }

    Push-Location $backendRoot
    try {
        Write-Host "Applying database migrations..." -ForegroundColor Cyan
        & $pythonExe -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) { throw "Database migrations failed." }

        Write-Host "Ensuring roles and the initial Admin exist..." -ForegroundColor Cyan
        & $pythonExe -m app.db.seed
        if ($LASTEXITCODE -ne 0) { throw "Database seed failed." }
    }
    finally {
        Pop-Location
    }

    Start-Process `
        -FilePath $pythonExe `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "3000") `
        -WorkingDirectory $backendRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $backendRoot "uvicorn.out.log") `
        -RedirectStandardError (Join-Path $backendRoot "uvicorn.err.log")

    Wait-ForService -Name "FastAPI" -Uri $backendHealthUrl
}

if (Test-ServiceEndpoint -Uri $frontendUrl) {
    Write-Host "Vite is already running." -ForegroundColor Green
}
else {
    Start-Process `
        -FilePath $npmExe `
        -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1") `
        -WorkingDirectory $frontendRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $frontendRoot "vite.out.log") `
        -RedirectStandardError (Join-Path $frontendRoot "vite.err.log")

    Wait-ForService -Name "Vite" -Uri $frontendUrl
}

Write-Host "CyberShield SOC is ready at $frontendUrl" -ForegroundColor Green
Start-Process -FilePath $frontendUrl
