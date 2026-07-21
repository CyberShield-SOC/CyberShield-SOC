$ErrorActionPreference = "Stop"

$backendRoot = Join-Path $PSScriptRoot "backend"
$frontendRoot = Join-Path $PSScriptRoot "frontend"
$envPath = Join-Path $PSScriptRoot ".env"
$pythonExe = Join-Path $backendRoot ".venv\Scripts\python.exe"
$npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
$backendHealthUrl = "http://127.0.0.1:3000/health"
$frontendUrl = "https://127.0.0.1:5173/"
$frontendPort = 5173

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

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port
    )

    # Vite serves HTTPS with a self-signed local certificate. Windows
    # PowerShell 5.1's Invoke-WebRequest uses the legacy .NET Framework
    # HttpWebRequest stack, which can fail TLS renegotiation against
    # Node's HTTPS server even when certificate validation is bypassed.
    # A plain TCP connect is enough to know the dev server is listening.
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $connected = $async.AsyncWaitHandle.WaitOne(1000) -and $client.Connected
        $client.Close()
        return $connected
    }
    catch {
        return $false
    }
}

function Wait-ForTcpPort {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-TcpPort -ComputerName $ComputerName -Port $Port) {
            Write-Host "$Name is ready." -ForegroundColor Green
            return
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "$Name did not become ready within $TimeoutSeconds seconds. Check its .err.log file."
}

function Test-DockerEngine {
    param([Parameter(Mandatory)][string]$DockerExe)

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & $DockerExe info *> $null
        return $LASTEXITCODE -eq 0
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Start-DockerDesktop {
    param([Parameter(Mandatory)][string]$DockerExe)

    if (Test-DockerEngine -DockerExe $DockerExe) {
        Write-Host "Docker engine is already running." -ForegroundColor Green
        return
    }

    $dockerDesktopExe = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path -LiteralPath $dockerDesktopExe)) {
        throw "Docker engine is not running and Docker Desktop.exe was not found at '$dockerDesktopExe'. Start Docker Desktop manually and re-run this script."
    }

    Write-Host "Starting Docker Desktop..." -ForegroundColor Cyan
    Start-Process -FilePath $dockerDesktopExe | Out-Null

    $timeoutSeconds = 120
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    do {
        if (Test-DockerEngine -DockerExe $DockerExe) {
            Write-Host "Docker engine is ready." -ForegroundColor Green
            return
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "Docker engine did not become ready within $timeoutSeconds seconds. Open Docker Desktop and check its status."
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
    Start-DockerDesktop -DockerExe $dockerExe

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
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "3000", "--reload") `
        -WorkingDirectory $backendRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $backendRoot "uvicorn.out.log") `
        -RedirectStandardError (Join-Path $backendRoot "uvicorn.err.log")

    Wait-ForService -Name "FastAPI" -Uri $backendHealthUrl
}

if (Test-TcpPort -ComputerName "127.0.0.1" -Port $frontendPort) {
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

    Wait-ForTcpPort -Name "Vite" -ComputerName "127.0.0.1" -Port $frontendPort
}

Write-Host "CyberShield SOC is ready at $frontendUrl" -ForegroundColor Green
Start-Process -FilePath $frontendUrl
