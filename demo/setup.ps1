$ErrorActionPreference = 'Stop'

function Get-ComposeInvocation {
  $docker = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $docker) {
    throw 'docker is not installed. Install Docker Desktop and enable Docker Compose.'
  }

  try {
    & docker compose version *> $null
    return @('docker', 'compose')
  } catch {
    $dc = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dc) { return @('docker-compose') }
  }

  throw 'Docker Compose not found. Ensure Docker Desktop is installed and WSL2 integration (if used) is enabled.'
}

$compose = Get-ComposeInvocation

function Invoke-Compose {
  param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
  )

  if ($compose.Count -eq 1) {
    & $compose[0] @Args
    return
  }

  $prefix = @($compose[0]) + @($compose[1])
  & $prefix[0] $prefix[1] @Args
}

Write-Host "=== MailX Demo Setup (Windows/PowerShell) ==="
Write-Host

Push-Location $PSScriptRoot
try {

Write-Host "1. Cleaning up old containers and data..."
try {
  Invoke-Compose down -v | Out-Null
} catch {
  # ignore (e.g. first run)
}

$dataRoot = Join-Path $PSScriptRoot 'data'
if (Test-Path $dataRoot) {
  Remove-Item -Recurse -Force $dataRoot
}

New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'server-a') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'server-b') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'server-c') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot 'client') | Out-Null

Write-Host
Write-Host "1b. Ensuring demo TLS certificate exists..."
$tlsCrt = Join-Path $PSScriptRoot 'config\tls.crt'
$tlsKey = Join-Path $PSScriptRoot 'config\tls.key'
if (!(Test-Path $tlsCrt) -or !(Test-Path $tlsKey)) {
  $openssl = Get-Command openssl -ErrorAction SilentlyContinue
  if ($openssl) {
    Write-Host "Generating self-signed TLS cert (config/tls.crt, config/tls.key)"
    $env:MSYS_NO_PATHCONV = '1'
    & $openssl.Path req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes `
      -keyout "config/tls.key" -out "config/tls.crt" `
      -subj "/CN=mailx-demo" `
      -addext "subjectAltName=DNS:server-a.local,DNS:server-b.local,DNS:server-c.local,DNS:alice.local,DNS:bob.local,DNS:carol.local,DNS:localhost,IP:127.0.0.1" | Out-Null
  } else {
    Write-Warning "openssl not found; demo will run without TLS"
  }
}

Write-Host
Write-Host "2. Building Docker images..."
Invoke-Compose build

Write-Host
Write-Host "3. Starting servers..."
Invoke-Compose up -d server-a server-b server-c

Write-Host
Write-Host "4. Waiting for servers to start..."
Start-Sleep -Seconds 5

Write-Host
Write-Host "5. Checking server status..."
Write-Host "Server A (alice.local): http://localhost:8080/.well-known/mailx-server"
Write-Host "Server B (bob.local):   http://localhost:8180/.well-known/mailx-server"
Write-Host "Server C (carol.local): http://localhost:8280/.well-known/mailx-server"

Write-Host
Write-Host "=== Setup Complete ==="
Write-Host
Write-Host "Servers are running:"
Write-Host "  - Server A (alice.local): gRPC on localhost:8443"
Write-Host "  - Server B (bob.local):   gRPC on localhost:8543"
Write-Host "  - Server C (carol.local): gRPC on localhost:8643"
Write-Host
Write-Host "To access interactive client:"
Write-Host "  $($compose -join ' ') run --rm client alice_config.json"
Write-Host "    (Note: run this from PowerShell, not Git Bash, to avoid /path rewriting)"
Write-Host
Write-Host "To stop servers:"
Write-Host "  $($compose -join ' ') down"

} finally {
  Pop-Location
}
