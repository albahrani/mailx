$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSCommandPath

function Write-Step([string]$Message) {
  Write-Host $Message
}

function Write-Ok([string]$Message) {
  Write-Host ("  [OK]  {0}" -f $Message)
}

function Write-Warn([string]$Message) {
  Write-Host ("  [WARN] {0}" -f $Message)
}

function Write-Fail([string]$Message) {
  Write-Host ("  [FAIL] {0}" -f $Message)
}

function Require-Command([string]$Name, [string]$InstallHint) {
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Write-Fail "$Name is not installed"
    Write-Host "  Hint: $InstallHint"
    exit 1
  }
  return $cmd
}

function Wait-HttpOk([string]$Uri, [int]$TimeoutSeconds) {
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-WebRequest -Uri $Uri -Method GET -TimeoutSec 3 -UseBasicParsing | Out-Null
      return $true
    } catch {
      Start-Sleep -Milliseconds 300
    }
  }
  return $false
}

Write-Host "=== MailX Build Verification (Windows/PowerShell) ==="
Write-Host

Write-Step "1. Checking Go installation..."
Require-Command -Name 'go' -InstallHint 'Install Go 1.21+ from https://go.dev/dl/' | Out-Null
Write-Ok (go version)

Write-Host
Write-Step "2. Checking Protocol Buffers compiler..."
$protoc = Get-Command protoc -ErrorAction SilentlyContinue
if (-not $protoc) {
  Write-Warn 'protoc not found (optional for building, required for modifying .proto files)'
} else {
  Write-Ok (protoc --version)
}

Write-Host
Write-Step "3. Building server..."
$serverDir = Join-Path $Root 'server'
Push-Location $serverDir
try {
  New-Item -ItemType Directory -Force -Path 'bin' | Out-Null
  $serverMain = Join-Path (Join-Path 'cmd' 'server') 'main.go'
  go build -o (Join-Path 'bin' 'mailx-server.exe') $serverMain | Out-Null
  $serverExe = Join-Path $serverDir (Join-Path 'bin' 'mailx-server.exe')
  if (-not (Test-Path $serverExe)) { throw "Server binary not found: $serverExe" }
  $size = (Get-Item $serverExe).Length
  Write-Ok ("Server built successfully ({0:N0} bytes)" -f $size)
} finally {
  Pop-Location
}

Write-Host
Write-Step "4. Building client..."
$clientDir = Join-Path $Root 'client'
Push-Location $clientDir
try {
  New-Item -ItemType Directory -Force -Path 'bin' | Out-Null
  $clientMain = Join-Path (Join-Path 'cmd' 'client') 'main.go'
  go build -o (Join-Path 'bin' 'mailx-client.exe') $clientMain | Out-Null
  $clientExe = Join-Path $clientDir (Join-Path 'bin' 'mailx-client.exe')
  if (-not (Test-Path $clientExe)) { throw "Client binary not found: $clientExe" }
  $size = (Get-Item $clientExe).Length
  Write-Ok ("Client built successfully ({0:N0} bytes)" -f $size)
} finally {
  Pop-Location
}

Write-Host
Write-Step "5. Testing server startup..."
$temp = $env:TEMP
$cfgPath = Join-Path $temp 'mailx-verify-test-config.json'
$dbPath = Join-Path $temp 'mailx-verify-test.db'
$keyPath = Join-Path $temp 'mailx-verify-test-key.json'
$outLogPath = Join-Path $temp 'mailx-verify-test.out.log'
$errLogPath = Join-Path $temp 'mailx-verify-test.err.log'

$cfg = @{
  domain         = 'verify.test'
  grpcPort       = '28443'
  httpPort       = '28080'
  databasePath   = $dbPath
  serverKeyFile  = $keyPath
  maxMessageSize = 26214400
  defaultQuota   = 10737418240
} | ConvertTo-Json -Depth 4

[System.IO.File]::WriteAllText($cfgPath, $cfg, (New-Object System.Text.UTF8Encoding($false)))

$serverExe = Join-Path $serverDir (Join-Path 'bin' 'mailx-server.exe')

$proc = Start-Process -FilePath $serverExe -ArgumentList @($cfgPath) -NoNewWindow -PassThru -RedirectStandardOutput $outLogPath -RedirectStandardError $errLogPath
try {
  Start-Sleep -Seconds 2
  $ok = Wait-HttpOk -Uri 'http://127.0.0.1:28080/.well-known/mailx-server' -TimeoutSeconds 10
  if ($ok) {
    Write-Ok 'Server started and responding'
  } else {
    Write-Fail 'Server not responding'
    if ((Test-Path $outLogPath) -or (Test-Path $errLogPath)) {
      Write-Host '--- server log ---'
      if (Test-Path $outLogPath) {
        Get-Content -Path $outLogPath -ErrorAction SilentlyContinue | Select-Object -Last 200
      }
      if (Test-Path $errLogPath) {
        Get-Content -Path $errLogPath -ErrorAction SilentlyContinue | Select-Object -Last 200
      }
      Write-Host '------------------'
    }
    exit 1
  }
} finally {
  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -Force -ErrorAction SilentlyContinue $cfgPath, $dbPath, $keyPath, $outLogPath, $errLogPath
}

Write-Host
Write-Step "6. Checking documentation..."
$docs = @(
  (Join-Path $Root (Join-Path 'docs' 'PRD_Server.md')),
  (Join-Path $Root (Join-Path 'docs' 'PRD_Client.md')),
  (Join-Path $Root (Join-Path 'docs' 'Architecture.md')),
  (Join-Path $Root (Join-Path 'docs' 'ThreatModel.md')),
  (Join-Path $Root (Join-Path 'docs' 'Protocol.md')),
  (Join-Path $Root (Join-Path 'docs' 'Roadmap.md'))
)

$allOk = $true
foreach ($doc in $docs) {
  if (Test-Path $doc) {
    Write-Ok (Split-Path -Leaf $doc)
  } else {
    Write-Fail ("{0} missing" -f (Split-Path -Leaf $doc))
    $allOk = $false
  }
}
if (-not $allOk) { exit 1 }

Write-Host
Write-Step "7. Checking demo setup..."
if (Test-Path (Join-Path $Root (Join-Path 'demo' 'docker-compose.yml'))) {
  Write-Ok 'Docker Compose configuration'
} else {
  Write-Fail 'Docker Compose configuration missing'
  exit 1
}

if (Test-Path (Join-Path $Root (Join-Path 'demo' 'setup.sh'))) {
  Write-Ok 'Demo setup script (bash)'
} else {
  Write-Warn 'Demo setup script (bash) missing'
}

if (Test-Path (Join-Path $Root (Join-Path 'demo' 'setup.ps1'))) {
  Write-Ok 'Demo setup script (PowerShell)'
} else {
  Write-Warn 'Demo setup script (PowerShell) missing'
}

Write-Host
Write-Host "=== Build Verification Summary ==="
Write-Host "[OK] Go toolchain working"
Write-Host "[OK] Server builds and starts correctly"
Write-Host "[OK] Client builds successfully"
Write-Host "[OK] All documentation present"
Write-Host "[OK] Demo environment configured"
Write-Host
Write-Host "MailX is ready to use."
Write-Host
Write-Host "Next steps:"
Write-Host "  - Run the demo: cd demo; .\\setup.ps1"
Write-Host "  - Read the docs: see docs\\"
Write-Host "  - Quick start: see QUICKSTART.md"
