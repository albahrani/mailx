param(
  [switch]$Wait
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$serverDir = Join-Path $Root 'server'
$serverExe = Join-Path $serverDir (Join-Path 'bin' 'mailx-server.exe')

if (-not (Test-Path $serverExe)) {
  throw "Server binary not found: $serverExe`nBuild it first: cd server; go build -o bin\\mailx-server.exe cmd\\server\\main.go"
}

Write-Host "=== MailX Integration Test (Windows/PowerShell) ==="
Write-Host

$temp = $env:TEMP
$cfg1 = Join-Path $temp 'mailx-test-server-1.json'
$cfg2 = Join-Path $temp 'mailx-test-server-2.json'
$log1 = Join-Path $temp 'mailx-test-server-1.log'
$log2 = Join-Path $temp 'mailx-test-server-2.log'

$cfgObj1 = @{
  domain         = 'server1.local'
  grpcPort       = '19443'
  httpPort       = '19080'
  databasePath   = (Join-Path $temp 'mailx-test-server1.db')
  serverKeyFile  = (Join-Path $temp 'mailx-test-server1-key.json')
  maxMessageSize = 26214400
  defaultQuota   = 10737418240
} | ConvertTo-Json -Depth 4

$cfgObj2 = @{
  domain         = 'server2.local'
  grpcPort       = '19543'
  httpPort       = '19180'
  databasePath   = (Join-Path $temp 'mailx-test-server2.db')
  serverKeyFile  = (Join-Path $temp 'mailx-test-server2-key.json')
  maxMessageSize = 26214400
  defaultQuota   = 10737418240
} | ConvertTo-Json -Depth 4

[System.IO.File]::WriteAllText($cfg1, $cfgObj1, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($cfg2, $cfgObj2, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "1. Starting test servers..."
$p1 = Start-Process -FilePath $serverExe -ArgumentList @($cfg1) -NoNewWindow -PassThru -RedirectStandardOutput $log1 -RedirectStandardError ($log1 + '.err')
$p2 = Start-Process -FilePath $serverExe -ArgumentList @($cfg2) -NoNewWindow -PassThru -RedirectStandardOutput $log2 -RedirectStandardError ($log2 + '.err')

try {
  Write-Host "   Waiting for servers to start..."
  Start-Sleep -Seconds 3

  Write-Host
  Write-Host "2. Checking server endpoints..."
  Invoke-WebRequest -Uri 'http://127.0.0.1:19080/.well-known/mailx-server' -TimeoutSec 3 -UseBasicParsing | Out-Null
  Write-Host "   [OK] Server 1 well-known responding"
  Invoke-WebRequest -Uri 'http://127.0.0.1:19180/.well-known/mailx-server' -TimeoutSec 3 -UseBasicParsing | Out-Null
  Write-Host "   [OK] Server 2 well-known responding"

  Write-Host
  Write-Host "=== Test Summary ==="
  Write-Host "[OK] Server 1 started on ports 19443 (gRPC) and 19080 (HTTP)"
  Write-Host "[OK] Server 2 started on ports 19543 (gRPC) and 19180 (HTTP)"
  Write-Host
  Write-Host "Logs:"
  Write-Host "  $log1"
  Write-Host "  $log2"
  Write-Host
  if ($Wait) {
    Write-Host "Servers are running in background (PIDs: $($p1.Id), $($p2.Id))"
  Write-Host "Press Enter to stop servers and cleanup."
  [void](Read-Host)
  } else {
    Write-Host "Stopping servers and cleaning up (pass -Wait to keep them running)."
  }
} finally {
  foreach ($p in @($p1, $p2)) {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  }
  Remove-Item -Force -ErrorAction SilentlyContinue $cfg1, $cfg2
}
