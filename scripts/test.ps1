$ErrorActionPreference = "Stop"

param(
  [switch]$Race
)

$modules = @("server", "client")

foreach ($m in $modules) {
  Write-Host "==> $m: go test ./..." -ForegroundColor Cyan
  Push-Location $m
  try {
    if ($Race) {
      $cc = $env:CC
      if ([string]::IsNullOrWhiteSpace($cc)) {
        $cc = (go env CC)
      }
      $hasCC = $false
      try {
        $null = Get-Command $cc -ErrorAction Stop
        $hasCC = $true
      } catch {
        $hasCC = $false
      }

      if (-not $hasCC) {
        Write-Warning "-race requested but C compiler '$cc' not found; running without -race"
        go test ./...
      } else {
        $oldCgo = $env:CGO_ENABLED
        $env:CGO_ENABLED = "1"
        try {
          go test -race ./...
        } finally {
          $env:CGO_ENABLED = $oldCgo
        }
      }
    } else {
      go test ./...
    }
  } finally {
    Pop-Location
  }
}
