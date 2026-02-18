#!/usr/bin/env bash
set -euo pipefail

modules=(server client)

mode="test"
if [[ "${1-}" == "-race" ]]; then
  mode="test-race"
fi

if [[ "${mode}" == "test-race" ]]; then
  cc="${CC:-$(go env CC 2>/dev/null || echo gcc)}"
  if ! command -v "${cc}" >/dev/null 2>&1; then
    echo "WARNING: -race requested but C compiler '${cc}' not found; running without -race" >&2
    mode="test"
  fi
fi

for m in "${modules[@]}"; do
  echo "==> ${m}: go ${mode#test-} ./..."
  (
    cd "${m}"
    if [[ "${mode}" == "test-race" ]]; then
      CGO_ENABLED=1 go test -race ./...
    else
      go test ./...
    fi
  )
done
