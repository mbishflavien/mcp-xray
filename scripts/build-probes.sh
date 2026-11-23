#!/usr/bin/env bash
# Compiles every WASI probe under cmd/probes/ to internal/probes/bin/*.wasm.
# Run this after changing a probe's Go source; the compiled .wasm is
# committed and embedded into the mcp-xray binary via //go:embed.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p internal/probes/bin

for dir in cmd/probes/*/; do
  name="$(basename "$dir")"
  echo "building $name.wasm"
  GOOS=wasip1 GOARCH=wasm go build -o "internal/probes/bin/$name.wasm" "./cmd/probes/$name"
done
