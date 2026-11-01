#!/usr/bin/env bash
# SherWatch Command Center launcher for Linux and macOS (counterpart of run.cmd).
# Starts the release build as root through sudo (byte counts and DNS capture need it) and logs to data/logs.
# Extra arguments are passed to the binary, e.g. ./run.sh --no-browser
set -euo pipefail
cd "$(dirname "$0")"

bin="target/release/sherwatch"
if [ ! -x "$bin" ]; then
  echo "Release binary not found. Building..."
  cargo build --release || { echo "Build failed. See docs/BUILDING.md"; exit 1; }
fi
mkdir -p data/logs

if [ "$(id -u)" -eq 0 ]; then
  exec "$bin" "$@"
fi
if command -v sudo >/dev/null 2>&1; then
  echo "Starting SherWatch with sudo (needed for per-process byte counts)."
  exec sudo --preserve-env=RUST_LOG "$bin" "$@"
fi
echo "sudo not available; starting without root (no byte counts)."
exec "$bin" "$@"
