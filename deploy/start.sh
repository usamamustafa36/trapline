#!/usr/bin/env bash
# Start / restart the Trapline C2 stack (native nginx deploy).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT/deploy/deploy-native.sh"
