#!/usr/bin/env bash
# Workspace-local SDK/cache/config; no global home or platform SDK modifications.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export HOME="$ROOT/.local-cache/flutter-home"
export XDG_CONFIG_HOME="$ROOT/.local-cache/flutter-config"
export XDG_CACHE_HOME="$ROOT/.local-cache/flutter-cache"
export PUB_CACHE="$ROOT/.local-cache/pub"
export FLUTTER_ROOT="$ROOT/.toolchains/flutter-3.38.10"
export CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$PUB_CACHE"
if [[ "${1:-}" == dart ]]; then
  shift
  exec "$FLUTTER_ROOT/bin/dart" "$@"
fi
exec "$FLUTTER_ROOT/bin/flutter" "$@"
