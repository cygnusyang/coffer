#!/usr/bin/env sh
# coffer-launch.sh — zero-config launcher for the coffer MCP server.
#
# A Claude Code plugin declares its MCP server statically in plugin.json, but
# coffer needs a per-machine COFFER_VAULT_DIR (fail-closed if missing) and must
# run from the App-signed binary. This wrapper resolves both at connect time so
# the plugin works with zero per-user config once the Coffer app is installed
# and unlocked once on that machine.
#
# Resolution order:
#   binary:  $COFFER_BIN → App helper under /Applications → coffer on PATH (warn)
#   vault:   $COFFER_VAULT_DIR → newest vault dir under the app container
#
# Any extra argv is forwarded to `coffer mcp` unchanged.

set -eu

# --- 1. locate the coffer binary -------------------------------------------
if [ -n "${COFFER_BIN:-}" ]; then
  BIN="$COFFER_BIN"
elif [ -x /Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer ]; then
  BIN=/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer
elif command -v coffer >/dev/null 2>&1; then
  BIN="$(command -v coffer)"
  echo "[coffer-launch] warning: using bare 'coffer' on PATH — signature/Keychain escrow may fail; prefer the Coffer app" >&2
else
  echo "[coffer-launch] coffer binary not found. Install the Coffer app, or set COFFER_BIN." >&2
  exit 1
fi

# --- 2. resolve the vault -----------------------------------------------------
if [ -z "${COFFER_VAULT_DIR:-}" ]; then
  CONTAINER="$HOME/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer"
  VAULT="$(ls -dt "$CONTAINER"/*/ 2>/dev/null | head -n 1)"
  if [ -z "$VAULT" ]; then
    echo "[coffer-launch] no vault found under $CONTAINER. Unlock the Coffer app once on this machine, or set COFFER_VAULT_DIR." >&2
    exit 1
  fi
  export COFFER_VAULT_DIR="${VAULT%/}"
fi

exec "$BIN" mcp --provider coffer "$@"
