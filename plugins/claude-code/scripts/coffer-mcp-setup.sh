#!/usr/bin/env sh
# coffer-mcp-setup.sh — register the coffer MCP server for Claude Code on THIS machine.
#
# The coffer MCP registration is user-scoped and machine-specific (it bakes in
# the coffer binary path and the vault directory), so it must be re-run on every
# new Mac / new user. This script auto-detects everything that varies:
#
#   - the Coffer App helper binary (the ONLY binary that unlocks via Keychain)
#   - the vault directory under the Coffer app container
#
# and then runs `claude mcp add coffer --scope user`.
#
# One-time use on a new machine:
#   sh plugins/claude-code/scripts/coffer-mcp-setup.sh   # from the coffer repo root
#   coffer-setup                                          # PATH shim while the plugin is enabled
#
# Overrides (set as env before running):
#   COFFER_BIN         path to a coffer binary (default: the App helper under /Applications)
#   COFFER_VAULT_DIR   path to a vault directory (default: newest vault in the app container)
#
# Per-machine prerequisites:
#   1. The Coffer app installed (or COFFER_BIN pointing at a working binary).
#   2. The vault unlocked ONCE via the Coffer app — Keychain escrow is per
#      machine + per user; until then the MCP cannot unlock without a password.
#   3. For the browser-login script only: `npm i -g playwright` + `npx playwright install chromium`.

set -eu

# --- 1. locate the coffer binary -------------------------------------------
if [ -n "${COFFER_BIN:-}" ]; then
  BIN="$COFFER_BIN"
elif [ -x /Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer ]; then
  BIN=/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer
else
  echo "✗ coffer binary not found. Install the Coffer app, or set COFFER_BIN." >&2
  exit 1
fi
echo "✓ coffer binary: $BIN"

# --- 2. locate the vault -----------------------------------------------------
CONTAINER="$HOME/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer"
if [ -n "${COFFER_VAULT_DIR:-}" ]; then
  VAULT="${COFFER_VAULT_DIR%/}"
else
  # Newest-modified vault wins when there are several.
  VAULT="$(ls -dt "$CONTAINER"/*/ 2>/dev/null | head -n 1)"
  if [ -z "$VAULT" ]; then
    echo "✗ no vault found under $CONTAINER." >&2
    echo "  Unlock the Coffer app once on this machine, or set COFFER_VAULT_DIR." >&2
    exit 1
  fi
  VAULT="${VAULT%/}"
fi
echo "✓ vault:        $VAULT"

# --- 3. register -------------------------------------------------------------
if ! command -v claude >/dev/null 2>&1; then
  echo "✗ claude CLI not found on PATH — is Claude Code installed?" >&2
  exit 1
fi

# Idempotent: `claude mcp add` errors out if the server already exists, so
# remove first when re-running on a machine that was already set up.
if claude mcp list 2>/dev/null | grep -q '^coffer:'; then
  echo "! coffer already registered — re-registering with the detected values."
  # 清除旧手动注册（主仓 README 的 `claude mcp add`）遗留的 local 作用域条目
  claude mcp remove coffer >/dev/null 2>&1 || true
  claude mcp remove coffer --scope user >/dev/null 2>&1 || true
fi

if ! claude mcp add coffer --scope user --env "COFFER_VAULT_DIR=$VAULT" -- "$BIN" mcp --provider coffer; then
  echo "✗ claude mcp add 失败——可能存在其他作用域的同名 coffer 条目，运行 claude mcp list 查看并手动清理后重试。" >&2
  exit 1
fi

echo
echo "✓ registered. Status:"
claude mcp list 2>&1 | grep '^coffer' || true
echo
echo "Note: Keychain escrow is per-machine — the MCP unlocks with no password only"
echo "after the Coffer app has been unlocked once on this machine."
