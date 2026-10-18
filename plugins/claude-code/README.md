# Coffer for Claude Code

[Claude Code plugin](https://code.claude.com/docs/en/plugins/overview) that wires your local
[`coffer`](https://github.com/cygnusyang/coffer) secrets gateway into Claude — with **zero per-user
configuration** and the rule *use secrets, never read them*.

- **MCP server**: coffer's stdio server (`list_secret_names` / `list_secrets` /
  `run_with_secret` / `get_secret_metadata`) is declared by the plugin and auto-started by Claude.
- **Zero-config discovery**: a launcher script resolves the App-signed coffer binary and your vault
  directory at connect time — you don't fill in paths or vault UUIDs after installing.
- **Skills**: `coffer-credentials` (how to use secrets via `run_with_secret` env injection, without
  leaking values into context) and `coffer-setup` (diagnose/repair the connection).
- **Login helper**: `coffer-login` on the Bash tool's PATH — a browser-login driver that reads the
  password from an env var injected by `run_with_secret`, so the password never enters Claude's
  context.

Secrets only ever reach a subprocess through its environment; no tool returns a secret value.

## Prerequisites

1. **macOS** with the **Coffer app** installed in `/Applications` (the MCP server must run from the
   app-signed binary — a bare binary fails signature/Keychain checks).
2. Unlock the Coffer app **once** on this machine so the Keychain escrow exists (Settings → MCP /
   Agent 协作 → 启用「MCP 解锁托管」). This is per-machine; redo on every new Mac.
3. *(Only for browser logins via `coffer-login`)*: `npm i -g playwright && npx playwright install chromium`.

## Install

```bash
claude plugin marketplace add cygnusyang/coffer
claude plugin install coffer@coffer
```

That's it. When enabled, `claude mcp list` shows `coffer: … - ✔ Connected` and the `mcp__coffer__*`
tools are available in every session.

Optional overrides (usually unnecessary — auto-detection handles it): set `COFFER_VAULT_DIR` or
`COFFER_BIN` in your environment to pin a specific vault or binary.

## What you get

| Piece | Purpose |
|---|---|
| `mcpServers.coffer` | Stdio MCP server via `scripts/coffer-launch.sh` (auto-detect binary + vault, then `exec coffer mcp --provider coffer`) |
| `skills/coffer-credentials` | Patterns for `run_with_secret`, browser login, and when to ask the user |
| `skills/coffer-setup` | First-run / repair checklist when the connection is missing or failing |
| `bin/coffer-login` | Browser-login driver (password via env, persistent profile, `--smoke` mode) |
| `bin/coffer-setup` | Fallback: register a standalone user-scope `coffer` server (`claude mcp add`) |

## Security model (read this)

- **The plugin's MCP server process is started automatically by Claude Code, outside the sandbox,
  and is not permission-prompted** (this is how all Claude Code plugin MCP servers work). In this
  case the process is your own local coffer daemon: it serves only read operations and `run_with_secret`
  only ever injects a secret into a command you/Claude explicitly asked to run. It never returns
  secret values over the protocol.
- Claude's **tool calls** to the coffer MCP (`run_with_secret`, `list_*`) still pass through the
  normal permission rules.
- `bin/` commands run through Claude's Bash tool, so they are permission-prompted like any shell
  command.
- The login helper never writes the password to stdout/stderr/logs and never takes it as argv.

Review [Claude Code's plugin security docs](https://code.claude.com/docs/en/plugins/security.md)
before installing any plugin.

## Usage example

```text
# Find a secret
mcp__coffer__list_secret_names {}

# Run a command with the secret injected as env (value never returned)
mcp__coffer__run_with_secret {
  secret: "example-site",
  cmd: "node",
  args: ["coffer-login", "--url", "https://example.com/login", "--email", "me@example.com", "--password-env", "PASSWORD"],
  env_name: "PASSWORD"
}
```

If a secret isn't in coffer, ask the user where it is — never guess values.

## Development

```bash
git clone https://github.com/cygnusyang/coffer
cd coffer
claude plugin validate --strict plugins/claude-code   # authoritative gate before release
```

Layout (paths relative to `plugins/claude-code/`; the marketplace manifest lives at the
repo root, `.claude-plugin/marketplace.json`):

```
.claude-plugin/
  plugin.json        # manifest: mcpServers → scripts/coffer-launch.sh
bin/                 # placed on the Bash tool PATH while enabled
  coffer-login       # → scripts/coffer-login.mjs
  coffer-setup       # → scripts/coffer-mcp-setup.sh
scripts/
  coffer-launch.sh   # MCP launcher: resolve binary+vault, exec coffer
  coffer-mcp-setup.sh# standalone registration fallback
  coffer-login.mjs   # env-injected browser login driver
skills/
  coffer-credentials/SKILL.md
  coffer-setup/SKILL.md
```

## License

AGPL-3.0, as part of the coffer repository — this plugin is distributed with the main
project under its root [LICENSE](../../../LICENSE) and does not carry a separate license.
