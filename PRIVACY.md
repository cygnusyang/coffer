# Privacy Policy

**中文摘要**：Coffer 不收集任何数据。没有账号、没有遥测、没有云同步、没有第三方 SDK。你的密码库只存在于你的 Mac 上，用你的主密码加密。**唯一**的网络访问是你在点「检查更新」时向 GitHub 的 4 个固定域名发一个 HTTP 请求。你可以用系统工具自行验证这些说法（见 §8）。

**TL;DR (English)** — Coffer collects nothing: no account, no telemetry, no analytics, no cloud sync, no third-party SDKs. Your vault exists only on your Mac, encrypted with your master password. The **only** network access happens when *you* click "Check for Updates", and it goes to four fixed GitHub hosts. §8 explains how to verify every claim below yourself.

---

## 1. What we do not do

| Not done | Detail |
| --- | --- |
| No account | There is no sign-up, no email, no user ID anywhere in the product |
| No telemetry | No analytics SDK, no crash reporter, no usage counters, no "anonymous" beacons |
| No cloud sync | The vault is a local file; Coffer never uploads it |
| No ads, no tracking | Nothing to opt out of, because nothing is collected |
| No third-party network SDKs | The app links no ad/analytics/font/CDN frameworks |

## 2. What stays on your Mac

| Data | Where | Protection |
| --- | --- |
| Vault (items, TOTP secrets, passkey metadata) | `~/Library/Containers/top.cygnusyang.coffer/Data/Documents/Coffer/<vault-uuid>/` | Argon2id-derived key + AEAD; master password never stored |
| Diagnostics log | `~/Library/Containers/top.cygnusyang.coffer/Data/Library/Logs/Coffer-diag.log` | Local text; **never uploaded automatically** |
| Clipboard | macOS pasteboard, only when you copy a field | Optional auto-clear after a timeout you set |
| Preferences | `UserDefaults` in the app container | Language, lock timeout, etc. |

Nothing here leaves the machine unless **you** export or copy it.

## 3. The only network access: update checks

Coffer performs a network request **only when you explicitly ask it to check for updates**. There is no background polling.

| Item | Value |
| --- | --- |
| Hosts (allow-listed) | `api.github.com`, `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` |
| What is sent | A standard HTTPS GET for `…/releases/latest/download/update-manifest.json`, plus the default HTTP headers of the system URL session (e.g. `User-Agent`). **No vault data, no identifiers, no version fingerprint beyond the request path.** |
| What is received | Signed manifest (Ed25519) + download URLs; the manifest signature is verified against a public key embedded in the app before anything is trusted |
| Downloads | `Coffer-vX.Y.Z.zip` from the same allow-list; SHA-256 is checked against the signed manifest |

If the update check fails, the app keeps working offline — it simply reports the error.

## 4. AI tools / MCP integration (opt-in)

- The MCP server speaks **stdio** or a **Unix domain socket** (`$COFFER_MCP_UDS`) — never TCP, never a public port.
- Tools are **read-only by default**: an AI client can list item names/metadata and, if you approve, run a command with a secret injected into that subprocess's environment.
- Secret values are never returned to the model context; there is no tool that prints a password.
- Registration with Claude Code / CodeBuddy / Codex writes a local config file; nothing is sent to us.
- If you never enable it, no MCP process runs.

## 5. Diagnostics

- Logs are written locally and **rotated on disk**. They never leave the machine on their own.
- If you file a bug, you may attach the relevant log manually — **review it first**; logs deliberately never contain password values (design rule R2), but they do contain timestamps, error codes and file paths.
- There is no automatic crash reporting. If the app crashes, macOS may create a crash report in `~/Library/Logs/DiagnosticReports/` — that file is yours, and is only shared if you choose to.

## 6. Deleting your data

| Action | Effect |
| --- | --- |
| Delete an item | Moves to Trash inside the vault; can be restored or permanently deleted |
| Delete a vault | Removes the vault directory; **unrecoverable** without an encrypted backup |
| Delete the app | Removes the binary; the vault directory stays unless you remove it |
| Full removal | Delete the app **and** `~/Library/Containers/top.cygnusyang.coffer/` |

## 7. Children / legal

Coffer collects no personal data at all, so it collects nothing from minors either. It is a local utility, not a service; there is no account relationship and no data processing agreement to enter into.

## 8. Verify these claims yourself

Trust should not require believing a markdown file:

1. **Entitlements** — the built app declares App Sandbox plus exactly one network entitlement:
   ```bash
   codesign -d --entitlements - /Applications/Coffer.app
   ```
   You should see `com.apple.security.app-sandbox` and `com.apple.security.network.client`, and no other `network.*` key.
2. **Watch the traffic** — run the app under Little Snitch / LuLu / `nettop`, or simply disconnect from the network: everything except the update check keeps working.
3. **Read the source** — network code is isolated in the updater: `macos/Coffer/Updater/`. Grep for `URLSession` to enumerate every call site.
4. **Check the logs** — `~/Library/Containers/top.cygnusyang.coffer/Data/Library/Logs/Coffer-diag.log` is plain text; read it.

## 9. Changes to this policy

Any change to data handling will be recorded in `CHANGELOG.md` and in this file's git history. Because Coffer has no server side, there is no way for us to change what happens to your data without shipping a new app version — and every version is a signed, inspectable artifact.

## 10. Contact

- Security issues: see [`SECURITY.md`](SECURITY.md) (private channel).
- Everything else: [GitHub Issues](https://github.com/cygnusyang/coffer/issues).

---

*Last updated: 2026-10-25 · applies to Coffer v2.13.x*
