# macos — the macOS app

**English** · [中文](README.zh.md)

**Status: v0.1 vertical slice delivered (T05 complete)** — create a vault / unlock / item CRUD / search / copy / auto-lock / CSV import all work end to end.

## One-command build

`bash
./tools/build_macos_app.sh          # output → macos/build/Coffer.app
open macos/build/Coffer.app         # launch
`

- Project layout: **swiftc + Info.plist straight into an .app bundle** (no xcodegen on the build machine; a hand-maintained pbxproj costs too much — see the script header). No Xcode project dependency; Xcode CLT is enough to reproduce.
- Prerequisite: the Rust static library and the Swift bindings are committed (`CoreBindings/`). If you changed the Rust FFI surface, run `tools/build_swift_bindings.sh` first (or pass `--rebuild-bindings` to the build script).
- Verifying the no-network promise (FR-14.5): `codesign -d --entitlements - macos/build/Coffer.app` — besides `app-sandbox` and `files.user-selected.read-write`, the output carries `device.camera` (FR-5.3 TOTP QR scanning, decision T09-A) and `keychain-access-groups` (escrow). The real list is `Coffer/Coffer.entitlements`; the core assertion remains **no** `com.apple.security.network.*` entry of any kind.

## Release flow (tag → CI builds, signs and creates the Release, v2.4.1+)

Every new tag (`v*`) triggers `.github/workflows/release.yml`: ubuntu reliability gate + clippy → macos-latest injects the signing certificate and provisioning profile from GitHub Secrets, runs `./tools/build_macos_app.sh --rebuild-bindings` to build the signed product → packages `Coffer-<tag>.zip` (the OTA payload; contract in `docs/03-功能设计/11-v2.7.0-OTA升级-设计.md` §6.1 — the app only accepts a zip overwrite) plus `./tools/make_dmg.sh` to package `Coffer-<tag>.dmg` (the human install, drag to Applications) → creates the GitHub Release automatically, with the body taken from **the current version section of `CHANGELOG.md`** (register the section before tagging, or the pipeline fails).

**One-time prerequisite** — export the local signing material into three secrets:

`bash
./tools/export_ci_secrets.sh --push   # exports cert+key p12 / profile as base64 and runs gh secret set
`

| Secret | Contents |
| --- | --- |
| `APPLE_CERT_P12_BASE64` | base64 of the Apple Development certificate + private key p12 |
| `APPLE_CERT_PASSWORD` | the export password for that p12 |
| `APPLE_PROVISIONING_PROFILE_BASE64` | base64 of `macos/build/app.coffer.Coffer.provisionprofile` |

**Per-release steps**:

1. Bump the version: edit `CFBundleShortVersionString` in `Coffer/Info.plist` (copied into the bundle since v2.4.1 and must match the tag — the `coffer-v241-settings-done-button` discipline);
2. Register the current version section in **`CHANGELOG.md`** (`## vX.Y.Z` heading + additions/fixes; the pipeline fails without it);
3. Run `./tools/run_gate.sh` locally (all green before tagging);
4. If the profile is close to its 7-day expiry, rerun `make_provisioning_profile.sh` + `export_ci_secrets.sh --push` (free-account profiles last 7 days; an expired one turns the pipeline red);
5. `git tag vX.Y.Z && git push origin vX.Y.Z`;
6. Watch GitHub Actions → collect `Coffer-<tag>.dmg` (manual install) and `Coffer-<tag>.zip` (OTA) from the Releases page.

The artefact is a signed `.app` (in a zip) with App Sandbox + `keychain-access-groups` entitlements and an embedded profile — the same signing line as `build_macos_app.sh` option A locally, **never falling back to ad-hoc** (BUG-2 discipline). No-network verification is as described above.

## The coffer CLI (MCP unlock escrow, v2.2.0)

`coffer` (the `coffer mcp` MCP server, `docs/03-功能设计/06-v2.0.0-MCP网关-设计.md`) **ships inside the app bundle and is not installed separately**:

- **Path**: `macos/build/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer` (assembled as a **nested bundle** `coffer.app` by step 3.5 of `tools/build_macos_app.sh`).
- **It must run from inside the app bundle**: copy the binary anywhere else and run it → **SIGKILL (exit 137)**. One sentence of reason: AMFI looks up the provisioning profile from the nearest `.app` bundle containing the executable in order to authorise the `keychain-access-groups` entitlement; with no bundle/profile covering the copy, the kernel SIGKILLs the process at spawn (proved on device by the D-6 spike and the G5 assembly). This is **user-visible discipline, not a bug**.
- Why a nested bundle rather than a bare `Contents/MacOS/coffer` (proved by the G5 assembly): ① `Contents/MacOS/Coffer` (the app's main executable) and `Contents/MacOS/coffer` are the same filename on macOS's default case-insensitive APFS, so they cannot coexist; ② for a bare Mach-O (not a main executable), AMFI applies the profile only to the **main code** of the nearest `.app`, even if a profile is embedded in the same bundle — a bare CLI carrying `keychain-access-groups` is SIGKILLed at spawn. Only a nested `.app` bundle with its own `embedded.provisionprofile` gets coverage.
- **Registration example** (Claude Code; same shape as `docs/03-功能设计/06-v2.0.0-MCP网关-设计.md` §5.4):

  `bash
  claude mcp add coffer -- "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer" mcp --provider op --vault <vault>
  `

  Note that the `mcp` subcommand **must be given explicitly** (the CLI does not understand a bare `--help`; a missing subcommand prints usage and exits 1).

## Browser-extension host (v2.3.0 G-E) — retired

> **Retirement note (2026-10-09)**: the browser extension is **retired entirely** (owner's decision — it is not even going to a store), and the app-side integration has been removed. The `browser-agent` / `browser-broker` / shim assembly notes in this section are void and kept for the record; the nested coffer bundle still ships with the app (see the CLI section above), but the `browser-*` subcommands are no longer used. The design document is archived at `docs/archive/01-v2.3.0设计-浏览器扩展.md`.

## What exists today

- `Coffer/` — the SwiftUI app (shell / vault creation / unlock / item list, detail and edit / trash / CSV import / Clipboard and AutoLockMonitor platform layer).
- `Coffer/CoreBindings/` — UniFFI-generated Swift bindings (**generated by `tools/build_swift_bindings.sh`, do not edit by hand**).
- `Coffer/SmokeTest/main.swift` — swiftc smoke sample (links the static library and exercises the whole Rust ↔ Swift path); the compile command is at the end of `tools/build_swift_bindings.sh`.
- Deliberately out of scope for v0.1 (see `docs/03-功能设计/01-v0.1.0-macOS纵切-设计.md` §1.2): Touch ID, menu-bar residency, global hotkey, Passkey, 1PUX import.
- **Touch ID status addendum**: the code is complete (`docs/03-功能设计/02-v0.2.0-TouchID解锁-设计.md` T01–T04) but was blocked by **BUG-2 (Keychain -34018, ad-hoc signing with no code-signing identity)** and was **not usable on device**; the on-device end-to-end acceptance (08-T05) was pending. See `docs/01-KNOWN-ISSUES.md` BUG-2.

---

## Planned layout

`
macos/
├── Coffer.xcodeproj
├── Coffer/                SwiftUI app
│   ├── Views/
│   └── Platform/              platform adapters (Keychain / Touch ID / clipboard)
├── CoreBindings/              UniFFI-generated Swift bindings
└── Frameworks/                libcf_ffi.a + modulemap
`

See `docs/01-需求与架构/02-概要设计.md` §2.2.

---

## Things to confirm before starting

### 1. Entitlements (the technical basis of the security promise)

`xml
<!-- Coffer.entitlements -->
<key>com.apple.security.app-sandbox</key>                    <true/>
<key>com.apple.security.files.user-selected.read-write</key> <true/>
<key>com.apple.security.device.biometric</key>               <true/>

<!-- deliberately absent: -->
<!-- com.apple.security.network.client -->
<!-- com.apple.security.network.server -->
`

**Not granting the network entitlement is what makes "no network" true on macOS.** Under Hardened Runtime the app cannot open a connection without it — the system refuses.

Verify at acceptance time with: `codesign -d --entitlements - Coffer.app`

### 2. Keychain `ThisDeviceOnly` (a quiet data-egress channel)

`swift
SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,   // ← the important part
    .biometryCurrentSet,
    &error
)
`

> ⚠️ **iCloud Keychain sync is a quiet data-egress channel.**
>
> Without `ThisDeviceOnly`, the biometric key **syncs to other devices via iCloud** — the "no network" promise is silently bypassed by a system-level channel.
>
> Keep two things apart: **key material** must never cross devices; **data** (the vault file, in ciphertext) may be backed up by Time Machine. Confusing them produces two opposite mistakes — see `docs/01-需求与架构/03-详细设计.md` §10.4.

### 3. Autofill approach (decided: clipboard)

macOS has **no** system-level Autofill framework like Android's; a third-party app cannot inject text into another app's field.

The decided approach is the **clipboard**: write to the clipboard, prompt the user to paste, clear on a timer. The Accessibility keyboard-simulation route is **not** used — the permission is too heavy and conflicts with least privilege.

Implementation details (including the `changeCount` check that avoids clearing something the user copied later) are in `docs/01-需求与架构/03-详细设计.md` §10.3.

> This UX gap must be stated in the user documentation so it is not mistaken for a bug.

### 4. OS version and architecture

| Item | Requirement |
| --- | --- |
| Minimum OS | **macOS 14 (Sonoma)** — the release where Apple opened third-party Passkey storage |
| Architecture | **arm64 native only**; no Intel build, no universal binary |
| Distribution | **App Store sandbox, single channel** (since 2026-10-09; the dual developer-id channel was cancelled) |

---

## Build chain

`
core/ (Rust)
  └─ cargo build --release --target aarch64-apple-darwin
       └─ libcf_ffi.a (staticlib)
            ├─ UniFFI generates the Swift bindings
            └─ linked into the Xcode project
                 └─ codesign --options runtime → notarytool submit → stapler staple
`

See `docs/01-需求与架构/04-系统设计.md` §5.3.

---

## Passkey boundary statement (degraded form, v2.6.0)

Passkey support on macOS is **degraded** (FR-10.1 import / 10.2 view / 10.5 delete / 10.6 keep the password; creation and use are out of scope). Three honest boundaries:

1. **Creation and use are absent (TCB-4)**: this build has **no credential provider extension** — Coffer never appears as a provider in System Settings, and no website or app can choose Coffer to create or use a Passkey. It is not "a menu item that is disabled"; the capability does not exist. Stated in the user documentation.
2. **Not syncing through iCloud is a feature** (lead decision, unchanged): Passkey private keys live in Coffer's own encrypted vault and **never go through iCloud Keychain** (under a third-party provider, syncing does not exist by design). Moving across devices means moving the vault file (encrypted backup/restore). Stated in the user documentation.
3. **Data-source boundary**: **1PUX from the desktop app has no Passkeys** — 1Password's desktop export does not include them (only the iOS/Android apps can export them). Users coming from 1Password desktop must export from iOS/Android, switch to Bitwarden JSON, or re-register on the websites (post-ADP). There is no technical way around this. Stated in the user documentation.

> The full version (credential provider extension + creation/assertion) restarts after the ADP purchase — mechanism in `docs/01-需求与架构/02-概要设计.md` §4.6, key points in `docs/03-功能设计/05-v0.5.0-Passkey降级-实现方案.md` §9 (dormant).

---

## Related documents

| Topic | Location |
| --- | --- |
| macOS implementation notes | `docs/01-需求与架构/03-详细设计.md` §10 |
| Passkey mechanism | `docs/01-需求与架构/02-概要设计.md` §4.6 |
| Build and release pipeline | `docs/01-需求与架构/04-系统设计.md` §5.3 |
| Phase breakdown | `docs/01-需求与架构/04-系统设计.md` §10.1 |
