# FEATURES.md — feature inventory

**English** · [中文](FEATURES.zh.md)

> De-Pro'd (2026-10-17, `docs/02-研发计划与决策/03-不可逆决策追认表.md` OS-1/OS-3).
> Everything is free and lives in one repository; there is no free/Pro split. This file is the single
> authority for the feature inventory and build switches. `set-env` (environment-container write
> surface) is an ordinary free feature with no feature gate; the old free/Pro two-repository
> ownership matrix and sync SOP are void.

## 1. Code layout

| Path | Notes |
|---|---|
| `core/cf-mcp/src/set_env.rs` + `set_env_tests.rs` | Environment-container write surface (docs/36 §4); ordinary module, always compiled |
| `core/cf-mcp/tests/cli_pro.rs` | set-env CLI integration tests; ordinary tests, always compiled |
| `macos/Coffer/Support/EnvironmentContainer.swift` | Environment-container detection and NAME validation helpers (app side); always compiled |
| `macos/Coffer/Views/ItemEditView.swift` / `ItemDetailView.swift` | Environment-container editing UI (tag lock / NAME validation / recognition badge); always compiled |
| `docs/` | Shared by everything |

> Note: `official-license` (offline activation assembly, a `core/cf-ffi` feature) and the FR-15
> licence-gate ports (`PermitAllGate` / `LicenseServicing`) are build-isolation capabilities and
> product-wide scaffolding. They are retained (OS-1) and are not Pro features.

## 2. Feature inventory (user-visible surface)

| Feature | Status | Notes |
|---|---|---|
| Local vault (22 item templates / custom fields / TOTP / generator) | ✅ | Core capability |
| Import / export / backup / audit log | ✅ | |
| Read-only MCP secret access (`coffer mcp`) | ✅ | The agent is the bridge |
| `coffer set-password` write surface | ✅ | FR-18 |
| `coffer set-env` environment-container write surface (CLI + in-app container editing: tag lock, NAME validation, recognition badge) | ✅ | docs/36 |
| Self-hosted OTA updates | ✅ | GitHub releases channel |
| Agent credential domain (full version) | Planned | Later version |
| Multiple vaults / cross-vault copy | ✅ | Delivered in v0.4.0 (FR-1.2 / FR-2.10) — not a gated or planned item |
| Passkey full version (tiered) | Degraded | Degraded read surface only |

## 3. Build switches

| Switch | Location | Notes |
|---|---|---|
| Cargo feature `pro` | `core/cf-mcp/Cargo.toml` | Removed (de-Pro OS-3) |
| Swift macro `COFFER_PRO` | `tools/build_macos_app.sh` | Removed (de-Pro OS-3) |
| Cargo feature `official-license` | `core/cf-ffi/Cargo.toml` | Retained (OS-1 build isolation) |
| Swift macro `OFFICIAL_LICENSE` | `tools/build_macos_app.sh` | Retained (OS-1 build isolation) |
