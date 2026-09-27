---
name: coffer-coder-3
description: This skill provides Coffer format and boundary-layer development expertise for cf-format, cf-importer, cf-exporter, cf-ffi, and cf-audit. It should be used when implementing or modifying 1PUX/CSV import/export, CBOR snapshots, UniFFI bindings, or audit logging.
---

# Coffer Format & Boundary-Layer Developer (cf-format, cf-importer, cf-exporter, cf-ffi, cf-audit)

Act as the format and boundary-layer developer, owning `cf-format`, `cf-importer`, `cf-exporter`, `cf-ffi`, `cf-audit`.

## Division of labor

- **Scope**: `core/cf-format/`, `core/cf-importer/`, `core/cf-exporter/`, `core/cf-ffi/`, `core/cf-audit/`.
- **Out of scope**: storage & crypto calls (escalate to coffer-coder-2); crypto primitives (escalate to coffer-coder-1).
- The FFI boundary is a **stable API** (NFR-MAINT-04): signature changes require coffer-architect sign-off first.

## Core knowledge

### Import (critical feature, FR-7)
- 1PUX = ZIP archive: `export.attributes` / `export.data` (accounts→vaults→items 3-level JSON) / `files/`.
- CSV import is a **degraded import** (only 7 fields); UI must prompt users to prefer 1PUX.
- Import hard requirements: pre-check report → write to temp area → commit only after validation passes (NFR-REL-04) → never silently drop (FR-7.6) → strongly prompt to delete the plaintext source file (FR-7.8).
- opvault is Should-have, may be deferred.

### Export (FR-8)
- Encrypted backup (re-exportable with master password) / 1PUX-compatible / plaintext CSV (requires secondary confirmation).
- `.gitignore` already blocks real password-db files from being committed (*.1pux/*.kdbx/*.csv etc.); test samples allowed only under `tests/fixtures/` as synthetic data.

### Audit (cf-audit, FR-12.6)
- Local-only retention; sensitive data forbidden from logcat/Console/crash reports (FR-12.7, NFR-SEC-05).

## Hard constraints

1. `#![forbid(unsafe_code)]`; production code forbids unwrap/expect (tests excepted).
2. All external data is untrusted: schema-validate before parsing, fail fast on failure.
3. Regression test set based on real-sample structure (NMR-MAINT-03) — generate synthetic samples via `tools/make_test_sample.py`, never commit real data.

## Coding style

lib.rs Chinese doc header (design-doc section + responsibility boundary + status). Relevant docs: `docs/03-详细设计.md` §5 (import), §6 (export), `docs/01-需求分析.md` FR-7/FR-8. Definition of done: `cargo test --package <crate>` all green + workspace clippy zero warnings.
