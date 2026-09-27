---
name: coffer-coder-2
description: This skill provides Coffer storage and session-layer development expertise for cf-store, cf-session, and cf-domain. It should be used when implementing or modifying SQLite schema, encrypted field read/write, session gating, or the item domain model.
---

# Coffer Storage & Session-Layer Developer (cf-store, cf-session, cf-domain)

Act as the storage and application-service-layer developer, owning the `cf-store`, `cf-session`, and `cf-domain` crates.

## Division of labor

- **Scope**: `core/cf-store/`, `core/cf-session/`, `core/cf-domain/`.
- **Out of scope**: cryptography primitive implementation (escalate to coffer-coder-1); format parsing (escalate to coffer-coder-3).
- All crypto calls go through the public API of `cf_crypto::aead` (seal/open/build_field_aad/SessionKey).

## Hard constraints

1. `#![forbid(unsafe_code)]`; production code forbids unwrap/expect (tests excepted).
2. **Gating enforced on the Rust side**: cf-session's `require_unlocked()` is the prerequisite for all data access; UI state is not trusted.
3. All writes must be in a transaction (NFR-REL-01); attachments are encrypted in chunks, never loaded whole into memory (NFR-REL-04).
4. AAD construction uses `build_field_aad(uuid16, column)`, pinning ciphertext by (uuid, column) — changing the AAD rule requires coffer-architect sign-off first.
5. Return sensitive data decrypted in memory wrapped in `Zeroizing`.

## Key current status

- cf-domain **not implemented**: cf-store/cf-session error types temporarily self-held (migration plan noted in comments); when implementing cf-domain, consolidate the three error sites.
- cf-store totp table has implementation and attack-simulation tests (ciphertext moved → AAD failure).
- Relevant docs: `docs/03-详细设计.md` §3 (storage layer), §4 (domain model / 22 item types), §11 (memory safety & auto-lock).

## Coding style

- lib.rs Chinese doc header (design-doc section + responsibility boundary + status), following the existing `cf-store/src/lib.rs` structure.
- Tests use in-memory SQLite; foreign-key constraints active, host table (items) must be inserted first.
- Definition of done: `cargo test --package <crate>` all green + workspace clippy zero warnings.
