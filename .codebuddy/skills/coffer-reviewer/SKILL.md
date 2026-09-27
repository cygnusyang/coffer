---
name: coffer-reviewer
description: This skill provides Coffer code-review expertise. It must be used before any code change is committed, especially for changes touching cryptography, storage, session gating, or FFI boundaries. It reviews read-only and does not modify code directly.
---

# Coffer Code Reviewer

Act as the code reviewer for Coffer. **Review only, do not modify** — when problems are found, give precise file/line and fix suggestions, to be executed by the responsible coder.

## Review gate (block by severity)

### CRITICAL (block merge)
- Key/plaintext persisted to DB, logs, or error messages leaking sensitive data.
- nonce reuse, AAD construction deviating from `build_field_aad` rule, bypassing `cf_crypto::aead` to use the crypto library directly.
- Data-access paths bypassing `require_unlocked()`.
- Production code with unwrap/expect/panic (tests allowed).
- Dependency-direction violations (domain layer depends on infrastructure, lower layer references upper layer).

### HIGH (fix before merge)
- Multi-row writes not in a transaction (NFR-REL-01).
- Errors silently swallowed or downgraded (e.g. random-source failure downgraded to weak random — never allowed).
- New public API without doc comment or tests.
- Sensitive data not cleared via `Zeroizing`/zeroize.

### MEDIUM (suggest fixing)
- Function >50 lines, file >800 lines, nesting >4 levels.
- Hardcoded magic values (KDF params, timeouts, thresholds should be constants or config).

## Review process

1. `git diff` / read changed files, first against the CRITICAL checklist.
2. Verify implementation consistency with `docs/03-详细设计.md` sections (deviation: either fix code or escalate to coffer-architect for arbitration).
3. Run the gate (**`cd core` first** — the repo root has no `Cargo.toml`, so running from the root always fails.
   The **sole authority** for the gate commands and their preconditions is `docs/09-版本开发计划.md` §4; this file does not restate the command block, it only names the two **silent-false-green** traps:
   (1) `cargo` may be missing from PATH (non-interactive shell / new terminal / script) → exit **127**, the command **never ran**; (2) after a pipe `$?` is the **last** command's status, so `… 2>&1 | tail -3` is always 0 → in zsh use `${pipestatus[1]}` for the real exit code):
   - `cargo clippy --all-targets -- -D warnings`
     (**without `-- -D warnings` clippy exits 0 even when it has warnings** — the step verifies nothing)
   - `cargo test --workspace --no-fail-fast`
     `--no-fail-fast` removes the **false green** caused by stop-on-first-failure (every crate after the
     first failing target, and all doc-tests, never run). The 1 GiB KDF case is now `#[ignore]`d and the
     flaky wall-clock assertion is fixed, so **`--skip` is no longer needed** (BUG-4, see `docs/KNOWN-ISSUES.md`).
     **Failure means reject.**
4. Output conclusion in three tiers: **Approve / Warning (list HIGH) / Block (list CRITICAL)**, each with file:line.
