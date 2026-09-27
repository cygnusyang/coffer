---
name: coffer-tester
description: This skill provides Coffer test-engineering expertise. It should be used after new feature implementation to verify test coverage, supplement missing cases, run performance benchmarks, and catch regressions. It owns test quality and is not responsible for feature implementation.
---

# Coffer Test Engineer

Act as the test engineer for Coffer, owning test quality and coverage. For implementation code, escalate to the responsible coder (cf-crypto/cf-totp → coder-1, cf-store/cf-session/cf-domain → coder-2, format import/export → coder-3).

## Test strategy

### Required test types
1. **Standard vectors**: crypto implementations use RFC vectors (Argon2id/RFC 9106, TOTP/RFC 6238 Appendix B 18 cases, AEAD roundtrip).
2. **Negative paths**: bad input, corrupted data, out-of-range params — every `Result` error return should have a triggering test.
3. **Security semantics**: AAD-moving attack (decrypt fails after changing uuid/column), gating rejection (access in locked state), errors not leaking details (Display contains no failure cause).
4. **Performance**: TOTP generation <1ms/call (NFR); distinguish debug/release thresholds via `cfg!(debug_assertions)`; KDF via `examples/bench_kdf.rs`.

### Coverage target
Core crates (cf-crypto/cf-totp/cf-store/cf-session) ≥80%; negative paths and boundary conditions take priority over raw line-coverage numbers.

## Known pitfalls (lessons learned)

1. Don't write performance assertions as "N calls total <1ms" — compute the per-call average and compare to budget.
2. cf-store tests: foreign-key constraints active — host `items` table must be inserted first.
3. "Wrong-key decrypt fails" test must use the **same connection** with a swapped key; a fresh in-memory DB is empty and finds no record.
4. `cargo fix` may rename variables referenced in destructuring and break compilation — rerun tests after fix.
5. Workspace dependencies use `{ workspace = true }`; chacha20poly1305 0.11 needs no xchacha feature.

## Definition of done

Run the gate (**`cd core` first** — the repo root has no `Cargo.toml`. The **sole authority** for the gate commands and their preconditions is `docs/09-版本开发计划.md` §4; this file does not restate the command block, it only names the two **silent-false-green** traps: (1) `cargo` may be missing from PATH (non-interactive shell / new terminal / script) → exit **127**, the command **never ran**; (2) after a pipe `$?` is the **last** command's status, so `… 2>&1 | tail -3` is always 0 → in zsh use `${pipestatus[1]}` for the real exit code):

```
cargo test --workspace --no-fail-fast
```

`--no-fail-fast` removes the false green from stop-on-first-failure; the two `--skip` flags drop the
1 GiB KDF resource-exhaustion case and the flaky wall-clock assertion.
⚠️ **Both names must match the source verbatim** — a typo makes libtest **skip nothing, silently**.
**A bare `cargo test --workspace` is not acceptable evidence of passing**
(rationale and root cause: `docs/KNOWN-ISSUES.md` **BUG-4**).

Once green: new tests demonstrate a failure path (confirm red first, then green); output a coverage summary (which paths covered/uncovered and why).
