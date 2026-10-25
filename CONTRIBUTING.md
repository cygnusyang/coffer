# Contributing to Coffer

Thanks for your interest in Coffer. This project **handles the most sensitive data a user owns**, so the bar for contributions is higher than usual.

**English** · [中文](CONTRIBUTING.zh.md)

---

## ⚠️ Rule one: agree to the CLA before contributing

Read and accept the [CLA](CLA.md) before opening any pull request.

### Why this is required

The community edition of Coffer is licensed under AGPL-3.0. Without a CLA, **the project permanently loses the ability to change its licence** — every contributor automatically holds copyright on their own code, and relicensing the project as a whole needs the consent of every copyright holder. After ten PRs are merged, relicensing would mean tracking down ten people one by one.

The CLA solves that while guaranteeing:

- You **keep** the copyright on your contribution — it is a **licence grant**, not a copyright assignment
- You may still use your contribution for anything else, including commercial work
- The licence granted to the project is **non-exclusive**
- It carries a **patent grant** with a defensive termination clause

### How to sign

On your first PR a CLA assistant bot comments; reply as instructed. **You sign once**; every later PR is covered automatically.

**If you do not accept the relicensing clause**, please do not contribute. You are still free to use the project — AGPL-3.0 grants you every right it offers — and to fork and maintain your own copy. We respect that choice.

> **Common misunderstanding**: a DCO (`Signed-off-by`) is **not** a substitute for a CLA. A DCO is an assertion, not a contract: it only states that you may submit code under the **project's current licence**. It grants **no relicensing right** and carries no patent grant. Why this project uses a CLA rather than a DCO: `docs/01-需求与架构/04-系统设计.md` §12.3.

---

## Development environment

| Requirement | Notes |
| --- | --- |
| Rust | **>= 1.85** (set by the MSRV of `getrandom` 0.4.3) |
| Toolchain | stable channel (see `core/rust-toolchain.toml`) |
| Python | 3.10+ (only for helper scripts under `tools/`, not a build dependency) |

`bash
git clone <repo-url>
cd coffer/core
cargo build
cargo test
`

---

## Code standards

### General

| Rule | Notes |
| --- | --- |
| `cargo fmt` | Must be run before committing |
| `cargo clippy` | No warnings allowed |
| **No `unsafe`** | Every crate declares `#![forbid(unsafe_code)]` at the top of `lib.rs` |
| **No `unwrap()` / `expect()`** | Not once on a production path — declared as deny in `lib.rs`. Test code is exempt |
| Doc comments | Every `pub` item needs `///`, every crate needs `//!` |

### Crypto and security-sensitive code (extra requirements)

This is where the project's risk is concentrated, and review is correspondingly stricter:

| Requirement | Rationale |
| --- | --- |
| **Never roll your own crypto primitives** | Use the high-level API of a mature library. Hand-assembling AEAD constructions is explicitly forbidden here |
| **Key types must implement `Zeroize` + `ZeroizeOnDrop`** | Key material must not linger in memory |
| **Error messages must not leak information that lowers attack cost** | e.g. an unlock failure must not distinguish "wrong password" from "corrupt file" |
| **Sensitive data must never reach a log** | Enforced at compile time by the `LogSafe` trait, not by review |
| **No network dependency of any kind** | Including `reqwest`, `hyper`, `ureq`, … CI checks the dependency tree automatically |

### Dependency management

Before adding a dependency, confirm:

1. It is not on the **deny list** in `docs/01-需求与架构/04-系统设计.md` §11.1 (anything network- or telemetry-related is forbidden)
2. Its licence is AGPL-3.0-compatible (permissive MIT / Apache-2.0 / BSD and copyleft GPL / LGPL / AGPL all qualify; **licences incompatible with AGPL-3.0 are forbidden**)
3. It is added to `[workspace.dependencies]` in `core/Cargo.toml` and consumed by each crate via `{ workspace = true }`, rather than pinning versions inside individual crates

---

## Commit conventions

Write commit messages in the **imperative mood**, describing *what the change does* rather than which files it touches:

`
✓  Make 1PUX attachment paths relative on import
✓  Add the 18 RFC 6238 Appendix B test vectors to cf-totp
✗  update
✗  fix bug
✗  changed importer.rs
`

If a commit changes a design, cite the relevant document section in the message (e.g. `docs/01-需求与架构/03-详细设计.md §6.3`).

---

## Testing requirements

| Scenario | Requirement |
| --- | --- |
| Ordinary functionality | New logic needs unit tests |
| Cryptography | Must pass the standard test vectors (`docs/01-需求与架构/04-系统设计.md` §8.2) |
| Importers | Must add tests for malformed input |
| Bug fix | Write the failing test that reproduces the bug first, then fix it |

### One hard rule about test data

**Never commit a real data sample.**

- Need test data? Generate a synthetic sample with `python3 tools/make_test_sample.py`
- If calibration requires a real sample, **use it offline on your own machine and never commit it**; delete it once calibration is done
- Commit only the derived **mapping table** (no concrete values), recording the SHA-256 fingerprint of the sample used

Why: this repository is public, and a leaked vault sample cannot be un-leaked.

---

## Security vulnerabilities

**Do not open a public issue.** Report privately following [SECURITY.md](SECURITY.md).

---

## Keeping docs in sync with code

One non-negotiable rule here: **any change to the crypto format must update the docs in the same change.**

| Change type | Docs to update |
| --- | --- |
| Feature scope | `docs/01-需求与架构/01-需求分析.md` → `02` → `03` → `04` (in that order) |
| Architecture or technology choice | `docs/01-需求与架构/02-概要设计.md` → `03` |
| Crypto parameters or format | `docs/01-需求与架构/03-详细设计.md` §1–§3 → `docs/01-需求与架构/04-系统设计.md` §6 |

Code without docs is the most common source of hidden debt in a project like this (`docs/01-需求与架构/04-系统设计.md` §15.2). Reviewers will send the PR back.

---

## Code of conduct

By participating you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
