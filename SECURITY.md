# Security policy

Coffer is a local password manager. **A security defect in this product category is not an ordinary bug** — it can expose every credential a user owns, irreversibly. Our process is therefore more serious than usual.

**English** · [中文](SECURITY.zh.md)

---

## Reporting a vulnerability

### ⚠️ Never report through a public channel

**Do not disclose security defects in GitHub Issues, Discussions, PR comments, social media or anywhere else public.**

Public disclosure puts every user at risk before a fix exists.

### Channels

| Channel | Notes |
| --- | --- |
| GitHub Security Advisory | **Preferred.** The repository's Security tab → "Report a vulnerability"; the report stays private |
| Maintainer email | Fallback; the address is published on the repository's Security page |

> If neither works, open an issue **with no technical detail** saying only that you have a security matter to report privately; a maintainer will establish a private channel with you.

### What to include

| Item | Notes |
| --- | --- |
| Affected version | Or a commit hash |
| Vulnerability class | See the scope tables below |
| Reproduction steps | As minimal as possible, as long as it reproduces reliably |
| Impact assessment | What an attacker gains, and what preconditions are needed |
| Proof of concept | Optional, but it speeds things up considerably |
| Already disclosed? | If you told anyone else, say so |

---

## Response targets

| Stage | Target |
| --- | --- |
| Acknowledgement | Within 3 business days |
| Initial assessment (is it a vulnerability, how severe) | Within 7 business days |
| Fix or mitigation | Depends on severity; an estimate follows the assessment |
| Public disclosure | After the fix ships, at a time agreed with the reporter |

> **The project is in early development**; no usable release has shipped yet, so maintainers may not always meet these targets. Say so in the report if the matter is urgent.

---

## Scope: what counts as a security issue

### In scope

| Class | Examples |
| --- | --- |
| **Cryptographic implementation** | Argon2id parameters and usage, HKDF subkey derivation, AEAD AAD construction, nonce strategy |
| **Key management** | Envelope wrap/unwrap, verifier design, biometric key wrapping, incomplete memory zeroisation |
| **Container format** | Version detection bypass, integrity check evasion, migration paths that corrupt data |
| **Importers** | Malformed 1PUX / CSV / opvault causing a crash, memory exhaustion, out-of-bounds access |
| **Authorisation bypass** | Reading data while locked, cross-vault access |
| **Information disclosure** | Sensitive data in logs, crash reports or system backups |
| **Bypassing the no-network promise** | Any network capability at all (the project's central promise — see below) |
| **Platform integration** | Misconfigured Android Keystore / macOS Keychain weakening key protection |

### Out of scope

| Class | Notes |
| --- | --- |
| **Attacks requiring physical access + root/jailbreak** | A root attacker can dump process memory; accepted as residual risk in the threat model (`docs/01-需求与架构/04-系统设计.md` §4.2) |
| **Full-disk encryption disabled** | A user environment setting, not a defect in this software |
| **Brute force against a weak master password** | A user choice — but if we **accept** a weak password without warning, that is our defect |
| **Known capability gaps** | See below |
| **Vulnerabilities in third-party dependencies** | Report them upstream; we will follow up if they affect us |

---

## Known capability gaps (not vulnerabilities)

The following are **direct consequences of deliberate design decisions**. They are recorded in the design docs and surfaced to users in the product and UI. They are not fixable defects:

| Gap | Cause | Recorded in |
| --- | --- | --- |
| Cannot detect "already breached" passwords | Requires querying an online breach corpus, which contradicts no-network | `docs/01-需求与架构/01-需求分析.md` FR-6.5 |
| Losing the master password loses the data | No server, no backdoor, no recovery in the original design (Touch ID unlock and an offline recovery code are opt-in mitigations, FR-17) | Same doc §4.2, scenario 3 |
| No full defence against rolling the whole vault back to an old version | No server to supply an authoritative timestamp | `docs/01-需求与架构/02-概要设计.md` §8.2 |
| No promise of forensic-erasure after deletion | Physically impossible on flash storage | `docs/01-需求与架构/04-系统设计.md` §3.4 |
| Metadata partially visible | Item count, field count, category and timestamps are readable | `docs/01-需求与架构/03-详细设计.md` §3.5 |
| Delayed security patches in air-gapped mode | A consequence of not networking by default (self-hosted OTA is opt-in and allowlisted) | `docs/01-需求与架构/01-需求分析.md` R-03 |
| Passkey private keys can be exported with the vault file | The necessary trade-off for cross-device portability | `docs/01-需求与架构/01-需求分析.md` FR-10 |
| No system-wide autofill on macOS | The platform has no equivalent framework | `docs/01-需求与架构/01-需求分析.md` FR-4.6 |

If you believe the **real impact of one of these is worse than documented**, that is still worth reporting — we may be underestimating it.

---

## A note on the no-network promise

The project's central security claim is: **the app has no networking capability, not merely that it does not use one.**

All of the following **are security vulnerabilities**; please report them first:

- Any form of network call in the code
- A network crate appearing in the dependency tree
- An `INTERNET` permission or network entitlement in a build artefact
- System-level backup (Android cloud backup / iCloud / Time Machine) capturing data that should be excluded
- Key material propagating across devices through a platform sync mechanism (e.g. iCloud Keychain)

### How to verify (anyone can do this)

`bash
# macOS: check entitlements
codesign -d --entitlements - /Applications/Coffer.app

# Core library: check the dependency tree
cd core && cargo tree --prefix none \
  | grep -E '^(reqwest|hyper|ureq|isahc|surf|curl|tokio-rustls|native-tls)' \
  && echo "network dependency present" || echo "OK"
`

**The value of this promise lies in being verifiable.** If verification contradicts the promise, that is the most severe class of issue there is.

---

## Security audit

A **two-stage third-party security audit** is planned before v1.0.0; the reports will be published. Scope, timing and vendor selection: `docs/01-需求与架构/04-系统设计.md` §12.5.

If you are a security researcher who would like to take part in the audit or in crowd review, contact us through the channels above.

---

## Acknowledgements

Researchers who report issues responsibly are credited once the fix ships (unless you ask to stay anonymous).
