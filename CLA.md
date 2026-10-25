# Coffer Contributor Licence Agreement (CLA)

**English** · [中文](CLA.zh.md)

> This English text is a convenience translation. If the two versions differ, [the Chinese version](CLA.zh.md) prevails.

| Item | Detail |
| --- | --- |
| Version | 1.1 |
| Effective | 2026-09-24 (v1.0) · 2026-10-15 (v1.1) |
| Type | Copyright licence grant (**not** a copyright assignment) |
| Applies to | All contributions submitted to this project (code, docs, design, test samples) |

> ⚠️ **This document is an engineering draft, not legal advice.**
> Have it reviewed by a practising lawyer before it goes live, in particular §2 (sublicensing) and §3 (patent grant).
> If the project takes no external contributions for a long time, this file can stay dormant — but it must be in place **before the first external PR is merged** (see "Timing" below).

---

## Why this agreement exists

The community edition of Coffer is open source under **AGPL-3.0**. AGPL lets anyone use, modify and distribute the project (including the source-availability duty when it is offered as a network service), which is what we want.

There is one restriction: **without this agreement the project permanently loses the ability to change its licence.**

The reason is a basic rule of copyright law — every contributor **automatically holds copyright** on the code they write, and changing the project's licence as a whole requires the consent of **every** copyright holder. Once ten people's PRs are merged, relicensing means obtaining ten separate consents; on a large project that is effectively impossible.

This agreement solves that problem while giving you, the contributor, the following guarantees:

| Your guarantee | Detail |
| --- | --- |
| **You keep your copyright** | This is a **licence grant**, not a **copyright assignment**. You retain every right in your contribution |
| **The licence is non-exclusive** | You may still use your contribution in any other project, under any other licence, including commercially |
| **The scope is explicit** | The rights you grant are limited to what running this project requires, and the sublicensing clause is spelled out (§2) |
| **The patent grant has defensive termination** | If someone sues the project over patents, the patent licence granted to them terminates automatically (§3) |

---

## Agreement

Submitting a contribution (a pull request, a patch, or any change to code / docs / design) to this project means you agree to the following, and that this agreement covers this contribution and **all of your future contributions to the project**.

### 1. Representations and warranties (you have the right to submit)

You represent and warrant that:

1. Your contribution is your original work, or you have the legal right to submit it;
2. Submitting it infringes no third party's rights and breaches no agreement you are bound by (**including your employer's IP agreement**);
3. If you created the contribution in the course of employment, you have your employer's authorisation, or your employer has waived the relevant rights.

> If you contribute on your employer's behalf, confirm that you are authorised first. Most companies have a standard open-source contribution process; it usually takes one internal email.

### 2. Copyright licence

You grant the project maintainers (and the recipients of software they distribute) a **perpetual, worldwide, non-exclusive, royalty-free, irrevocable** copyright licence to:

- reproduce your contribution
- modify your contribution and create derivative works from it
- display and publicly perform it
- distribute your contribution and its derivative works (as source or as object code)
- **sublicense** the above rights

**The scope of that licence includes distributing your contribution under any licence terms the maintainers choose, including proprietary / commercial terms, as well as the project's current open-source licence.**

> **This is the core of the agreement, and we put it in plain sight rather than burying it in the small print.**
> The reason is simple: you are entitled to know exactly what you are agreeing to. This clause is how "the project keeps the ability to change its licence" is implemented in law.
> How we intend to use that right, and our commitments around licence changes, are set out in "About the sublicensing clause" below.

### 3. Patent licence

You grant the project maintainers and the recipients of the software a **perpetual, worldwide, non-exclusive, royalty-free, irrevocable** patent licence to make, have made, use, sell, offer for sale, import and otherwise transfer your contribution (and the combination of your contribution with the project).

That licence **covers only** patent claims that you have the right to license and that are **necessarily infringed** by your contribution alone or by its combination with the project.

**Defensive termination**: if any entity brings a patent action against the project (including a counterclaim or cross-claim in litigation), the patent licence granted to that entity under this agreement terminates as of the date the action is filed.

> AGPL-3.0 already contains a patent grant with defensive termination (§10). This clause is consistent with it and explicitly covers the case where a contribution is redistributed under other terms (e.g. a commercial licence) — a gap the AGPL licence itself does not address.

### 4. Rights you retain

- You retain all right, title and interest in your own contribution.
- This agreement **does not transfer your copyright**. You grant a **licence**, not **ownership**.
- You remain free to use your contribution for any other purpose, including distributing it in other projects under other licences, or in a commercial product.
- This agreement grants you no right to use the project's trademarks (name, logo).

### 5. No warranty

Apart from the representations in §1, your contribution is provided **"as is"**, without warranties or conditions of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose and non-infringement.

### 6. Records and effect

- You sign through the CLA assistant on the pull request; your GitHub username and the signing time are recorded;
- A single signature covers all of your subsequent contributions to the project;
- The agreement is irrevocable — merged contributions must remain lawfully usable;
- When the agreement is revised, the CLA assistant asks contributors to sign again.

---

## How to sign

1. You open your first pull request;
2. The CLA assistant bot comments on it automatically;
3. Reply as instructed to confirm; your username is recorded;
4. The check turns green and the PR can be merged. **Every later PR is covered automatically — no need to sign again.**

> If you do not accept the sublicensing clause in §2, please do not contribute — we understand and respect that choice.
> You may still use the project freely (AGPL-3.0 grants you every right it offers), and you may fork and maintain your own copy.

---

## About the sublicensing clause

We would rather spell this out than have you discover it after signing.

### Why sublicensing is needed

Two concrete scenarios:

| Scenario | Why sublicensing is needed |
| --- | --- |
| **Commercial / enterprise distribution** | The project may distribute an enhanced edition under commercial terms (a paid or enterprise edition) while the community edition stays open source under AGPL-3.0. That requires distributing the same code under different terms |
| **Open-source licence migration** | If the ecosystem or compliance requirements change, the project may migrate to another open-source licence (e.g. Apache-2.0). A new licence needs different rights, which requires the sublicensing right |

Without it neither is possible — **not "hard", but impossible** — short of contacting every past contributor.

### The project's commitments

These commitments bound how that right is used:

1. **The community edition (this public GitHub repository) is distributed under AGPL-3.0.** Commercial redistribution, if any, applies to separate distribution channels and does not affect the community edition staying open source.
2. **Any material change to the licence or distribution terms is announced in the release notes and the repository in advance**, stating what changes, why, and what it means for existing users.
3. **Released versions are never relicensed retroactively.** The rights AGPL-3.0 gives you are permanent — even if a future version ships under different terms, the version you already have stays under the original terms forever.

> Point 3 deserves emphasis: **an open-source licence grant is irrevocable.** Even if the project changes terms later, anyone who obtained a version before the change keeps it under the original terms permanently. That is a matter of law, not a promise — so a "relicensing" affects existing users far less than it sounds.

---

## Timing (important)

**This agreement must be in place before the first external pull request is merged.**

The trigger is "an external PR merged without a signed contributor agreement". Once that happens there is a **permanent, unrecoverable** rights gap: there is no remedy short of contacting every past contributor, some of whom may no longer be reachable.

Enabling it now is the cheapest moment: there are no external contributors yet, so nobody is asked to sign retroactively. Doing it after ten contributors exist multiplies both the work and the uncertainty.

**If the project stays single-maintainer**, the problem never arises in practice. In that case this file can exist without an active signing flow, enabled when the first external PR appears — the rules are written and ready.

---

## Alternatives considered

| Option | Preserves the right to relicense | Friction | Verdict |
| --- | --- | --- | --- |
| **This agreement (licence-grant CLA)** | ✅ Yes | Low (one click on the PR, automated) | **Adopted** |
| Copyright-assignment CLA (as the FSF uses) | ✅ Yes, most complete | High (contributors lose copyright) | Rejected — too harsh on contributors for no need |
| DCO (`Signed-off-by`) | ❌ **No** | Minimal | Not adopted on its own. A DCO is an assertion, not a contract: no sublicensing right, no patent grant. It may complement the CLA (provenance tracking) but cannot replace it |
| Do nothing | ❌ No | None | Rejected — equivalent to accepting a permanently locked licence |

> **A common misunderstanding about the DCO**: many assume that signing off lets a project relicense freely. **It does not.** A DCO speaks to the **project's current licence**; it only asserts that the contributor may submit code under that licence and grants nothing beyond it. DCO and CLA solve different problems: the DCO covers **whether the code's provenance is lawful**, the CLA covers **how much the project may do with it**. They can coexist, but a DCO cannot replace a CLA.

---

## Engineering setup

| Item | Practice |
| --- | --- |
| Automation | **CLA Assistant** (open source, GitHub integration) or equivalent |
| Enforcement | Unsigned PRs **must not be mergeable** (enforced by branch protection) |
| Signing records | Stored automatically by the tool and publicly auditable (the "lost signatures" lesson) |
| Revisions | A revision triggers re-signing by all contributors |
| Companion docs | `CONTRIBUTING.md` must state this agreement and why it is needed, prominently |

---

*v1.1 (v1.0 2026-09-24; v1.1 aligns with the AGPL-3.0 baseline and adjusts the sublicensing commitments, 2026-10-15). Have it reviewed by counsel before enabling, and archive the signing records together with the agreement version.*
