# Triage Policy

**中文摘要**：这是单人维护的开源项目，下面给的是**尽力而为的目标**，不是服务等级协议（SLA）。安全漏洞请走私密渠道（见 SECURITY.md），不要开公开 issue。

---

## 1. What this document is (and is not)

- It **is** a statement of how issues are read, labelled and prioritised, so you know what to expect.
- It is **not** an SLA. Coffer is maintained by one person in their spare time. Targets below are goals; missing them is possible and is not a breach of contract — this is free software under AGPL-3.0.
- Issues and PRs are welcome in **English or 简体中文**.

## 2. Severity levels

| Level | Definition | Examples |
| --- | --- | --- |
| **S1 — Critical** | Data loss, vault corruption, unlock bypass, or the app cannot start on a mainstream macOS version | Vault fails to open after an update; a wrong password unlocks; crash on every launch |
| **S2 — Major** | A core feature is broken, or a security weakness exists that is not immediately exploitable | Import silently drops entries; auto-update loops; OTP codes wrong |
| **S3 — Normal** | Incorrect behaviour with a workaround, UI defects, edge-case crashes | Row misaligned at large text size; a menu item does nothing in a specific layout |
| **S4 — Cosmetic / request** | Wording, spacing, feature ideas | Dark icon request |

Security-impacting issues are always treated as **at least S2**, and reported through the private channel in SECURITY.md — **not** in a public issue.

## 3. Response targets (best effort)

| Level | First human response | Fix target |
| --- | --- | --- |
| S1 | **within 72 hours** | hotfix release (PATCH) as soon as a fix is verified |
| S2 | within 7 days | next release (usually within 2 weeks) |
| S3 | within 14 days | batched into a later release |
| S4 | when time permits | no commitment |

First human response means a real reply that says what happens next — not an auto-label. If a report is missing information, the reply says exactly what is needed.

## 4. Labels you will see

| Label | Meaning |
| --- | --- |
| `bug` | Confirmed or plausible defect |
| `enhancement` | Feature request or improvement |
| `documentation` | Docs only |
| `question` | Needs clarification — from you or from us |
| `good first issue` | Scoped, with pointers; suitable for a first PR |
| `help wanted` | Maintainer would welcome a PR |
| `duplicate` / `invalid` / `wontfix` | Closed with a reason in the thread |
| `accessibility` | VoiceOver, keyboard, contrast, text size |

## 5. What a good report contains

1. **Coffer version** — from the About panel (设置 → 关于), e.g. v2.13.3.
2. **macOS version**, and whether it is Apple Silicon or Intel.
3. **Steps to reproduce** — ideally starting from a fresh launch.
4. **Expected vs actual** behaviour.
5. **Logs** — the tail of `~/Library/Containers/top.cygnusyang.coffer/Data/Library/Logs/Coffer-diag.log`. Read it first: it contains timestamps, error codes and file paths. It never contains password values by design, but it is your file to review.
6. **Screenshots** if the problem is visual.

> Redact anything you consider sensitive. Never paste real passwords or your master password — we will never ask for them.

## 6. How the queue is worked

1. New issues get a label and a severity, usually within the targets in §3.
2. S1/S2 are fixed before any feature work; S3/S4 are batched.
3. A fix ships with a commit that references the issue (Closes #N), a CHANGELOG entry, and — for behaviour changes — a version bump.
4. When a version ships, the issue gets a comment with the version and release link, then is closed.

## 7. Closing without a fix

An issue may be closed **without a fix**, with the reason stated in the thread, when:

- it cannot be reproduced and the reporter cannot provide more detail after one follow-up;
- it is a design decision already recorded in `docs/` (the decision link is posted);
- it is out of scope for a local-first, single-maintainer product (e.g. cloud sync);
- it has had no activity for **90 days** and no reproduction path (marked stale first, then closed).

Reopening with new information is always welcome.

## 8. Pull requests

- Small fixes: open the PR directly and reference the issue if there is one.
- Behaviour changes: open an issue first; a design note may be needed.
- Every PR must keep `tools/check_l10n.sh`, the relevant test harnesses and the build green (see CONTRIBUTING.md).
- Personal data or secrets in a PR (even in a test fixture) will be rejected.

## 9. What is not supported

| Not supported | Reason |
| --- | --- |
| macOS older than 14 | Uses APIs unavailable earlier |
| Vault formats from forks | Not our schema |
| Recovering a forgotten master password | By design: no backdoor. Use the recovery code generated at setup |
| Hosted / cloud instance | Coffer is local-only by design |

---

*Last updated: 2026-10-25 · maintainer: @cygnusyang*
