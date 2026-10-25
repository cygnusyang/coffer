# Documentation

**English** · [中文](README.zh.md)

The design corpus under `docs/` is **written in Chinese** — it doubles as the engineering log for a
single-maintainer project (design rationale, acceptance criteria, post-mortems), and translating
~60 documents would cost more than it returns. This page is the map; the full file-by-file index,
including the historical numbering table, is in the **[Chinese navigation page](README.zh.md)**.

Issues, PRs and comments in English are always welcome.

## How the corpus is organised

Documents are numbered `NN` within each topic folder and are cited by folder + full filename.

| Folder | Contents |
| --- | --- |
| [`01-需求与架构/`](01-需求与架构/) | Requirements, architecture overview, detailed and system design |
| [`02-研发计划与决策/`](02-研发计划与决策/) | Development status, per-version plans, decision records |
| [`03-功能设计/`](03-功能设计/) | One design document per version, plus focused specs |
| [`04-测试与验收/`](04-测试与验收/) | Test plans, acceptance cases and criteria |
| [`05-技术研究/`](05-技术研究/) | Spikes: KDF calibration, format cross-checks, feasibility |
| [`archive/`](archive/) | Retired browser-extension design and decision drafts |
| [`assets/`](assets/) | Diagrams, icons and design material |
| [`01-KNOWN-ISSUES.md`](01-KNOWN-ISSUES.md) | Defect register (Chinese; mirrored to GitHub Issues when user-visible) |
| [`00-WORK-ITEMS.md`](00-WORK-ITEMS.md) | Internal work-item board |
| [`DESIGN.md`](DESIGN.md) | UI/UX standard: components, spacing, terminology |
| [`00-文档风格指南.md`](00-文档风格指南.md) | Documentation style guide |

## If you only read five documents

| Document | Why it matters |
| --- | --- |
| [`01-需求与架构/01-需求分析.md`](01-需求与架构/01-需求分析.md) | The requirement IDs (`FR-*` / `NFR-*`) every design and test refers back to |
| [`01-需求与架构/04-系统设计.md`](01-需求与架构/04-系统设计.md) | Threat model, storage layout, crypto boundaries |
| [`01-需求与架构/05-Agent凭据域.md`](01-需求与架构/05-Agent凭据域.md) | The MCP / agent credential model (read-only surface, env injection) |
| [`02-研发计划与决策/03-不可逆决策追认表.md`](02-研发计划与决策/03-不可逆决策追认表.md) | Decisions that cannot be reversed without a migration |
| [`02-研发计划与决策/02-版本开发计划.md`](02-研发计划与决策/02-版本开发计划.md) | Version-by-version delivery record (§0 is the authoritative table) |

## Recent designs worth reading

| Document | Topic |
| --- | --- |
| [`03-功能设计/24-v2.13.0-多语言-设计.md`](03-功能设计/24-v2.13.0-多语言-设计.md) | Localisation: Chinese-source-as-key, why only `en.lproj` ships, placeholder pitfalls |
| [`03-功能设计/25-v2.13.1-设置页紧凑化-设计.md`](03-功能设计/25-v2.13.1-设置页紧凑化-设计.md) | Why the system `Form` could not be tightened, and what replaced it |
| [`04-测试与验收/22-v2.13.0-多语言-验收判据.md`](04-测试与验收/22-v2.13.0-多语言-验收判据.md) | 64 acceptance criteria incl. the device-vs-bundle nuances |

## Conventions you will see

- **`FR-x.y` / `NFR-xx`** — requirement IDs from the requirements analysis; every design and test cites them.
- **`D-x.y`** — irreversible or standards-level decisions; registered in the decision table and `DESIGN.md`.
- **`TC-*`** — test cases; **`AC-*`** — acceptance criteria.
- Version numbers are `MAJOR.MINOR.PATCH`; each release's entry lives in [`CHANGELOG.md`](../CHANGELOG.md).
- Design documents are named `NN-vX.Y.Z-topic-type`; the number never changes, and references always use the full filename.

## Elsewhere

- Product overview and install instructions: [`README.md`](../README.md)
- macOS build and release flow: [`macos/README.md`](../macos/README.md)
- Contributing: [`CONTRIBUTING.md`](../CONTRIBUTING.md) · Security: [`SECURITY.md`](../SECURITY.md) · Conduct: [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)

> Operations and hand-over material (launch copy, release thresholds, key-escrow procedures) is not
> published in this repository; it lives on an internal operations branch.
