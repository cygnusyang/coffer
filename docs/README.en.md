# Coffer — documentation index (English)

The complete design corpus lives under `docs/` and is written in **Chinese**; this page is a map so English readers can navigate it. Start with the [English README](../README.md) for product-level material.

> Why Chinese? Coffer is a single-maintainer project; the docs double as the engineering log (design decisions, acceptance criteria, post-mortems). Translating all ~60 documents would cost more than it returns — this index plus the English README is the deliberate compromise. Issues and PRs in English are welcome.

## How the docs are organised

| Folder | Contents |
| --- | --- |
| `01-需求与架构/` | Requirements, high-level/detailed/system design, architecture overview |
| `02-研发计划与决策/` | Roadmap, per-version plans, irreversible-decision register |
| `03-功能设计/` | Per-version feature designs (one document per version) |
| `04-测试与验收/` | Acceptance criteria and test plans per version |
| `05-技术研究/` | Spikes: KDF calibration, OPVault layout, passkeys, licensing research |
| `01-KNOWN-ISSUES.md` | Defect register (Chinese; mirrored to GitHub Issues when shipped-affecting) |
| `00-WORK-ITEMS.md` | Internal work-item board |
| `DESIGN.md` | UI/UX standard: components, spacing, terminology |

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

## Contributing

See [`CONTRIBUTING.md`](../CONTRIBUTING.md). Bug reports in English are fine — please attach the log paths (`/tmp/coffer-mcp-register.log` etc.) and the version string from the About panel.
