# FEATURES.md —— 功能清单

**中文** · [English](FEATURES.md)

> 去 Pro 化（2026-10-17，docs/02-研发计划与决策/03-不可逆决策追认表.md OS-1/OS-3）
> 建档：全产品免费单仓，无免费/Pro 区分。本文件是功能清单与编译开关的唯一权威。
> set-env（环境容器写面）已转普通免费功能，不再有 feature 门控；原免费/Pro
> 双仓归属矩阵与同步 SOP 作废。

## 一、代码面组织

| 路径 | 说明 |
|---|---|
| `core/cf-mcp/src/set_env.rs` + `set_env_tests.rs` | 环境容器写面（docs/36 §4），普通模块恒编译 |
| `core/cf-mcp/tests/cli_pro.rs` | set-env CLI 集成测试，普通测试恒编译 |
| `macos/Coffer/Support/EnvironmentContainer.swift` | 环境容器识别与 NAME 校验辅助（App 侧），恒编译 |
| `macos/Coffer/Views/ItemEditView.swift` / `ItemDetailView.swift` | 环境容器编辑 UI（标签锁 / NAME 校验 / 识别徽章），恒编译 |
| `docs/` | 全部共享 |

> 说明：`official-license`（离线激活装配，`core/cf-ffi` feature）与 FR-15 许可门禁
> 端口（`PermitAllGate` / `LicenseServicing`）是构建隔离能力与全产品通用骨架，
> 保留（OS-1），不属于 Pro 功能。

## 二、功能清单（用户可见面）

| 功能 | 状态 | 备注 |
|---|---|---|
| 本地密码库（22 类条目模板 / 自定义字段 / TOTP / 生成器） | ✅ | 核心能力 |
| 导入导出 / 备份 / 审计日志 | ✅ | |
| MCP 只读取密（`coffer mcp`） | ✅ | agent 即桥 |
| `coffer set-password` 写面 | ✅ | FR-18 |
| `coffer set-env` 环境容器写面（CLI + App 容器编辑：标签锁、NAME 校验、识别徽章） | ✅ | docs/36 |
| OTA 自更新 | ✅ | GitHub releases 渠道 |
| Agent 凭据域（完整版） | 规划 | 后续版本 |
| 多库 / 跨库复制 | ✅ | v0.4.0 已交付（FR-1.2 / FR-2.10），非门控项、非规划项 |
| Passkey 完整版（分级） | 降级版 | 保留降级读面 |

## 三、编译开关

`pro` Cargo feature 与 `COFFER_PRO` Swift 宏已随去 Pro 化（OS-3）删除，当前树内无任何引用；只剩 OS-1 的构建隔离开关：

| 开关 | 位置 | 说明 |
|---|---|---|
| Cargo feature `official-license` | `core/cf-ffi/Cargo.toml` | 保留（OS-1 构建隔离能力） |
| Swift 宏 `OFFICIAL_LICENSE` | `tools/build_macos_app.sh` | 保留（OS-1 构建隔离能力） |
