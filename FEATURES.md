# FEATURES.md —— 免费 / Pro 功能归属矩阵

> 免费/Pro 隔离轮（2026-10-11）建档。本文件是**唯一权威归属清单**：任何新功能
> 落地时在此登记归属，任何免费/Pro 同步操作以本文件为核对基准。
>
> 双仓模型：**Pro trunk**（自托管 GitLab `coffer-pro`，私有，开发主线）与
> **免费版**（GitHub `cygnusyang/coffer` 公开 + GitLab `coffer` 镜像，AGPL-3.0）。
> 免费版 = Pro 主线的裁剪发布，同步机制见文末。

## 一、代码面归属（目录级）

| 路径 | 归属 | 说明 |
|---|---|---|
| `core/cf-mcp/src/set_env.rs` + `set_env_tests.rs` | **Pro 专属** | 环境容器写面（docs/36 §4）；免费仓不存在 |
| `core/cf-mcp/tests/cli_pro.rs` | **Pro 专属** | set-env CLI 集成测试（整文件 `#![cfg(pro)]`）；免费仓不存在 |
| `core/cf-mcp/tests/common/mod.rs`、`tests/cli.rs` | 共享 | 免费侧同文（pro 关时 cli_pro 编译为空） |
| `core/` 其余全部（cf-store / cf-session / cf-crypto / cf-domain / cf-ffi …） | 共享 | 核心库两侧一致 |
| `macos/Coffer/Pro/` | **Pro 专属** | `EnvironmentContainer.swift`；免费仓不存在 |
| `macos/Coffer/Views/ItemEditView.swift` / `ItemDetailView.swift` | 共享 | Pro 段以 `#if COFFER_PRO` 门控，两侧同文 |
| `tools/build_macos_app.sh` | 共享 | `Pro/` 目录存在即注入 `-DCOFFER_PRO`（两侧同文，唯一差异 = 目录有无） |
| `docs/` | 共享为主 | 归档文档（`docs/archive/`）仅在免费仓归档 Pro 专属设计 |

## 二、功能归属（用户可见面）

| 功能 | 免费 | Pro | 备注 |
|---|---|---|---|
| 本地密码库（22 类条目模板 / 自定义字段 / TOTP / 生成器） | ✅ | ✅ | 核心能力 |
| 导入导出 / 备份 / 审计日志 | ✅ | ✅ | |
| MCP 只读取密（`coffer mcp`） | ✅ | ✅ | agent 即桥 |
| `coffer set-password` 写面 | ✅ | ✅ | FR-18 |
| OTA 自更新 | ✅ | ✅ | 渠道不同：免费 GitHub releases / Pro GitLab permalink |
| **环境容器写面**（`coffer set-env` + App 容器编辑：标签锁、NAME 校验、识别徽章） | ❌ | ✅ | docs/36；免费版保留 `coffer:environment` 读面兼容（打开含容器的库不丢数据） |
| Agent 凭据域（完整版） | 规划 | ✅ | 后续版本 |
| 多库 | 规划 | ✅ | 后续版本 |
| Passkey 完整版（分级） | 降级版 | ✅ | 免费侧保留降级读面 |

## 三、编译开关

| 开关 | 位置 | 免费 | Pro |
|---|---|---|---|
| Cargo feature `pro` | `core/cf-mcp/Cargo.toml`（default 数组） | 关（default 只含 `coffer-store`） | 开 |
| Swift 宏 `COFFER_PRO` | `tools/build_macos_app.sh`（按 `Pro/` 目录有无自动） | 不定义 | 定义 |

共享文件中的门控行（cfg / #if）**两侧仓库同文**——同步时零冲突；免费仓的
Pro 专属文件直接不存在（非注释、非空壳），杜绝 Pro 代码进入免费分发面。

## 四、免费/Pro 同步机制（维护 SOP）

1. **开发一律在 Pro trunk**（GitLab `coffer-pro` main）。
2. 新功能落地时在本文件登记归属（第二节表格 + 第一节目录表）。
3. **共享改动**（核心库 / 共享 Views / docs）→ 直接 cherry-pick 到免费分支，零冲突。
4. **Pro 专属改动** → 只在 Pro trunk，永不挑到免费分支。
5. 免费分支同步固定步骤：
   ```bash
   # 在 free-carve 分支（本地 worktree）
   git cherry-pick <共享提交…>
   git rm -r --ignore-unmatch core/cf-mcp/src/set_env.rs core/cf-mcp/src/set_env_tests.rs \
     core/cf-mcp/tests/cli_pro.rs macos/Coffer/Pro/
   # Cargo.toml：default 数组去掉 "pro"（唯一的手工差异行）
   PATH="$HOME/.cargo/bin:$PATH" cargo test --workspace   # 免费侧门禁
   # 双推：GitHub（走代理）+ GitLab
   ```
6. 门禁要求：Pro 侧 `cargo test --workspace`（默认含 pro）+ `cargo test -p cf-mcp
   --no-default-features --features coffer-store`（免费形态模拟）双侧绿后方可推送。
