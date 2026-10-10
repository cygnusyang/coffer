# Coffer 变更记录（Changelog）

本文件为**发布版变更记录**：每个已发布版本一行「主题 + 交付要点」，对齐
docs/09 §0 速览表（权威版本→交付记录）。发版时由 release.yml 取本文件
当前版本段落作为 GitHub Release body（2026-10-10 用户需求：changelog 在
release 中有体现）。

格式约定：
- 顶部为**最新版本**；每个版本段以 `## vX.Y.Z` 标题开头，release.yml 按此切取。
- 版本段内两节：`### 新增/变化` 与 `### 修复/纪律`，可按实际取舍。
- 未发版但在途的版本标 `## [Unreleased]`，发版时改为 `## vX.Y.Z` 并补日期。

---

## [Unreleased] — v2.8.0 环境容器写面

### 新增/变化
- **CLI `coffer set-env` 写子命令**（docs/36 契约冻结）：`--scope <owner> NAME=VALUE`
  原子写，owner 缺失自动建容器；`--id <UUID>` 兜底定位；`--unset` 删除；
  裸 NAME 走 stdin 取值（值不落 argv/stdout/日志，R2 纪律）；退出码 0/1/2/4。
- **App 环境容器编辑保护**：标签锁（保留标签 `coffer:environment`）+ 识别徽章 +
  NAME 校验告警 + 通用「添加字段」能力；三方识别统一 SecureNote + tag 双条件。
- 并发首写双守卫 + `prune_race` 只删空容器（防已提交写入硬删丢失）+ BUSY 有界重试。

## v2.7.0 — 2026-10-10

### 新增/变化
- **OTA 自研最小更新器**（docs/35 契约冻结）：App 内「关于 → 主动升级」，设置页排除。
  固定清单 URL（`releases/latest/download/update-manifest.json`）挂 EdDSA 签名，
  只认 4 个白名单 host；更新密钥放 CI secrets（绝不落仓）。
- **安装辅助器**（`Contents/Helpers/CofferUpdater.app` 嵌套 bundle）：单缝 relaunch
  安全门 + 静态验签（C-1/C-2 双锚），替换/回滚/Keychain 不破/profile 过期拒装。
- 零网络边界维持：更新期**最小豁免** `network.client` 一项，其余 network.* 全禁。

### 修复/纪律
- CI 上传 update-manifest 显式注入 `GH_TOKEN`（裸 gh 不读 Actions GITHUB_TOKEN）。

## v2.5.1 — 2026-10-10

### 新增/变化
- **密码更新写面 FR-18 补发**（v2.5.0 tag 先切未纳入，用户裁定归 v2.5.1）：
  App 条目「更新密码」快捷动作（FR-18.1）+ CLI `coffer set-password`（FR-18.2，
  stdin 取密不进 argv/log/ps，escrow→env 兜底 fail-closed）。

## v2.5.0 — 2026-10-10

### 新增/变化
- **主密码恢复通道**：FR-17.1 生物识别重置主密码（免旧密码）+ FR-17.2 离线恢复码
  （BIP39-12，header `recovery_wrap`）+ BUG-17 可见窗口锁定态激活自动弹 Touch ID。

## v2.4.1 — 2026-10-09

### 新增/变化
- 设置页改**独立窗口 + 左上角红绿灯**（macOS 系统设置样式，红绿灯不随内容滚动、
  随时可关闭）；标题栏强制不透明；主密码强度要求常驻 UI。
- **GitHub CI 发版自动化**：tag `v*` → 门禁 + clippy + macOS 构建签名 + 自动创建 Release。

## v2.4.0 — 2026-10-09

### 新增/变化
- 浏览器扩展整体废弃收口（App 侧集成移除）；构建双渠道 → **沙盒单渠道**；
  DEK retention 层 + unlock_with_dek 裁除。

## v2.2.0 — 2026-10-07

### 新增/变化
- **MCP 解锁托管**：HKDF 派生 `mcp_key`（非主密码本身）入 Keychain escrow；
  CLI 取密回退（托管优先 → env 兜底）；设置页 provider 翻转收口。

## v2.1.0 — 2026-10-07

### 新增/变化
- MCP 缺省 provider 翻转（自家 vault 转正）；生产级随机轮换；审计日志 subscriber；
  **UDS 传输**（D-4 §3.6 防护全套）；零网络措辞全仓改写。

## v2.0.0 — 2026-10-07

### 新增/变化
- **Agent 凭据域 / MCP**：门面 8 操作真实实现 + CofferStoreProvider feature 门控
  + `coffer mcp` 接线 + L-7 有界读取 + 缺陷收敛（M-1/M-4/L-1~L-3/L-4/L-7）。

## v1.0.0 — 2026-10-05

### 新增/变化
- 冻结 + 审计轮：不新增功能；Argon2id 标定；验收标准逐条核对（判据②③ 挂 E-6 审计采购）。

## v0.7.0 — 2026-10-05

### 新增/变化
- 1PUX 导出（FR-8.2）/ opvault 导入（FR-7.3）/ 大字号（FR-12.4）/ 生成器默认参数·
  诊断·网络自证设置项（FR-14.3~14.5）/ TOTP QR 相机扫描（FR-5.3）。

## v0.6.0 — 2026-10-04

### 新增/变化
- **商业化：注册激活**：离线序列号激活（Ed25519 本地验签）、7 天试用、到期只读门禁、
  许可信息页、闭源激活模块（构建隔离）。

## v0.5.0 — （范围并入 v2.6.0）

### 说明
- Passkey **降级版**（FR-10.1/10.2/10.5/10.6）设计基准 docs/17 r2.4，
  2026-10-09 用户裁定随 v2.6.0 重启（完整版随 ADP 购买）。

## v0.4.0 — （真机项移交 TC-M 清单）

### 新增/变化
- 菜单栏常驻、全局快捷键、模糊搜索、多库 UI、跨库复制、附件 UI、密码短语。

## v0.3.0 — 2026-09-28

### 新增/变化
- 1PUX 导入（含 `files/`）、预检报告、附件存储、条目历史、安全体检。

## v0.2.0 — （Swift UI 接线完成）

### 新增/变化
- 加密备份 / 恢复 / 校验、CSV 导出、改主密码、剪贴板清除配置、暴力退避。

## v0.1.1

### 新增/变化
- TOTP 语义补强：保留三态、只读配置 API、强度评估上移。

## v0.1.0

### 新增/变化
- macOS 纵切闭环：建库 / 主密码解锁 / 四类 CRUD / 搜索 / 回收站 / 复制+剪贴板清除 /
  自动锁定 / CSV 导入。
