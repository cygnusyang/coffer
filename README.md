# Coffer

> 一个**完整移除网络能力**的本地密码管理器。App 内不存在任何网络通信代码路径，这一条可被技术审计验证（NFR-SEC-07）。面向 macOS 与 Android，纯单机运行，数据永不离开设备。

- 命名：仓库目录 `coffer` · 项目代号 **Coffer** · Rust crate 前缀 `cf-`
- 仓库：<https://github.com/cygnusyang/coffer>
- 许可证：MIT

---

## 名字：Coffer 是什么

**Coffer /ˈkɒfər/**，名词，本义是**带锁的贵重物品箱——保险箱、钱匣**；复数 `coffers` 引申为「金库、资金」（如 *the company's coffers*）。

词源链（主流词典一致记载）：古法语 `cofre` → 拉丁语 `cophinus`「篮子」→ 希腊语 `kophinos`「筐、篮」。含义从「装东西的容器」逐步收窄为「装**贵重**东西的、上锁的容器」。

**为什么选它做项目名**：

| 层面 | 理由 |
| --- | --- |
| 语义 | 密码管理器的本质就是一个「上锁保管贵重物的容器」——不比喻、不引申，字面直给 |
| 与产品定位契合 | Coffer 是不联网的**本地箱子** |
| 形式 | 一个词、两音节、六个字母，好念好记，做仓库名与 crate 前缀都干净 |


---

## 核心特性

| 特性 | 说明 | 状态 |
| --- | --- | --- |
| **零网络可验证**（NFR-SEC-07） | 不是"不联网"，是**没有联网能力**。Android 不申请 `INTERNET` 权限；macOS 不授予 network entitlement；CI 自动检查依赖树中无网络 crate | 架构级承诺，发布后可验证 |
| **强加密** | Argon2id（RFC 9106）+ XChaCha20-Poly1305 信封加密，主密码只封装数据密钥，换密不重加密全库 | 核心原语已实现 |
| **22 类条目** | Login、Credit Card、Identity、Passport、SSH Key 等 22 类模板 + 自定义字段 | 领域模型设计完成，待实现 |
| **TOTP** | 内置验证码生成（RFC 6238），当前支持 SHA-1 | ✅ 已实现，全链路测试绿 |
| **从 1PUX / CSV 迁移** | 1PUX / CSV 导入，字段映射逐项可核对、未知字段不静默丢弃 | 导入器未实现（M2） |
| **Passkey** | 完整能力进 v1.0 | 平台验证未完成 |
| **离线安全检查** | 弱密码 / 重复密码 / 弱 URL / 陈旧密码检测 | 🟡 仅 zxcvbn 强度评估可用，检测项未实现 |
| **原生而非 Electron** | Android = Kotlin + Compose；macOS = Swift + SwiftUI | 两端 UI 未开始 |
| **开源 MIT** | 代码可审计、可验证 | ✅ |

### 零网络如何验证（发布后适用）

```bash
# Android：反编译确认无 INTERNET 权限
aapt dump permissions Coffer.apk

# macOS：确认无 network entitlement
codesign -d --entitlements - /Applications/Coffer.app

# 核心库：确认依赖树中无网络 crate
cd core && cargo tree --prefix none \
  | grep -E '^(reqwest|hyper|ureq|isahc|surf|curl|tokio-rustls|native-tls)' \
  && echo "FAIL" || echo "OK"
```

### 能力缺口（架构决定的必然结果）

- **无法检测"密码已泄露"**（需查询在线泄露库，与零网络根本冲突）
- **主密码遗失 = 数据永久丢失**（无服务端、无后门、无恢复机制）
- **无跨端同步**（架构层面的排除项；跨端只能人工导出加密文件 + 搬运）
- **无自动更新** → 安全补丁需用户手动获取

---

## 架构一览

![Coffer 分层架构](docs/assets/layered-architecture.svg)

**依赖方向严格单向**：表示层 → 绑定层 → 应用服务层 → 领域层 → 基础设施层，禁止反向依赖。加密、存储、业务逻辑全部在 Rust 核心，**两端 UI 不含任何密码学代码**。

Rust 工作区（`core/`）11 个 crate：

| crate | 职责 |
| --- | --- |
| `cf-crypto` | 加密原语封装：Argon2id KDF、XChaCha20-Poly1305 AEAD、CSPRNG、内存清零 |
| `cf-format` | 库容器结构层：头部读写、格式版本识别、格式迁移 |
| `cf-domain` | 领域模型：条目 / 字段 / 保险库、22 类模板、校验规则 |
| `cf-store` | 存储引擎：SQLite schema、加密字段读写、事务、附件、历史版本 |
| `cf-importer` | 1PUX / CSV / opvault 解析、字段映射、预检报告 |
| `cf-exporter` | 加密备份、1PUX 兼容导出、CSV 导出 |
| `cf-totp` | TOTP 生成（RFC 6238）、otpauth URI 解析 |
| `cf-audit` | 离线安全检查：弱 / 重复 / 陈旧密码检测 |
| `cf-session` | 会话与用例编排：解锁 / 锁定、权限门禁、TOTP 会话验证 |
| `cf-ffi` | 唯一对外边界：UniFFI 类型与错误映射，暴露给 Kotlin / Swift |
| `cf-testkit` | 测试夹具、合成样本生成、跨端一致性比对辅助 |

设计文档：`docs/01-需求分析.md` → `docs/02-概要设计.md` → `docs/03-详细设计.md` → `docs/04-系统设计.md` → `docs/05-Argon2id 参数标定.md`。进度追踪见 `docs/06-开发计划.md`。

---

## 当前状态与路线图

| 里程碑 | 目标 | 状态 |
| --- | --- | --- |
| **M0 技术预研** | UniFFI 双向打通、Argon2id 最低端设备标定、真实 1PUX 样本校准、opvault 交叉验证、Passkey 平台验证 | 🟡 **部分完成** |
| **M1 核心库** | Rust 核心完整可用：cf-crypto / cf-format / cf-domain / cf-store / cf-totp / cf-audit | 🔵 **进行中** |
| **M2 导入器** | 1PUX 完整导入 + CSV 导入、预检报告、映射表校准 | ⬜ 未开始 |
| **M3 macOS MVP** | 可日常使用的 macOS 端（**首版交付目标**） | ⬜ 未开始 |
| **M4 macOS 完整** | 附件、opvault 导入、1PUX 导出、Passkey | ⬜ 未开始 |
| **M5 Android 端** | 第二交付目标 | ⬜ 未开始 |

**当前进展（2026-09-25）**：

- ✅ `cargo build` 通过，`cargo test` **62 个用例全部通过**，`cargo clippy --all-targets` 零警告
- ✅ `cf-crypto`：Argon2id KDF + XChaCha20-Poly1305 AEAD + 内存清零，实现并测试通过
- ✅ TOTP 全链路：`cf-totp`（RFC 6238 SHA-1）→ `cf-store`（加密持久化）→ `cf-session`（会话门禁 + 验证），已串联打通
- 🟡 `cf-audit`：密码强度评估（zxcvbn）与基础密码生成两个函数可用；Watchtower 检测未实现
- 🟡 Argon2id 参数：开发机摸底完成（见 `05-Argon2id参数标定.md`），**最低端设备待做**
- ⬜ 6 个 crate 为纯占位（cf-format / cf-domain / cf-importer / cf-exporter / cf-ffi / cf-testkit，无任何可调用接口）；cf-store / cf-session 仅 TOTP 相关路径可用
- ⬜ **导入器、完整存储引擎、两端 UI 均未实现**

> 现在拿不到能用的软件，没有任何可安装产物。请不要用它存真实密码。
> 诚实说明：TOTP 已实现，但导入器还没有；"功能丰富"是目标而非现状。

---

## 快速开始

要求 Rust **>= 1.85**（stable channel，由 `getrandom` 0.4.3 的 MSRV 决定；工具链由 `core/rust-toolchain.toml` 固定）。

```bash
cd core

cargo build            # 编译整个 workspace
cargo test             # 62 个测试
cargo clippy --all-targets   # 零警告
```

> 若通过 rustup 以 `--no-modify-path` 安装，新终端需先 `source "$HOME/.cargo/env"`。

### 测试中的经典案例

`nfc_归一化使等价密码产生相同密钥` —— 覆盖「Android 设的密码 macOS 打不开」这个经典坑：主密码会先做 Unicode NFC 归一化再送入 KDF。

---

## 测试与质量门

| 检查项 | 结果 |
| --- | --- |
| `cargo test` | ✅ **62 个用例全部通过**（含 RFC 6238 标准测试向量） |
| `cargo clippy --all-targets` | ✅ **零警告** |
| `cargo build` | ✅ 通过，无警告 |
| 生产代码 `unsafe` / `unwrap()` / `expect()` | 🚫 编译期禁止（deny） |
| 网络依赖 | 🚫 CI 自动检查依赖树，发现即失败 |
| 测试数据 | 只允许合成样本，真实数据禁止入库 |

---

## 许可证

[MIT](LICENSE)。Copyright (c) 2026 Coffer contributors。
