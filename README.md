# Coffer

> 一个功能对齐 1Password 8、但**完整移除了网络能力**的本地密码管理器。

面向 **Android（优先）** 与 **macOS（Apple Silicon 原生）** 两端，纯单机运行，数据永不离开设备。

> **命名**：仓库目录 `coffer` · 项目代号 **Coffer** · Rust crate 前缀 `cf-`。
> 改名已于 2026-09-24 完成 —— 当时跨 crate 代码引用仅有 1 处，是成本最低的时机。

---

## ⚠️ 当前状态（先读这一节）

坦白说清楚，避免误判进度：

| 项 | 状态 |
| --- | --- |
| 设计文档（4 份 + 标定报告） | ✅ 完成 |
| Rust 工具链 | ✅ 1.98.1（rustup 安装） |
| Rust workspace 骨架 | ✅ 11 个 crate 就位 |
| **`cf-crypto`（KDF 模块）** | ✅ **编译通过、8 个测试全绿、clippy 无警告** |
| **Argon2id 参数标定** | 🟡 开发机摸底完成，**最低端设备待做** |
| 其余 10 个 crate | ⬜ 仅占位（无任何可调用接口） |
| Android 端 | ⬜ 未开始（M3） |
| macOS 端 | ⬜ 未开始（M5） |
| 安全审计 | ⬜ 未开始（计划两阶段，见 `docs/04-系统设计.md` §12.5） |

### 必须明确的两件事

**1. 能编译、能测试，但远不是可用的软件。**

截至 2026-09-24：

| 检查项 | 结果 |
| --- | --- |
| `cargo build` | ✅ 通过，无警告 |
| `cargo test` | ✅ 8 个用例全部通过 |
| `cargo clippy --all-targets` | ✅ 无警告 |
| 工具链 | rustc 1.98.1 (2026-09-01)，aarch64-apple-darwin |

但**只有 `cf-crypto` 的 KDF 模块有实质实现**。AEAD、存储引擎、导入器、会话管理、两端 UI 全部未写 —— 其余 10 个 crate 是空占位。

> 一个值得记录的细节：这批代码最初是在**没有 Rust 工具链**的机器上、依据官方文档写成的。装上工具链后**一次编译通过**，没有出现任何 API 不匹配。

**2. 现在拿不到能用的软件。**

没有任何可安装的产物。**请不要用它存真实密码。**

---

## 这个项目在做什么

1Password 从 8.0 版本起**删除了本地独立保险库**（standalone vault），转为纯云架构，官方明确表示该功能不会回归。第三方评测至今仍把「无法本地托管保险库」列为其主要缺陷。

Coffer 要填的就是这个空位：**要 1Password 的功能，不要 1Password 的云。**

三个关键承诺：

| 承诺 | 含义 |
| --- | --- |
| **零网络可证明** | 不是"不联网"，是**没有联网能力**。Android 不申请 `INTERNET` 权限；macOS 不授予 network entitlement。任何人可用工具自行验证 |
| **迁移不失真** | 从 1Password 导入的数据，字段映射逐项可核对，未知字段不静默丢弃 |
| **原生而非 Electron** | 1Password 8 转 Electron 是社区主要抱怨点之一，本项目坚持 SwiftUI / Compose 原生 |

---

## 目录结构

```
coffer/
├── README.md                      ← 你在这里
├── CLA.md                           贡献者许可协议（保留再许可权）
├── LICENSE                          MIT
├── CONTRIBUTING.md                  贡献指南（含 CLA 要求）
├── SECURITY.md                      安全漏洞披露流程
├── CODE_OF_CONDUCT.md
├── docs/                            设计文档（4 份）
│   ├── 01-需求分析.md               做什么、不做什么、为什么
│   ├── 02-概要设计.md               分层架构、模块职责、技术选型
│   ├── 03-详细设计.md               格式规范、DDL、算法、接口签名
│   ├── 04-系统设计.md               运行时、部署、发布、威胁模型、路线图
│   └── 05-Argon2id参数标定.md       M0 标定报告（环境 + 逐档数据 + 分析）
├── core/                            Rust 工作区
│   ├── Cargo.toml                   workspace 定义（依赖版本含校准状态标注）
│   ├── rust-toolchain.toml
│   ├── cf-crypto/                   ✅ KDF 已实现，8 个测试通过
│   ├── cf-domain/                   ⬜ 占位
│   ├── cf-format/                   ⬜ 占位
│   ├── cf-store/                    ⬜ 占位
│   ├── cf-importer/                 ⬜ 占位
│   ├── cf-exporter/                 ⬜ 占位
│   ├── cf-totp/                     ⬜ 占位
│   ├── cf-audit/                    ⬜ 占位
│   ├── cf-session/                  ⬜ 占位
│   ├── cf-ffi/                      ⬜ 占位
│   └── cf-testkit/                  ⬜ 占位
├── android/                         未开始（M3）
├── macos/                           未开始（M5）
├── tools/
│   ├── inspect_1pux.py              1PUX 结构探查器（安全模式：不输出任何字段值）
│   └── make_test_sample.py          合成样本生成器（22 类 + 6 条边界情况）
└── tests/fixtures/
    └── sample_coverage.1pux         合成测试样本（内含"非真实数据"标记）
```

---

## 快速开始

### 第 0 步：Rust 工具链（已安装）

✅ `rustc 1.98.1 (2026-09-01)` / `cargo 1.98.1`，通过 rustup 以 **`--no-modify-path`**
方式安装，**没有修改你的 shell 配置**。

因此新开终端需先启用 PATH：

```bash
. "$HOME/.cargo/env"
```

> **希望全局可用**：在 `~/.zshrc` 末尾追加一行
> `[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"`
>
> **完全卸载**：`rustup self uninstall`
>
> 版本要求 ≥ 1.85（由 `getrandom` 0.4.3 的 MSRV 决定）。

### 第 1 步：编译并校准 API

```bash
cd core
cargo build
```

⚠️ **第一次 `cargo build` 大概率会报错，这是预期内的。** 需要校准的点已在 `core/cf-crypto/src/kdf.rs` 顶部列出（`Params::new` 的签名、`m_cost` 单位、枚举变体名）。校准方法：

```bash
# 用 cargo 查实际 API，而不是猜
cargo doc --open -p argon2
```

### 第 2 步：跑测试

```bash
cargo test
```

其中 `nfc_归一化使等价密码产生相同密钥` 最值得关注 —— 它覆盖了「Android 设的密码 macOS 打不开」这个经典坑。

### 第 3 步：M0 参数标定

```bash
# ⚠️ 必须用 --release，debug 构建的数字无参考价值
cargo run --release --example bench_kdf
```

产出的表请连同**设备型号、CPU、系统版本、Rust 版本**一起归档 —— 没有这些上下文，无法判断该参数在目标设备上是否成立。

---

## M0 待办（五项，必须时间盒）

| # | 事项 | 进度 |
| --- | --- | --- |
| ① | 用真实 1PUX 样本校准 `categoryUuid` 映射表 | ⏸ 待真实样本（见下） |
| ② | UniFFI 在 Android + macOS 双向打通 | ▶ **可立即开始**（Rust 已就绪） |
| ③ | 在**最低端目标设备**上标定 Argon2id 参数 | 🟡 **开发机摸底已完成**（见 `docs/05-Argon2id参数标定.md`），低端设备待做 |
| ④ | 用第三方实现交叉验证 opvault 解密 | ⏸ 待样本 |
| ⑤ | **Passkey 平台能力验证**（两端各跑通创建与断言） | ⏸ 需真机 |

**M0 必须时间盒**：设定期限，到期无论结论如何都要做决策（继续 / 调整方案 / 放弃某功能），避免在不确定性上无限期打转。

> **⑤ 为什么是必验项**：Passkey 是本项目**唯一一项"平台做不到就只能砍功能"**的技术依赖。若验证不通过，唯一选择是把它从 v1.0 移除 —— 这个决策越早做越好，拖到 M5 就是灾难。

### 如何安全地提供 1PUX 样本

M0 第 ① 项需要真实 1PUX 的**结构信息**。但 `.1pux` 是**未加密的明文导出**，里面有全部密码 —— **不要把这个文件发给任何人**。

用仓库里的探查工具，它只输出**结构骨架**，不输出任何字段值：

```bash
python3 tools/inspect_1pux.py <你的导出文件>.1pux > report.md
```

它输出键名、designation、字段类型、计数、长度区间。这些是 1Password 的**格式定义**，所有人一样，不含你的任何信息。凡是「你自己填进去的内容」——标题、用户名、密码、URL、备注、自定义字段名 —— 一个都不碰。

**完成后立即删除源 `.1pux` 文件。**

> 该工具的可信度依赖于你愿意读它。全部逻辑在一个文件里（约 390 行），可以直接打开检查输出路径上有没有碰过 `value` 之类的键。这也是本项目选择开源的同一个理由：**承诺不如可验证**。

---

## 关键决策（ADR 摘要）

| 编号 | 决策 | 结论 |
| --- | --- | --- |
| ADR-01 | 项目形态 | **纯单机**。两端各管各的库，零同步、零配对、零连接 |
| ADR-02 | 技术栈 | **Rust 核心 + 原生 UI**（Kotlin/Compose、Swift/SwiftUI） |
| ADR-03 | 加密方案 | **Argon2id + XChaCha20-Poly1305**，信封加密 |
| ADR-04 | 存储模型 | SQLite 结构明文 + 敏感字段密文 |
| ADR-05 | 库文件形态 | 工作形态=目录；交换形态=单文件 `.lvvault` |
| ADR-06 | macOS 技术栈 | SwiftUI 原生，**禁用 Electron / Tauri** |
| ADR-07 | 零网络落地 | 不申请 `INTERNET` / 不授予 network entitlement；CI 自动检查依赖树 |
| ADR-10 | Passkey 范围 | **完整能力进 v1.0**（Android API 34+ / macOS 14+） |
| ADR-11 | 开源 | **MIT** |
| ADR-13 | 系统备份策略 | 备份库文件（密文）；**不备份密钥材料与日志** |
| ADR-16 | 贡献者协议 | **许可授予型 CLA**，非 DCO（DCO 不授予再许可权） |

完整的决策背景与依据见各文档的修订记录与 `docs/04-系统设计.md`。

---

## 安全承诺与验证方法

本项目有几处能力缺口是**设计决定的必然结果**，无法通过努力弥补。这些内容同时出现在产品文档、UI 与发布说明中，不含糊：

| 缺口 | 原因 |
| --- | --- |
| **无法检测"密码已泄露"** | 需查询在线泄露库，与零网络根本冲突 |
| **主密码遗失 = 数据永久丢失** | 无服务端、无后门、无恢复机制 |
| **无跨端同步** | 架构层面的排除项 |
| **无法完全防御"整库回滚到旧版本"** | 无服务端提供时间戳权威 |
| **不承诺"删除后可防取证恢复"** | 闪存在物理层面做不到，应依赖设备全盘加密 |
| **不保证元数据完全隐藏** | 条目数量、字段数、分类、时间戳可被读取（清单见 `03` §3.5） |
| **无自动更新 → 安全补丁滞后** | 不联网的必然结果 |
| **macOS 无系统级填充能力** | 平台没有对应框架，只能靠剪贴板 |
| **Passkey 私钥可随库文件导出** | 为支持跨端搬运的必然取舍 |

**"零网络"的可验证方法**（发布后适用）：

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

---

## 贡献

请先阅读 [`CONTRIBUTING.md`](CONTRIBUTING.md)。**贡献前必须同意 [`CLA.md`](CLA.md)** —— 它让项目保留变更许可证的能力，同时你保留自己贡献的版权。

安全漏洞请勿开公开 issue，按 [`SECURITY.md`](SECURITY.md) 的流程私下报告。

---

## 许可证

[MIT](LICENSE)。Copyright (c) 2026 Coffer contributors.

本项目与 AgileBits Inc.（1Password 的开发方）**无任何关联**，也未获其授权或背书。「1Password」是其商标，本项目仅在对数据格式做互操作性描述时提及。
