# macos —— macOS 端

**状态：v0.1 纵切已交付（T05 完成）——建库 / 解锁 / 条目 CRUD / 搜索 / 复制 / 自动锁定 / CSV 导入全流程可用**

## 一条命令构建

```bash
./tools/build_macos_app.sh          # 产物 → macos/build/Coffer.app
open macos/build/Coffer.app         # 启动
```

- 工程组织：**swiftc + Info.plist 直出 .app bundle**（本机无 xcodegen；
  手写 pbxproj 维护成本高，理由见脚本头注释）。无 Xcode 工程依赖，
  装有 Xcode CLT 即可复现。
- 构建前置：Rust 静态库 + Swift 绑定已入库（`CoreBindings/`）；如改了 Rust
  FFI 接口，先跑 `tools/build_swift_bindings.sh`（或给构建脚本加
  `--rebuild-bindings`）。
- 零网络承诺核查（FR-14.5）：`codesign -d --entitlements - macos/build/Coffer.app`
  —— 输出除 `app-sandbox`、`files.user-selected.read-write` 外，还含 `device.camera`
  （FR-5.3 TOTP QR 扫描，T09 裁定 A）与 `keychain-access-groups`（escrow 取密），
  真实清单见 `Coffer/Coffer.entitlements`；核心断言仍是**无任何** `com.apple.security.network.*`。

## 发版流程（tag → CI 自动构建签名 + 触发 Release，v2.4.1+）

每个新 tag（`v*`）触发 `.github/workflows/release.yml`：ubuntu 可靠门禁
+ clippy → macos-latest 从 GitHub Secrets 注入签名证书与 provisioning profile，
`./tools/build_macos_app.sh --rebuild-bindings` 构建签名产物 → 打包
`Coffer-<tag>.zip`（OTA 更新载体，docs/35 §6.1 契约，App 只认 zip 覆盖）
+ `./tools/make_dmg.sh` 打包 `Coffer-<tag>.dmg`（人类手动安装包，拖拽安装）
→ 自动创建 GitHub Release，Release body 取 **`CHANGELOG.md` 当前版本段**
（发版前须在 CHANGELOG.md 登记该版本段落，缺失则流水线 fail）。

**首次前置（一次性）**——把本机签名材料导出为三个 Secrets：

```bash
./tools/export_ci_secrets.sh --push   # 导出证书+私钥 p12 / profile 为 base64 并 gh secret set
```

| Secret | 内容 |
| --- | --- |
| `APPLE_CERT_P12_BASE64` | Apple Development 证书 + 私钥 p12 的 base64 |
| `APPLE_CERT_PASSWORD` | 上述 p12 的导出密码 |
| `APPLE_PROVISIONING_PROFILE_BASE64` | `macos/build/app.coffer.Coffer.provisionprofile` 的 base64 |

**每次发版步骤**：

1. bump 版本：改 `Coffer/Info.plist` 的 `CFBundleShortVersionString`（v2.4.1 起直拷入 bundle，须与 tag 一致，见 `coffer-v241-settings-done-button` 纪律）；
2. 在 **`CHANGELOG.md`** 登记当前版本段落（`## vX.Y.Z` 标题 + 新增/修复，缺失则流水线 fail）；
3. 本地过一遍 `./tools/run_gate.sh`（全绿才打 tag）；
4. 若 profile 临近 7 天有效期，重跑 `make_provisioning_profile.sh` + `export_ci_secrets.sh --push` 刷新（免费账号 profile 7 天有效，过期流水线会红）；
5. `git tag vX.Y.Z && git push origin vX.Y.Z`；
6. 到 GitHub Actions 看流水线 → Releases 页收 `Coffer-<tag>.dmg`（手动安装）与 `Coffer-<tag>.zip`（OTA）。

产物为 App Sandbox + `keychain-access-groups` entitlements、profile 内嵌的
签名 `.app`（zip 包）——与本地 `build_macos_app.sh` 方案 A 签名线同源，
**不回退 ad-hoc**（BUG-2 纪律）。零网络承诺核查同「一条命令构建」节。

## coffer CLI（MCP 解锁托管，v2.2.0）

`coffer`（`coffer mcp` MCP 服务器，docs/20）**随 App bundle 分发，不独立安装**：

- **路径**：`macos/build/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer`
  （装配为**嵌套 bundle** `coffer.app`，构建脚本 `tools/build_macos_app.sh` step 3.5 自动完成）。
- **必须从 App 内路径运行**：把该二进制拷出到任何位置再运行 → **SIGKILL（exit 137）**。
  原因一句话：AMFI 按可执行文件最近的 `.app` bundle 查找 provisioning profile 来授权
  `keychain-access-groups` entitlement；拷出后没有 bundle/profile 覆盖，进程 spawn 即被
  内核 SIGKILL（D-6 spike 与 G5 装配真机实证）。这是**用户可见纪律**，不是 bug。
- 为什么是嵌套 bundle 而非裸 `Contents/MacOS/coffer`（G5 装配实证）：
  ① `Contents/MacOS/Coffer`（App 主可执行文件）与 `Contents/MacOS/coffer` 在 macOS 默认
  case-insensitive APFS 上是同一文件名，无法共存；② 裸 Mach-O（非主可执行文件）即使同
  bundle 内嵌 profile，AMFI 也只对最近 `.app` 的**主代码**应用 profile——带
  `keychain-access-groups` 的裸 CLI spawn 即 SIGKILL；嵌套 `.app` bundle 自带
  `embedded.provisionprofile` 才获得覆盖。
- **注册命令示例**（Claude Code，docs/20 §5.4 同构）：

  ```bash
  claude mcp add coffer -- "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer" mcp --provider op --vault <vault>
  ```

  注意 `mcp` 子命令**必须显式给出**（CLI 不识别裸 `--help`；缺子命令打印 usage 并以 1 退出）。

## 浏览器扩展 host（v2.3.0 G-E）—— 已废弃

> **废弃注记（2026-10-09）**：浏览器扩展**整体废弃**（用户裁定，扩展连商城上架都不要），App 侧集成已移除。本节 `browser-agent` / `browser-broker` / shim 装配说明作废留档；嵌套 bundle coffer 二进制仍随 App 分发（coffer CLI，见上节），`browser-*` 子命令不再使用。设计文档已归档 `docs/archive/31-v2.3.0设计-浏览器扩展.md`。

## 当前已有内容

- `Coffer/` —— SwiftUI 应用（App 壳 / 建库 / 解锁 / 条目列表·详情·编辑 /
  回收站 / CSV 导入 / Clipboard·AutoLockMonitor 平台层）。
- `Coffer/CoreBindings/` —— UniFFI 生成的 Swift 绑定（**由
  `tools/build_swift_bindings.sh` 生成，勿手改**）。
- `Coffer/SmokeTest/main.swift` —— swiftc 冒烟样例（链接静态库验证
  Rust ↔ Swift 全链路），编译命令见 `tools/build_swift_bindings.sh` 尾部注释。
- v0.1 明确不做（推后清单见 `docs/07-macOS纵切设计.md` §1.2）：Touch ID、
  菜单栏常驻、全局快捷键、Passkey、1PUX 导入。
- **Touch ID 现状补充**：代码已完成（`docs/08-TouchID解锁设计.md` T01–T04），
  但被 **BUG-2（Keychain -34018，ad-hoc 签名无代码签名身份）** 阻塞，
  **真机上尚不可用**；解锁流程的真机端到端验收（08-T05）待 cygnus 执行。
  详见 `docs/KNOWN-ISSUES.md` BUG-2。

---

## 规划结构

```
macos/
├── Coffer.xcodeproj
├── Coffer/                SwiftUI 应用
│   ├── Views/
│   └── Platform/              平台适配（Keychain / Touch ID / 剪贴板）
├── CoreBindings/              UniFFI 生成的 Swift 绑定
└── Frameworks/                libcf_ffi.a + modulemap
```

详见 `docs/02-概要设计.md` §2.2。

---

## 开工前必须确认的几件事

### 1. Entitlements（安全承诺的技术基础）

```xml
<!-- Coffer.entitlements -->
<key>com.apple.security.app-sandbox</key>                    <true/>
<key>com.apple.security.files.user-selected.read-write</key> <true/>
<key>com.apple.security.device.biometric</key>               <true/>

<!-- 明确不包含： -->
<!-- com.apple.security.network.client -->
<!-- com.apple.security.network.server -->
```

**不授予 network entitlement 是 macOS 侧"零网络"的技术保证。** Hardened Runtime 下不给该权限，App 无法发起网络连接（系统层面拒绝）。

验收时必须确认：`codesign -d --entitlements - Coffer.app`

### 2. Keychain 的 `ThisDeviceOnly`（隐蔽的数据外流通道）

```swift
SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,   // ← 关键
    .biometryCurrentSet,
    &error
)
```

> ⚠️ **iCloud 钥匙串同步是一个隐蔽的数据外流通道。**
>
> 若不用 `ThisDeviceOnly`，生物识别密钥会**随 iCloud 同步到其他设备**——"零网络"承诺会被系统级通道静默绕过。
>
> 必须区分两类东西：**密钥材料**绝对禁止跨设备；**数据**（库文件，密文）允许被 Time Machine 备份。混为一谈会犯两种相反的错，见 `docs/03-详细设计.md` §10.4。

### 3. 自动填充方案（已定：剪贴板）

macOS **没有** Android 那样的系统级 Autofill 框架，第三方 App 无法在其他 App 的输入框中直接注入文本。

已定采用**剪贴板方案**：写入剪贴板 + 提示粘贴 + 定时清除。**不采用**辅助功能（Accessibility）模拟键盘方案——权限过重，与最小权限原则冲突。

实现细节（含 `changeCount` 检查，防止误清用户后来复制的内容）见 `docs/03-详细设计.md` §10.3。

> 该体验差距需在用户文档中明确说明，避免用户误判为 bug。

### 4. 系统版本与架构

| 项 | 要求 |
| --- | --- |
| 最低系统 | **macOS 14（Sonoma）** —— 该版本同时是 Apple 开放第三方 Passkey 存储的起点 |
| 架构 | **仅 arm64 原生**，不做 Intel 版本，不做 universal binary |
| 分发 | **appstore 沙盒单渠道**（2026-10-09 起，双渠道 developer-id 已取消） |

---

## 构建链路

```
core/ (Rust)
  └─ cargo build --release --target aarch64-apple-darwin
       └─ libcf_ffi.a (staticlib)
            ├─ UniFFI 生成 Swift 绑定
            └─ 链接进 Xcode 工程
                 └─ codesign --options runtime → notarytool submit → stapler staple
```

详见 `docs/04-系统设计.md` §5.3。

---

## Passkey 边界声明（降级形态，v2.6.0）

macOS 端 Passkey 为**降级形态**（FR-10.1 导入 / 10.2 查看 / 10.5 删除 / 10.6 保留密码；创建与使用不在本版），三条诚实边界如下：

1. **创建/使用能力 absent（TCB-4）**：本版**无凭据提供者扩展**——系统设置里不会出现 Coffer 提供者，网站/App 无法选择 Coffer 创建或使用 Passkey。这不是「有菜单但禁用」，是能力不存在。用户文档明示。
2. **iCloud 不同步是特性**（lead 裁定沿用）：Passkey 私钥存 Coffer 自有加密库，**不经 iCloud Keychain**（第三方提供者路径下同步从设计上不存在）；跨设备 = 库文件搬运（加密备份/恢复）。用户文档主动声明。
3. **数据源边界**：桌面端 1PUX **无 Passkey**——1Password 桌面端导出的 1PUX 不含 Passkey（官方明确只有 iOS/Android 能导出）。已用 1Password 桌面版的用户首建数据需 iOS/Android 导出或改用 Bitwarden JSON，或网站重新注册（ADP 后）。这条无法通过技术绕过，用户文档明示。

> 完整版（凭据提供者扩展 + 创建/断言）随 ADP 购买后重启——机制设计见 `docs/02-概要设计.md` §4.6，要点摘录见 `docs/17-v0.5实现方案.md` §9（休眠）。

---

## 相关文档

| 内容 | 位置 |
| --- | --- |
| macOS 实现要点 | `docs/03-详细设计.md` §10 |
| Passkey 机制 | `docs/02-概要设计.md` §4.6 |
| 构建与发布管线 | `docs/04-系统设计.md` §5.3 |
| 阶段划分 | `docs/04-系统设计.md` §10.1 |
