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
  —— 输出只应包含 `app-sandbox` 与 `files.user-selected.read-write`，
  无任何 `com.apple.security.network.*`。

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

## 浏览器扩展 host（v2.3.0 G-E）

浏览器 native messaging 的 host 复用嵌套 bundle 里的 `coffer` 二进制（docs/31 §2.1 D-2）：

- **`browser-agent`**（浏览器 spawn 的 host，薄中继）：manifest `path` 不能传参、浏览器
  把扩展 origin 作为 argv[1] 注入（P-S spike 实证）——故 manifest `path` 指向 **shim**，
  由 shim 补 `browser-agent` 子命令并 `exec` 真正的 coffer 二进制（保 PID/父进程链，
  host 验父进程 = 浏览器仍成立）。
- **shim 路径**：`macos/build/Coffer.app/Contents/Helpers/coffer-shim`（签名 Mach-O，
  源码 `tools/coffer-shim.c`，构建脚本 step 3.5 自动编译+同身份签名，**无受限
  entitlement**，AMFI 门禁不适用）。shim 相对自身解析 coffer 二进制路径，App 被移动/
  重装后无需改 manifest。
- **`browser-broker`**（长驻 daemon，持解锁会话）：由 App 直接 spawn，**不走 manifest/
  shim**，无需注册。
- 真机验证：嵌套 bundle 双 codesign --strict 过；bundle 内调用 exit 0/1（AMFI 放行）、
  拷出 137（拷出即 SIGKILL 纪律与 coffer CLI 一致）。

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
│   ├── Platform/              平台适配（Keychain / Touch ID / 剪贴板）
│   └── PasskeyExtension/       凭据提供者扩展（macOS 14+）
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
| 分发 | Developer ID 签名 + Hardened Runtime + 公证（Notarization） |

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

## Passkey 的额外复杂度

macOS 侧的 Passkey 实现复杂度**显著高于 Android**，原因有二：

1. **进程边界**：凭据提供者扩展是**独立进程**，而 DEK 只存在于主 App 会话中。两者之间如何传递凭据需要专门设计。
2. **能力限制**：扩展有内存与执行时间约束，不能长时间持有解密数据。

**已定的设计原则**：**扩展只做轻量代理 —— 向主 App 请求一次签名，DEK 永不进入扩展进程。**

这条原则的作用是把私钥暴露面锁在主 App 内，扩展被攻破也拿不到库密钥。详见 `docs/02-概要设计.md` §4.6。

> ⚠️ 另有一条硬限制：macOS 端 **Passkey 没有数据源** —— 1Password 桌面端导出的 1PUX **不含 Passkey**（官方明确只有 iOS/Android 能导出）。因此 macOS 端首次建立 Passkey 只能靠两条路：① 在网站重新注册；② 从 Android 端库文件搬运。**这条无法通过技术绕过。**

---

## 相关文档

| 内容 | 位置 |
| --- | --- |
| macOS 实现要点 | `docs/03-详细设计.md` §10 |
| Passkey 机制 | `docs/02-概要设计.md` §4.6 |
| 构建与发布管线 | `docs/04-系统设计.md` §5.3 |
| 阶段划分 | `docs/04-系统设计.md` §10.1 |
