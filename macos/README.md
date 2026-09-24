# macos —— macOS 端

**状态：未开始**（计划 **M5** 阶段）

本目录将来放置 macOS 客户端工程。当前为空，**没有任何可构建的内容**。

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
