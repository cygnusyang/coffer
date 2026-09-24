# android —— Android 端

**状态：未开始**（计划 **M3** 阶段）

本目录将来放置 Android 客户端工程。当前为空，**没有任何可构建的内容**。

---

## 规划结构

```
android/
├── app/                      主应用（Kotlin + Jetpack Compose）
├── autofill/                 AutofillService 模块
├── passkey/                  CredentialProviderService（API 34+）
└── core-bindings/            UniFFI 生成的 Kotlin 绑定 + .so
```

详见 `docs/02-概要设计.md` §2.2。

---

## 开工前必须确认的几件事

这些是 Android 端特有的、**做错就会造成安全事故或数据损失**的点。开工时逐条核对：

### 1. 权限声明（安全承诺的技术基础）

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />

<!-- 明确不声明：INTERNET、ACCESS_NETWORK_STATE、ACCESS_WIFI_STATE -->
```

**`INTERNET` 权限的缺失是"零网络"的技术保证。** Android 的权限模型在此处是硬约束：没有该权限，任何 socket 创建都会抛 `SecurityException`，无绕过方式。这是需求 NFR-SEC-07 在 Android 侧的落地。

验收时必须反编译确认：`aapt dump permissions app-release.apk`

### 2. 备份策略（ADR-13）

```xml
<application android:allowBackup="true"
             android:fullBackupContent="@xml/backup_rules"
             android:dataExtractionRules="@xml/data_extraction_rules">
```

| 数据类型 | 位置 | 是否备份 |
| --- | --- | --- |
| 库文件 | `files/vaults/` | ✅ 允许（内容是密文，换机可恢复） |
| 日志 | `files/logs/` | ❌ 排除 |
| 导出文件 | `files/exports/` | ❌ 排除 |

> ⚠️ **一个必须纠正的常见误解**：`android:allowBackup` 是**开发者在 manifest 中声明的属性，用户无法在系统设置里针对单个 App 关闭它**。用户在系统设置里能关的是**整机备份**（影响所有 App）。因此 App 内必须如实告知用户，见 `docs/03-详细设计.md` §9.1。

### 3. 生物识别密钥（绝对不能可备份）

```kotlin
KeyGenParameterSpec.Builder(alias, ...)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(true)   // ← 生物特征变更即失效
```

Android Keystore 的密钥**天然不可导出**，这是好事——它保证了密钥材料不会被系统备份带走。**不要试图把密钥导出或"备份"它。**

### 4. 最低版本与降级

| 功能 | 最低 API | 低版本行为 |
| --- | --- | --- |
| Autofill | 26（Android 8.0） | 无此功能，提供"复制密码"路径 |
| Passkey | **34（Android 14）** | 隐藏相关 UI 并说明原因；密码与 Autofill 不受影响 |

---

## 交叉编译

Rust 核心需编译为 Android 目标：

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
```

构建链路（含 `cargo-ndk`、UniFFI 绑定生成、Gradle 集成）见 `docs/04-系统设计.md` §5.2。

> NDK 版本需与 Rust target 兼容，**具体版本在 M0 阶段锁定并记录**——不要凭印象选版本。

---

## 相关文档

| 内容 | 位置 |
| --- | --- |
| Android 实现要点 | `docs/03-详细设计.md` §9 |
| 自动填充机制 | `docs/02-概要设计.md` §4.5 |
| Passkey 机制 | `docs/02-概要设计.md` §4.6 |
| 阶段划分 | `docs/04-系统设计.md` §10.1 |
