# KNOWN-ISSUES —— 已知问题登记簿

> 本文件是 Coffer 项目**未修复缺陷与延后决策**的唯一登记处。
> 修复后请把状态改为 ✅ 并在 docs/06-开发计划.md 修订记录中注明。
> 登记纪律：每条必须有——现象、精确根因（有证据）、影响面、修复路径选项、当前状态。

---

## BUG-2（🔴 未修复，延后）：Touch ID 启用失败——Keychain -34018

**登记日期**：2026-09-27
**发现环境**：cygnus 真机（MacBookPro17,1 / macOS 26.6.2 / Touch ID 已录入）
**状态**：🔴 延后修复——等待签名身份决策（方案 A/B/C 见下）
**证据**：`~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`（两条 -34018 记录）

### 现象

设置页点击「启用 Touch ID 解锁」并输入正确主密码后，弹窗报：
`错误 4001：生物识别解锁不可用（Keychain 异常 -34018），请使用主密码解锁。`
K_bio 未写入，header 未变（有测试断言的补偿逻辑生效）。

### 根因（已实证）

-34018 = `errSecMissingEntitlement`。**ad-hoc 签名（临时签名）的 App 没有代码签名身份，钥匙串系统拒绝其创建带访问控制（ACL）的条目**。三条路全部实证堵死：

| 尝试 | 结果 |
| --- | --- |
| 文件型登录钥匙串 + biometryCurrentSet ACL | ❌ -34018 |
| 数据保护钥匙串（kSecUseDataProtectionKeychain=true） | ❌ -34018（DP 钥匙串访问凭证绑定 application-identifier，ad-hoc 没有） |
| 加 `keychain-access-groups` entitlement | ❌ **App 直接拒绝启动**（launchd error 163，entitlement 对 ad-hoc 非法），已回滚 |

### 修复路径（按优先级）

- **方案 A（推荐）**：cygnus 在 Xcode → Settings → Accounts 登录 Apple ID（免费账号即可），Xcode 自动生成「Apple Development」证书。构建脚本改用真证书签名 → DP 钥匙串 + biometryCurrentSet ACL 按原设计工作，**安全语义零妥协**。代码侧无需改动（`useDataProtection` 缝隙已就位）。
- **方案 B（立即可用，安全降级）**：`save/read` 改为 `requireBiometry: false`（去掉条目级 ACL），K_bio 以普通 ThisDeviceOnly 项存储；解锁时 App 层 LAContext 把关。**安全降级**：门禁从「系统强制」降为「App 自律」，理论上同用户权限的恶意程序可读取。需在 README 与 docs/08 标注。
- **方案 C**：先 B 后 A——构建脚本检测到真证书自动用 A，否则降级 B。

### 复现与诊断

1. 构建：`./tools/build_macos_app.sh && open macos/build/Coffer.app`
2. 解锁 → 工具栏「安全设置」→ 启用 Touch ID → 输主密码
3. 读证据：`cat ~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log`

### 相关改动（已落地，方案 A 时直接复用）

- `BiometricKeychain` 全接口带 `useDataProtection` 测试缝隙（默认 true）
- `DiagLog` 共享诊断日志（Support/DiagLog.swift）+ 模块内步级日志
- 回滚记录：keychain-access-groups entitlement 尝试已撤销（导致拒启动）

---

## 模板（新条目按此格式追加）

```
## BUG-N（🔴/🟡/✅ 状态）：一句话标题

**登记日期**：YYYY-MM-DD
**发现环境**：
**状态**：
**证据**：（日志/截图路径）

### 现象
### 根因（已实证 / 待查）
### 修复路径
### 复现与诊断
```
