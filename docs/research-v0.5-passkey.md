# v0.5.0 技术调研：Passkey / Credential Provider（FR-10.1~10.6）

- 调研人：dev-researcher（任务 #11）；日期：**2026-09-29**；状态：**已决策**（2026-09-29 用户裁定：暂不购买 ADP，v0.5.0 走降级版；本报告结论 5/6 为裁定依据，ADP 购买后本报告重新生效）
- **修订注记（v2）**：本文件存在两次独立调研（双发事故，见任务 #11/#13 记录）——v1（commit `a92f2fa`，dev-researcher：DTS 论坛口径 + M0-⑤a 探针设计）被本 v2（dev-researcher-2：Apple 官方 capability 表实测 + 成本对比）在工作树覆写；两版结论同向，v2 证据分级更强。v1 全文可在 `a92f2fa` 检索，其探针设计在 ADP 购买后重启 #14 时仍可用
- 目标环境：macOS 14+（`01` FR-13.2）、Apple Silicon、App Sandbox、零网络（NFR-SEC-07）；`01` md5 `c7944fbf56fa92cea7cfac2709d5798e`，`09` md5 `abc2d57dfa8aa725f0fd268b331d8d18`（本报告引用其 §5-J / §2 v0.5.0 卡片时有效）
- 证据分级：【实测】= 本机复现（macOS 26.4 SDK / curl 原始 HTML / 本机文件）；【文档】= Apple 官方文档或多方一致来源；【单源】= 单一来源未交叉验证；【推测】= 未经真机验证的推断
- API 可用性一律以本机 Xcode 的 AuthenticationServices Headers / swiftinterface 实测为准（查证日期 2026-09-29），不采信训练记忆

## 结论（一句话）

**技术路径成立：macOS 14+ 标准 Credential Provider Extension（appex + `ProvidesPasskeys`）是唯一正道，API 面已全部实测确认；但「创建/使用」存在一个非技术的一票否决前置——AutoFill Credential Provider entitlement 免费账号无法签发（实测 Apple 官方 capability 表），M0-⑤ 启动的真正前提是把 E-1 的「免费证书」升级为付费 ADP（$99/年）或直接走降级版；同步矛盾不存在（第三方 provider 的私钥由 Coffer 自持，不进 iCloud Keychain，无须用户裁定）。**

## 0. 逐问结论速览

| # | 问题 | 结论 |
| --- | --- | --- |
| 1 | 架构 | 标准 appex（extension point `com.apple.authentication-services-credential-provider-ui`），macOS 14.0+ 起全量 passkey API；主 App + `Contents/PlugIns/*.appex` 双进程、静态链同一 `libcf_ffi.a` |
| 2 | 签名/profile | **免费账号覆盖不了**：capability 表实测 ADP ✓ / Developer ID ✓ / 免费 ✗；App Groups 与 Keychain sharing 免费 ✓；extension 需独立 App ID + 自带 embedded profile + 嵌套签名 |
| 3 | 同步 vs 设备绑定 | **不冲突，无须裁定**：Coffer 作为 provider 自持私钥，iCloud Keychain 不经手 |
| 4 | 存储模型 | 1PUX 桌面端无 passkey（`01` 已记录）；**Bitwarden JSON 导出含 passkey**（官方文档确认）；cf-store 建议新增结构化字段而非 attachment 旁路 |
| 5 | M0-⑤ | ADP 前置 → 扩展骨架 1~2 周 → webauthn.io 冒烟 + GitHub/Google/GitLab 真站人工闭环（自动化不划算） |
| 6 | 降级成本 | 降级版（导入/查看/删除）≈ 1~1.5 周、零签名新依赖、免费账号可交付；完整版 ≈ 5~9 周 + ADP |
| 7 | 零网络 | 扩展进程不引入网络面（XPC + 浏览器侧 HTTP）；判据②测量边界需纳入 appex 进程 |

## 1. macOS Credential Provider 架构

### 1.1 标准接入路径（appex）

第三方密码管理器接入 Safari/系统 passkey 流的唯一标准路径是 **Credential Provider Extension**（App Extension，principal class 继承 `ASCredentialProviderViewController`），不存在独立于 appex 的「AuthServices 直连」通道。

【实测】本机 `/System/Library/ExtensionKit/ExtensionPoints/com.apple.authentication-services-credential-provider-ui.appexpt`（macOS 26）：

- `NSExtensionPointIdentifier`: `com.apple.authentication-services-credential-provider-ui`
- `NSExtensionContextClass`: `ASCredentialProviderExtensionContext`
- `NSExtensionHostEntitlement`: `com.apple.authentication-services.access-credential-identities`（Apple 内部 host 侧，非开发者申请项）

【文档】`ASCredentialProviderViewController` 基类 macOS 11.0+（Apple 文档页，查证 2026-09-29）。用户启用入口：系统设置 → 密码 → 密码选项 → 自动填充来源（macOS 13 起第三方可做密码 provider；**passkey 存储自 macOS 14 开放**——`01` §5-J 已引用 Apple Platform Security，查证 2026-09-24）。

### 1.2 passkey 相关 API 面与可用性（全部本机 SDK 实测，2026-09-29）

| API | 可用性（Headers 注解原文） | 用途 |
| --- | --- | --- |
| `prepareCredentialList(for:requestParameters:)` | iOS 17.0 / **macOS 14.0** | 展示凭据选择 UI（passkey + 密码混合列表） |
| `provideCredentialWithoutUserInteraction(for:)` | iOS 17.0 / **macOS 14.0** | 无交互断言（QuickType 直填路径） |
| `prepareInterface(toProvideCredentialFor:)` | iOS 17.0 / **macOS 14.0** | 需解锁时的交互断言 |
| `prepareInterface(forPasskeyRegistration:)` | iOS 17.0 / **macOS 14.0** | 注册 UI 入口 |
| `ASPasskeyCredentialRequestParameters`（rpId / userVerificationPreference / allowedCredentials） | iOS 17.0 / **macOS 14.0** | 请求参数（rpId、UV 偏好、允许的凭据） |
| `ASPasskeyRegistrationCredential` / `ASPasskeyAssertionCredential` | iOS 17.0 / **macOS 14.0** | 注册/断言产物（回填给系统） |
| `ASCredentialIdentityStore.saveCredentialIdentities` | iOS 17.0 / **macOS 14.0** | 喂 QuickType/自动填充建议（rpId+username 元数据，无私钥） |
| `performWithoutUserInteractionIfPossible(passkeyRegistration:)`（条件注册） | iOS 18.0 / **macOS 15.0** | 可选优化，基线不需要 |
| `ASPasskeyCredentialExtensionInput`（WebAuthn 扩展输入，PRF 等） | iOS 18.0 / **macOS 15.0** | 可选，基线不需要 |

**关于 `ASCredentialProviderExtensionIdentity`（任务描述中提到的符号）**：【实测】macOS 26.4 SDK 的 AuthenticationServices Headers 与 swiftinterface 中**不存在**该符号（两处 0 命中）；ExtensionFoundation 有个 `AppExtensionIdentity`（iOS 26+，另一码事）。请 lead 核对符号出处——若来自某篇文章，可能指「请求方 App 身份」，其载体是 `ASPasskeyCredentialRequestParameters.relyingPartyIdentifier` 与 `ASCredentialServiceIdentifier`（均 macOS 14+，实测存在）。设计时按后者理解。

### 1.3 扩展进程的宿主结构（Coffer 特化）

```
Coffer.app
├── Contents/MacOS/Coffer                      ← SwiftUI 壳 + libcf_ffi.a（现状不动）
└── Contents/PlugIns/CofferCredentialProvider.appex
    ├── Contents/MacOS/CofferCredentialProvider ← 扩展二进制 + 同一 libcf_ffi.a 静态链入
    ├── Contents/Info.plist                     ← NSExtension dict（extension point + PrincipalClass）
    └── embedded.provisionprofile               ← 扩展自己的 profile
```

- 主 App 与扩展是**两个独立进程**：都静态链接 `libcf_ffi.a`（UniFFI 绑定两侧复用）；扩展内自带解锁 UI（主密码输入），不跨进程调主 App。
- **库文件可达性是结构性改动点**：现 vault 落在 `homeDirectoryForCurrentUser/Documents/Coffer/`（`macos/Coffer/AppModel.swift:250-271`），App Sandbox 下该 home 即主 App 容器——**扩展进程默认读不到**（appex 有自己的容器）。两条路：
  1. **App Group 共享容器**（推荐）：`com.apple.security.application-groups`（免费账号可用，见 §2）+ vault 位置迁移到 group 容器（一次性数据迁移）。组标识须 TeamID 前缀：`A6DS985SJJ.group.app.coffer`。
  2. 不迁移：扩展首次运行经 NSOpenPanel 让用户选 vault（user-selected read-write）——体验差，Passkey 场景的免交互断言路径（`provideCredentialWithoutUserInteraction`）拿不到文件句柄，**基本不可行**【推测，基于 sandbox 权限继承常识】。
- 扩展与主 App 并发写库的仲裁（§4.4）。

## 2. 签名 / profile 影响（E-2 的真正门槛）

### 2.1 免费账号能否覆盖 extension —— 不能（决定性发现）

【实测，2026-09-29，Apple 官方「Supported capabilities (macOS)」表格原始 HTML（curl 直取，勾选图标逐行解析）】：

| Capability | ADP（付费） | Developer ID | Apple Developer（免费） |
| --- | --- | --- | --- |
| **AutoFill credential provider** | ✓ | ✓ | **—（无）** |
| App groups | ✓ | ✓ | ✓ |
| Keychain sharing | ✓ | ✓ | ✓ |
| App Sandbox / Hardened runtime | ✓ | ✓ | ✓ |

佐证【文档】：entitlement `com.apple.developer.authentication-services.autofill-credential-provider`（macOS 11.0+，**主 App 与 extension 都必须带**，Apple entitlement 文档页）；Apple DTS 在论坛明确该 entitlement 必须经 provisioning profile allowlist，仅付费账号可做（forum thread 655154）。这与现 `make_provisioning_profile.sh` 的免费账号 ProfileGen 流程**不在同一能力级**：ProfileGen 能生成 keychain-access-groups profile，但免费 App ID 加不上 AutoFill credential provider capability。

**含义**：E-2（M0-⑤）的启动前提不是证书技术问题，而是**账号资质问题**。三条路：
1. **购入 ADP（$99/年）**——唯一正路；顺带解锁未来 notarization / Developer ID 分发（v1.0.0 审计后对外分发大概率也要）。
2. 关 SIP/AMFI 伪签【文档：DTS 明确不支持的本地测试手段】——**排除**，与可审计性矛盾。
3. 不购买 → **直接走降级版**（§6），M0-⑤ 无从启动。

### 2.2 对 build_macos_app.sh / make_provisioning_profile.sh 的影响面

| 项 | 变更 |
| --- | --- |
| App ID | 新增显式 App ID `app.coffer.Coffer.CredentialProvider`（付费账号下 Xcode 自动管理或手动注册） |
| entitlements | 新文件 `CofferCredentialProvider.entitlements`：app-sandbox + autofill-credential-provider + app-group + keychain-access-groups（同组）；主 App entitlements 也要加 autofill-credential-provider + app-group【文档：capability 须 app/extension 双侧】 |
| profile | ProfileGen 流程扩为两个 App ID 各生成一份；**appex bundle 内也要嵌自己的 `embedded.provisionprofile`**【文档；与主 App 同型，实测验证放扩展骨架阶段】 |
| 构建 | 新增第二个 swiftc 编译目标 + appex bundle 组装（`Info.plist` 含 `NSExtension → NSExtensionPointIdentifier + NSExtensionPrincipalClass`）+ **嵌套签名**（先签 appex 带其 entitlements，再签外层 app） |
| 无 Xcode 工程 | 现有「swiftc 直出 bundle」决策可延续，appex 同样可手工组装；【推测】风险点是 ExtensionKit 对 bundle 结构/版本的校验细节，需骨架阶段排雷（1~2 天量级） |

## 3. 同步 vs 设备绑定：与「数据不出本机」不冲突（无须用户裁定）

- iCloud Keychain 只同步**Apple 自家 provider**存储的 passkey。第三方 provider 的 passkey 私钥由 provider 自己生成、自己加密存储，Apple 明确「credential metadata/凭据保存在 provider app 自己的容器内」（Apple Platform Security「Credential provider extensions」页；passkey 存储开放记录同 `01` §5-J 引文）。**不存在「iCloud 接管」机制**：Safari 的注册 sheet 由用户选 provider，选 Coffer 即由扩展生成密钥对并落 Coffer 库。
- 因此「能否创建 device-bound passkey 并防 iCloud 接管」这个问题在 provider 模式下**不成立**——Coffer 存的就是非同步凭据，无需专门 API。
- `01` §5-J 已按「私钥可导出、随库加密存储」的行业惯例设计（2026-09-24 修订记录），与第三方 provider 模式自洽，无需求级矛盾。**唯一待用户裁定的是 §2.1 的付费账号问题（属 E-1 资源决策，不是 D-5 需求变更）。**

## 4. 存储模型

### 4.1 导入数据源（FR-10.1）

| 来源 | passkey 覆盖 | 依据 |
| --- | --- | --- |
| 1Password 1PUX | **桌面端导出不含 passkey**（仅 iOS/Android 可导出） | `01` §5-J 限制①（官方支持页，查证 2026-09-23），未变化 |
| **Bitwarden JSON** | **含 passkey**（官方文档：".json exports include … Stored passkeys"；CSV 不含） | Bitwarden 官方 Export Vault Data / Storing Passkeys 页，查证 2026-09-29。注意其同页声明「导出到第三方 provider 的互通计划在未来版本」——schema 非官方互操作承诺，实现期需逆向核对字段（`fido2Credentials`）【单源】 |
| Apple `ASImportableCredential` | 平台级凭据导入/导出 API（含 `.passkey` case） | 【实测】macOS 26.4 SDK swiftinterface 可见；但为 macOS 26+ API，**不在 macOS 14 基线内**，记为未来互通选项 |

### 4.2 cf-store 存放方式

推荐**新增结构化 passkey 字段**（挂在条目下），而非 attachment 式旁路：rpId / userName / credentialId / signCount / 创建时间必须可查询——凭据列表、`ASCredentialIdentityStore` 喂元数据、FR-10.2 展示全依赖字段级访问；attachment 是不透明二进制，语义 wrong。私钥材料本身复用现有字段级加密（同 `01` §5-J 限制② 的声明设计）。FR-10.6（保留原密码）天然满足——passkey 是条目的新字段，不动密码字段。

### 4.3 安全设计注意点

- signCounter 每次断言后须写回库（防克隆检测），意味着**扩展进程需要完整写路径**——扩展的解锁态管理（主密码缓存策略、Touch ID 可用性【推测：LAContext 在 appex 内通常可用，未实测】）是设计题。
- FR-10.2「不展示私钥」：导出/调试界面同样不得有私钥出口路径。

### 4.4 跨进程并发写

主 App 与扩展并发写同一库文件：cf-store 是否支持跨进程文件锁【未核实，实现前必须验证】。最简缓解：扩展侧写操作经独占文件锁串行化（`flock`），冲突概率本就低（用户操作离散）。

## 5. M0-⑤ 真机验证方案

- **前置（决定性）**：ADP 账号就位 + 扩展骨架（UI 可最简：解锁框 + 凭据列表两页）。
- **站点选择**（≥3 真实网站，创建 + 断言各一次）：先 `webauthn.io` 冒烟（开发工具站，不计入 3 站），再 GitHub / Google / GitLab / Microsoft 任选 3——这些是 1Password/Bitwarden 作第三方 provider 被最广泛验证的站点【单源/社区一致，非官方承诺；逐站兼容性以实测为准】。
- **自动化边界**：XCUITest 理论上可驱动 Safari 与系统 sheet，但扩展 UI 经 view service 跨进程呈现，脚本脆弱且 M0-⑤ 是一次性门禁——**建议纯人工**。可给 `SmokeTest` 式的 opt-in 主 App 内自检（喂 identity store 后查询）作为辅助。
- **工作量**：账号/证书 0.5 天（ADP 到账后）；扩展骨架 + 双 profile + 嵌套签名排雷 3~5 天；注册/断言最小实现（COSE/attestation 组包，Rust 侧 `p256` + CBOR，选型实现期做）3~5 天；人工三站闭环 1~2 天。**合计 ~2~3 周一人**。
- **测试账号准备**：GitHub/Google/GitLab 各备 1 个可注册 passkey 的账号（现成账号即可，Google 需要能改两步验证设置）。

## 6. 降级路径成本对比（D-5 决策依据）

| 维度 | 降级版：导入 / 查看 / 删除 | 完整版：+ 创建 / 使用 |
| --- | --- | --- |
| 账号要求 | **免费账号即可** | **必须 ADP（$99/年）** |
| 签名/build 影响 | 零（现 E-1 体系原样） | appex 目标 + 双 entitlements + 双 profile + 嵌套签名 |
| 架构影响 | 无新进程；vault 不动 | vault 迁 App Group 容器（一次性数据迁移）；跨进程写锁 |
| Rust 侧 | 1PUX/Bitwarden-JSON passkey 字段解析 + 存储 + 删除（1.5~3 天） | 上述 + COSE/attestation 组包 + 断言签名 + signCounter 写回（1~2 周） |
| Swift 侧 | 条目详情页 passkey 区块（FR-10.2 展示 + 删除确认）2~3 天 | 上述 + 扩展解锁/列表/注册 UI + identity store 同步（1.5~2 周） |
| 验证 | 门禁内回归即可 | M0-⑤ 真机三站 + 扩展进程零 socket 核查 |
| **合计** | **≈ 1~1.5 周一人** | **≈ 5~9 周一人（含 M0-⑤）** |
| 风险 | 低（纯数据面） | 平台排雷（bundle 校验、profile、并发写）＋账号依赖 |

给 lead 的口径：D-5 的分叉条件除「M0-⑤ 不通过」外，应新增一条前置——**「用户不购买 ADP」直接等价于走降级版**（连 M0-⑤ 都无法启动）。若购买，则按完整版排期且 v0.5.0 必须给足 5~9 周余量。

## 7. 零网络核实

- **扩展进程本身不引入网络面**：ASAuthorization/AuthenticationServices 是系统框架，扩展与系统/Safari 经 XPC（view service）通信【实测 appexpt 配置 + 文档】；passkey 流程中的 HTTP（challenge 获取、attestation 上送）全部发生在 **Safari/网站侧**，属浏览器 socket，不是 Coffer 进程。
- NFR-SEC-07 口径修订建议（实现期落）：① AC-07 的 `otool -L` 检查范围**加 appex 二进制**；② 出口判据②「运行时 0 socket」的测量边界**加扩展进程**（`lsof` 按两进程枚举）；③ `tools/check_no_network.sh` 依赖图侧不受影响（Rust 依赖树不变；Swift 侧本就不在其范围）。
- 残余不确定：系统设置「密码」页对 provider 的展示是否联网拉 favicon【推测：属系统进程行为，即便存在也不在 Coffer 进程边界内，判据不受影响】。

## 风险与缓解

| 风险 | 级别 | 缓解 |
| --- | --- | --- |
| 免费/付费账号资质（§2.1） | 阻断级 | 用户裁定购买 ADP 或直接降级；**任何工程开工前先定** |
| appex 手工构建（无 Xcode 工程）排雷 | 中 | 骨架阶段先用最小 appex 验证 bundle 结构与双 profile，1~2 天即知成败 |
| vault 迁 App Group 的数据迁移 | 中 | 一次性迁移 + 回滚保留旧库；迁移逻辑过门禁 |
| 跨进程并发写库 | 中 | 先验证/加文件锁（§4.4） |
| 站点对第三方 provider 兼容性参差 | 低 | 三站可替换；webauthn.io 保底可证平台链路（但不满足「真实网站」门禁） |
| Bitwarden JSON schema 非官方互操作承诺 | 低 | 解析器容错 + 测试样本锁定（`tools/make_test_sample.py` 同型） |

## 集成注意点（对当前项目的具体影响）

1. **v0.5.0 卡片（`09` §2）的依赖行应改写**：「E-1（证书）」不足以支撑 M0-⑤——须为「E-1′：ADP 账号 + 扩展双 profile 体系」；建议 lead 把 ADP 裁定提给用户后再启动 E-2。
2. `make_provisioning_profile.sh` / `build_macos_app.sh` / `Coffer.entitlements` 三处都挂在扩展骨架工单下动，避免与 v0.4 收尾工单并发改同一文件。
3. Rust 侧新增 crate（`p256`、CBOR 库）须走 NFR-LEGAL-02 许可核对 + `check_no_network.sh` 黑名单——选型留到实现期工单。
4. 本报告的「macOS 14.0+」判定基于本机 macOS 26.4 SDK 头注解——deployment target 仍为 14.0 时这些 API 全部可用（注解即最低可用版本）。

## 参考来源（均查证于 2026-09-29，另有标注者除外）

- Apple：[ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)、[ASCredentialProviderExtensionCapabilities](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionattributes/ascredentialproviderextensioncapabilities)、[AutoFill Credential Provider Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider)、[Supported capabilities (macOS)](https://developer.apple.com/help/account/reference/supported-capabilities-macos/)、[Credential provider extensions（Platform Security）](https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web)、[Supporting passkeys](https://developer.apple.com/documentation/AuthenticationServices/supporting-passkeys)
- Apple 论坛（付费账号要求佐证）：[thread 655154](https://developer.apple.com/forums/thread/655154)、[thread 666558（macOS 可用性）](https://forums.developer.apple.com/forums/thread/666558)
- Bitwarden：[Export Vault Data](https://bitwarden.com/help/export-your-data/)、[Storing Passkeys](https://bitwarden.com/help/storing-passkeys/)
- 本机实测：macOS 26.4 SDK AuthenticationServices Headers/swiftinterface；`/System/Library/ExtensionKit/ExtensionPoints/com.apple.authentication-services-credential-provider-ui.appexpt`；Apple capability 表原始 HTML；仓库 `tools/build_macos_app.sh` / `tools/make_provisioning_profile.sh` / `macos/Coffer/AppModel.swift`
