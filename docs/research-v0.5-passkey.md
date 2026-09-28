# v0.5.0 技术调研：Passkey / Credential Provider（FR-10.1~10.6）

- 调研人：dev-researcher；日期：**2026-09-29**；状态：供 v0.5.0 / M0-⑤（`09` §2 v0.5.0、§5 E-2）选型与启动条件核验
- 需求基线：`01` §4.J FR-10.1~10.6（含两条风险提示：macOS 无 Passkey 数据源、私钥可导出须知情）；`09` v0.5.0 卡片（M0-⑤ 分叉判据、E-1→E-2 依赖）；macOS 14+、App Sandbox、零网络（数据不出本机）
- 证据分级：【实测】本机复现；【文档】Apple 官方或多方一致来源；【单源】单一来源未交叉验证；【推测】未验证推断

## 结论（一句话）

**macOS 14 起第三方凭据提供者扩展（ASCredentialProviderViewController + autofill-credential-provider entitlement）是「创建/使用 Passkey」的唯一官方路径，该 entitlement 须由 provisioning profile 授权且 Apple DTS 明示仅付费账号可行——这使 E-2 的启动条件「E-1 已就位」很可能不成立（免费证书拿不到 entitlement），M0-⑤ 第一步应先做一个约 1 小时的 entitlement 探测，探测不过则降级路径（导入/查看/删除，纯库功能无需 entitlement）成为 v0.5.0 实际交付面；Passkey 数据全程存 Coffer 自有加密库，不经 iCloud，与「数据不出本机」无冲突、无须禁用同步。**

## 1. 平台机制：第三方凭据提供者扩展（【文档】）

- 扩展类型：App Extension（`.appex`，嵌入宿主 `Contents/PlugIns/`），`NSExtensionPointIdentifier = com.apple.authentication-services-credential-provider-ui`，主类继承 `ASCredentialProviderViewController`（macOS 11.0+ 可用）。
- 用户启用路径（macOS 13+）：系统设置 → 通用 → 登录项与扩展（Sonoma 起）/ 扩展面板，选中该提供者；「密码选项」面板管理 iCloud Keychain 与自动填充开关。
- macOS 14（Sonoma）起开放第三方**存储 Passkey**（与 `01` §4.J 表格记载一致）。Passkey API 面（均 macOS 14.0+）：
  - 注册：`prepareInterface(forPasskeyRegistration:)` / `performWithoutUserInteractionIfPossible(passkeyRegistration:)` → `completeRegistrationRequest`；
  - 断言：`provideCredentialWithoutUserInteraction(for:)` 处理 `ASPasskeyCredentialRequest`（含 challenge）→ `completeAssertionRequest`；
  - 无 UI 直通：`prepareCredentialList(for:requestParameters:)`（`ASPasskeyCredentialRequestParameters`）；
  - AutoFill 建议列表：`ASCredentialIdentityStore` 写入 `ASPasskeyCredentialIdentity`（仅 rpId+用户名等元数据，明文不含密码/私钥）。
- 「密码元数据存在提供者 App 自有容器内，卸载即清除；OS 仅在填充时向扩展取密码」【文档：Apple Platform Security「Credential provider extensions」】。

## 2. 关键门槛：entitlement 与免费账号（本研究最重要的发现）

- 所需 entitlement：`com.apple.developer.authentication-services.autofill-credential-provider`（宿主 App 与扩展**都要**）。【文档：Apple entitlements 文档，macOS 11.0+】
- **Apple DTS（Quinn）原文**：「The entitlement in question … must be allowlisted by a provisioning profile and that's only possible for a paid account.」（developer.apple.com/forums/thread/661139，2020 年口径；后续未见放开记录，未见需要表单申请——Xcode 里 Paid 团队直接开 capability）。【文档：Apple 工程师答复；年代较久，故 §6 置了廉价实测探针】
- 本项目现况对照：E-1 已就位 = **免费** Apple Development 证书 + 手工 profile 机制（`tools/make_provisioning_profile.sh`：ProfileGen 假工程 + `xcodebuild -allowProvisioningUpdates`）。该机制已验证免费账号能拿到 `keychain-access-groups` 授权，但**能否拿到 autofill-credential-provider 未经证实**——Quinn 口径下不能。
- 与 `09` §5 的冲突点：E-2 现载「启动条件 = E-1 证书就位」且 E-1 标注「M0-⑤ 启动条件满足」。按本研究，**该评估很可能不成立**：免费证书大概率开不出该 capability。这不推翻「证书已就位」事实，但推翻「就位即够 M0-⑤ 用」的推论。若坐实，v0.5.0 的真实前置是 **E-7（付费账号 $99/年）提前**——原本只为 v1.0.0 公证分发（E-7 已在依赖表），不是新增投入，是**提前**。
- 附带发现（影响 v1.0.0 分发模式）：Developer ID profile 也曾被报「AutoFill Credential Provider capability is not available for Developer ID provisioning profiles」（thread/691927，Xcode 13 时代）【单源，后可能有变化】。若 v1.0.0 维持「MIT 源码 + 用户自建」（E-7），则**用户自建出的 Coffer 无付费账号也拿不到该 entitlement，Passkey 创建/使用在自建分发下可能整体不可用**——需在 v1.0.0 分发模式决策时一并裁定，本研究只登记不裁定。

## 3. iCloud 同步问题：「数据不出本机」裁定核查

- 第三方提供者的 Passkey **不存在 iCloud Keychain 参与**：凭据与私钥存提供者自有数据面（本项目即 Coffer 加密库，Rust core，随库文件走）；iCloud Keychain 同步只作用于 Apple 自家密码管理器的凭据。【文档：Apple Platform Security（元数据在提供者容器）+ API 结构（系统只在填充时向扩展取数据）】
- 因此「能否显式禁用同步」这个问题的答案是：**无须禁用——同步能力在第三方路径下从设计上就不存在**。用户文档中反而应主动声明「Coffer 的 Passkey 不跨设备同步，跨设备靠库文件搬运」（与 FR-10 风险提示 2 一致）。
- 已知限制（【单源】社区一致经验，待 M0-⑤ 顺带验证）：FIDO2 跨设备传输（QR/iPhone hybrid）只对 iCloud Keychain 开放，第三方提供者的 Passkey 不参与该流程。对本项目无碍（零网络反而要求如此），但应写进用户文档。

## 4. Sandbox / entitlements / profile 影响（对现有构建体系）

- 扩展独立进程、独立签名：自己的 entitlements（app-sandbox=true + autofill-credential-provider + 与宿主相同的 keychain-access-groups 组以共享钥匙串）、自己的 Info.plist（NSExtension 声明）、同一 Team 签名 + 各自 profile。**宿主 App 也要加该 entitlement**【文档】。
- 构建脚本影响：`tools/build_macos_app.sh` 需扩展为组装 `.appex`（`Contents/PlugIns/`）+ 双 profile 嵌入。工作量有限（现脚本已手工组装 .app），但属于新增构建面。
- **宿主与扩展共享库文件的数据面**（M0-⑤ 必须解决的设计点）：
  - 钥匙串侧：现有 `keychain-access-groups`（`A6DS985SJJ.app.coffer.Coffer`）扩展侧加同名组即可共享【文档：TN3137 访问组语义】；
  - 库文件侧：主 App 的库文件路径来自 NSOpenPanel（`user-selected.read-write`），**security-scoped 授权不会自动传给扩展**——扩展要么经 App Group 容器放共享数据（免费账号 App Groups 可用性未验证），要么在扩展 UI 内让用户重选文件。推荐在 M0-⑤ 探针里同时验证这两条。
- 零网络影响：AuthenticationServices 扩展链路无网络框架诉求；判据②口径（运行时 0 socket）在扩展进程上同样适用，验证时 `lsof` 须覆盖扩展 PID。

## 5. M0-⑤ 真机验证方案（E-2 落地设计）

建议把 M0-⑤ 拆为两步，**第 0 步是新增的、极廉价、应在排任何工期前先做**：

| 步骤 | 内容 | 通过判据 | 成本 |
| --- | --- | --- | --- |
| **M0-⑤a（entitlement 探针，新增建议）** | 复用 ProfileGen 机制：假工程加 `autofill-credential-provider` capability + `xcodebuild -allowProvisioningUpdates`（免费账号），profile 生成后 `security cms -D` 查 entitlement 是否入 profile；再加最小 `.appex` 骨架签名验证 spawn 不被杀 | profile 含该 entitlement 且扩展进程可启动 | ~1 小时 |
| **M0-⑤b（功能验证，原定义）** | 最小 Demo（独立探针 App，非 Coffer）：Safari 在 ≥3 个真实网站（建议含一个支持条件式注册的）分别跑 创建 Passkey → 选择 Coffer 探针 → 登录断言闭环；另验 扩展无 UI 直通、锁定态拒绝、0 socket（含扩展 PID） | 3 站点创建+断言全闭环 | 1–2 天 |

- M0-⑤a 通过 → 付费账号不是前置，E-2 按原计划；M0-⑤a 不过 → E-2 前置改为 E-7（付费账号提前），**或**直接走 D-5 降级（须用户确认，`01` MoSCoW 同步改）。
- 探针不过的判读要诚实：xcodebuild 报错文案（capability 不可用 vs profile 生成失败）都落盘留证，避免「静默零匹配」式误判。

## 6. 降级路径（M0-⑤ 不通过 / D-5）

降级面 = FR-10.1 导入 / FR-10.2 查看 / FR-10.5 删除 + FR-10.6（保留密码，设计约束）——**全部是纯库功能，不需要任何 entitlement**：

- 导入：1PUX 的 Passkey 字段解析（macOS 桌面端 1PUX 无 Passkey，数据源只有 iOS/Android 导出——`01` 已定论）；核心理解为新增一种条目数据类型 + 加密存储，v0.2 起的库格式设计里 Passkey 字段是否已预留**须由 dev-architect 核实**（本研究未查库格式文档）【推测：未核实】。
- 查看：rpId、用户名、创建时间、签名计数器、凭据 ID（不展示私钥——`01` FR-10.2 已定）。
- 删除：删除即提示后果（FR-10.5 文案）。
- 降级下 v0.5.0 的出口判据①②（创建/断言）整体作废，改以「导入回环 + 查看展示 + 删除」为判据——这是需求变更，须人类确认（D-5），本研究只提供技术边界。

## 风险与缓解汇总

1. **免费账号拿不到 entitlement（高概率，高影响）**→ M0-⑤a 探针先行；不过则付费账号提前（E-7 前置到 v0.5.0）或降级。
2. **用户自建分发下 Passkey 可能整体不可用（v1.0.0 层面）**→ 登记，分发模式决策时裁定。
3. **扩展与宿主共享库文件路径无现成方案**（security-scoped bookmark 不继承）→ M0-⑤ 探针同时验证 App Groups（免费账号可用性未验证）与扩展内重选两条路。
4. **数据源缺失确定存在**（桌面 1PUX 无 Passkey，`01` 已定）→ 用户文档明示「首建靠网站重新注册」。
5. **API 行为细节以真机为准**（论坛口径多为 2020–2023，跨多个大版本）→ 本报告所有平台行为断言在 M0-⑤ 真机环节复验后再进实现规格。

## 集成注意点（对当前项目）

- `docs/09` §5 E-2 的「启动条件 = E-1 证书就位」建议由 lead 决定是否先按本研究改为「E-1 + M0-⑤a 探针通过」——这是一处文档级修正，不改代码。
- 库格式是否已预留 Passkey 字段是降级路径可行性的前提，建议派给 dev-architect 查 `03`/`04`（本研究未覆盖）。
- Rust core 侧 Passkey 数据类型/加密封装完全独立于扩展机制，无论降级与否都是第一步（与 v0.4 后的内核工作不冲突）。
- 出口判据②（0 socket）验证面在 v0.5.0 扩大到含扩展进程。

## 依据（查询日期 2026-09-29）

- Apple：AutoFill Credential Provider entitlement 文档（macOS 11.0+）：https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider
- Apple：ASCredentialProviderViewController（Passkey API 面 macOS 14.0+）：https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller
- Apple Platform Security：Credential provider extensions（元数据存提供者容器）：https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web
- Apple 论坛 661139（Quinn：entitlement 须 profile 授权、仅付费账号）：https://developer.apple.com/forums/thread/661139
- Apple 论坛 691927（Developer ID profile 不支持该 capability，Xcode 13 时代）：https://developer.apple.com/forums/thread/691927
- Apple 论坛 666558（macOS App Store 校验曾误报该 entitlement，后修复）：https://developer.apple.com/forums/thread/666558
- 仓库内：`tools/make_provisioning_profile.sh`（免费账号 profile 机制）、`docs/09` §5 E-1/E-2/E-7、`docs/01` §4.J FR-10
