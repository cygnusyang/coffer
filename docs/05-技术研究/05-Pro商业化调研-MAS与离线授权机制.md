# Coffer Pro 商业化分发机制调研报告（R1）

- 调研人：dev-researcher
- 查询日期：2026-10-15
- 状态标注：`[文档]`=Apple 官方文档原文；`[论坛]`=Apple Developer Forums（含 DTS/Engineer 答复）；`[业界]`=第三方实践/案例；`[未证实]`=未能从一手来源核实，属推断或二手传闻
- 只报事实与机制，不做路线拍板（拍板归架构师 + 用户）。

---

## 结论先行（事实摘要，不拍板）

1. **MAS 禁止序列号/激活码/自建防盗版**：Guideline 2.4.5 (vi) 原文「不得在启动时呈现许可屏、要求 license key、或实现自有 copy protection」。现有「离线序列号激活」方案**与 MAS 直接冲突**。`[文档]`
2. **StoreKit 2 验签可完全离线**：JWS 的 `x5c` 头内嵌完整证书链（Apple Root CA - G3 为末位），本地即可验签，无需联网；但**拉取**最新 entitlement 数据需联网（本地有缓存、上线时推送）。`[文档][论坛]`
3. **旧版 receipt 可本地完全离线验签**：PKCS#7 签名链追溯到 Apple 根证书 + bundle id + 版本 + 设备哈希（macOS 用 `copy_mac_address`），全部本地完成。`[文档]`
4. **换机/退款天然跟 Apple ID 走**：授权跟随账号，新机需联网拉取 entitlement（离线则拿不到）；退款通过 `revocationDate`/`Transaction.updates` 反映，离线时只能在下一次拉取时发现。`[文档]`
5. **双渠道须两套 bundle ID + 两套签名配置**（无法合并）：MAS 强制 Sandbox，Developer ID 强制 hardened runtime + notarization。`[文档]`
6. **离线授权业界完全成熟**：Ed25519/RSA 签名 license + 机器指纹（HWID）绑定 + 本地公钥验签是标准模式；但**完全离线的单一序列号（不绑机）无法防一码多机**——机器绑定要求厂商已知机器 ID（激活时至少一次联网，或人工离线交换）。`[业界]`
7. **两条路径都要求 ADP**（$99/年）：MAS 还要审核；Developer ID 不审核但必须公证（也须 ADP 会员）。`[文档]`
8. **与 Coffer 现状的吻合度**：现有「Ed25519 本地验签 + 7 天试用 + 只读门禁」正是业界标准离线授权模式；App 已启用 Sandbox。MAS 路径与现有 **OTA 自更新（2.4.5 (vii)：更新必须走 MAS）** 也冲突。Developer ID + 离线序列号 + OTA 与现有架构最吻合。`[文档][代码核实]`

---

## ① Mac App Store 付费买断路径

### 1.1 收据验证的离线性

**StoreKit 2（macOS 13+）**
- `VerificationResult` 的 JWS 签名验证**不需要网络**：WWDC21「Meet StoreKit 2」明确「x5c 头含完整证书链，因此无需互联网即可验证 JWS 签名」；Apple「Choosing a receipt validation technique」文档原文：证书链内嵌于 JWS（叶证书在前、Apple Root CA - G3 在后），可本地验证，**无需 call home**。`[文档]`
- 但**获取**交易数据需联网：`Transaction.currentEntitlements` / `Transaction.latest(for:)` / `AppTransaction.shared` 会请求 App Store 服务器；Apple App Store Commerce Engineer 在论坛确认：设备**本地缓存交易数据**，上线时推送新交易，离线时可能拿不到其他设备上的购买。离线时抛 `NSURLErrorDomain -1009`。`[文档][论坛]`
- 结论：**首次购买后**，只要本地已有缓存 JWS/entitlement，即可完全离线验证；冷启动换机/全新设备离线时无法确认付费状态。`[文档]`

**旧版 App Store receipt（PKCS#7 本地验签）**
- Apple「Validating receipts on the device」文档给出完整离线流程：
  1. `Bundle.appStoreReceiptURL`（macOS 位于 `Contents/_MASReceipt/receipt`）读取，PKCS#7 解码；
  2. 验签：签名链须追溯到 **Apple Inc. Root Certificate**（须自苹果 PKI 下载根/中间证书并**内嵌进 App**；勿硬编码中间证书，兼容 SHA-256 与 SHA-1）；
  3. 校验 bundle id（ASN.1 Field 2）与版本（Field 3）；
  4. 设备哈希校验（Field 5）——macOS/Mac Catalyst 取 `copy_mac_address`；
  5. 用 `receipt_creation_date`（Field 12）验签，避免默认取当前时间导致「签名证书过期」误判。
- Apple「Choosing a receipt validation technique」原文：「设备仅需联网让 App Store 签发收据；验证本身不需要网络」。`[文档]`
- 本地验签弱项：越狱/破解设备可绕过、无法做服务器侧最新状态校验（仅对自动续订订阅是硬要求）。`[文档]`

### 1.2 机器绑定与「是否已付费」鉴权是谁做的

- **购买绑定 Apple ID，与机器无关**：App Store 付费购买挂在用户 Apple ID 下；换机登录同一 Apple ID 重新下载即已付费（entitlement 跟随账号）。本地 receipt/AppTransaction 的机器哈希（Field 5 / `deviceVerification`）只是「此 receipt 属于本机」的防拷贝校验，**不是**付费判定依据。`[文档]`
- 本地可校验的付费相关字段：
  - `originalAppVersion`（旧版 `original_application_version`，Field 19）：「首次购买时的版本号」——付费 App 有值；沙盒环境恒为 `"1.0"`。这是「付费 vs 免费」判定的标准依据。`[文档][论坛]`
  - `AppTransaction.originalPurchaseDate` / `originalAppVersion`（StoreKit 2，macOS 13+）。`[文档]`
- **换机场景**：新机首启需联网拉取 AppTransaction/entitlement；离线无本地缓存则判定为未付费（Apple 文档明确此局限）。`[文档][论坛]`
- **退款场景**：`Transaction.revocationDate` / `Transaction.updates` 异步序列（须启动即监听）反映退款撤销；离线时只能在下一次联网拉取时发现。付费买断制退款低频，且退款流程由 Apple（reportaproblem.apple.com）主导，App 侧责任=启动时复查 entitlement。`[文档]`

### 1.3 MAS 上架要求

- **Sandbox 强制**：App Sandbox 文档「要通过 Mac App Store 分发必须启用 App Sandbox」；Guideline 2.4.5 (i)「必须适当沙盒化」。`[文档]`
- **严禁自有授权机制**：2.4.5 (vi) 原文「may not present a license screen at launch, require license keys, or implement their own copy protection」——序列号/激活码/许可屏全部禁止，Apple 用 FairPlay + 收据机制替代。论坛 DTS 对「Serial Key 保护 App」「Activation Key」询问均答会被拒。`[文档][论坛]`
- **更新必须走 MAS**：2.4.5 (vii) 原文「must use the Mac App Store to distribute updates; other update mechanisms are not allowed」——**现有 OTA 自更新器在 MAS 版不合法**。`[文档]`
- 其他：2.4.5 (ii) 只能用 Xcode 技术打包、无第三方安装器、单一独立 bundle；(v) 不得 root/setuid。`[文档]`
- 密码管理器类别：无专门类别条款，落到通用安全条款——2.5 只用公开 API（Keychain/Security 框架 OK）、2.5.13 生物识别用 LocalAuthentication、5.1 数据处理与隐私（App Store Connect 需填 App Privacy + 支持 URL + 隐私政策 URL）。**隐私清单（PrivacyInfo.xcprivacy）2024 春起 App 必须、2025-02-12 起第三方 SDK 必须**（ITMS-91061 拒收）。`[文档][论坛]`
- 审核不确定性：涉安全类 App 的审核时长/通过率无官方量化指标，属个案。`[未证实]`
- 付费买断制：价格在 App Store Connect 设定，无需配置 IAP 产品（买断无 Transaction 订阅语义，靠 AppTransaction/receipt 判付费）。`[文档]`

### 1.4 MAS 与 Developer ID 双渠道共存

- 事实：同一 App 走双渠道完全合法，常见做法是**两套 bundle ID + 两个 target/构建变体**——MAS 用 Apple Distribution 签名 + App Sandbox；Developer ID 用 Developer ID Application 签名 + hardened runtime + notarization（2019-06-01 后所有 Developer ID 分发必须公证，非人工审核是自动扫描）。两套 App ID 之后**无法合并**，须提前规划。`[文档][论坛]`
- 已确认的坑：
  - 双渠道需维护两套签名/entitlement 配置，功能/版本易漂移（升级路径分裂）；
  - MAS 版无法用自有 OTA（2.4.5 vii），Developer ID 版可以 → 同一产品的升级通道机制分叉；
  - MAS 版受 2.4.5 (vi) 约束不能带激活模块；Developer ID 版可以 → **授权模型也要分叉**。
- 对 Coffer 的含义：当前单仓单产物架构若要双渠道，等于维护两个显著分叉的构建面（Sandbox+revenue 收据 对比 hardened runtime+序列号激活+OTA）。`[推断，基于上述事实]`

---

## ② 直接分发 + 自建授权路径

### 2.1 完全离线 license 方案的业界成熟度

**模式**：非对称签名 license（RSA/Ed25519）+ 机器指纹（HWID）绑定 + 客户端内置公钥本地验签，运行期零服务器依赖。代表实现：py-rizmi（PyPI，RSA + HWID + 时钟回拨防护）、AuthForge（NuGet，离线 license 文件含 HWID 策略）、Cryptolens/Devolens 离线验证模式、LicenseSeat node-locked 文档。`[业界]`

**防重放 / 防一码多机**（关键局限，业界共识）：
- **完全离线 + 不绑机的单一序列号：无法防一码多机**——签名验签只能证明「序列号合法」，不能证明「只有一人用」。离线方案在此**无解**（无服务端激活计数）。业界明确定位：node-locked 的目标是「防 casual 分享」，不防「决意破解者」。`[业界]`
- **机器绑定（HWID 入签）**：license 明文含机器指纹 + 签名，验签时比对本机指纹。**代价**：厂商必须知道机器 ID 才能签发 → 激活时至少一次联网（用户上报指纹、厂商返回签名 license），或人工离线交换（用户导出指纹文件 → 邮件/支持 → 返回 license 文件，全离线但体验差）。绑定后运行期完全离线。`[业界]`
- 防时钟回拨：持久化 high-water mark（记录见过的最大时间戳，拒绝回拨）；py-rizmi「ClockGuard」、学术框架（SCIRP）均实证此为离线方案必做的防御。`[业界]`
- VM 克隆/双实例：纯本地无法彻底解决（克隆体指纹相同），需服务端激活身份（ActivationId + 心跳）才可观测——这已超出「零网络」范围。`[业界]`
- HWID 选型教训：避免 MAC 地址（USB 网卡/VPN 会变），用主板 UUID + 磁盘序列号 + CPU ID 等长寿命标识（scienx 案例实证）。`[业界]`
- **升级换机惯例**：提供「重置激活」/有签名的 license 迁移授权（多设备转移），避免硬件升级/故障把客户锁死——这是成熟厂商的标准做法。`[业界]`
- 与 Coffer 现状：现有「Ed25519 本地验签 + 7 天试用 + 到期只读门禁」（`core/cf-domain/src/license.rs` 端口 trait + 闭源 cf-license 注入）即上述标准离线模式；**是否已含 HWID 机器绑定 = 未证实**（闭源仓 GitLab，本仓库看不到实现；若未绑定则当前方案 =「可共享序列号」档位）。`[代码核实 + 未证实]`

### 2.2 需联网激活的第三方服务（Paddle / Lemon Squeezy）离线惯例

- Lemon Squeezy License API：激活/校验走 `api.lemonsqueezy.com` HTTPS，**必须联网**。`[文档]`
- **平台无统一离线宽限**——由各软件商自己在客户端配置「缓存 + 宽限」策略。现实案例：
  - Lactuca EULA（2026-07）：约每 30 天重新在线校验；离线时用到本地存储到期日为止；会话级宽限 3 天（最后一次成功联系服务器后离线可再启动 3 天，之后拒绝新启动）。`[业界]`
  - TontonTools：校验后 0-7 天重用缓存零联网；7-14 天尝试在线校验、失败进 7 天宽限；14 天以上转只读降级。`[业界]`
- 结论：联网授权服务都要求**运行期周期联网**（宽限只是容忍短暂离线），与「注册/验证全程零网络」卖点冲突；Coffer 现有唯一联网豁免是 OTA 4 host 白名单（`macos/Coffer/Coffer.entitlements` 的 `network.client` + 应用层 host 校验），若引入联网授权须扩展豁免面。`[业界 + 代码核实]`

---

## ③ 约束对照

| 维度 | MAS 买断 | 直接分发 + 自建离线授权 |
|---|---|---|
| Apple 前提 | ADP $99/年 + **App 审核** | ADP $99/年（Developer ID + 公证，无人工审核） |
| 服务器成本 | 无（Apple 托管） | 离线方案零服务器；可选激活服务器/支付网关 |
| 支付处理 | Apple 收单（佣金 30%，小企业计划 <$1M/年 15%） | 自建（Stripe 等）或第三方（Paddle/Lemon Squeezy，收佣金但**需联网**） |
| 注册/验证期联网 | 首次/换机拉取 entitlement 需联网；后续本地可验 | 非绑机序列号可**全程零网络**；绑机则激活期一次联网（或人工离线交换） |
| 运行期联网 | 无需（除 entitlement 刷新） | 无需（纯本地验签） |
| 自更新 | **禁止自有更新器（2.4.5 vii）**，只能走 MAS | 允许自更新（Coffer 现有 OTA 白名单架构可沿用） |
| 自有授权机制 | **禁止（2.4.5 vi）**——序列号激活不可用 | 允许（现有激活模块可沿用） |
| 审核不确定性 | 涉安全类 App 无公开量化指标 | 无审核（公证为自动扫描） |
| 与现有架构匹配 | 需砍 OTA + 砍序列号激活 + 加收据校验，分叉最大 | 保留 OTA + 保留现有激活模块，匹配度最高 |

---

## 风险与未证实清单

- Apple 根证书**内嵌重分发**的许可条款：业界普遍做法，未找到 Apple 明示的再分发许可条款原文。`[未证实]`
- 2.4.5 (vi) 的边界：论坛确认「license key / activation key / 许可屏」会被拒；但「试用期宽限 UI / 读入门禁」是否算「own copy protection」无官方明示——若走 MAS 需在提交前与审核沟通或弃用激活 UI。`[未证实]`
- 密码管理器在 MAS 的通过率/时长：无官方数据。`[未证实]`
- StoreKit 2 本地缓存的具体窗口/失效语义：Apple 文档只说「缓存本地、上线时推送」，无量化保证。`[未证实]`
- Coffer 闭源 cf-license 是否已做 HWID 机器绑定：本仓库（开源 AGPL 侧）看不到。`[未证实]`
- `AppTransaction.shared` 需联网的确切触发条件：Apple 文档明示「可能需联网」，未给白名单场景明细。`[文档][未量化]`

---

## 主要来源

- Apple「Choosing a receipt validation technique」https://developer.apple.com/documentation/storekit/choosing-a-receipt-validation-technique
- Apple「Validating receipts on the device」https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device
- Apple AppTransaction https://developer.apple.com/documentation/storekit/apptransaction
- Apple App Sandbox https://developer.apple.com/documentation/security/app-sandbox
- Apple App Review Guidelines（2.4.5 vi/vii 原文已逐条核对）https://developer.apple.com/app-store/review/guidelines/
- WWDC21「Meet StoreKit 2」https://developer.apple.com/videos/play/wwdc2021/10114/
- Apple Developer Forums「currentEntitlements without internet」（Commerce Engineer 答复）https://developer.apple.com/forums/thread/706450
- Apple「revocationDate」https://developer.apple.com/documentation/storekit/transaction/revocationdate
- Apple「Handling refund notifications」https://developer.apple.com/documentation/storekit/handling-refund-notifications
- Apple「Membership Details」（$99/年）https://developer.apple.com/programs/whats-included/
- Apple「Adding a privacy manifest」https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk
- Lemon Squeezy License Keys docs https://docs.lemonsqueezy.com/guides/tutorials/license-keys
- 离线授权业界：LicenseSeat node-locked https://licenseseat.com/node-locked-license ；py-rizmi https://pypi.org/project/py-rizmi/ ；scienx HWID 案例 https://www.scienx.com/2026/06/09/building-a-b2b-software-licensing-system-surviving-webhooks-race-conditions-and-hwid-chaos/ ；SCIRP 学术框架 https://www.scirp.org/journal/paperinformation?paperid=148310 ；Cryptolens 离线验证 https://help.cryptolens.io/examples/offline-verification
- 离线宽限案例：Lactuca EULA https://www.lactuca.io/latest/eula_es.html ；TontonTools https://www.tontontools.com/docs/licensing
