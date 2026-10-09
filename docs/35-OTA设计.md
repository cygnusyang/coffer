# Coffer OTA 升级设计（v2.7.0 立项）

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-HLD-035 |
| 版本 | r0.4 |
| 状态 | 设计稿待评审（v2.7.0 立项；2026-10-10 用户已裁定 4 决策点 + UI 入口，见 §0/§2.6）；**契约已冻结（§6，2026-10-10，实现公共前提；§6.4 经 r0.4 修订——沙盒继承实证后替换协议修正）** |
| 创建日期 | 2026-10-10 |
| 作者 | dev-architect-ota（lead 收编用户裁定） |
| 上游文档 | `docs/01`（X-11/NFR-SEC-07）、`docs/09`（v2.7.0 卡）、`docs/16`（判据②）、`docs/27`（D-4）、`docs/29`（D-6 嵌套 bundle）、`docs/34`（v2.5.0 写面） |
| 关联代码 | `.github/workflows/release.yml`、`tools/build_macos_app.sh`、`macos/Coffer/`（新增 Updater/Installer） |

---

## 0. 结论先行 + 裁定记录

**方案：自研最小更新器**（纯 Swift，复用既有 SecStaticCode 验签先例，不动 Rust 侧、不动 swiftc 手编构建链），叠加**「更新期白名单端点」的最小零网络豁免**，版本归属 **v2.7.0**。

**2026-10-10 用户裁定（4 决策点，均落档）**：

| 决策点 | 裁定 | 备注 |
|---|---|---|
| 签名/分发模型 | **免费账号本机自更新先行**；ADP（Developer ID+公证）为长期目标 | 免费阶段诚实定位「开发自更新」，非公开分发；ADP 到位后升级公开通道（与 docs/09 挂起项 E-1' 合并推进） |
| 零网络豁免 | **接受最小豁免**：更新期 + 4 白名单端点 + 默认手动不静默 | 不可逆；同步修订 X-11/NFR-SEC-07/docs/16 判据② + docs/27 新 D-x 追认（§2.2） |
| 更新密钥管理 | **CI secrets**（架构师推荐离线持有，用户否决） | ⚠️ 信任单点接受；残留风险与可选加固见 §2.3 注 |
| 强制更新力度 | **警告 + 显著提示**（不阻断使用） | `security:critical` 低于 minimumVersion 时 |
| 机制选型 | 自研最小更新器（否决 Sparkle） | swiftc 手编无 SPM + 无 Developer ID → Sparkle 核心价值落空，无现实替代 |
| 版本归属 | v2.7.0 | 新功能不塞 v2.5.0/v2.6.0 收口轮（docs/09 r2.24 先例） |

> **前置事实（决定「OTA 服务谁、何时上线」）**：当前签名体系 = 免费账号 Apple Development 证书 + 7 天 provisioning profile，**无 Developer ID、无公证**（developer-id 渠道 v2.4.0 已移除，沙盒单渠道）。OTA 完整面向用户的落地 **gate 在 ADP 采购**。

---

## 1. 现状核对（事实清单）

| 事实 | 证据 |
|---|---|
| CI 签名用 Apple Development 证书（非 Developer ID） | `release.yml:5-6`、`:79-97` |
| 证书约 1 年有效；**profile 7 天 TTL** | `tools/build_macos_app.sh:13-14`、`:158`；docs/29 §8（挂起用户项⑦） |
| 无公证（notarization） | release.yml 无 notarytool 步骤；build 脚本明说无 notarization 依赖 |
| developer-id 渠道已移除，现为沙盒单渠道 | docs/09 r2.23；build 脚本 `分发渠道: appstore` |
| ADP 采购挂起，无 Developer ID 证书来源 | docs/09 r2.26（卡 Passkey 完整版） |
| **产物已是 zip**（`ditto -c -k --keepParent` 打包 Coffer-${TAG}.zip 内含 .app） | `release.yml:116-121` → **直接 OTA 就绪，非 dmg** |

### 既有纪律与先例（设计直接复用）

| 约束/先例 | 证据 | 对 OTA 的意义 |
|---|---|---|
| 零网络硬承诺：判据② = 运行时无外部网络连接（`lsof -a -i -p` 空 + 阳性对照） | `docs/16:43-48`（TC2-B）、`:105-107` | OTA 必须修此判据，否则与验收冲突（§2.2） |
| NFR-SEC-07 =「没有能力联网」可技术验证；Rust 依赖图黑名单（reqwest/hyper/...） | `docs/01:489-491`、`tools/check_no_network.sh:62` | **网络代码必须放 Swift 侧**（URLSession 不经 cargo tree），否则 check_no_network 直接 FAIL |
| X-11「自动更新检查 = 明确排除」 | `docs/01:117`、`:121` | OTA = 需求文档修订，不只是加功能 |
| SecCode 验签裁定：TeamID/DR 主锚、CDHash 次锚（`kSecCodeInfoUnique`） | memory coffer-v230-ps-spike-seccode-ruling | 更新验签沿用：DR 主、清单绑定 CDHash 次 |
| D-6 嵌套 bundle 纪律：`Contents/Helpers/coffer.app` 随 App 分发、拷出即 SIGKILL | docs/29 §8、build 脚本 | 整体替换 .app 即天然覆盖嵌套 coffer.app，无新增负担 |
| Keychain escrow 条目（`mcp_wrap`）同 TeamID 同 DR → 替换不破 | docs/29 §5.1 + D-6 冻结 | 替换安全关键判据，需真机核销 |
| 项目无 SPM/Xcode 工程，纯 swiftc 手编 | `tools/build_macos_app.sh:112-123` | Sparkle 集成硬障碍（§2.1） |

---

## 2. 设计决策

### 2.1 Q1 机制选型：自研最小更新器（否决 Sparkle）

| 维度 | Sparkle | 自研最小更新器 |
|---|---|---|
| Gatekeeper 静默替换 | 强项但要求 Developer ID + notarization，当前免费账号用不上 | 不依赖公证；免费阶段本机路径、ADP 后公证验证兼容 |
| 构建集成 | 需 SPM/xcframework，破坏 swiftc 手编链 | 纯 Swift 源码文件，零新依赖 |
| 零网络叙事 | 框架管 appcast/下载 URL，豁免粒度粗 | 白名单端点硬编码进单一 Updater 模块，审计面 = 一个目录 |
| 供应链 | 历史 CVE 面大，密码库引入需额外审计 | 完全可控，验签复用已实证 SecStaticCode 先例 |
| 代码量/维护 | 免写但集成成本高 | 约 400-600 行 Swift + 一个安装 helper |

否决 Sparkle 三条硬理由：① 无 Developer ID/公证，核心价值落空；② swiftc 手编链集成 xcframework 成本高且脆弱；③ 零网络最小豁免叙事自研更干净。**不建议预留未来换 Sparkle 的接口**（YAGNI）。

### 2.2 Q2 零网络最小豁免（不可逆，已裁定接受）

豁免范围（应用层白名单，硬编码 4 host）：
- `api.github.com`（发布查询；若走固定清单 URL 可退化为 2 个）
- `github.com`（下载重定向源）
- `objects.githubusercontent.com`、`release-assets.githubusercontent.com`（Release asset 下载 CDN）

实现层三道锁：
1. **entitlement 层**：`com.apple.security.network.client = true`（沙盒总开关，无法按域限，只能应用层限）。
2. **应用层**：Updater 模块 URLSession delegate 强制校验 host ∈ 白名单 + 强制 HTTPS；非白名单一律拒绝。所有网络代码**只在 Swift 侧**（`check_no_network.sh` 黑名单不受影响，cargo tree 不变）。新增 `tools/check_ota_whitelist.sh`（grep Updater 模块只允许白名单 host，防未来漂移）。
3. **行为层**：默认「手动检查更新」，启动静默检查默认关；常态（非更新时段）不持有 socket。

威胁面：

| 威胁 | 风险 | 缓解 |
|---|---|---|
| MITM 篡改清单/产物 | 高 | 清单 EdDSA 签名 + 产物 SecStaticCode 验签（DR 主 + CDHash 次）+ HTTPS + host 白名单 |
| DNS 劫持指向假 github | 中 | 系统 CA + 强制 HTTPS + host 白名单拒绝任意域 |
| 降级攻击（回滚到旧有漏洞版） | 中高 | 清单 `minimumVersion`，低于即拒装；清单「只增不减」纪律 |
| 仓库/账号被攻陷 → 恶意产物 | 高 | 纵深：产物须同 TeamID + DR 签名；更新密钥与代码签名分离（§2.3） |
| 更新端点不可用 | 中 | 失败静默降级「稍后再试」，不阻塞 App 使用；更新始终可选 |

**需同步修订的文档**：docs/01 X-11（:117）改「受限豁免」+ 新增 NFR-SEC-08（更新豁免条款）；docs/16 判据② + TC2-B（:43-48、:105-107）加豁免注记——**修订为「常态无外部网络连接；用户触发更新检查/下载时，仅白名单端点短时连接」**；docs/27 新 D-x 追认落档（不可逆，审计叙事不可撤回）。

### 2.3 Q3 完整性验证（密码库不能省）

**下载产物验签**（三级，全过才允许替换）：
1. `SecStaticCodeCreateWithPath` + DR 验证：TeamID=`A6DS985SJJ` + identifier=`app.coffer.Coffer`（主锚，沿用 P-S spike 裁定）。
2. 清单 CDHash 比对：清单声明该版本 `kSecCodeInfoUnique`，下载实测比对（次锚，防「合法签名但非官方构建」）。
3. 嵌套 `Contents/Helpers/coffer.app` 一并验签（同 TeamID + identifier）——D-6 纪律替换侧对偶。
4. ADP 到位后加公证 ticket 校验（`SecStaticCodeCheckValidity` flags），设计留位。

**清单自身防篡改**：EdDSA 签名（采纳 A 方案）；否决「仅 HTTPS+白名单」与「依赖 Release 不可变」。

> **⚠️ 更新密钥裁定 = CI secrets（用户 2026-10-10）**：架构师原推荐离线持有（信任分离最强：CI 被攻陷也产不出可装版本），用户裁定放 CI secrets（全自动优先）。**残留风险**：代码签名 p12 与更新 EdDSA 密钥同处 CI → CI 全量被攻陷时，攻击者既能产出同 TeamID 合法签名产物、又能签发对应清单，更新通道完全失守（DR/CDHash 纵深不抵御此场景）。**接受此信任单点。可选加固（不阻塞自动化）**：更新密钥放独立 GitHub **Environment** secret + release workflow 设 required reviewer 门；或后续改离线签名（回退路径始终开放）。

**回滚安全**：
- 替换前把当前 .app 完整备份到临时区；替换后新 .app 首次启动校验（能启动 + 版本正确）才删备份；失败自动回滚。
- D-6 影响：整体替换 Coffer.app 即覆盖嵌套 coffer.app；Keychain escrow 条目不随 bundle 删除、同 TeamID 同 DR 可读——**替换不破托管解锁**（需真机核销）。
- **profile TTL 是替换侧新风险**：免费 profile 7 天有效，构建后 7 天才被下载安装则新 .app 的 embedded.provisionprofile 过期 → 首启可能 SIGKILL(137)（D-6 同源）。缓解：清单携带构建/签名时间戳，App 安装前校验 profile `expirationDate`，过期即拒装并提示重新下载——把「及时更新」从纪律变成机制。

### 2.4 Q4 CI 侧

- 产物：现状 zip 即 OTA 就绪，不改。
- 更新发现：**固定清单 URL**（`releases/latest/download/update-manifest.json`），App 只认一个恒定 URL，不依赖版本枚举；比直读 `api.github.com/releases/latest` 更显式且天然挂 EdDSA 签名。
- CI 改动（release.yml 追加）：构建后提取 CDHash（`codesign -dv --verbose=4` 或小工具）→ 生成 `update-manifest.json`（version/minimumVersion/downloadUrl/cdHash/构建时间/`security:critical` 标记）→ 上传 Release asset。签名在 CI（裁定 §2.3）。
- `security:critical` 标记支撑安全补丁强制提示（§2.6）。

### 2.5 Q5 沙盒与 entitlement

- 加 `com.apple.security.network.client = true`。`macos/Coffer/Coffer.entitlements:5-6` 现明确「任何 network.* 都是违规」→ 改写注释为豁免注记。
- 域级限制 entitlement 层做不到（布尔开关），落在应用层 URLSession host 白名单（§2.2）。
- **沙盒写外部路径（替换 /Applications 下的自己）需非沙盒进程**——替换机制实现约束（§2.6）。
- 连锁影响：release.yml:110-114 零网络核查 `grep com.apple.security.network || true` 需调整；新增 `tools/check_ota_whitelist.sh`。

### 2.6 Q6 UX 与版本语义

| 项 | 结论 |
|---|---|
| 入口（用户裁定 2026-10-10） | **关于对话框主动点升级**——「关于 Coffer」对话框版本区「检查更新…」按钮（主入口）+ 应用菜单同项（快捷入口，对齐 Sparkle 惯例）；**设置页不放任何更新入口**；不做后台静默检查（「启动静默检查」开关已裁掉，零网络姿态 + 用户强调主动触发） |
| 下载进度 | URLSession `downloadTask` progress 代理 → 进度条；前台会话，不引入 background session |
| 安装时机 | **退出后替换**：点「安装更新」→ 下载验签 → 弹「Coffer 将退出并更新」→ 安装代理替换 → relaunch。不做「下次启动替换」存活逻辑 |
| 跳过此版本 | 本地记录（Preferences），后续版本才重新提示 |
| 强制最低版本 | 清单 `minimumVersion`；`security:critical` → **警告 + 显著提示**（不阻断使用，裁定） |
| 替换机制 | **嵌入式非沙盒 install helper**（嵌套 bundle，复用 D-6 装配经验，但无受限 entitlement——只有文件替换职责）。沙盒 App 无法写容器外，须非沙盒 helper；无 `keychain-access-groups` 则不受 D-6 SIGKILL 纪律约束。**前置 spike**：实证无受限 entitlement 的非沙盒裸二进制 AMFI 放行（D-6 的 SIGKILL 均因受限 entitlement）。目标位置 `/Applications`（McpStatusConfig.swift:89） |
| Gatekeeper 接受度 | 免费阶段 = App 自下载不设 quarantine → 本机可跑（开发签名本质）；**该路径不适用于第三方机器**，须随 ADP 切换公证模型。诚实标注而非依赖 quarantine 绕过 |
| 与现有入口 | 仅「关于 Coffer」对话框 + 应用菜单（设置页明确排除，用户裁定）；App translocation 风险：替换须落到固定位置再启动 |

### 2.7 Q7 版本归属

**v2.7.0**。理由：① 项目惯例「新功能不塞进行中的收口轮」（docs/09 r2.24 先例）；② v2.5.0 写面收口、v2.6.0 Passkey 收口轮进行中——不抢跑道；③ OTA 若 gate 在 ADP 采购，时间线天然落到 v2.7.0。

---

## 3. 任务分解（并行分组，文件范围显式互斥）

**契约冻结（串行前置，所有组公共前提）**：清单 schema v1 + 白名单端点 + Updater 公开接口（`UpdaterManager.check/install/state`）+ 替换协议（路径/回滚/退出码）。冻结后各组并行。

| 组 | 模块 | 文件范围 | 依赖 |
|---|---|---|---|
| Spike-0 | AMFI helper 实证 | 仅 /tmp 实验目录，不落仓 | 前置（非并行） |
| A | Updater 核心 | `macos/Coffer/Updater/*.swift`（新建）+ `macos/Tests/UpdateTests/`（新建）——清单解析/验签/下载/DR 校验 | 契约冻结后即启 |
| B | 安装辅助 + 装配 | `tools/build_macos_app.sh`（改）+ `macos/Coffer/Installer/*`（新建） | Spike-0 + 替换协议 |
| C | CI + 清单生成 + 静态检查 | `release.yml`（改）、`tools/sign_update_manifest.sh`+`tools/check_ota_whitelist.sh`+CDHash 提取工具（新建）、`Coffer.entitlements`（改） | 清单 schema 冻结 |
| D | UI 接线 | `macos/Coffer/Views/`（新建 Update/About 视图）+ AppModel 接线 | A 公开接口冻结 |
| E | 文档批 | `docs/01`、`docs/16`、`docs/27`（新 D-x 追认）、`docs/09`（v2.7.0 卡）、本文档演进 | 豁免范围定稿 |

**互斥性核对**：A/B/C/D/E 五组文件集合两两不相交。⚠️ 唯一张力：组 D Views 与 v2.5.0 写面在改的 `ItemDetailView.swift`/`PasswordStrengthSection.swift` 同目录——组 D 拆独立新文件（`UpdateSheet.swift`、`AboutUpdateSection.swift`）不与 v2.5.0 在改文件交叉；若不可避免触碰同一文件，组 D 串行至 v2.5.0 收口后。

**串行链**：契约冻结 →（Spike-0 ∥ A 骨架）→ B/C/D 并行 → 集成轮 → 真机核销（替换/回滚/Keychain 不破/profile 过期拒装）。

---

## 4. 开放点（设计期未决，落实现/验收期）

1. ~~替换 helper 的 AMFI 放行实证（Spike-0，无受限 entitlement 非沙盒裸二进制）~~ —— **✅ 2026-10-10 Spike-0 实证定稿（PASS）**：裸二进制（Apple Development 签名、无任何 entitlements）spawn 退出码 42 放行；阳性对照（带 keychain-access-groups 无 profile）SIGKILL 137 精确复现 D-6（环境自证）；嵌套 .app bundle（无受限 entitlement、无 profile）亦放行。**AMFI 放行条件 = 无受限 entitlement + 无需 embedded.provisionprofile**。**helper 装配形态 = 嵌套 `.app` bundle**（r0.4 集成轮定稿：`open`/LaunchServices 打不开裸 Mach-O，§6.4）。实证细节见 `/tmp/spike-ota-amfi/log.md`（2026-10-10）。
2. 替换后 TCC 授权（摄像头/辅助功能）同 bundle id 继承需真机核销。
3. profile 过期拒装的边界行为需 spike 确认 AMFI 判定。
4. ADP 采购后公证 ticket 校验的接入点。

---

## 5. 修订记录

| 修订 | 日期 | 说明 |
|---|---|---|
| r0.1 | 2026-10-10 | 初稿——dev-architect-ota 设计决策报告 + lead 收编用户 4 裁定（签名模型免费先行 / 最小零网络豁免接受 / 更新密钥 CI secrets / 强制更新警告不阻断；机制自研、归属 v2.7.0 确认） |
| r0.2 | 2026-10-10 | **UI 入口裁定（用户）**：§2.6 入口 = 关于对话框「检查更新…」按钮（主）+ 应用菜单同项（快捷），**设置页明确排除**；「启动静默检查」开关裁掉（主动触发 + 零网络姿态，不做后台静默）。修订记录历史行不改写 |
| r0.3 | 2026-10-10 | **契约冻结（§6，实现公共前提）**：清单 schema v1 + canonical JSON 约定（CryptoKit Ed25519 双侧同实现，swiftc 实证可行）+ 白名单 4 host + Updater 公开接口（check/install/state + UpdateInfo/UpdaterState）+ 替换协议（目标 /Applications、备份→替换→回滚、helper 退出码 0-4、profile TTL 拒装）。lead 收编 Spike-0 需求（§4 开放点 1 实证，进行中）。修订记录历史行不改写 |
| r0.4 | 2026-10-10 | **§6.4 替换协议修订（沙盒继承实证，集成轮发现）**：原「App `Process()` spawn helper + waitpid」三处不可行——① 沙盒父 spawn 子进程继承沙盒、写不了 /Applications（探针退出码 7）；② `open` 无法 waitpid（"Unable to block on application"）；③ `open` 打不开裸 Mach-O。**修订**：helper 装配为嵌套 `.app` bundle（`Contents/Helpers/CofferUpdater.app`）；App 经 LaunchServices（`NSWorkspace`/`open -n --args`）启动、不备份不 spawn 不 waitpid；替换/回滚/备份全归非沙盒 helper；退出码改经 **result-file** 握手，被 relaunch 的 .app 首启读 result 呈现成败。§4 开放点 1 helper 装配形态随之定稿为嵌套 bundle。修订记录历史行不改写 |

---

## 6. 契约冻结（2026-10-10，实现公共前提）

> 本契约是 §3 各组（A/B/C/D）并行的公共前提。**冻结后不得单方面改动**；任何改动须升级 lead 裁决并全组同步。契约锚点：清单 schema v1 / canonical JSON / 白名单 / Updater 公开接口 / 替换协议。

### 6.1 清单 schema v1（`update-manifest.json`）

固定清单 URL：`https://github.com/cygnusyang/coffer/releases/latest/download/update-manifest.json`（恒一 URL，不依赖版本枚举）。

```json
{
  "schemaVersion": 1,
  "appId": "app.coffer.Coffer",
  "version": "2.7.0",
  "minimumVersion": "2.6.0",
  "buildTime": "2026-10-10T00:00:00Z",
  "downloadUrl": "https://github.com/cygnusyang/coffer/releases/download/v2.7.0/Coffer-v2.7.0.zip",
  "cdHash": "<hex kSecCodeInfoUnique of Coffer.app>",
  "securityCritical": false,
  "notes": "可选发布说明",
  "signature": "<base64 Ed25519 signature>"
}
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `schemaVersion` | int | 恒 `1`；不识别即拒装 |
| `appId` | string | 恒 `app.coffer.Coffer`；不匹配即拒装 |
| `version` | string | 新版本号（`CFBundleShortVersionString` 语义，如 `2.7.0`） |
| `minimumVersion` | string | 可安装本版本的最低当前版本；低于即拒装（防降级/防旧版漏洞回滚） |
| `buildTime` | RFC3339 | 构建时间戳；驱动 profile TTL 校验（§2.3）与「清单只增不减」审计 |
| `downloadUrl` | https URL | Release asset 下载直链（github.com → CDN 重定向） |
| `cdHash` | hex string | 产物 `kSecCodeInfoUnique`（验签次锚） |
| `securityCritical` | bool | true = 安全补丁 → 警告 + 显著提示（不阻断，§2.6 裁定） |
| `notes` | string? | 可选发布说明（UI 展示） |
| `signature` | base64 string | Ed25519( canonical(前 9 字段 JSON) )，见 6.2 |

**canonical JSON 约定（双侧同实现，契约关键）**：用 CryptoKit `Curve25519.Signing` 签名/验签；被签名内容 = 去除 `signature` 字段后的 JSON，序列化方式双侧一致：`JSONSerialization` + `.sortedKeys` + `.withoutEscapingSlashes`（无缩进）。签名侧（CI 工具）与验签侧（App）都用同一个 Swift 函数保证字节一致。**实证**：swiftc 直编 CryptoKit Ed25519 sign+verify 通过（2026-10-10，无 SPM）。

### 6.2 白名单端点（应用层硬编码 4 host）

`api.github.com`、`github.com`、`objects.githubusercontent.com`、`release-assets.githubusercontent.com`（§2.2）。Updater 模块 URLSession delegate 强制校验 host ∈ 白名单 + 强制 HTTPS；非白名单一律拒绝。所有网络代码只在 Swift 侧（`tools/check_ota_whitelist.sh` 防漂移）。

### 6.3 Updater 公开接口（组 D 依赖，冻结）

`macos/Coffer/Updater/UpdaterManager.swift`（@MainActor ObservableObject）：

```swift
/// 校验通过的更新信息（组 D 展示用）。
struct UpdateInfo {
    let version: String          // 新版本
    let minimumVersion: String
    let downloadUrl: URL
    let cdHash: String
    let buildTime: Date
    let securityCritical: Bool
    let notes: String?
}

/// Updater 状态机（组 D 渲染 + 按钮可用性）。
enum UpdaterState: Equatable {
    case idle                 // 未检查
    case checking             // 检查中
    case updateAvailable(UpdateInfo)  // 发现可更新
    case upToDate             // 已是最新
    case downloading(Double)  // 下载中（0...1 进度）
    case downloaded           // 下载+验签完成，等待安装
    case installing           // 安装中（退出+替换+relaunch）
    case failed(String)       // 失败（用户可见文案）
}

@MainActor
final class UpdaterManager: ObservableObject {
    @Published private(set) var state: UpdaterState = .idle
    func check() async        // 拉清单+验签+版本比较
    func install() async      // 下载+三级验签+备份+helper 替换+relaunch
    func dismiss()            // 关面板/清理失败态
}
```

**组 D 只依赖 6.1–6.3**：渲染 state + 调 check/install/dismiss；不碰网络/验签/替换细节。

### 6.4 替换协议（组 B 依赖，冻结；r0.4 修订——沙盒继承实证后修正）

> **r0.4 修订动因（2026-10-10 沙盒继承实证，/tmp/ota-probe 已清理）**：
> 原 r0.3 契约写「App 侧 `Process()` spawn helper + waitpid 读退出码 + App 侧备份回滚」。
> 集成轮探针实证该路径**三处不可行**，§6.4 随之修订（机制选型、UX、退出码语义不变，
> 只改启动/握手/装配形态）：
>
> 1. **沙盒继承（致命）**：沙盒父进程 `posix_spawn`/`Process()` 产生的直系子进程**继承父沙盒**
>    （`sandbox-exec` 探针：沙盒父 spawn 的 child 写 `/Applications` DENIED，退出码 7）。
>    App 是沙盒单渠道 → **App 直接 spawn helper 必失败**。唯一放行路径 = **LaunchServices
>    `open`/`NSWorkspace` 按目标自身 entitlements 启动**（launchd 加载，非沙盒继承）——探针实证：
>    嵌套 bundle 经 `open -n <绝对路径>.app --args ...` 启动后写 `/Applications` 成功、参数可达。
> 2. **`open` 无法 waitpid**：`open -W` 实测报 "Unable to block on application"
>    （GetProcessPID 返回 0xFFFF...）→ **退出码不能经 waitpid，改经 result-file 握手**。
> 3. **`open` 打不开裸 Mach-O**：`open` 只能打开 bundle 形态 → **helper 必须装配成嵌套
>    `.app` bundle**（非裸二进制），放 `Contents/Helpers/CofferUpdater.app`。

- **目标位置**：`/Applications/Coffer.app`（替换须落到固定位置再启动，防 App translocation；§2.6）。
- **helper 形态**：嵌入式非沙盒 install helper，**嵌套 `.app` bundle** `Contents/Helpers/CofferUpdater.app`
  （Spike-0 裁定无受限 entitlement、无 embedded.provisionprofile 即 AMFI 放行，§4 开放点 1；
  嵌套 bundle 形态由 r0.4 定稿——`open` 不认裸二进制）。组 B 装配：swiftc 直编 binary +
  最小 Info.plist + 自身 Apple Development 签名（无 entitlement、无 profile）。
- **调用协议**（App 侧，组 A 实现）：
  1. App 点「安装更新」→ 下载验签通过（三级）→ 弹「Coffer 将退出并更新」。
  2. **App 不备份、不 spawn、不 waitpid**（沙盒无权写 `/Applications`，备份与替换全归 helper）。
  3. App 写 **install 配置文件**（JSON，临时区）：`newAppPath / currentAppPath / backupPath /
     resultFilePath / pid`，字段与 6.4 退出码语义对应。
  4. App 经 **LaunchServices 启动 helper**：`open -n <Contents/Helpers/CofferUpdater.app> --args
     --config <配置文件路径>`（生产实现用 `NSWorkspace.shared.openApplication` 等价；`open`
     命令路径作为装配/真机验证基线）。
  5. helper（非沙盒，launchd 加载）读配置 → 等 App pid 退出 → **备份 → 替换 → relaunch** →
     **写 result 文件**（JSON：成功/失败 + 退出码 + 文案）→ 自身退出。
  6. **App 侧在发起 launch 后随即退出**（不阻塞等 helper——`open` 无法 waitpid）。被 relaunch
     的 .app（新或旧）首次启动时**读 result 文件**：成功 → 删备份 + 静默（UI 呈现新版本）；
     失败 → 呈现 `failed`（含退出码文案）。result 文件一次性消费后删除。
- **退出码（helper 内部，经 result 文件传递，语义不变）**：`0` 成功；`1` 备份失败；`2` 替换
  失败；`3` relaunch 失败；`4` 用法错误（含等待超时，契约无专门码，此时未做任何修改）。
  等待 App pid 退出超时归入 `3`（relaunch 失败语义：安装未完成）。
- **回滚**：替换前 helper 完整备份当前 .app 到 `backupPath`；helper 替换失败（退出码 2）时
  由 **helper 自身**恢复备份并 relaunch 旧 .app（App 已退出，无法代劳回滚）；替换成功后新
  .app 首次启动校验（能启动 + 版本正确）才删备份，失败自动回滚。helper 不删备份。
- **profile TTL**：安装前校验新 .app `embedded.provisionprofile` 的 `expirationDate`
  （buildTime 近似）未过期；过期即拒装并提示重新下载（§2.3）。
- **Keychain 不破**：整体替换 .app 即覆盖嵌套 coffer.app；Keychain escrow 条目同 TeamID 同
  DR 可读（§1 先例）——真机核销项，自动化只做结构断言。

### 6.5 Spike-0 收编（§4 开放点 1 实证，进行中）

实证「无受限 entitlement 非沙盒裸二进制 AMFI 是否放行 spawn」：本机 Apple Development 身份签名 + 阳性对照（带 keychain-access-groups 应 SIGKILL 137）+ 嵌套 bundle 变体。结论落 §4 开放点 1（helper 形态定稿）。