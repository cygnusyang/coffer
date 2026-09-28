# v0.4.0 技术调研：菜单栏常驻（FR-13.3）+ 全局快捷键（FR-4.5）

- 调研人：dev-researcher；日期：**2026-09-29**；状态：供 T02（`09` §3.4 v0.4.0-T02）选型
- 目标环境：macOS 14+（`01` FR-13.2）、Apple Silicon、App Sandbox（`Coffer.entitlements`：仅 app-sandbox / user-selected 文件 / keychain-access-groups，**无 network.\***）、零网络（NFR-SEC-07，出口判据②「关主窗口后 App 仍驻留，运行时 0 socket」，`09` §2 v0.4.0）
- 证据分级：【实测】= 本机 Xcode（Apple Swift 6.3.1，macOS 26 SDK，deployment target arm64-apple-macos14.0）typecheck/otool 复现；【文档】= Apple 官方或多方一致来源；【单源】= 单一第三方来源，未交叉验证；【推测】= 未经真机验证的推断

## 结论（一句话）

**推荐组合：不改构建脚本——纯 SwiftUI `MenuBarExtra(.menu)` 做菜单栏图标 + 手写 ~100 行 Carbon `RegisterEventHotKey` 做全局快捷键（默认 ⌥⌘P 呼出/聚焦主窗口搜索框）+ 常规 App（保留 Dock 图标）+ 关主窗口仅隐藏（`applicationShouldTerminateAfterLastWindowClosed` 返回 false）。**

## 1. 构建系统现状（核实）

【实测+仓库核实】当前 Swift 侧**无任何包管理**：`find` 全仓无 `Package.swift` / `.xcodeproj` / pbxproj / Tuist。`tools/build_macos_app.sh:60-69` 用 `swiftc -O -target arm64-apple-macos14.0` 直出可执行文件，源集 = `macos/Coffer/**/*.swift`（排除 SmokeTest）+ UniFFI 绑定 + bridging header（`-import-objc-header`）。脚本头注释明确记录了决策理由（docs/07 §7 T05：无 xcodegen、手写 pbxproj 脆弱）。

两条路成本对比：

| 维度 | a) 纯手写 Carbon（推荐） | b) 引入 SPM 依赖（HotKey / KeyboardShortcuts） |
| --- | --- | --- |
| 新增依赖 | 0（系统框架） | 1 个 SPM 包 |
| 构建脚本改动 | 无 | 需引入 `swift package resolve` + 先把依赖编成静态库再链入 swiftc 单命令编译流；`-import-objc-header` 单命令模式与 SPM 产物拼接受限，改造量不小且引入新维护面 |
| 代码量 | ~100–150 行（注册/反注册/InstallEventHandler/KeyEquivalent 解析） | ~10 行调用 |
| 许可证 | 无（系统 API） | HotKey：MIT，v0.2.1，最后发布 2024-12-29，1.1k stars（低活跃但极小）；KeyboardShortcuts：MIT，v3.1.0（2026-09-11），2.7k stars，活跃，自称「fully sandboxed and Mac App Store compatible」【其 README】 |
| 审计面（零网络/安全审查） | 零新增第三方 | 新增第三方源码进入发布二进制，须过 NFR-LEGAL-02 许可核对 + 审计面扩大 |

**推荐 a)**。所需 API 面极小（`RegisterEventHotKey` / `UnregisterEventHotKey` / `InstallEventHandler` + `EventHotKeyID`），Apple 从未给全局快捷键提供现代替代且 Carbon 这部分仍在 SDK 中【实测：`import Carbon.HIToolbox` 于 macOS 26 SDK 正常编译，无 deprecation error】；为百行代码引入 SPM 改造不划算。KeyboardShortcuts 可作为日后功能升级（录制 UI、key sequence）时的迁移目标，非 v0.4 必需。

## 2. 菜单栏常驻：MenuBarExtra vs NSStatusItem

| 维度 | MenuBarExtra（SwiftUI，macOS 13+） | NSStatusItem（AppKit） |
| --- | --- | --- |
| 可用性 | 【实测】macOS 26 SDK、target 14.0 编译通过（`.menu` 与 `.window` 两种 style 均解析） | 【文档】长期稳定 |
| Sandbox | 无任何限制（纯 UI API） | 同左 |
| 与现有结构契合 | 加一个 Scene 即可（`CofferApp.swift` 已是 `App` 协议 + `@NSApplicationDelegateAdaptor`），零侵入 | 需自管生命周期、window frame |
| 精细控制（激活策略、panel 样式、点击行为） | 弱——`.window` style 是 SwiftUI 托管 NSPanel，**TextField 键盘焦点有已知缺陷**【文档：Apple 论坛 729920（日文输入法下丢焦点）、多源一致的「非激活 panel 不成为 key window → 收不到键入」问题，需 `NSApp.activate(ignoringOtherApps:)` + 延时 makeKey 等绕法】 | 强（自建 NSPanel 子类 override `canBecomeKey` 是成熟模式） |

**推荐结构**：
- 菜单栏图标：`MenuBarExtra("Coffer", systemImage:) { … }.menuBarExtraStyle(.menu)`——只放状态与动作（显示主窗口 / 锁定全部 / 设置 / 退出），不含文本输入。风险最低。
- **不要**把快速搜索面板塞进 `.menuBarExtraStyle(.window)`（FR-4.5 的「快速搜索面板」）——焦点缺陷在 v0.4 会直接顶上出口判据①（快捷键 → 解锁 → 搜索 → 回车复制）。若判据① 的「搜索」实现为主窗口搜索框聚焦，则此风险整体消失；若必须做独立悬浮面板，用自建 NSPanel（`canBecomeKey == true` + `NSApp.activate`），该模式是 Raycast 类工具的成熟路径【多源一致】。

## 3. 全局快捷键：三方案对比

| 方案 | TCC 权限 | Sandbox | 前台/后台 | 可拦截/吞事件 | 结论 |
| --- | --- | --- | --- | --- | --- |
| **Carbon `RegisterEventHotKey`** | **无需任何权限**【文档：Apple DTS Quinn 论坛 735223/811443 一致口径；KeyboardShortcuts FAQ「Does this package cause any permission dialogs? No」】 | 允许（App Store 沙盒应用多年实践；macOS 10.15+ 沙盒内 CGEventTap/快捷键均有支持路径，HotKey 是唯一无需权限者） | 全局生效（含本 App 前台时） | 是（按组合触发回调，事件不再下传） | **推荐** |
| `NSEvent.addGlobalMonitorForEvents` | 键盘事件需 辅助功能/Input Monitoring 授权【文档：Quinn 811443——沙盒内「测试机上有缓存态所以看起来能用」不可信，Apple 认可的沙盒键盘监听路径是 CGEventTap+Input Monitoring，不是它】 | 「沙盒内仍工作」属未承诺行为【文档：Quinn 同帖】 | 仅其他 App 前台时收到（本 App 前台不触发，需配 local monitor）；只读副本，**不能拦截** | 否 | 排除 |
| `CGEventTap` | 需 Input Monitoring（首次弹授权，用户摩擦） | 10.15+ 沙盒支持（listen-only） | 全局 | 是 | 功能过剩（Coffer 只需固定组合，不需监听任意键盘），且引入授权弹窗 |

**关键版本风险（Sequoia 回归）**【文档：Apple 论坛 763878，Apple Frameworks Engineer 确认】：macOS 15.0–15.1 中，沙盒应用注册**仅含 ⌥/⇧ 修饰**的热键失败，报 `-9868 (eventInternalErr)`；规则为「至少含一个非 ⌥/⇧ 的修饰键」（⌘/⌃ 参与的组合不受影响）；15.2 beta 2 恢复 ⌥-only。另有一例 2025-11 报告称解锁屏幕后 ⌥-only 热键复现失效【单源】。**缓解：默认候选一律含 ⌘ 或 ⌃（见 §4）**，从根上避开。

另注【单源】：chyshkala 博文称 Carbon 热键「不能用 Space 键」；KeyboardShortcuts README 并无此记载。未交叉验证——凡候选含 Space（⌃⌥⌘Space）须真机实测后再定稿。

**实现要点**（手写 Carbon 的骨架，非生产代码）：`RegisterEventHotKey(keyCode, modifiers, EventHotKeyID(signature:id:), GetApplicationEventTarget(), 0, &ref)` + `InstallEventHandler(GetApplicationEventTarget(), …, kEventClassKeyboard, kEventHotKeyPressed/Released)`；modifier 常量 `cmdKey | optionKey | controlKey` 来自 Carbon.HIToolbox【实测编译通过】。注册失败须显式报错（静默降级 = 快捷键永远不响）。

## 4. 默认快捷键候选（NFR-UX-03）

**系统级已占用（【文档】support.apple.com/102650「Mac 键盘快捷键」，2026-09-29 查询）**：⌘Space=Spotlight；⌃Space 与 ⌃⌥Space=切换输入源（多输入源用户——本项目中文用户为主——几乎必撞）；⌥⌘Space=Finder 内 Spotlight 窗口；**⇧⌘Space=macOS 27+ Siri AI（Beta）询问活动窗口（新占用！）**；⇧⌘3/4/5=截图；⌃⌘Q=锁屏；⌥⌘M=最小化全部；⌥⌘D=Dock；⇧⌘C=打开「电脑」窗口；⌥⌘C=拷贝样式；⌘⌥P=Finder 路径栏；⇧⌘P=Finder 预览面板/页面设置。⌃⌥⌘Space 未被该页收录（未占用）。

**密码管理器/启动器生态已占用（【文档】各家官方支持页）**：⌥Space=Raycast/Alfred 默认（且 ⌥Space 在 macOS 文本输入中产生不断行空格 U+00A0，双重冲突）；1Password Quick Access=⇧⌘Space（新版本改 ⌥⌘\）；1Password 填充=⌘\；Bitwarden 浏览器扩展=⌘⇧L。

**候选组合（均含 ⌘ 或 ⌃，规避 §3 Sequoia 沙盒回归）**：

| 功能 | 候选 | 冲突面 | 备注 |
| --- | --- | --- | --- |
| 呼出/聚焦主窗口快速搜索（唯一全局热键） | ⌥⌘P（主推） | 仅 Finder 路径栏切换（局部、低频） | P=Password 语义直白；与 1Password 新默认 ⌥⌘\ 不撞 |
| 同上备选 | ⌃⌥⌘Space | Apple 默认未收录 | 需真机验证 Carbon+Space（§3 单源疑点） |
| 同上备选 | ⌥⌘K | 未占用 | K 语义弱于 P |
| 复制用户名（面板内局部） | ⌃⌘U | 仅本 App 内 | **建议做成局部快捷键而非全局**：Coffer 流程是「呼出→搜索→回车复制」，全局复制热键脱离面板无目标 |
| 复制密码（面板内局部） | ⇧⌘C | 对齐 1Password 肌肉记忆 | 局部无系统冲突代价 |
| （若产品坚持全局）复制用户名/密码 | ⌃⌥⌘U / ⌃⌥⌘C | 系统未占用 | 四修饰键成本高，作下位替代 |

NFR-UX-03 定稿前须在真机（含 15.0–15.1 若仍在支持范围）回归注册返回值。

## 5. 运行时 0 socket（判据②）

- MenuBarExtra=SwiftUI、NSStatusItem=AppKit、RegisterEventHotKey=Carbon——均无网络框架依赖。
- 【实测】编译含 `import Carbon.HIToolbox` 的探针二进制，`otool -L` 仅链接 Carbon/Foundation/libSystem/swift 运行时，**无 CFNetwork**；现有 `macos/build/Coffer.app/Contents/MacOS/Coffer`（SwiftUI+AppKit）grep CFNetwork 零命中。
- 判据②的验证路径不变：真机 `lsof -p <pid>` 0 socket + `otool -L` 无网络框架 + entitlements 无 network.*（现有 `tools/check_no_network.sh` 管 Rust 依赖图侧，脚本头已声明边界）。
- 与「零网络=无云端、数据不出本机，本地 API 允许」的裁定（2026-09-27，见项目记忆）无冲突：本方案不引入任何本地 socket（XPC/stdio）以外的机制，且连 XPC 都不需要。

## 6. App 生命周期：两种模式取舍

| 模式 | 实现 | 取舍 | 行业参照 |
| --- | --- | --- | --- |
| A. 常规 App + 菜单栏图标（**推荐**） | 保留 Dock 图标；`MenuBarExtra` 常驻；关主窗口仅隐藏（`AppDelegate` 显式实现 `applicationShouldTerminateAfterLastWindowClosed -> false`【其文档页正文未能抓取，默认值此条为多方经验+实测建议，成本低、显式声明消除歧义】；或关窗时 `orderOut`） | 主窗口 UI（设置、多库、导入向导）是产品主体，Dock/⌘Tab 存在合理；实现最简 | Bitwarden 桌面端：主窗口 + 可选菜单栏图标 |
| B. LSUIElement=1 纯菜单栏 App | Info.plist 加 `LSUIElement`（无 Dock/⌘Tab） | 锁定态解锁流程、多库管理、附件操作都挤进小面板，可用性差；且改回需重装 | 1Password 8：默认菜单栏+Quick Access，但完整主窗口仍在（其「Show in menu bar」是设置项而非 LSUIElement 一刀切） |

**推荐 A + 设置项「在菜单栏显示图标」**（默认开，v0.4 可只做开态，开关延后）。判据②「关主窗口后 App 仍驻留」在模式 A 下天然满足。可选的「隐藏 Dock 图标」需求若日后出现，用运行时 `NSApp.setActivationPolicy(.accessory)`（即时生效）比 LSUIElement（需重启）灵活，v0.4 不做。

## 风险与缓解汇总

1. **⇧⌘Space 被 macOS 27 Siri AI 占用**（【文档】102650）→ 候选集已排除；定稿前重查一次 Apple 快捷键页（快捷键默认值会随大版本变化）。
2. **⌥-only 修饰在 15.0–15.1 沙盒回归（-9868）**→ 默认组合一律含 ⌘/⌃；实现时对非零返回值显式报错。
3. **MenuBarExtra(.window) 焦点缺陷**→ 搜索面板不进 MenuBarExtra；判据①落主窗口聚焦。
4. **Carbon+Space 支持存疑（单源）**→ ⌃⌥⌘Space 候选须真机验证后才能定稿。
5. **快捷键注册冲突（用户机器上被其他软件占用）**→ 设置项允许改键 + 注册失败提示（NFR-UX-03 之外的顺带建议）。

## 集成注意点（对当前项目）

- `CofferApp.swift`：加 `MenuBarExtra` Scene 即可，现有 `@NSApplicationDelegateAdaptor(AppDelegate.self)` 正好承载 `applicationShouldTerminateAfterLastWindowClosed` 与 Carbon handler 的安装（在 `applicationDidFinishLaunching` 注册，`applicationWillTerminate` 反注册）。
- `Info.plist`：模式 A **无需改动**（无 LSUIElement、无新 key）；构建脚本 `tools/build_macos_app.sh` **无需改动**；`Coffer.entitlements` **无需改动**。
- 呼出主窗口聚焦搜索框需要 `NSApp.activate(ignoringOtherApps: true)` + `makeKeyAndOrderFront`（沙盒下自家 App 唤起自身窗口是允许的）。
- 快捷键触发时 App 可能处于锁定态：判据①要求 锁定→快捷键→解锁→搜索→回车复制 通路，热键回调须能处理锁定态（弹解锁视图而非直接搜索）——与 `AppModel.phase` 的既有门禁（1001）一致。

## 依据（查询日期 2026-09-29）

- 实测环境：Apple Swift 6.3.1 (swiftlang-6.3.1.1.2)，macOS 26 SDK，`-target arm64-apple-macos14.0`，本机 Darwin 25.6.0
- Apple 论坛 763878（Sequoia 沙盒 ⌥/⇧ 热键回归与 15.2 修复，Apple 工程师确认）：https://developer.apple.com/forums/thread/763878
- Apple 论坛 811443（Quinn：沙盒键盘监听认可路径为 CGEventTap+Input Monitoring；全局 monitor 不可靠）：https://developer.apple.com/forums/thread/811443
- Apple 支持 102650（macOS 默认快捷键全集）：https://support.apple.com/en-us/102650
- 1Password Quick Access / 键盘快捷键：https://support.1password.com/quick-access/ 、https://support.1password.com/keyboard-shortcuts/
- Bitwarden 快捷键：https://bitwarden.com/help/keyboard-shortcuts/
- KeyboardShortcuts（MIT，v3.1.0，2026-09-11）：https://github.com/sindresorhus/KeyboardShortcuts ；HotKey（MIT，v0.2.1，2024-12-29）：https://github.com/soffes/HotKey
- MenuBarExtra 焦点缺陷多源：Apple 论坛 729920、exchangetuts（NSPanel canBecomeKey）、Qiita（borderless NSWindow 输入）
- 单源存疑项：chyshkala.com（Carbon Space 限制、未证实的「Global Shortcut entitlement」说法——后者在 Apple 官方 entitlement 列表中未见对应，采信度低）
