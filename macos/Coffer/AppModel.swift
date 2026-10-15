// AppModel.swift —— 应用全局状态（@MainActor ObservableObject）。
//
// 职责（docs/07 §2.4）：
//   - 持有 FFI 工厂（CofferApp）与当前 VaultSession 引用
//   - appPhase 状态机：booting → noVault / locked → unlocked
//   - 建库 / 解锁 / 锁定的异步编排（Argon2id 慢调用用 Task.detached 包裹）
//
// 明文纪律（docs/07 §2.4 / §4.2；docs/08 §7.4）：
//   - 主密码只作为方法参数传入，不落任何 @State / @Published 属性
//   - 明文字段值只在取值那一刻经 FFI 取回，用完即弃，不进本模型
//   - K_bio（bio unwrap-key）同纪律：Keychain 取回即用，不落任何属性

import AppKit
import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    // MARK: - Published 状态

    /// 启动/呼出自动引导一次性旗标：同一次锁定态内只弹一次（用户 2026-10-03
    /// 裁定，docs/08 §7.6）。发起自动认证时置位；phase 离开 .locked（解锁
    /// 成功 / 手动锁定 / 切库 / 无库）时复位——下一锁定态允许再次自动弹。
    private var autoPromptBiometricFired = false

    @Published var phase: AppPhase = .booting {
        didSet {
            // 复位时机（docs/08 §7.6）：phase 离开锁定态即复位；同一次锁定态
            // 内多次呼出不重复弹（取消后仍置位，避免启动/呼出反复骚扰用户）。
            if phase != .locked {
                autoPromptBiometricFired = false
            }
        }
    }
    @Published private(set) var vaultName: String = ""
    /// 当前库 UUID 文本（Keychain bio 项的 account，docs/08 §3.2；非密钥材料）。
    @Published private(set) var vaultUUID: String = ""
    /// 最近一次可呈现的错误文案（code+message 直出，见 ErrorPresenter）。
    @Published var lastErrorMessage: String?
    /// 慢调用（建库 / 解锁 / 导入）进行中标记，用于禁用按钮。
    @Published private(set) var isBusy = false

    // MARK: 主窗口 sheet 触发状态（@Published 提升到此：菜单栏「数据」
    // 菜单与工具栏/横幅按钮需要跨视图触发同一 sheet，验收反馈补齐）。
    // 设置不在本列：v2.4.1 改独立窗口（CofferApp Window scene，openWindow
    // id "settings" 触发，左上角红绿灯关闭），不占 sheet 状态。
    /// 导入 CSV sheet（工具栏 + 菜单 ⌘I）。
    @Published var showImport = false
    /// 导入 1PUX sheet（工具栏「导入」菜单 + 菜单 ⌘⇧I，v0.3.0-T05 FR-7.1）。
    @Published var showImportPux = false
    /// 导入 Bitwarden JSON sheet（工具栏「导入」菜单，v0.5.0 PK3 FR-10.1）。
    @Published var showImportBitwarden = false
    /// 导入 OPVault sheet（v2.9.0 P3 IA-06：工具栏「导入」菜单 + 菜单栏「数据」
    /// 双渠道同源触发。自 MainView 本地 @State 提升到 AppModel @Published，
    /// 与 showImport/showImportPux/showImportBitwarden 同纪律）。
    @Published var showImportOpvault = false
    /// 放置区导入 sheet（v2.11.0，docs/03 §21a §3.1）：三处入口（MainView 工具栏
    /// 导入菜单 + 空态菜单 + DataCommands「数据」菜单）同源触发；sheet 挂载是
    /// G6 的职责（MainView `.sheet(isPresented:)`），本属性只作跨视图触发开关，
    /// 与 showImport/showImportOpvault 提升同先例。
    @Published var showImportDropzone = false
    /// 导出 sheet（备份 + CSV，工具栏 + 菜单 ⌘E + 备份横幅「立即备份」）。
    @Published var showExport = false
    /// 库切换器 sheet（v0.4 FR-1.2，MB-1：MainView 工具栏切换器触发，
    /// sheet 挂 RootView——与导入/设置同一跨视图触发模式）。
    @Published var showVaultSwitcher = false
    /// 密码库管理面 sheet（v2.10.0 D1，docs/17 §4）：库切换 sheet 底部深链 /
    /// LockView「管理密码库…」工厂级入口经此在**主窗**（RootView）呈现，
    /// 规避 sheet-on-sheet（UDR-6，先关切换 sheet 再弹管理面）。设置「数据」
    /// 区入口走 SettingsView 本地 @State sheet（设置窗源，F3 随窗口自关），
    /// 不占本状态。
    @Published var showVaultManagement = false
    /// OTA 更新 sheet 触发（v2.7.0，docs/35 §2.6）：关于页「检查更新…」按钮与
    /// UpdateSheet 内部重试触发（应用菜单「检查更新…」同项于 BUG-24 复测裁定
    /// 2026-10-14 移除）；设置页不放任何更新入口（用户裁定）。
    @Published var showUpdateSheet = false
    /// 「关于 Coffer」对话框 sheet 触发（应用菜单「关于 Coffer…」；自建关于
    /// 视图以容纳「检查更新…」按钮，见 AboutUpdateView）。
    @Published var showAbout = false
    /// 「检查更新…」触发后、About sheet 尚未关闭前为 true，由 onDismiss 回调消费
    /// （BUG-24 复测「sheet 延迟呈现修正」：About 在屏时等它真正关闭再开
    /// UpdateSheet，见 checkForUpdates/aboutSheetDidDismiss）。
    private var updateSheetPendingAfterAboutDismiss = false
    /// 「键盘快捷键」速查 sheet 触发（v2.9.1，GitLab issue #5）：帮助菜单
    /// 「键盘快捷键…」触发，CommandGroup 菜单不可达视图层 @State，与
    /// showImport/showAbout 提升同先例。帮助无密级，锁定/解锁态均可触发，
    /// 故不随 lock() 清理（静态只读面板，无密级内容残留问题）。
    @Published var showShortcuts = false
    /// 「使用入门」sheet 触发（v2.9.1，GitLab issue #6）：帮助菜单「使用
    /// 入门…」触发，正文为本地静态文案（零网络纪律，禁外链/禁自动更新
    /// 检查）。与 showShortcuts 同纪律：无密级、不随 lock() 清理。
    @Published var showHelp = false
    /// 「帮助中心」sheet 触发（v2.10.1，docs/19 §3/§7）：帮助菜单「帮助
    /// 中心…」触发，正文为九章静态本地文案（零网络纪律同 showHelp；内容
    /// 源 HelpCenterContent）。与 showShortcuts/showHelp 同纪律：无密级、
    /// 不随 lock() 清理。
    @Published var showHelpCenter = false
    /// 新建条目 sheet 触发类别（v2.9.0 P7，docs/14 §A P7 §3.1）：自 MainView
    /// 本地 @State 提升到 AppModel @Published——CommandGroup 菜单不可达视图层
    /// @State，与 showImport/showImportOpvault 提升同先例。⌘N 置 `.login`
    /// （`editableCategories` 首项）；工具栏「新建」菜单置用户所选类别；
    /// sheet 关闭时 sheet(item:) 绑定自动置 nil。lock() 内清 nil（防锁定后
    /// 残留 sheet，与 selectedItemID/currentDetails 同组纪律）。
    @Published var pendingNewCategory: FfiItemCategory?

    // MARK: 放置区导入授权（v2.11.0，docs/03 §21a §3.1/§3.2；D-18.4 广播单源）

    /// 放置区授权目录（**单一真相**，docs/03 §21a §3.2 / DESIGN.md D-18.4）：
    /// `nil` = 未授权。写侧只由向导 S0（`DropzoneBookmarkStore.save` 单点）经
    /// `setDropzoneBookmark` 更新；删侧只由设置页「移除授权」经
    /// `removeDropzoneAuthorization` 置 nil 广播——向导（打开中）与设置页
    /// 同源同步回 `.notAuthorized`。启动时从 store 装载（含跨重启持久性，
    /// §5.1 实证第 5 步）。本属性是 D-18.4「状态广播可达」的枢纽：任一出现面
    /// 移除/失效都经此属性下发。
    @Published var dropzoneBookmark: DropzoneBookmark? = DropzoneBookmarkStore.shared.load()

    /// 放置区授权三态（docs/03 §21a §3.1 / DESIGN.md D-18.2）：由
    /// `dropzoneBookmark` 派生——nil → `.notAuthorized`；非 nil 且
    /// `validate` 通过 → `.authorized`；非 nil 但校验失败（目录移动/删除/
    /// 权限变更/系统清理）→ `.stale`（D-18.3 失效非静默）。派生而非独立
    /// @Published：bookmark 变化即经 objectWillChange 广播，多出现面
    /// （向导 + 设置页 DropzoneAuthStatusView）同源同步，无旁路分支。
    var dropzoneAuthStatus: DropzoneAuthStatus {
        guard let bookmark = dropzoneBookmark else { return .notAuthorized }
        return DropzoneBookmarkStore.shared.validate(bookmark)
            ? .authorized(bookmark)
            : .stale(bookmark)
    }

    /// 落盘放置区授权（D-18.4 唯一写点接线）：向导 S0 经 `save` 成功后回调，
    /// 更新单一真相并广播（设置页 DropzoneAuthStatusView 同源切到 .authorized）。
    /// - Parameter bookmark: `DropzoneBookmarkStore.save` 返回的持久化凭据。
    func setDropzoneBookmark(_ bookmark: DropzoneBookmark) {
        dropzoneBookmark = bookmark
    }

    /// 移除放置区授权（D-18.4 唯一删点 + 广播）：设置页「移除授权」调用——
    /// 清除 store 持久化 bookmark，置 nil 广播；向导（打开中）与设置页同步回
    /// `.notAuthorized`。只删授权凭据，目录与文件不动（D-1.3 非破坏性）。
    func removeDropzoneAuthorization() {
        DropzoneBookmarkStore.shared.remove()
        dropzoneBookmark = nil
    }

    /// 解锁失败暴力退避（FR-12.5，T-J）门禁截止时刻；nil = 无倒计时。
    ///
    /// 计时模式：只在收到 1002 时经 `backoffRemainingSecs` 旁路读**一次**
    /// 剩余秒数，换算成本地截止 Date（LockView 用 TimelineView 本地倒数），
    /// 不轮询 FFI。1002 一码两义（普通密码错 / 门禁期拒绝），区分即靠该
    /// 旁路：剩余 > 0 才是门禁期。门禁期内强试 unlock 返回 1002 但不计数、
    /// 不延长门禁（core/cf-session/src/backoff.rs `try_acquire` 门禁优先），
    /// 倒计时不被强试推迟。内存级：计数器在 Rust 会话内，App 重启归零
    /// （docs/09 冻结裁决，设计接受）。
    @Published private(set) var lockBackoffDeadline: Date?

    /// 建库成功后的可选「启用 Touch ID」步骤标记（docs/08 §4.1 建库可选启用）。
    /// 建库成功时置位（仅 Touch ID 设备）；用户在首次解锁后的引导 sheet 中
    /// 完成或跳过后清除。无 Touch ID 设备恒 false——v0.1 建库流程零变化
    /// （docs/08 §9 T04 验收①）。
    @Published var pendingBioOffer = false

    /// 首次解锁后的可选「生成恢复码」引导（v2.5.0 FR-17.2，docs/31 §4.3 D-8）。
    /// 建库成功时置位；RootView 在解锁态呈现 RecoveryCodeOfferSheet，且用
    /// `!pendingBioOffer` 保证不与 Touch ID 引导同屏（bio 先、恢复码后）。
    @Published var pendingRecoveryOffer = false

    // MARK: 首启引导合并 + 首次高亮兜底（v2.9.0 P2-A，docs/14 §A P2 §2/§2.5；
    // DESIGN.md P-2.1 契约）

    /// 首启引导向导呈现条件（P2-A）：解锁态下两枚引导旗标任一置位即呈现
    /// **单个 sheet 向导**（RootView 挂载 OnboardingWizard，替代原先两个独立
    /// sheet，FW-01 关闭）。派生计算属性非 @Published——无独立状态，完全由
    /// pendingBioOffer / pendingRecoveryOffer 驱动，两旗标均清即自动收口。
    var showOnboarding: Bool {
        phase == .unlocked && (pendingBioOffer || pendingRecoveryOffer)
    }

    /// 引导步骤「跳过」记录（DESIGN.md P-2.1 契约）：向导 Step1 跳过时置位，
    /// Touch ID 启用成功时清位（enableTouchID 成功路径）；落盘 UserDefaults
    /// （didSet，对齐 clipboardClearSecs 模式）。仅作设置页首次高亮兜底判定，
    /// 不参与引导流程本身。**「已完成」不落盘**——由 touchIDStatus live 派生。
    nonisolated static let bioOfferSkippedKey = "bio_offer_skipped"
    @Published var bioOfferSkipped: Bool = AppModel.loadBioOfferSkipped() {
        didSet {
            UserDefaults.standard.set(bioOfferSkipped, forKey: Self.bioOfferSkippedKey)
        }
    }

    /// 引导 Step2（恢复码）跳过记录（同上，docs/14 §A P2 §2.5）。启用恢复码
    /// 成功时清位（enableRecoveryCode 成功路径）；「已完成」由 hasRecoveryWrap
    /// live 派生，不落盘。
    nonisolated static let recoveryOfferSkippedKey = "recovery_offer_skipped"
    @Published var recoveryOfferSkipped: Bool = AppModel.loadRecoveryOfferSkipped() {
        didSet {
            UserDefaults.standard.set(recoveryOfferSkipped, forKey: Self.recoveryOfferSkippedKey)
        }
    }

    nonisolated private static func loadBioOfferSkipped() -> Bool {
        UserDefaults.standard.bool(forKey: bioOfferSkippedKey)
    }
    nonisolated private static func loadRecoveryOfferSkipped() -> Bool {
        UserDefaults.standard.bool(forKey: recoveryOfferSkippedKey)
    }

    /// 设置页首次高亮条件（P2-A §2.5 / AC-2.9.0-P2A-10）：引导 Step1 被跳过
    /// 且 Touch ID 未启用。启用对应功能后即清除（enableTouchID 成功清位 +
    /// touchIDStatus 刷新，两路皆 @Published → 高亮 live 消失）。
    var showBioSetupHighlight: Bool {
        bioOfferSkipped && touchIDStatus == .disabled
    }

    /// 设置页恢复码区首次高亮条件（P2-A §2.5 / AC-2.9.0-P2A-11）：引导 Step2
    /// 被跳过且恢复码未生成（hasRecoveryWrap live 判定）。
    var showRecoverySetupHighlight: Bool {
        recoveryOfferSkipped && !hasRecoveryWrap
    }

    // MARK: P4 安全体检 destination（v2.9.0，docs/14 §A P4 §2/§4）

    /// 详情区「安全体检」整页 destination 呈现标记（P4）：true 时详情区
    /// 渲染 HealthCheckView 整页（优先级最高，覆盖条目详情与「未选中」占位）。
    /// 入口=中列工具栏「安全体检」按钮（toggle 语义）；退出=再次点击按钮 /
    /// 选择任一列表条目（MainView onChange 清位）/ 体检页跳条目
    /// （HealthCheckView.jump 先行清位）/ 锁定（lock() 复位，与 selectedItemID
    /// 同纪律，防锁定后残留 destination）。
    @Published var showHealthDestination = false

    // MARK: 条目列表 / 详情状态（T05 阶段二）

    /// 当前过滤 + 搜索下的条目摘要列表。
    @Published var items: [FfiItemSummary] = []
    /// 侧栏过滤条件（变更即重载列表）。
    @Published var sidebarFilter: SidebarFilter = .all {
        didSet { guard oldValue != sidebarFilter else { return }; reloadItems() }
    }
    /// 标题搜索词（非空时走 search 接口）。
    @Published var searchText: String = ""
    /// 当前选中条目 ID。
    @Published var selectedItemID: String? {
        didSet { guard oldValue != selectedItemID else { return }; loadSelectedDetails() }
    }
    /// 选中条目的完整详情（Concealed 值已掩码）。
    @Published var currentDetails: FfiItemDetails?

    // MARK: 复制禁用谓词 + 复制动作（v2.9.0 P7 / REV2-08，docs/14 §A P7 §2.2）

    /// 复制密码禁用谓词（⌘⇧C 菜单项与列表 Enter 按钮**同一来源**，REV2-08）：
    /// `currentDetails` 为 nil 或无密码字段时禁用——HK-3 同一语义（含 FR-5.6
    /// TOTP 序列复制）。视图层只消费、不各自派生，无「菜单可用/按钮禁用」分叉。
    var canCopyPassword: Bool {
        currentDetails?.fields.contains { $0.designation == .password } ?? false
    }

    /// 复制用户名禁用谓词（⌘U，HK-4 同语义：无用户名禁用）。用户名为普通
    /// 字段，值已随详情直出（掩码纪律只约束 Concealed 字段），不经
    /// fieldValue 跨桥——与 MainView 原局部 `selectedUsername` 判定一致，
    /// 上收为 AppModel 派生谓词（REV2-08）。
    var canCopyUsername: Bool {
        guard let field = currentDetails?.fields.first(where: {
            $0.designation == .username
        }), let value = field.value, !value.isEmpty else { return false }
        return true
    }

    /// 复制验证码禁用谓词（⌥⇧C）：`currentDetails` 为 nil 或条目无 TOTP
    /// （`totp == nil`）时禁用。
    var canCopyTotp: Bool {
        currentDetails?.totp != nil
    }

    /// 复制选中条目密码（HK-3 / P7 ⌘⇧C 与 Enter 共用，docs/15 §3.3.3
    /// FR-5.6 序列）：条目含 TOTP（details.totp 非空）才走「密码 → 延迟 →
    /// TOTP」序列，否则单次自动清除复制（现状）。明文经 fieldValue 随取随
    /// 用，不落状态。无选中 / 无密码字段由谓词 canCopyPassword 禁用拦截，
    /// 此处 guard 兜底。
    func copySelectedPassword() {
        guard let itemId = selectedItemID,
              let details = currentDetails,
              let passwordField = details.fields.first(where: {
                  $0.designation == .password
              }) else { return }
        do {
            guard let password = try fieldValue(itemId: itemId, fieldId: passwordField.uuid),
                  !password.isEmpty else { return }
            if details.totp != nil {
                // totpProvider 延迟执行取 fresh code；闭包体内访问本 @MainActor
                // 的 AppModel，经 assumeIsolated 进入——ClipboardManager 保证
                // 回调只在主队列触发。self 强捕获无循环（ClipboardManager 为
                // 单例，AppModel 不反向持有它）。
                ClipboardManager.shared.copyPasswordThenTotp(password: password) {
                    MainActor.assumeIsolated { try? self.totpCode(itemId: itemId).code }
                }
            } else {
                ClipboardManager.shared.copyWithAutoClear(password)
            }
        } catch {
            // 1001（取值时会话已锁）→ 切回锁定界面；其余 code+message 直出
            handleFfiError(error)
        }
    }

    /// 复制选中条目用户名（HK-4 / P7 ⌘U，copyPlain 不自动清除，与
    /// FieldRowView 普通字段复制同纪律）。无用户名由谓词 canCopyUsername
    /// 禁用拦截，此处 guard 兜底。
    func copySelectedUsername() {
        guard let field = currentDetails?.fields.first(where: {
            $0.designation == .username
        }), let value = field.value, !value.isEmpty else { return }
        ClipboardManager.shared.copyPlain(value)
    }

    /// 复制选中条目当前 TOTP 验证码（P7 ⌥⇧C，FR-5.5：copyPlain 不清除——
    /// 验证码 30/60 s 内自动轮换）。无选中 / 无 TOTP 由谓词 canCopyTotp
    /// 禁用拦截，此处 guard 兜底。
    func copySelectedTotp() {
        guard let itemId = selectedItemID, currentDetails?.totp != nil else { return }
        do {
            let code = try totpCode(itemId: itemId)
            ClipboardManager.shared.copyPlain(code.code)
        } catch {
            handleFfiError(error)
        }
    }

    // MARK: 自动锁定配置（T05 阶段四）

    /// 空闲自动锁定分钟数（0 = 从不）。默认 5 分钟（FR-12.1）。
    @Published var autoLockMinutes: Int = AppModel.loadAutoLockMinutes() {
        didSet {
            // 0（从不）落盘为 -1，与「从未配置」区分
            UserDefaults.standard.set(autoLockMinutes == 0 ? -1 : autoLockMinutes,
                                      forKey: Self.autoLockDefaultsKey)
            applyIdleTimeout()
        }
    }

    // MARK: 剪贴板清除配置（T06 / FR-14.2）

    /// 剪贴板自动清除秒数（FR-14.2 五档：10 / 30 / 60 / 120 / 0=从不）。
    /// 注意哨兵语义与 autoLockMinutes 相反：这里 0 = 从不（不落 -1）。
    /// didSet：① UserDefaults 落盘 ② 同步 ClipboardManager 定时器
    /// ③ 回放到 Rust 会话（try? 原因：该调用锁定态也可用，失败仅意味
    /// Rust 侧镜像值未更新——Swift 侧定时器（实际执行者，C-5）已生效，
    /// 且新值在写入前已经两侧档位校验，失败属理论路径，无安全影响）。
    @Published var clipboardClearSecs: Int = AppModel.loadClipboardClearSecs() {
        didSet {
            // 防御校验（P3）：当前无调用方可写非法值，但一旦有未来路径
            // 写入非法值，会导致 UserDefaults / ClipboardManager / Rust
            // 会话三处状态互相不一致——宁可不生效也不落脏数据。
            guard ClipboardManager.isValidClearSecs(clipboardClearSecs) else { return }
            guard oldValue != clipboardClearSecs else { return }
            UserDefaults.standard.set(clipboardClearSecs,
                                      forKey: Self.clipboardClearDefaultsKey)
            ClipboardManager.shared.updateClearInterval(secs: clipboardClearSecs)
            if let session {
                try? session.setClipboardClearSecs(secs: Int64(clipboardClearSecs))
            }
        }
    }

    /// 从 UserDefaults 读档位（nonisolated，供属性默认值使用）。
    /// 校验与回退规则在 ClipboardManager.loadStoredClearSecs（两侧共用一处）。
    nonisolated private static func loadClipboardClearSecs() -> Int {
        ClipboardManager.loadStoredClearSecs()
    }
    nonisolated static let clipboardClearDefaultsKey = ClipboardManager.clearSecsDefaultsKey

    /// 从 UserDefaults 读已保存档位（nonisolated，供属性默认值使用）。
    nonisolated private static func loadAutoLockMinutes() -> Int {
        let stored = UserDefaults.standard.integer(forKey: "autoLockMinutes")
        // 未配置（键不存在时 integer 返回 0）→ 默认 5 分钟；-1 = 用户选了「从不」
        switch stored {
        case 0: return 5
        case -1: return 0
        default: return autoLockOptions.contains(stored) ? stored : 5
        }
    }
    /// 可选档位：1 / 5 / 15 / 30 / 60 分钟、从不（FR-14.1 六档）。
    nonisolated static let autoLockOptions: [Int] = [1, 5, 15, 30, 60, 0]
    nonisolated static let autoLockDefaultsKey = "autoLockMinutes"
    /// 自动锁定平台驱动（锁屏 / 休眠 / 屏保立即锁定 + 空闲喂入）。
    private var lockMonitor: AutoLockMonitor?

    // MARK: 备份提醒（FR-8.5 / T06 设置页归位；T-G 评估逻辑已接入）

    /// 备份提醒间隔天数（FR-8.5 四档：0 = 禁用 / 7 / 14 / 30，默认 30）。
    /// 哨兵语义注意（三者互不相同，勿混淆）：
    ///   - autoLockMinutes：运行态 0 = 从不，落盘 -1 = 从不；
    ///   - clipboardClearSecs：0 = 从不（落盘同值）；
    ///   - backupReminderDays：0 = 禁用提醒（落盘同值）。
    /// didSet 落盘 + 解锁态下重评估（T-G）：改档即重算横幅
    /// （如从 30 天改 7 天且已超期，横幅立即出现；反之立即消失）。
    @Published var backupReminderDays: Int = AppModel.loadBackupReminderDays() {
        didSet {
            // 防御校验（与 clipboardClearSecs 同纪律）：非法值宁可不生效，
            // 也不落脏数据破坏「UserDefaults / 设置页」两处一致。
            guard Self.backupReminderOptions.contains(backupReminderDays) else { return }
            guard oldValue != backupReminderDays else { return }
            UserDefaults.standard.set(backupReminderDays,
                                      forKey: Self.backupReminderDefaultsKey)
            evaluateBackupReminder()
        }
    }

    /// 备份提醒横幅可见性（FR-8.5，T-G）。提醒非配置：不入 UserDefaults，
    /// 每次解锁成功 / 改档 / 备份导出成功时重算（见 evaluateBackupReminder）。
    @Published private(set) var showBackupBanner = false

    /// 从 UserDefaults 读档位（nonisolated，供属性默认值使用）。
    /// 用 object(forKey:) 区分「未配置」与「显式 0（禁用）」——integer(forKey:)
    /// 对键不存在也返回 0，而 0 是合法档位，必须区分（同 ClipboardManager 纪律）。
    nonisolated private static func loadBackupReminderDays() -> Int {
        guard let stored = UserDefaults.standard.object(forKey: backupReminderDefaultsKey) as? Int
        else { return defaultBackupReminderDays }
        return backupReminderOptions.contains(stored) ? stored : defaultBackupReminderDays
    }
    /// 可选档位：禁用 / 7 / 14 / 30 天。
    nonisolated static let backupReminderOptions: [Int] = [0, 7, 14, 30]
    /// 默认档位：30 天（FR-8.5）。
    nonisolated static let defaultBackupReminderDays = 30
    nonisolated static let backupReminderDefaultsKey = "backupReminderDays"

    /// 评估是否显示备份提醒横幅（FR-8.5，T-G）。
    ///
    /// 调用时机纪律：shouldSuggestBackup 有解锁态门禁（Rust 1001），只能在
    /// 解锁完成后调用——本模型在 unlock / unlockWithTouchID 成功切 .unlocked
    /// 之后、backupReminderDays didSet（改档即重评估）三处调用。
    ///
    /// - days == 0（禁用）→ 直接置 false，不发 FFI 调用（Rust 侧
    ///   threshold <= 0 同样视为禁用，此处提前短路省一次跨桥）。
    /// - 从未备份：Rust 侧 lastBackupAt 为 nil 同样返回应提醒，无需区分文案。
    /// - FFI 失败（含 1001）按「不提醒」处理：提醒是 Should 级非门禁功能，
    ///   评估失败静默降级为不显示横幅，不阻塞解锁流程、不打扰用户。
    func evaluateBackupReminder() {
        guard phase == .unlocked, let session else {
            showBackupBanner = false
            return
        }
        // 防御校验（与 didSet 同纪律）：非法档位视为禁用
        guard Self.backupReminderOptions.contains(backupReminderDays) else {
            showBackupBanner = false
            return
        }
        // 0 = 禁用提醒（FR-8.5 档位语义）：不发 FFI 调用
        guard backupReminderDays > 0 else {
            showBackupBanner = false
            return
        }
        let threshold = Int64(backupReminderDays) * 86_400
        let now = Int64(Date().timeIntervalSince1970)
        showBackupBanner = (try? session.shouldSuggestBackup(thresholdSecs: threshold, nowSecs: now)) == true
    }

    /// 「暂不」：本会话隐藏横幅。下次解锁成功 / 改档 / 备份导出成功时
    /// 会重评估（提醒非配置，状态不持久化）。
    func dismissBackupBanner() {
        showBackupBanner = false
    }

    // MARK: 生成器默认参数（FR-14.3 / T08，docs/22 §2.4；docs/23 §1.4 TC-GEN）

    /// 生成器默认参数（FR-14.3）：启动时从 UserDefaults 读档
    /// （GeneratorDefaults.load 自处理缺失/损坏回退内置默认，TC-GEN-04）。
    /// **不在 didSet 落盘**——持久化只在用户显式「另存为默认」
    /// （saveGeneratorDefaults）时发生：设置页编辑中的草稿不污染存档
    /// （编辑→放弃不留痕）。生成器面板预填钩子读本值（TC-GEN-01，
    /// ItemEditView 接线，T11 收尾）。
    private(set) var generatorDefaults: GeneratorDefaults = GeneratorDefaults.load()

    /// 「另存为默认」（FR-14.3，TC-GEN-01/03）：校验通过才更新内存态并写
    /// UserDefaults；非法参数返回 false 且不落盘（对齐 generate_password
    /// 1012 Validation 语义，见 GeneratorDefaults.isValid）。
    @discardableResult
    func saveGeneratorDefaults(_ draft: GeneratorDefaults) -> Bool {
        guard draft.isValid else { return false }
        generatorDefaults = draft
        draft.save()
        return true
    }

    // MARK: - FFI 对象

    /// Rust 侧应用工厂（库的枚举 / 创建 / 打开注册表）。
    let factory: CofferApp
    /// 当前打开的库会话；noVault 阶段为 nil。
    private(set) var session: VaultSession?

    // MARK: - 多库（v0.4 FR-1.2，MB-1）

    /// 工作目录内库列表缓存（已锁定元数据，非密钥材料）：bootstrap 装载，
    /// 切换器 sheet 打开时经 `reloadVaultBriefs()` 刷新（建库 / 切换不在此
    /// 更新，下次打开 sheet 时刷新即可）。
    @Published private(set) var vaultBriefs: [FfiVaultBrief] = []

    /// UserDefaults 键：最近使用的库 UUID（UUIDv7 文本，非密钥材料）。
    /// bootstrap 默认库选择依据（docs/15 §3.2.1：lastVaultUUID 优先，
    /// 失效回退 createdAt 最新）；删除该键即回退旧行为（可逆）。
    nonisolated static let lastVaultUUIDDefaultsKey = "lastVaultUUID"

    /// 删除库后的落位结果（v2.10.0 D1，docs/17 §3.1）：视图 Step5 反馈与
    /// 管理面生命周期据此呈现。Equatable 以断言。
    enum DeleteVaultLanding: Equatable {
        /// 多库：当前会话落位到 createdAt 最近者（已锁 / 保持锁定态引导解锁）。
        case switchedToMostRecent(FfiVaultBrief)
        /// 单库：删光全库，落 .noVault 空库首屏（VaultSetupView）。
        case noVault
        /// 删非当前库：会话不变（解锁态保持、不切库、不重建 session、不重写
        /// lastVaultUUID），仅列表刷新 + 反馈（lead 裁定 2026-10-13，docs/17
        /// §3.3；AC-2.10.0-DL-6）。
        case sessionUnchanged
    }

    // MARK: - 路径

    /// L3 AX 黑盒库隔离 seam（docs/19 §5.3，lead 批准 2026-10-16）：非空时
    /// 把 baseDir 重定向到该绝对路径，隔离真实库——dev build 与已装 App 共享
    /// 同一沙盒容器同一真实库，不隔离必触 R2 红线（见 init）。
    /// 用法：`defaults write top.cygnusyang.coffer coffer.testBaseDir <绝对路径>`
    /// 后重启 App；`defaults delete top.cygnusyang.coffer coffer.testBaseDir`
    /// 恢复（nil / 空串 = 现状，零行为变化）。
    nonisolated static let debugTestBaseDirKey = "coffer.testBaseDir"

    /// 库工作目录（沙盒内 Documents/Coffer）。
    let baseDir: URL

    /// 当前库的库目录（`<baseDir>/<vaultUUID>`，含 header.json）。
    /// 注意与 baseDir 区分：`exportBackup(vaultDir:)` 的契约参数是**库目录**
    /// （非合法库目录 → 1012），restoreBackup 的 target 才是工作目录
    /// （BUG-7 修复时新增，此前 ExportView 误传 baseDir）。
    var vaultDirPath: String {
        baseDir.appendingPathComponent(vaultUUID, isDirectory: true).path
    }

    private var terminateObserver: NSObjectProtocol?

    // MARK: - 生命周期

    nonisolated init() {
        // 注意：AppModel 是 @MainActor，但 Swift 5 模式下 @StateObject
        // 初始化发生在主线程，这里的非隔离初始化只做确定性、无 IO 副作用的装配。
        self.factory = CofferApp()

        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
        let defaultBaseDir = documents.appendingPathComponent("Coffer", isDirectory: true)
        // L3 AX 黑盒库隔离 seam（docs/19 §5.3）：`coffer.testBaseDir` 非空 →
        // 用其绝对路径作工作目录（隔离真实库，L3 驱动不触 R2 红线）；nil /
        // 空串 → 现状沙盒 Documents/Coffer，零行为变化。用法 / 风险见
        // debugTestBaseDirKey 注释。
        let configuredBaseDir = UserDefaults.standard.string(forKey: Self.debugTestBaseDirKey)
        if let testBaseDir = configuredBaseDir, !testBaseDir.isEmpty {
            self.baseDir = URL(fileURLWithPath: testBaseDir, isDirectory: true)
        } else {
            self.baseDir = defaultBaseDir
        }
    }

    /// 启动入口（RootView.onAppear 调用）：建目录 + 枚举已有库 + 启动自动锁定监视。
    func bootstrap() {
        // 幂等：仅在 booting 阶段执行一次。
        guard phase == .booting else { return }
        try? FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        // 官方许可装配（契约 #2，docs/03 §14.9）：任何 vault 操作之前注入。
        //   - 公开构建（无 OFFICIAL_LICENSE）：本块不编译，行为 = PermitAll
        //     全功能免费版（TC-BLD-02）；
        //   - 官方构建：Rust 侧 installOfficialLicense 注入 gate + Q-17a 试用
        //     起点预热；Swift 侧 LicenseAssembly.shared 换入官方适配。装配失败
        //     （构建期不变量破坏，理论不可达）→ 保持 PermitAll 免费版语义
        //     （契约 #2 fallback：闭源侧缺失时公开仓保持可用）并落诊断日志。
        //   同步执行与既有 listVaults 同纪律（bootstrap 主线程一次性的短路径；
        //   若实测 Keychain 访问过慢，改 Task.detached 并在 openSession 前等待）。
        #if OFFICIAL_LICENSE
        do {
            try factory.installOfficialLicense()
            LicenseAssembly.shared = try OfficialLicenseService()
        } catch {
            DiagLog.append("official license assembly failed: \(error)")
        }
        #endif

        // 自动锁定监视（持弱引用，无循环）
        let monitor = AutoLockMonitor()
        monitor.start(model: self)
        lockMonitor = monitor

        do {
            let briefs = try factory.listVaults(baseDir: baseDir.path)
                .sorted { $0.createdAt < $1.createdAt } // createdAt 升序（列表展示稳定序）
            vaultBriefs = briefs
            // 默认库选择（v0.4 MB-1，docs/15 §3.2.1）：lastVaultUUID 优先
            // （记录仍存在 → 打开它）；无记录 / 记录失效 → 回退 createdAt
            // 最新（现状行为，单库用户零感知）；无库 → noVault（现状）。
            let lastUUID = UserDefaults.standard.string(forKey: Self.lastVaultUUIDDefaultsKey)
            if let brief = Self.selectBootstrapVault(briefs, lastVaultUUID: lastUUID) {
                openSession(brief)
            } else {
                phase = .noVault
            }
            // 启动自动 Touch ID 引导（用户 2026-10-03 裁定，docs/08 §7.6）：
            // 库已打开（phase == .locked）且 refreshTouchIDStatus 已跑（adoptSession
            // 内），单库 ∧ 设备支持 ∧ 通道 enabled → 不经点击直接弹指纹认证框。
            // 仅启动路径触发——openSession 其他调用方（切换库/恢复备份）不得自动弹。
            maybeAutoPromptBiometric()
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
        // 首启消费上次 OTA 安装结果（r0.4 §6.4 第 6 步）：无论库相位（含 .fatal）
        // 都执行——更新成败呈现与密码库无关；成功静默，失败经 showUpdateSheet
        // 呈现 .failed（含退出码文案）。
        consumePendingUpdateResultIfNeeded()
    }

    /// bootstrap 默认库选择（纯函数，docs/15 §3.2.1）：lastVaultUUID 仍在
    /// 列表中 → 打开它（优先级高于创建时间）；否则回退 createdAt 最新。
    /// 纯函数（无 IO / 无 UserDefaults 依赖），独立单测覆盖
    /// （Tests 手册模式：记录命中 / 失效 / 单库 / 空列表四组）。
    nonisolated static func selectBootstrapVault(
        _ briefs: [FfiVaultBrief], lastVaultUUID: String?
    ) -> FfiVaultBrief? {
        if let lastVaultUUID,
           let recorded = briefs.first(where: { $0.vaultUuid == lastVaultUUID }) {
            return recorded
        }
        return briefs.max { $0.createdAt < $1.createdAt }
    }

    /// 自动 Touch ID 引导统一入口（启动 / 菜单栏呼出共用，用户 2026-10-03
    /// 裁定，docs/08 §7.6）：
    ///   - 判定：`phase == .locked` 状态前置 + 纯函数
    ///     shouldAutoPromptBiometric（含一次性旗标与 isBusy 判重）+ header
    ///     双保险。同一次锁定态只弹一次（旗标 phase 离开 .locked 复位）；
    ///     自动认证进行中（isBusy）不重复触发。
    ///   - 发起：置旗标后 Task 抛异步认证（unlockWithTouchID 是 async，
    ///     bootstrap / summon 均为同步上下文；与 LockView 手点同一调用方式）。
    ///     错误分派统一在 unlockWithTouchID（reviewer HIGH 处置，docs/08 §7.6）：
    ///     用户取消（.userCanceled）静默、凭据失效（.itemNotFound/.authFailed）
    ///     呈现 4002 并置 stale——手动/自动路径语义一致。
    ///   - 呼出场景的「窗口确从隐藏恢复」由 AppDelegate.summonMainWindow 先行
    ///     判定（wasHidden）后再调用本方法；窗口开着时自动锁定后再解锁
    ///     不自动弹（用户未裁定，不实现）。
    /// - Returns: 是否发起了自动认证（调用方可据此判重）。
    @discardableResult
    func maybeAutoPromptBiometric() -> Bool {
        guard phase == .locked,
              AutoPromptBiometric.shouldAutoPromptBiometric(
                  vaultCount: vaultBriefs.count,
                  isSupported: BiometricKeychain.isBiometricsAvailable(),
                  status: touchIDStatus,
                  firedInLockState: autoPromptBiometricFired,
                  isBusy: isBusy
              ),
              let session, session.hasBiometricWrap() else { return false }
        autoPromptBiometricFired = true
        Task { await unlockWithTouchID() }
        return true
    }

    // MARK: - 会话管理

    /// 建库 / 启动 / 恢复后打开统一入口（openVault + 状态收尾，phase → .locked
    /// 由 LockView 承担解锁引导）。T-H（FR-8.1）：恢复流为第三个调用点——
    /// RestoreBackupView 恢复完成后按 vaultUuid 匹配 brief 经此开会话，故由
    /// private 收紧为 internal 最小可见性（签名与行为不变）。
    func openSession(_ brief: FfiVaultBrief) {
        do {
            let opened = try factory.openVault(baseDir: baseDir.path, vaultUuid: brief.vaultUuid)
            adoptSession(opened, brief: brief)
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
    }

    /// 会话装配（openSession / switchVault 成功路径的公共收尾，语义与
    /// v0.3 openSession 一致）：状态赋值 + 配置回放 + lastVaultUUID 记录。
    /// lastVaultUUID 在此单点落盘——bootstrap / 建库 / 恢复 / 手动切换
    /// 四条「成功打开」路径全覆盖（docs/15 §3.2.1）。
    private func adoptSession(_ opened: VaultSession, brief: FfiVaultBrief) {
        session = opened
        vaultName = brief.displayName
        vaultUUID = brief.vaultUuid
        applyIdleTimeout()
        // 回放剪贴板清除档位到 Rust 会话（FR-14.2）：Rust 侧无持久化，
        // 每次开会话都要把 UserDefaults 持久值重放过去；try? 理由同
        // didSet 注释（锁定态即可调用，失败无安全影响）。
        try? opened.setClipboardClearSecs(secs: Int64(clipboardClearSecs))
        // 新会话退避计数从 0 起算（FR-12.5 内存级）：清掉旧会话可能
        // 残留的倒计时截止时刻（如恢复备份替换会话的边缘路径）。
        lockBackoffDeadline = nil
        phase = .locked
        refreshTouchIDStatus()
        refreshMcpEscrowStatus()
        UserDefaults.standard.set(brief.vaultUuid, forKey: Self.lastVaultUUIDDefaultsKey)
    }

    // MARK: - 库切换（v0.4 FR-1.2，MB-1）

    /// 切换到指定库（单活跃会话不变量，docs/15 §3.2.1）：任一时刻至多一个
    /// 解锁会话。先开新会话（失败 → 旧会话原样保留，错误经 lastErrorMessage
    /// 呈现），成功后 `lock()` 锁旧会话（已清 UI 条目状态 + 剪贴板）再装配
    /// 新会话。方案文字顺序为「锁旧 → 开新」，此处反序为失败安全：开新失败
    /// 不破坏当前会话；不变量与顺序无关（新会话装配前处于锁定态）。
    ///
    /// openVault 只读 header 不做 KDF（会话保持锁定态，解锁才派生密钥），
    /// 与 openSession 同为快路径，无需 Task.detached。
    ///
    /// - Returns: 是否切换成功（false = 原样保留当前会话，错误文案已置入
    ///   lastErrorMessage 呈现——切换器 sheet 据此决定关闭或留驻重试）。
    @discardableResult
    func switchVault(to brief: FfiVaultBrief) -> Bool {
        // 同库切换无操作（切换器已禁用当前库行，此处为防御）；慢调用
        // （建库 / 解锁）进行中禁止切换——会话即将被替换，调用无处落地。
        guard brief.vaultUuid != vaultUUID, !isBusy else { return false }
        do {
            let opened = try factory.openVault(baseDir: baseDir.path, vaultUuid: brief.vaultUuid)
            lock()
            adoptSession(opened, brief: brief)
            return true
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return false
        }
    }

    /// 刷新库列表缓存（切换器 sheet onAppear 调用；listVaults 为目录扫描 +
    /// header 读取，快路径）。失败经 lastErrorMessage 呈现，保留旧缓存。
    func reloadVaultBriefs() {
        do {
            vaultBriefs = try factory.listVaults(baseDir: baseDir.path)
                .sorted { $0.createdAt < $1.createdAt }
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
        }
    }

    // MARK: - 库删除（v2.10.0 D1，docs/17 §3）

    /// 是否可管理（删除）密码库（UDR-7 / C6，AC-2.10.0-EN-7）：**逐许可状态
    /// 镜像 Rust license.rs `LicensedOp::VaultWrite` 实际判定**（lead 正式裁定
    /// r0.5）——`expired`（6002）与 `unavailable`（6003 只读退化，fail-closed）
    /// 隐藏「管理密码库…」入口与行内 [删除…]，其余状态放行。公开构建默认
    /// .unactivated（PermitAllGate 恒放行）恒可管理。只读判定委托
    /// DeleteVaultPolicy.canManage 纯函数（可独立单测，docs/04 §1 EN-7 逐状态
    /// 对表）。
    var canManageVaults: Bool {
        DeleteVaultPolicy.canManage(licenseStatus: LicenseAssembly.shared.licenseStatus())
    }

    /// 删除库编排（docs/17 §3，工厂级）：`lock()` 锁旧（仅删当前库，C5）→
    /// FFI delete_vault（内含会话注册表 lock+forget + 文件族 rename-then-delete）
    /// → Keychain 双清 best-effort（C2）→ lastVaultUUID 清键（C4）→
    /// reloadVaultBriefs → 落位（**仅删当前库**：多库切 createdAt 最近者
    /// `.locked` / 单库 `.noVault`；删非当前库返回 `.sessionUnchanged` 会话
    /// 不变，lead 裁定 2026-10-13，docs/17 §3.3）。
    ///
    /// 错误语义（docs/17 §3.4）：FFI 失败 → 返回 .failure（视图留驻可重试），
    /// lastErrorMessage 已置（ffiErrorAlert 呈现）；删当前库失败（已先锁）→
    /// 用户处锁定态可重解锁重试，无数据丢失。Keychain 双清失败非致命
    /// （库已删，orphan 项无害，仅 DiagLog 登记）。
    @discardableResult
    func deleteVault(uuid: String) async -> Result<DeleteVaultLanding, Error> {
        guard !isBusy else { return .failure(DeleteVaultPolicyError.busy) }
        isBusy = true
        defer { isBusy = false }

        let isCurrent = (uuid == vaultUUID)
        // C5 删当前库先锁旧：防在打开连接上删库导致 WAL/SHM 半删。lock()
        // 幂等清 Rust 会话密钥 + UI 明文状态 + 剪贴板 + phase → .locked。
        if isCurrent {
            lock()
        }

        do {
            let factory = self.factory
            let dir = self.baseDir.path
            try await Task.detached(priority: .userInitiated) {
                try factory.deleteVault(baseDir: dir, vaultUuid: uuid)
            }.value

            // C2 Keychain 双清（best-effort）：库已删，orphan Keychain 项
            // 无害（docs/16 §4.4 接受残余），清理失败仅落诊断日志不弹错。
            do { _ = try BiometricKeychain().delete(vaultUUID: uuid) }
            catch { DiagLog.append("deleteVault K_bio 清理失败（无害）: \(error)") }
            do { _ = try McpEscrowKeychain().delete(vaultUUID: uuid) }
            catch { DiagLog.append("deleteVault escrow 清理失败（无害）: \(error)") }

            if isCurrent {
                // 步骤 6：清当前会话状态（lock() 只锁不清 uuid；此处删除后
                // 彻底清空，供落位重开会话）。
                session = nil
                vaultUUID = ""
                vaultName = ""
                lockBackoffDeadline = nil
            }

            // C4 lastVaultUUID 清键（仅指向被删库时；删除该键 bootstrap 回退
            // createdAt 最新，可逆）。
            if UserDefaults.standard.string(forKey: Self.lastVaultUUIDDefaultsKey) == uuid {
                UserDefaults.standard.removeObject(forKey: Self.lastVaultUUIDDefaultsKey)
            }

            reloadVaultBriefs()

            // 落位（docs/17 §3.2/§3.3，AC-2.10.0-DL-5/6）：**仅删当前库落位**
            // ——多库切 createdAt 最近者（不自动解锁，回主窗 LockView 引导）；
            // 单库 .noVault。删非当前库（isCurrent == false）**不做落位**：当前
            // 会话不变（解锁态保持、不切库），仅列表刷新 + .sessionUnchanged 反馈
            // （lead 裁定 2026-10-13：删非当前 B 时按 createdAt 跳到 C 属无来由
            // 跳变；当前 A 恒非被删目标，无自切可能）。
            if isCurrent {
                if let next = DeleteVaultPolicy.selectLandingVault(
                    briefs: vaultBriefs, deletedUUID: uuid
                ) {
                    openSession(next)
                    return .success(.switchedToMostRecent(next))
                }
                phase = .noVault
                return .success(.noVault)
            }
            return .success(.sessionUnchanged)
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return .failure(error)
        }
    }

    // MARK: - 建库

    /// 创建库（zxcvbn 门禁在 Rust 侧，score < 3 → 错误码 1010）。
    /// Argon2id 256 MiB 档位派生耗时约 0.5–1 s，用 Task.detached 包裹避免卡主线程。
    func createVault(name: String, password: String) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        let factory = self.factory
        let dir = self.baseDir.path
        do {
            let brief = try await Task.detached(priority: .userInitiated) {
                try factory.createVault(baseDir: dir, name: name, password: password)
            }.value
            // H-1（#7 审查）：v0.4 MB-1 把建库入口从 noVault 相暴露到解锁相
            // （切换器「新建密码库…」），解锁态建库若不锁前会话，旧库 Rust
            // 会话保持解锁留在 factory——单活跃不变量被破坏，且 items/
            // currentDetails 明文残留、clearOnLock 不触发。镜像
            // RestoreBackupView.handoffToRestoredVault 先例：openSession 前
            // 锁当前会话（lock 幂等清 UI 明文状态 + 剪贴板）；noVault 相
            // （bootstrap 后无会话）guard 跳过，v0.1 首建路径零变化。
            if session != nil {
                lock()
            }
            openSession(brief)
            // 建库成功 → 首次解锁后提供可选「启用 Touch ID」步骤（docs/08 §4.1）。
            // 仅 Touch ID 设备置位；无 Touch ID 机器不置位，v0.1 流程零变化。
            // 注意：enable 需解锁态（Rust 1001 门禁），故引导 sheet 挂在
            // 首次解锁完成后（RootView），而非建库成功即刻。
            pendingBioOffer = isTouchIDSupported
            // 恢复码引导（FR-17.2 D-8）：所有建库成功者都置位；RootView 侧
            // `!pendingBioOffer` 保证 bio 引导优先、其关闭后再呈现恢复码引导
            // （无 Touch ID 设备则直接呈现恢复码引导）。
            pendingRecoveryOffer = true
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
        }
    }

    // MARK: - 解锁 / 锁定

    /// 解锁（Argon2id 慢调用，Task.detached 包裹）。
    /// 密码只作为参数传入：拷贝进 Task 闭包使用后即弃，不落任何属性。
    func unlock(password: String) async {
        guard let session, !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let target = session
            let info = try await Task.detached(priority: .userInitiated) {
                try target.unlock(password: password)
            }.value
            vaultName = info.displayName
            applyIdleTimeout()
            phase = .unlocked
            // 解锁成功清零退避（Rust on_success），倒计时随之撤销（FR-12.5）
            lockBackoffDeadline = nil
            // 解锁成功即评估备份提醒（FR-8.5，T-G）：仅解锁态可调（1001 门禁）
            evaluateBackupReminder()
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            // FR-12.5：1002 后刷新倒计时——第 3 次失败起门禁激活（剩余 > 0，
            // 记截止时刻）；前 2 次普通密码错（剩余 == 0）置 nil 不显示倒数
            if case let .Coffer(code, _) = error as? FfiError, code == 1002 {
                refreshBackoffDeadline()
            }
        }
    }

    /// 解锁失败退避（FR-12.5）门禁剩余秒数（旁路读一次）。
    ///
    /// Swift 绑定 `backoffRemainingSecs()` 为非抛掷纯读（UInt64，0 =
    /// 无门禁；> 0 = 剩余秒数向上取整）——无 `try?` 场景。会话缺失按
    /// 无门禁处理（倒计时无意义）。
    private func refreshBackoffDeadline() {
        guard let session else {
            lockBackoffDeadline = nil
            return
        }
        let secs = session.backoffRemainingSecs()
        lockBackoffDeadline = secs > 0 ? Date().addingTimeInterval(TimeInterval(secs)) : nil
    }

    /// 倒计时归零清除（FR-12.5）：LockView 的 TimelineView 倒数到 0 时经
    /// Task 派发调用（避免视图更新周期内直接改 @Published）；按截止时刻
    /// 复核，过期才清——按钮恢复可用、计时条卸载。
    func clearBackoffIfExpired() {
        if let deadline = lockBackoffDeadline, deadline <= Date() {
            lockBackoffDeadline = nil
        }
    }

    /// 手动锁定：清零 Rust 侧密钥，回到锁定态，并清空 UI 侧条目状态。
    func lock() {
        session?.lock()
        // 锁定时刻剪贴板里可能仍有刚复制的密码：立即清空（clearOnLock
        // 沿用 changeCount 纪律，用户已复制自己的内容则不动剪贴板）。
        ClipboardManager.shared.clearOnLock()
        // 锁定即清空已解密数据的 UI 状态（docs/07 §2.4：锁定后清空已取回明文状态）
        items = []
        currentDetails = nil
        selectedItemID = nil
        // P4（v2.9.0）：体检 destination 随 selectedItemID 同纪律复位，防锁定
        // 后回到解锁态残留体检页（AC-2.9.0-P4-5/10）。
        showHealthDestination = false
        // P7（v2.9.0）：新建条目 sheet 类别随 selectedItemID/currentDetails 同组
        // 复位，防锁定后残留 sheet（AC-2.9.0-P7-8）。
        pendingNewCategory = nil
        searchText = ""
        // 退避倒计时兜底清 nil（FR-12.5）：lock 只能从解锁态进入，而成功
        // 解锁已在 Rust 侧清零计数，此处是状态一致性兜底（新开会话计数
        // 必从 0 起算，不应残留旧会话的倒计时）。
        lockBackoffDeadline = nil
        phase = session != nil ? .locked : .noVault
        refreshTouchIDStatus()
        refreshMcpEscrowStatus()
    }

    /// 把当前超时配置应用到会话（0 或负数 = 禁用自动锁定）。
    private func applyIdleTimeout() {
        guard let session else { return }
        let secs = autoLockMinutes > 0 ? Int64(autoLockMinutes) * 60 : 0
        session.setIdleTimeoutSecs(secs: secs)
    }

    // MARK: - Touch ID 解锁（docs/08 §7.2 / §7.4 / §8）

    /// Touch ID 通道状态（openSession / lock 时刷新；enable/disable 后由
    /// 设置页再触发刷新）。三态定义与组合规则见 Support/TouchIDStatus.swift
    /// （docs/08 §9 T04 验收②：组合逻辑为纯函数，独立单测）。
    @Published private(set) var touchIDStatus: TouchIDStatus = .disabled

    /// 降级验证开关（docs/08 §9 T04 验收①）：强制视为「无 Touch ID 设备」，
    /// 验证全 UI 降级路径（设置入口隐藏 / LockView 无按钮 / 建库步骤不出现）。
    /// 用法：`defaults write top.cygnusyang.coffer debugDisableTouchID -bool true`
    /// 后重启 App；`-bool false` / `defaults delete` 恢复。
    nonisolated static let debugDisableTouchIDKey = "debugDisableTouchID"

    /// 当前设备是否支持生物识别（LAContext 只检测不弹窗，docs/08 §8 第一行）。
    /// false 时 UI 应整体隐藏 Touch ID 入口（LockView 按钮 / 设置入口 / 建库步骤）。
    var isTouchIDSupported: Bool {
        if UserDefaults.standard.bool(forKey: Self.debugDisableTouchIDKey) {
            return false
        }
        return BiometricKeychain.isBiometricsAvailable()
    }

    /// 刷新三态：纯读操作（header 布尔 + Keychain 属性查询），无密钥操作。
    /// 组合逻辑委托 TouchIDStatus.resolve 纯函数（docs/08 §9 T04 验收②）。
    /// 注意：biometryCurrentSet 失效后 Keychain 项通常仍「存在」（读取才失败），
    /// 因此 stale 终判以 unlockWithTouchID 的 read 失败为准（docs/08 §4.1）。
    func refreshTouchIDStatus() {
        guard let session, !vaultUUID.isEmpty else {
            touchIDStatus = .disabled
            return
        }
        touchIDStatus = TouchIDStatus.resolve(
            headerWrapAvailable: session.hasBiometricWrap(),
            keychainItemExists: BiometricKeychain().itemExists(vaultUUID: vaultUUID)
        )
    }

    /// Touch ID 解锁（docs/08 §7.2 时序）：
    /// Keychain 读 K_bio（钥匙串自有单次认证：全新 LAContext + localizedReason）→
    /// FFI unlockWithBiometric → 与主密码解锁完全相同的收尾
    /// （D-5：一次 Touch ID 换一次 DEK 解封）。
    ///
    /// K_bio 纪律（§7.4）：取回即用——K_bio 只作局部变量捕获进 Task 闭包，
    /// 用完即弃，不落任何 @Published / 不进全局状态（与主密码同纪律）。
    /// isBusy 互斥与主密码解锁共用。
    ///
    /// 错误分派（reviewer HIGH 处置，docs/08 §7.3/§7.6；authFailed 瞬时/持久
    /// 分道为 PL-7）：catch 按错误类型分道——用户取消（.userCanceled）完全
    /// 静默；.itemNotFound 持久失效 → 4002 + 置 touchIDStatus = .stale；
    /// .authFailed 按失败瞬间 isBiometricsAvailable() 分道（瞬时 → 温和文案
    /// 按钮保留；持久 → 4002 + stale，§4.1 终判落地）；其余错误照常呈现
    /// （自动路径也呈现）。手动/自动路径语义一致。取消/失效均落回锁定页
    /// （phase 未变），按钮可再点。
    func unlockWithTouchID() async {
        guard let session, !isBusy, phase == .locked else { return }

        // 前置门禁（Swift 侧先行判定，避免无谓跨桥；Rust 侧同语义兜底 4001，D-8）：
        // ① header 未启用 bio 封装（available=false → Rust 会回 4001）；
        // ② 设备无 Touch ID / 未录入指纹（canEvaluatePolicy=false → 4001）。
        guard session.hasBiometricWrap(), BiometricKeychain.isBiometricsAvailable() else {
            lastErrorMessage = ErrorPresenter.text(TouchIDError.unavailable)
            return
        }

        isBusy = true
        defer { isBusy = false }

        do {
            // ① 钥匙串自有单次认证：read 查询带全新 LAContext（localizedReason
            //    = 「解锁密码库」），由 Keychain 自行发起唯一一次指纹弹窗
            //    （PL-4 修复：删除 App 侧预认证——macOS 26 上
            //    kSecUseAuthenticationContext 复用已认证结果不生效，
            //    预认证 + 读取再认证 = 双弹窗）。
            // ② 读取失败分道（catch 分派，reviewer HIGH 处置，docs/08 §7.3）：
            //    .userCanceled（用户取消）→ 静默；.itemNotFound / .authFailed
            //    （凭据失效）→ 4002 + 置 stale——不改 header、不删项，用户主
            //    密码解锁后可在设置页「重新启用」（docs/08 §4.1）。
            let kBio = try BiometricKeychain().read(vaultUUID: vaultUUID)

            // ③ 后半段走 FFI：open(K_bio, aad) → DEK → SubKeys → ItemStore。
            //    K_bio 拷贝进 Task 闭包，本函数返回后局部变量即弃。
            //    AEAD open 失败（K_bio 不匹配 / 篡改）→ Rust 统一 1002（D-8）。
            let target = session
            let info = try await Task.detached(priority: .userInitiated) {
                try target.unlockWithBiometric(kBio: kBio)
            }.value

            // ④ 状态机切换：与主密码解锁同收尾（锁定/自动锁定路径零新增，D-5）
            vaultName = info.displayName
            applyIdleTimeout()
            phase = .unlocked
            // 解锁成功清零退避倒计时（FR-12.5，与主密码解锁同收尾）
            lockBackoffDeadline = nil
            // 解锁成功即评估备份提醒（FR-8.5，T-G）：仅解锁态可调（1001 门禁）
            evaluateBackupReminder()
        } catch {
            // 错误分派（reviewer HIGH 处置，docs/08 §7.3/§7.6，用户 2026-10-03
            // 裁定；authFailed 瞬时/持久分道为 PL-7，2026-10-03 用户反馈）：
            //   - .userCanceled（用户取消认证）：完全静默——手动/自动路径一致。
            //     取消不是失败，不写 lastErrorMessage（ErrorPresenter 对该 case
            //     返回空串，写入也会弹空白框，故显式跳过），DiagLog 记诊断；
            //     落回锁定页按钮可再点。
            //   - .itemNotFound（项不存在）：持久失效——呈现 4002 + 置 stale。
            //     §4.1 以 read 失败为 stale 终判落地：LockView 按钮消失引导
            //     主密码，设置页可重新启用。
            //   - .authFailed（errSecAuthFailed）：瞬时/持久分道（PL-7）——
            //     失败瞬间 isBiometricsAvailable()==false（锁屏/刚唤醒/传感器
            //     未就绪/biometry lockout）→ 瞬时：不置 stale、touchIDStatus
            //     不变、按钮保留可再点，呈现温和文案；==true（canEvaluatePolicy
            //     通过仍读失败，指纹集变更/ACL 失效）→ 持久：维持 4002 + 置
            //     stale（§4.1 语义不变）。分道判定抽成纯函数
            //     TouchIDAuthFailure.disposition（独立单测）。
            //   - 其余（unexpected / FfiError 1002 / 4001 / 5999）：照常呈现
            //     （自动路径也呈现）并刷新状态行，与设置页/LockView 一致。
            switch error {
            case BiometricKeychainError.userCanceled:
                DiagLog.append("Touch ID 解锁已取消（用户取消认证，静默，docs/08 §7.6）")
            case BiometricKeychainError.itemNotFound:
                let errText = ErrorPresenter.text(error)
                DiagLog.append(errText)
                touchIDStatus = .stale
                lastErrorMessage = errText
            case BiometricKeychainError.authFailed:
                // 不调 refreshTouchIDStatus：refresh 以 itemExists 判定，authFailed
                // 场景项仍「存在」会被翻回 .enabled，此处以 read 失败为终判。
                switch TouchIDAuthFailure.disposition(
                    biometryAvailable: BiometricKeychain.isBiometricsAvailable()
                ) {
                case .transient:
                    DiagLog.append("Touch ID 解锁失败判定为瞬时不可用（isBiometricsAvailable=false，docs/08 §7.3 PL-7），按钮保留可再点")
                    lastErrorMessage = ErrorPresenter.text(TouchIDError.transientUnavailable)
                case .persistent:
                    let errText = ErrorPresenter.text(error)
                    DiagLog.append(errText)
                    touchIDStatus = .stale
                    lastErrorMessage = errText
                }
            default:
                let errText = ErrorPresenter.text(error)
                DiagLog.append(errText)
                lastErrorMessage = errText
                refreshTouchIDStatus()
            }
            // FR-12.5 兜底：unlockWithBiometric 完全豁免退避（不门禁也不
            // 计数，见 vault.rs「bio解锁不受退避门禁且不计数」单测），本
            // 路径 1002 只会是 K_bio 不匹配 / 篡改（AEAD open 失败），正常
            // 读不到门禁剩余秒数；判定保留为防御——错误码与 unlock 共用，
            // enable 主密码错计入同一计数器（共享 oracle 语义）。
            if case let .Coffer(code, _) = error as? FfiError, code == 1002 {
                refreshBackoffDeadline()
            }
        }
    }

    /// 启用 Touch ID 解锁（docs/08 §4.1 enable 流程，T04 设置页与建库可选
    /// 步骤共用编排）。D-6：enable 需主密码重新验证——Rust 侧 recover_dek
    /// 校验密码并解出 DEK（错 → 1002），密码不落任何属性。
    ///
    /// 顺序裁定 D-9：**先 Keychain 后 header**——
    ///   ① Rust CSPRNG 生成 K_bio（32B）；
    ///   ② Keychain 写入（失败 → 直接报错，header 未动，无半启用态）；
    ///   ③ FFI enableBiometric（失败 → 补偿删除 Keychain 项，不留孤儿半启用态；
    ///     孤儿项本身危害 ≈ 0，但补偿使幂等重试路径更干净）。
    ///
    /// - Parameter password: 主密码（仅作参数传入，用后即弃，不落状态）。
    /// - Returns: 是否启用成功（调用方据此关闭对话框）。
    @discardableResult
    func enableTouchID(password: String) async -> Bool {
        guard let session, !isBusy, phase == .unlocked,
              isTouchIDSupported, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let factory = self.factory
        let uuid = vaultUUID
        do {
            // ① K_bio：Rust CSPRNG 随机 32B（docs/08 D-3；非 DEK、非派生物）
            let kBio = try factory.newBiometricUnwrapKey()
            // ② 先 Keychain（D-9）：biometryCurrentSet 门禁，ThisDeviceOnly
            try BiometricKeychain().save(key: kBio, vaultUUID: uuid, requireBiometry: true)
            // ③ 后 header：recover_dek(password) → seal → 原子重写（慢调用，
            //    Argon2id 约 1s，Task.detached 包裹）。K_bio 拷贝进 Task 闭包，
            //    本函数返回后局部变量即弃（docs/08 R-2 同纪律）。
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.enableBiometric(password: password, kBio: kBio)
            }.value
            refreshTouchIDStatus()
            // P2-A 兜底：启用成功即清「跳过」记录——设置页首次高亮随之消失
            // （AC-2.9.0-P2A-12，DESIGN.md P-2.1 清除路径）。
            bioOfferSkipped = false
            return true
        } catch {
            // 失败补偿（docs/08 §4.1）：删除刚写入的 Keychain 项（幂等），
            // header 保持原样（Rust 失败时不重写文件）。密码错 1002 与
            // Keychain 失败均经 ErrorPresenter 呈现（T04 验收③）。
            _ = try? BiometricKeychain().delete(vaultUUID: uuid)
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            refreshTouchIDStatus()
            return false
        }
    }

    /// 关闭 Touch ID 解锁（docs/08 §4.1 disable 流程）。D-9 反向：
    /// **先删 Keychain 再改 header**——Keychain 删除幂等；header 写失败时
    /// 功能实际已失效（项已删），报非致命错误、可重试。
    ///
    /// - Returns: 是否关闭成功。
    @discardableResult
    func disableTouchID() async -> Bool {
        guard let session, !isBusy, phase == .unlocked, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let uuid = vaultUUID
        // ① 先删 Keychain（D-9 反向；幂等）
        do {
            try BiometricKeychain().delete(vaultUUID: uuid)
        } catch {
            // 删除失败属系统层异常：header 未动，功能未关，可重试
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return false
        }
        // ② 后 header：原子重写 → 禁用态（幂等）
        do {
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.disableBiometric()
            }.value
            refreshTouchIDStatus()
            return true
        } catch {
            // header 写失败：非致命（docs/08 §8）——Keychain 已删，Touch ID
            // 解锁实际已不可用；header 残留密文无泄露面，可重试关闭
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            refreshTouchIDStatus()
            return false
        }
    }

    // MARK: - MCP 解锁托管（docs/29 §5.2 生命周期，镜像 Touch ID D-9 编排）

    /// MCP 解锁托管三态（docs/29 §5.2，镜像 touchIDStatus）。
    @Published private(set) var mcpEscrowStatus: McpEscrowStatus = .disabled

    /// 刷新三态：纯读操作（header 布尔 + Keychain 属性查询），无密钥操作。
    /// 组合逻辑委托 McpEscrowStatus.resolve 纯函数（docs/29 §5.2）。
    func refreshMcpEscrowStatus() {
        guard let session, !vaultUUID.isEmpty else {
            mcpEscrowStatus = .disabled
            return
        }
        mcpEscrowStatus = McpEscrowStatus.resolve(
            headerMcpWrapAvailable: session.hasMcpWrap(),
            keychainItemExists: McpEscrowKeychain().itemExists(vaultUUID: vaultUUID)
        )
    }

    /// 启用 MCP 解锁托管（docs/29 §5.2 enable 流程，镜像 enableTouchID 编排）。
    ///
    /// 顺序裁定（docs/29 §5.2，先 Keychain 后 header，同 Touch ID D-9）：
    ///   ① FFI `derive_mcp_key(password)`：recover_dek → HKDF 确定性派生
    ///      mcp_key（慢调用，Argon2id 约 1s，Task.detached 包裹）；
    ///   ② Swift `McpEscrowKeychain.save`：无 ACL + ThisDeviceOnly + access
    ///      group（失败 → 直接报错，header 未动，无半启用态）；
    ///   ③ FFI `enable_mcp_escrow(password, mcp_key)`：recover_dek → seal →
    ///      原子重写 header `mcp_wrap`（失败 → 补偿删除 Keychain 项，不留
    ///      孤儿半启用态）。
    ///
    /// 主密码只作参数传入，用后即弃（docs/07 §2.4 同纪律）；mcp_key 拷贝进
    /// Task 闭包，本函数返回后局部变量即弃（docs/29 §5.3）。
    ///
    /// - Parameter password: 主密码（仅作参数传入，用后即弃，不落状态）。
    /// - Returns: 是否启用成功（调用方据此关闭对话框）。
    @discardableResult
    func enableMcpEscrow(password: String) async -> Bool {
        guard let session, !isBusy, phase == .unlocked, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let uuid = vaultUUID
        do {
            let target = session
            // ① mcp_key：HKDF 确定性派生（docs/29 §3；DEK 派生，换主密码不吊销）
            let mcpKey = try await Task.detached(priority: .userInitiated) {
                try target.deriveMcpKey(password: password)
            }.value
            // ② 先 Keychain（§5.2 顺序）：无 ACL 条目，ThisDeviceOnly + access group
            try McpEscrowKeychain().save(key: mcpKey, vaultUUID: uuid)
            // ③ 后 header：recover_dek → seal → 原子重写（慢调用，Task.detached）
            try await Task.detached(priority: .userInitiated) {
                try target.enableMcpEscrow(password: password, mcpKey: mcpKey)
            }.value
            refreshMcpEscrowStatus()
            return true
        } catch {
            // 失败补偿（docs/29 §5.2）：删除刚写入的 Keychain 项（幂等），
            // header 保持原样（Rust 失败时不重写文件）。密码错 1002 / 派生
            // 失败 / Keychain 失败均经错误文案呈现（镜像 enableTouchID catch）。
            _ = try? McpEscrowKeychain().delete(vaultUUID: uuid)
            let errText = (error as? McpEscrowKeychainError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            refreshMcpEscrowStatus()
            return false
        }
    }

    /// 关闭 MCP 解锁托管（docs/29 §5.2 disable 流程，镜像 disableTouchID）。
    ///
    /// 顺序裁定（docs/29 §5.2，先删 Keychain 再改 header，D-9 反向同款）：
    ///   ① Swift `McpEscrowKeychain.delete`（幂等；失败 → 报错，header 未动，
    ///      功能未关可重试）；
    ///   ② FFI `disable_mcp_escrow`（header 原子重写 available=false；失败非
    ///      致命——Keychain 已删，MCP 实际已不可用，可重试关闭）。
    ///
    /// - Returns: 是否关闭成功。
    @discardableResult
    func disableMcpEscrow() async -> Bool {
        guard let session, !isBusy, phase == .unlocked, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let uuid = vaultUUID
        // ① 先删 Keychain（§5.2 关闭顺序，镜像 disableTouchID；幂等）
        do {
            try McpEscrowKeychain().delete(vaultUUID: uuid)
        } catch {
            // 删除失败属系统层异常：header 未动，功能未关，可重试
            let errText = (error as? McpEscrowKeychainError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return false
        }
        // ② 后 header：原子重写 → 禁用态（幂等）
        do {
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.disableMcpEscrow()
            }.value
            refreshMcpEscrowStatus()
            return true
        } catch {
            // header 写失败：非致命（docs/29 §5.2）——Keychain 已删，MCP 实际
            // 已不可用；header 残留 mcp_wrap 密文无泄露面，可重试关闭
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            refreshMcpEscrowStatus()
            return false
        }
    }

    // MARK: - 恢复码 / 主密码重置（FR-17，docs/31 §3.3 reset；v2.5.0-design §4.2）

    /// 恢复码 / 主密码重置的失败统一文案（FR-1.4 不可区分纪律，docs/31 §3.5
    /// 与 v2.5.0-design §4.2）：1002（恢复码错 / K_bio 错 / wrap 损坏 / header
    /// 损坏）在重置路径统一呈现，不区分「凭证错」与「数据损坏」；1010 弱
    /// 密码等其余错误经 ErrorPresenter 直出（可操作的修正引导不能丢）。
    /// 三文案同时供 View 层（RecoveryResetSheet / LockView）引用。
    /// 恢复码重置失败统一文案。
    nonisolated static let recoveryResetFailedCopy = "重置失败：恢复码无效或密码库数据损坏。"
    /// 生物识别重置失败统一文案。
    nonisolated static let bioResetFailedCopy = "重置失败：无法完成身份验证或密码库数据损坏。"
    /// 主密码重置成功文案（View 层成功视图展示，D-9）。
    nonisolated static let resetSucceededCopy = "主密码已重置，条目数据不受影响。请用新密码解锁。"
    /// Touch ID 重置主密码时的生物认证弹窗文案（Keychain 自有单次认证
    /// 的 localizedReason，与解锁「解锁密码库」区分，docs/31 §4.2 B 裁定）。
    nonisolated static let bioResetAuthPrompt = "验证身份以重置主密码"

    /// 重置失败文案映射（纯函数）：1002 → 统一文案（FR-1.4 不可区分纪律）；
    /// 其余（1010 / 4003 / license / Keychain / IO）→ ErrorPresenter 直出。
    private static func resetFailedText(for error: Error, unifiedCopy: String) -> String {
        if case let .Coffer(code, _) = error as? FfiError, code == 1002 {
            return unifiedCopy
        }
        return ErrorPresenter.text(error)
    }

    /// 是否已启用恢复码封装（header `recovery_wrap.available`，docs/31
    /// §1.1：语义 = 「用户意图开启」，锁定态可查）。纯读 header，无密钥
    /// 操作；供 LockView 决定是否显示「忘记密码 → 恢复码重置」入口
    /// （docs/31 §4.2）。
    var hasRecoveryWrap: Bool {
        session?.hasRecoveryWrap() ?? false
    }

    /// 生成新的 BIP39-12 恢复码（FR-17.2，docs/31 §2.4：**只生成、不落盘**）。
    /// 返回的 code 仅存内存（Swift 会话局部一次性展示），用户确认抄写后才
    /// 经 `enableRecoveryCode(password:code:)` 写入 header 密文槽位
    /// （D-10：恢复码明文永不落盘）。纯随机无密钥操作、无文件 IO（Rust
    /// 无门禁）。
    /// - Returns: 恢复码文本；nil = 无会话或生成失败（随机源 / 编码失败 1007）。
    func generateRecoveryCode() -> String? {
        do {
            return try session?.generateRecoveryCode()
        } catch {
            // 不静默吞错：随机源/编码失败（1007 等）落诊断并呈现（reviewer L-2）。
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return nil
        }
    }

    /// 启用 / 重新生成恢复码封装（FR-17.2，docs/31 §3.1 enable）。
    /// 解锁态执行（Rust write_guard 兜底 1001）；Swift 侧已在
    /// RecoveryCodeSetupSheet 完成「展示恢复码 + 用户确认抄写」前置
    /// （D-10），本方法只做 FFI 提交。已启用时再次调用用新 code 覆盖旧
    /// 槽位（旧恢复码立即失效，**不可回滚**）。主密码错 / code 无效 →
    /// 1002 经 ErrorPresenter 呈现。
    /// 主密码 / code 只作参数传入，用后即弃（docs/07 §2.4 同纪律）。
    func enableRecoveryCode(password: String, code: String) async {
        guard let session, !isBusy, phase == .unlocked else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.enableRecoveryCode(password: password, code: code)
            }.value
            // P2-A 兜底：启用成功即清「跳过」记录——设置页恢复码区首次高亮
            // 随之消失（AC-2.9.0-P2A-12，DESIGN.md P-2.1 清除路径）。
            recoveryOfferSkipped = false
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
        }
    }

    /// 用恢复码重置主密码（FR-17.2，docs/31 §3.3 reset-with-recovery）。
    /// 锁定态执行（忘记密码场景）：恢复码 → 解出 DEK → 换 KEK 重封装 →
    /// 原子重写 header。**成功不切 phase**（D-9：保持锁定，由用户决定
    /// 是否用新密码解锁）。失败 1002 统一文案（FR-1.4 不区分「码错」与
    /// 「数据损坏」）；1010 弱密码等其余错误经 ErrorPresenter 直出。
    /// 新密码 / code 只作参数传入，用后即弃。
    /// - Returns: true=重置成功（保持锁定，D-9）；false=失败（lastErrorMessage
    ///   承载已映射文案：1002 统一不可区分 / 1010 弱密码具体引导）。
    func resetPasswordWithRecoveryCode(newPassword: String, code: String) async -> Bool {
        guard let session, !isBusy, phase == .locked else { return false }
        isBusy = true
        defer { isBusy = false }

        do {
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.resetPasswordWithRecoveryCode(newPassword: newPassword, code: code)
            }.value
            // 成功不切 phase：保持锁定（D-9）
            return true
        } catch {
            let errText = Self.resetFailedText(for: error, unifiedCopy: Self.recoveryResetFailedCopy)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return false
        }
    }

    /// 用生物识别（Touch ID）重置主密码（FR-17.1，docs/31 §3.3
    /// reset-with-bio）。镜像 unlockWithTouchID 的 Keychain 路径：
    /// 钥匙串读 K_bio（自带单次认证弹窗）→ FFI reset → 保持锁定。
    ///
    /// K_bio 纪律（docs/08 §7.4 同款）：取回即用——只作局部变量捕获进
    /// Task 闭包，用完即弃，不落任何 @Published / 不进全局状态。
    ///
    /// 前置门禁（Swift 侧先行判定，镜像 unlockWithTouchID :665-670）：
    /// ① header 未启用 bio 封装；② 设备无 Touch ID / 未录入指纹——
    /// 不过 → 4001 文案（Rust 侧同语义兜底）。
    ///
    /// 错误分派：.userCanceled（用户取消认证）→ 完全静默（返回 false 但不置
    /// lastErrorMessage，调用方不得误报成功）；其余（Keychain itemNotFound /
    /// authFailed / unexpected、FFI 1002 等）→ lastErrorMessage
    /// （1002 统一重置失败文案，FR-1.4）。
    /// - Returns: true=重置成功（保持锁定，D-9）；false=失败或用户取消认证。
    func resetPasswordWithBio(newPassword: String) async -> Bool {
        guard let session, !isBusy, phase == .locked, !vaultUUID.isEmpty else { return false }

        // 前置门禁（镜像 unlockWithTouchID）：Swift 侧先行判定，避免无谓
        // 跨桥；Rust 侧同语义兜底 4001（D-8）。
        guard session.hasBiometricWrap(), BiometricKeychain.isBiometricsAvailable() else {
            lastErrorMessage = ErrorPresenter.text(TouchIDError.unavailable)
            return false
        }

        isBusy = true
        defer { isBusy = false }

        do {
            // ① 钥匙串读 K_bio：read 自带单次指纹认证弹窗（全新
            //    LAContext，Keychain 自行发起唯一一次认证；文案沿用
            //    BiometricKeychain.unlockPrompt，PL-4 双弹窗规避同解锁路径）。
            // ② 读取失败分道（catch 分派）：.userCanceled 静默；其余
            //    → 重置失败文案。
            let kBio = try BiometricKeychain().read(vaultUUID: vaultUUID, reason: Self.bioResetAuthPrompt)

            // ③ 后半段走 FFI：K_bio 拷贝进 Task 闭包，本函数返回后局部
            //    变量即弃（K_bio 纪律）。AEAD open 失败（K_bio 不匹配 /
            //    篡改）→ Rust 统一 1002（D-8）。
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.resetPasswordWithBio(newPassword: newPassword, kBio: kBio)
            }.value
            // 成功不切 phase：保持锁定（D-9）
            return true
        } catch {
            switch error {
            case BiometricKeychainError.userCanceled:
                DiagLog.append("Touch ID 重置主密码已取消（用户取消认证，静默，docs/08 §7.6）")
                // 取消非成功也非错误：静默返回 false（不置 lastErrorMessage），
                // 调用方保持表单不呈现——避免「取消却被误报已重置」。
                return false
            default:
                let errText = Self.resetFailedText(for: error, unifiedCopy: Self.bioResetFailedCopy)
                DiagLog.append(errText)
                lastErrorMessage = errText
                return false
            }
        }
    }

    /// 进程退出兜底（AppDelegate.applicationWillTerminate 调用）。
    nonisolated func lockAllForTermination() {
        MainActor.assumeIsolated {
            factory.lockAll()
        }
    }
    // MARK: - OTA 更新（v2.7.0，docs/35 §2.6 / §6.3；主动触发，无启动静默检查）

    /// Updater 状态机（契约 6.3 冻结接口：state / check / install / dismiss）。
    /// lazy：AppModel 为非隔离 init（@StateObject 主线程初始化），UpdaterManager
    /// 为 @MainActor 类，首次访问（@MainActor 的 checkForUpdates / installUpdate
    /// 或 RootView 注入 UpdateSheet 时）才实例化。
    private(set) lazy var updater = UpdaterManager()

    /// 「检查更新…」统一入口（关于页按钮触发；应用菜单同项入口已移除，BUG-24
    /// 复测裁定）：先关关于 sheet——双 `.sheet` 挂同一 RootView，关于在屏时
    /// UpdateSheet 不叠加（docs/01 BUG-24 根因），不关则结果被关于挡住、又回到
    /// 「点了没反应」。About 在屏时经 onDismiss（aboutSheetDidDismiss）再开
    /// UpdateSheet：每个事务只翻一个 sheet 旗标，规避同事务双 sheet 同发、第二个
    /// 被 SwiftUI 丢弃。不做启动静默检查（§2.6 用户裁定：主动触发，零网络姿态）；
    /// 正在检查/下载/安装中不重复触发（UpdateCopy.canStartCheck 纯函数判定）。
    func checkForUpdates() {
        switch UpdateCopy.checkPresentationPlan(
            canStartCheck: UpdateCopy.canStartCheck(updater.state),
            aboutVisible: showAbout) {
        case .presentAfterAboutDismiss:
            updateSheetPendingAfterAboutDismiss = true
            showAbout = false
        case .presentNow:
            showUpdateSheet = true
            Task { await updater.check() }
        case .revealByClosingAbout:
            showAbout = false
        case .none:
            break
        }
    }

    /// About sheet 关闭回调（CofferApp `.sheet(onDismiss:)`）：仅当 checkForUpdates
    /// 请求过（pending 旗标置位）才开 UpdateSheet + 开始检查——用户普通「关闭」
    /// About 不触发。showUpdateSheet = true 与 showAbout = false 分处两个事务，
    /// 确保 UpdateSheet 在 About 真正消失后呈现。
    func aboutSheetDidDismiss() {
        guard updateSheetPendingAfterAboutDismiss else { return }
        updateSheetPendingAfterAboutDismiss = false
        showUpdateSheet = true
        guard UpdateCopy.canStartCheck(updater.state) else { return }
        Task { await updater.check() }
    }

    /// 安装更新（UpdateSheet「下载并安装」/「安装更新…」确认后调用）。
    ///
    /// r0.4（docs/35 §6.4 第 5-6 步，沙盒继承实证修订）：install() 经 LaunchServices
    /// 启动非沙盒 helper（嵌套 bundle）后即返回——App 不备份 / 不 spawn / 不 waitpid
    /// （沙盒无权写 /Applications，替换全归 helper）；helper 等本 App pid 退出才做
    /// 备份 → 替换 → relaunch，故 install() 返回后 App 应尽快退出。但
    /// NSWorkspace.openApplication 是异步请求，须留 ~0.5s 窗口让 launch 落地，
    /// 不得在提交前退出。仅安装进行中（.installing）才退出——install() 失败
    /// （.failed）要留在前台呈现错误。
    func installUpdate() {
        DiagLog.append("BUG-26 插桩：installUpdate 进入（调度 Task → updater.install）")
        Task {
            await updater.install()
            DiagLog.append("BUG-26 插桩：updater.install 返回，state=\(String(describing: updater.state))")
            guard UpdateCopy.installDismissPlan(state: updater.state) == .dismissThenTerminate else {
                DiagLog.append("BUG-26 插桩：install 未到 .installing，不退出（留在前台呈现错误）")
                return
            }
            // BUG-26 根因修复：先程序化关掉更新 sheet 再 terminate。.installing 下
            // UpdateSheet 的 interactiveDismissDisabled 曾把 NSApp.terminate 的 quit
            // 当作 sheet 交互关闭尝试并取消整个终止（AppKit userCanceledErr，真机
            // 三重实证）；程序化 dismiss（showUpdateSheet=false，绑定值变化）不受
            // interactiveDismissDisabled 拦截。UpdateSheet 侧 dismissing 也已放开
            // （UpdateCopy.blocksInteractiveDismiss 不含 .installing），此处属双保险
            // + 呈现收尾（先关 sheet，再留 0.5s 窗口后退出）。
            showUpdateSheet = false
            DiagLog.append("BUG-26 插桩：install 返回 .installing，程序化关闭更新 sheet（showUpdateSheet=false）")
            DiagLog.append("BUG-26 插桩：调度 asyncAfter(\(Self.updaterTerminateDelay)s) → NSApp.terminate")
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.updaterTerminateDelay) {
                DiagLog.append("BUG-26 插桩：asyncAfter 回调执行 → NSApp.terminate")
                NSApp.terminate(nil)
            }
        }
    }

    /// install() 返回后到 App 退出的延迟：给 LaunchServices launch 请求落地留窗口
    /// （helper 等本 App pid 退出，退出越早越好，但不得早于 launch 提交）。
    nonisolated static let updaterTerminateDelay: TimeInterval = 0.5

    /// 首启消费上次安装结果（r0.4 §6.4 第 6 步）：被 relaunch 的 .app 首次启动
    /// 读 result 文件——成功静默（用户看到新版本）；失败置 `.failed` 并打开更新
    /// sheet 呈现（含退出码文案）。result 文件与 UserDefaults key 一次性消费后
    /// 由 Updater 清除，无 pending 则 no-op（幂等，不打扰正常启动）。
    private func consumePendingUpdateResultIfNeeded() {
        updater.consumePendingInstallResult()
        if case .failed = updater.state {
            showUpdateSheet = true
        }
    }

    // MARK: - 密码强度（非门禁展示用）

    /// 强度估算：走 Rust 工厂版 zxcvbn（纯计算、无会话依赖，建库前
    /// 可用 —— v0.1 的「无会话只能本地粗估」限制已移除）。
    func estimateStrength(_ candidate: String) -> FfiStrengthEstimate? {
        try? factory.strengthEstimate(candidate: candidate)
    }
}

// MARK: - DropzoneImportContext conform（v2.11.0 W1a 追加）

// 放置区导入 model（DropzoneImportModel）需要的 AppModel 窄面（docs/19 §3.2 五成员：
// phase / dropzoneAuthStatus / session / setDropzoneBookmark / reloadItems）。
// 原随 W1a 放在 DropzoneImportContext.swift 内，v2.11.0 AppPhase 迁移时移到本文件
// 末尾——协议文件须保持 standalone 可编译（L1 harness 编译协议但不编译本类，
// docs/19 §3.3「不可 standalone 实例化」），生产 conform 归位到被 conform 类型
// 所在文件（对齐 ItemStore.swift 对 AppModel 的 extension 先例）。
extension AppModel: DropzoneImportContext {}
