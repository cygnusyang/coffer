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

/// 应用阶段状态机。
enum AppPhase: Equatable {
    /// 启动中：枚举工作目录里的库。
    case booting
    /// 工作目录没有库：进入建库流程。
    case noVault
    /// 已有库但处于锁定态。
    case locked
    /// 已解锁，进入条目管理。
    case unlocked
    /// 不可恢复的启动失败（列出原因，引导用户检查环境）。
    case fatal(String)
}

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
    /// 导入 CSV sheet（工具栏 + 菜单 ⌘I）。
    @Published var showImport = false
    /// 导入 1PUX sheet（工具栏「导入」菜单 + 菜单 ⌘⇧I，v0.3.0-T05 FR-7.1）。
    @Published var showImportPux = false
    /// 导入 Bitwarden JSON sheet（工具栏「导入」菜单，v0.5.0 PK3 FR-10.1）。
    @Published var showImportBitwarden = false
    /// 导出 sheet（备份 + CSV，工具栏 + 菜单 ⌘E + 备份横幅「立即备份」）。
    @Published var showExport = false
    /// 统一设置 sheet（工具栏 + 菜单 ⌘,）。
    @Published var showSettings = false
    /// 库切换器 sheet（v0.4 FR-1.2，MB-1：MainView 工具栏切换器触发，
    /// sheet 挂 RootView——与导入/设置同一跨视图触发模式）。
    @Published var showVaultSwitcher = false

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

    // MARK: - 路径

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
        self.baseDir = documents.appendingPathComponent("Coffer", isDirectory: true)
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
            // R1-3 缓解（裁定书 §1.7 R1-3）：浏览器集成已启用 → 解锁前开启 DEK
            // 保留。必须在 Rust `set_current_dek`（本解锁）之前置位——retention
            // 只在「开启后触发的解锁」才保留 DEK，解锁后才开则 current_dek 已弃。
            // 下一行是本链路生效的关键（enable 时开不够，须每轮解锁前置）。
            if browserIntegrationEnabled {
                session.setDekRetention(enabled: true)
            }
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
            // 解锁成功 → 浏览器集成已启用则 spawn broker（锁态镜像 docs/31 §2.1）
            startBrowserBrokerIfNeeded()
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
        searchText = ""
        // 退避倒计时兜底清 nil（FR-12.5）：lock 只能从解锁态进入，而成功
        // 解锁已在 Rust 侧清零计数，此处是状态一致性兜底（新开会话计数
        // 必从 0 起算，不应残留旧会话的倒计时）。
        lockBackoffDeadline = nil
        phase = session != nil ? .locked : .noVault
        refreshTouchIDStatus()
        refreshMcpEscrowStatus()
        // 锁定 → kill broker（锁态镜像 docs/31 §2.1：扩展锁态恒等于 App 锁态）
        stopBrowserBroker()
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
    /// 用法：`defaults write app.coffer.Coffer debugDisableTouchID -bool true`
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
            //    R1-3 缓解（同主密码解锁）：浏览器集成已启用 → 解锁前开启 DEK
            //    保留（须在 Rust set_current_dek 之前置位，本解锁会话才保留 DEK）。
            if browserIntegrationEnabled {
                session.setDekRetention(enabled: true)
            }
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
            // 解锁成功 → 浏览器集成已启用则 spawn broker（锁态镜像 docs/31 §2.1）
            startBrowserBrokerIfNeeded()
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

    // MARK: - 浏览器集成（docs/31 §6.2 / §9.1 G-D：manifest + broker 生命周期 + 配对）

    /// 「启用浏览器集成」开关（非敏感布尔，UserDefaults；镜像 McpSettings 纪律）。
    @Published private(set) var browserIntegrationEnabled: Bool = BrowserIntegrationSettings.loadEnabled()

    /// broker 运行态（App 解锁 spawn / 锁定 kill，锁态镜像 docs/31 §2.1 状态机）。
    /// `.failed` 携带可呈现文案（spawn 失败 / 缺解锁材料等，fail-closed）。
    @Published private(set) var browserBrokerState: BrowserBrokerRuntime = .stopped

    /// 待用户确认的配对请求（docs/31 §4.2：显式批准才下发 PSK + 公钥；密钥
    /// 材料不经 App——本属性只携带请求元数据，PSK/公钥由 broker 生成下发）。
    @Published var pendingPairingRequest: BrowserPairingRequest?

    /// 当前 broker 进程句柄（App 是 broker 的父进程，锁定/退出即杀，docs/31 §2.1）。
    private var browserBrokerProcess: Process?

    /// 配对决策转发（真实实现写 notify.sock pair_decision，契约 §2.3/§4）。
    private var browserPairingResponder: BrowserPairingResponder = RecordingBrowserPairingResponder()

    /// notify.sock 反向通道客户端（App 客户端持长连，契约 §2.3；随 broker
    /// spawn 建立 / kill 停止）。
    private var brokerNotifyClient: BrokerNotifyClient?

    /// 最近一次配对弹框结束态（视图呈现 拒绝/超时 文案，契约 §8-3「超时即拒」）。
    @Published private(set) var lastPairingDismissal: BrowserPairingDismissal?

    /// 配对弹框挂起超时任务（契约 §8 裁定 3：120s，超时即拒关框）。
    private var pairingTimeoutWorkItem: DispatchWorkItem?

    /// 配对弹框挂起超时秒数（契约 §8 裁定 3 冻结：120s；broker 侧同值）。
    private static let pairingTimeoutInterval: TimeInterval = 120

    /// 开关切换（docs/31 §2.3 启/配对流）：启用 = 写 manifest + spawn broker；
    /// 停用 = kill broker + 删 manifest（幂等）。
    ///
    /// 错误路径 fail-closed：启用时任一浏览器写失败 → 不 spawn broker、不落
    /// 开关（无半启用态，可重试）；停用时删除失败仅报错不回滚开关（停用优先，
    /// 保证不残留运行态）。
    ///
    /// - Parameter enabled: 目标开关值。
    /// - Returns: 是否成功（false = 错误文案已置 lastErrorMessage，开关回滚）。
    @discardableResult
    func setBrowserIntegration(_ enabled: Bool) async -> Bool {
        guard phase == .unlocked, session != nil else {
            lastErrorMessage = "请先解锁密码库后再更改浏览器集成设置。"
            return false
        }
        if enabled {
            // 先置开关再启用：enableBrowserIntegration 内 startBrowserBrokerIfNeeded
            // 以 browserIntegrationEnabled == true 为前置（顺序敏感，勿调换）。
            browserIntegrationEnabled = true
            let ok = await enableBrowserIntegration()
            if ok {
                BrowserIntegrationSettings.saveEnabled(true)
            } else {
                // 失败回滚开关（未落盘，无半启用态）
                browserIntegrationEnabled = false
            }
            return ok
        } else {
            await disableBrowserIntegration()
            browserIntegrationEnabled = false
            BrowserIntegrationSettings.saveEnabled(false)
            return true
        }
    }

    /// 启用：写三浏览器 manifest + spawn broker。
    /// 顺序裁定（docs/31 §2.3 配对流）：① 校验 coffer 二进制 → ② 写 manifest
    /// （任一失败 → 报错返回 false，不 spawn、不落开关）→ ③ spawn broker。
    ///
    /// R1-3 缓解（裁定书 §1.7 R1-3）：进入使能路径即开启 DEK 保留（idempotent）。
    /// B1 修复时序缺口（docs/31 §4.1）：retention 只在 **解锁时**
    /// （`set_current_dek`）前置开启才填 DEK——若本会话在 retention 开启前已
    /// 解锁，`exportDek()` 会 5002；此时经 `reauthForBrowserIntegration` 强制
    /// 重认证补回 DEK（单次 Touch ID），仍失败才 fail-closed 不 spawn（保持
    /// 「锁后重解再启用」的诚实降级路径）。
    private func enableBrowserIntegration() async -> Bool {
        guard let binary = McpStatusProbe.cofferBinaryPath() else {
            lastErrorMessage = BrowserIntegrationError.missingCofferBinary.userText
            return false
        }
        let home = BrowserStatusProbe.userHomeDirectory()
        do {
            for browser in BrowserKind.allCases {
                try BrowserManifest.write(
                    browser: browser,
                    shimPath: BrowserManifest.shimPath(cofferBinaryPath: binary),
                    homeDirectory: home)
            }
        } catch {
            let errText = (error as? BrowserIntegrationError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
            return false
        }
        // 决策①：启用集成即生成 PSK 并存 keychain（幂等——重复 enable 不轮换，
        // 重启用才轮换，契约 §4.1/§4.3）。必须在 spawn 前就绪（broker stdin
        // PSK_HEX= 必填，缺即 fail-closed exit 1）。生成/落库失败 → 报错返回
        // false（不 spawn，无半启用态）。
        do {
            let keychain = BrowserPairingKeychain()
            if !keychain.itemExists(vaultUUID: vaultUUID) {
                guard let psk = BrowserPairingKeychain.randomPSK() else {
                    let text = BrowserIntegrationError.unexpected("无法生成配对 PSK（系统随机源失败）").userText
                    DiagLog.append(text)
                    lastErrorMessage = text
                    return false
                }
                try keychain.save(key: psk, vaultUUID: vaultUUID)
            }
        } catch {
            let errText = (error as? BrowserPairingKeychainError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append("浏览器集成 PSK 生成/落库失败：\(errText)")
            lastErrorMessage = errText
            return false
        }
        // R1-3：浏览器集成使能 → 开启 DEK 保留（startBrowserBrokerIfNeeded 前，
        // 裁定书 §1.7 R1-3）。B1：本会话若已在 retention 开启前解锁（解锁瞬间
        // retain_dek 未开，R1-3 时序缺口）→ dekRetained() 纯读探测无 DEK → 按
        // K_bio 补种；失败 fail-closed 不 spawn（guard 提前返回，保留
        // retainDekForBrowserIntegration 置的可操作状态行，不被下方
        // startBrowserBrokerIfNeeded 的缺料文案覆盖）。
        session?.setDekRetention(enabled: true)
        if let session, phase == .unlocked, !session.dekRetained() {
            guard await retainDekForBrowserIntegration(session: session) else { return true }
        }
        startBrowserBrokerIfNeeded()
        return true
    }

    /// B1 按 K_bio 补种保留 DEK：补回当前会话的 DEK（R1-3 时序缺口修复，
    /// docs/31 §4.1）。
    ///
    /// 解锁后启用集成时 `set_dek_retention(true)` 对已解锁会话无效（R1 只在
    /// 解锁瞬间填 `current_dek`）→ 经 FFI `retainDekWithBio` 解锁态补种 DEK
    /// （不改解锁态、不换 store，与解锁路径同错误语义；门禁：锁定 1001 /
    /// retention 未开 5002 / 解封失败 1002）。
    ///
    /// 复用 `BiometricKeychain().read` 单次指纹弹窗（localizedReason 同解锁，
    /// PL-4：不另加 App 侧预认证），不经 `unlockWithTouchID`（其 `phase ==
    /// .locked` 门禁不适用）。失败（用户取消 / 凭据失效 / 未启用 bio）→
    /// fail-closed：置 `browserBrokerState` 可操作指引，不 spawn broker。
    private func retainDekForBrowserIntegration(session: VaultSession) async -> Bool {
        // 前置门禁（镜像 unlockWithTouchID：避免无谓跨桥，Rust 侧同语义兜底 4001）
        guard session.hasBiometricWrap(), BiometricKeychain.isBiometricsAvailable() else {
            let text = "浏览器集成需要重新认证，但生物识别未启用：请锁定后重新解锁，再启用浏览器集成"
            DiagLog.append(text)
            browserBrokerState = .failed(text)
            return false
        }
        do {
            let kBio = try BiometricKeychain().read(vaultUUID: vaultUUID)
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.retainDekWithBio(kBio: kBio)
            }.value
            DiagLog.append("B1 补种成功：已补回浏览器集成所需 DEK（R1-3 时序缺口修复）")
            return true
        } catch {
            // 用户取消 / 凭据失效 / FFI 失败统一 fail-closed（不 spawn），
            // 状态行呈现可操作指引（含解锁路径重试）。
            let errText = ErrorPresenter.text(error)
            DiagLog.append("B1 补种失败（fail-closed 不 spawn）：\(errText)")
            browserBrokerState = .failed("浏览器集成需要重新认证（\(errText)）：请锁定后重新解锁，再启用浏览器集成")
            return false
        }
    }

    /// 停用：kill broker（幂等）+ 删三浏览器 manifest（幂等）。
    /// 顺序裁定：先停进程后删文件（优先保证不残留运行态）；删除失败仅报错
    /// 不回滚开关（停用优先：docs/31 §6.2「停用即删除」语义不因单浏览器失败
    /// 而阻塞，开关恒关闭）。返回 Void——停用为 best-effort，无失败态。
    private func disableBrowserIntegration() async {
        stopBrowserBroker()
        let home = BrowserStatusProbe.userHomeDirectory()
        do {
            for browser in BrowserKind.allCases {
                try BrowserManifest.delete(browser: browser, homeDirectory: home)
            }
        } catch {
            let errText = (error as? BrowserIntegrationError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append(errText)
            lastErrorMessage = errText
        }
        // 决策①：停用即删 PSK（契约 §4.3：重启用 = 新 PSK，旧扩展失配须重配对）。
        // 删除失败仅记日志不阻塞停用（停用优先，镜像 manifest 删除语义）。
        do {
            try BrowserPairingKeychain().delete(vaultUUID: vaultUUID)
        } catch {
            let errText = (error as? BrowserPairingKeychainError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append("浏览器集成 PSK keychain 删除失败：\(errText)")
        }
    }

    /// 解锁态 spawn broker（unlock / unlockWithTouchID 成功路径调用）。
    ///
    /// 前置（docs/31 §4.1）：开关开 + 解锁态 + coffer 二进制存在——任一不满足 →
    /// 不 spawn，状态行呈现缺项（fail-closed）。幂等：已运行不重复 spawn。
    /// broker 解锁 = App 已解锁态 + stdin DEK 交付（docs/31 §4.1：已否决
    /// 「broker escrow 免密自解锁」，B1 移除 escrow guard，broker 与 MCP
    /// 托管零耦合）。
    func startBrowserBrokerIfNeeded() {
        guard browserIntegrationEnabled, phase == .unlocked,
              let binary = McpStatusProbe.cofferBinaryPath() else {
            return
        }
        if let process = browserBrokerProcess, process.isRunning {
            return
        }
        // stdin 私有管道材料（HIGH-3，docs/31 §3.1：DEK/UUID/PSK/unlocked 四行）。
        // DEK/UUID 已接线（R1，见 brokerStdinSecrets）；PSK 由 pairingPskHex() 读
        // keychain（决策①，v2.3.0 配对集成已接线）——四行任一取不到即返回 nil，
        // fail-closed 不 spawn（不留半配置 broker，G-B resolve_broker_secrets
        // 必填缺即 exit 1）。
        guard var secrets = brokerStdinSecrets() else {
            browserBrokerState = .failed("broker 解锁材料不齐（PSK/DEK 缺失，fail-closed）")
            return
        }
        let home = BrowserStatusProbe.userHomeDirectory()
        do {
            try BrowserBroker.prepareSocketDirectory(homeDirectory: home)
        } catch {
            DiagLog.append("BrowserBroker socket 目录准备失败：\(error.localizedDescription)")
            browserBrokerState = .failed("broker socket 目录准备失败")
            return
        }
        let socketPath = BrowserBroker.brokerSocketPath(homeDirectory: home)
        do {
            var payload = secrets.payload
            // 用后即毁（M-7 纵深，裁定书 §1.4）：defer 保证 spawn 成败两路都覆零——
            // ① stdin 载荷本地副本（H-3 核销）；② export 出的 DEK 原始字节（R1-2，
            // 与 brokerStdinSecrets 内局部 dek 共享同一 COW 缓冲，此处覆零即终局）。
            defer {
                zeroize(&payload)
                secrets.zeroizeDek()
            }
            let process = try BrowserBroker.spawn(
                executable: binary,
                arguments: BrowserBroker.SpawnConfig.brokerArguments(
                    udsPath: socketPath,
                    logPath: BrowserBroker.SpawnConfig.brokerLogPath(homeDirectory: home)),
                environment: [BrowserBroker.SpawnConfig.vaultDirEnv: vaultDirPath],
                stdinPayload: payload)
            browserBrokerProcess = process
            browserBrokerState = .running(pid: process.processIdentifier)
            // 配对集成 V：spawn 成功后建 notify.sock 反向通道（App 客户端）+ 注入
            // 真实决策 responder（契约 §2.3/§4）。
            startBrokerNotifyClient(homeDirectory: home)
        } catch {
            let errText = (error as? BrowserIntegrationError)?.userText ?? ErrorPresenter.text(error)
            DiagLog.append(errText)
            browserBrokerState = .failed(errText)
        }
    }

    /// 配对集成 V：spawn 成功后建立 notify.sock 反向通道客户端（App 客户端持长连，
    /// 契约 §2.3）+ 注入真实决策 responder。broker 被杀（断连）→ 客户端清理连接态，
    /// 挂起弹框由 120s 超时兜底关框。帧回调从客户端读线程触发——经 `Task { @MainActor }`
    /// hop 回主线程（pendingPairingRequest / @Published 均 MainActor 隔离）。
    private func startBrokerNotifyClient(homeDirectory: String) {
        let notifyPath = BrowserBroker.notifySocketPath(homeDirectory: homeDirectory)
        let client = BrokerNotifyClient(
            socketPath: notifyPath,
            onPairRequest: { [weak self] request in
                Task { @MainActor in self?.submitPendingPairing(request) }
            },
            onPairCancel: { [weak self] requestId in
                Task { @MainActor in self?.cancelPendingPairing(requestId: requestId) }
            },
            onDisconnect: {
                // broker 被杀 → 客户端 EOF 清理连接态；挂起弹框由 120s 超时兜底
            },
            log: { DiagLog.append($0) })
        client.start()
        brokerNotifyClient = client
        browserPairingResponder = NotifyBrowserPairingResponder(
            sendFrame: { [weak client] frame in _ = client?.send(frame: frame) },
            pskHexLoader: { [weak self] in self?.pairingPskHex() },
            log: { DiagLog.append($0) })
    }

    /// broker stdin 私有管道材料 seam（HIGH-3，docs/31 §3.1 四行）。
    ///
    /// 取值（v2.3.0 配对集成接线完成，裁定书 §1.4 / §1.7 R1-1）：
    ///   - DEK = `session.exportDek()`（Rust session 解锁态保留的 32B 原始值，
    ///     R1 (a-i) seam）——retention 未开 / 未解锁 / 已锁定 → Rust 5002，
    ///     fail-closed 返回 nil（不 spawn，不留半配置 broker）。
    ///   - VAULT_UUID = vaultUUID 去横线（16 字节 hex，32 字符）。
    ///   - PSK = `pairingPskHex()` 读 keychain（决策①，v2.3.0 已接线）——未启用
    ///     集成/项缺失 → nil（fail-closed，绝不伪造占位 PSK 腐蚀确定性身份派生）。
    ///
    /// 零化纪律（§1.4 / M-7）：export 出的 DEK Data 与返回结构的 `dekBytes` 共享
    /// COW 缓冲——失败路径在此 `zeroize(&dek)` 覆零（refcount=1 原地），成功路径
    /// 由调用方写 stdin 后 `secrets.zeroizeDek()` 覆零同一缓冲（用后即毁）。
    private func brokerStdinSecrets() -> BrokerStdinSecrets? {
        guard let session, phase == .unlocked else { return nil }
        var dek: Data
        do {
            dek = try session.exportDek()
        } catch {
            DiagLog.append("broker DEK 导出失败（retention 未开启或未解锁）：\(ErrorPresenter.text(error))")
            return nil
        }
        // 失败路径覆零已取出的 DEK；成功路径交由调用方覆零（同缓冲，二选一执行）
        var kept = false
        defer { if !kept { zeroize(&dek) } }
        // VAULT_UUID：vaultUUID 去横线（16 字节 hex，32 字符——Rust uuid::Uuid
        // 字符串为横线分隔 36 字符，broker 解析面需 32 字符 hex）。
        let vaultUUIDHex = vaultUUID.replacingOccurrences(of: "-", with: "")
        // PSK：读 keychain（决策①，v2.3.0 已接线）——取不到 → nil（fail-closed）
        guard let pskHex = pairingPskHex() else {
            DiagLog.append("broker 配对 PSK 缺失（未启用集成/项缺失，fail-closed 不 spawn）")
            return nil
        }
        let secrets = BrokerStdinSecrets(
            dekBytes: dek, vaultUUIDHex: vaultUUIDHex, pskHex: pskHex, unlocked: true)
        kept = true
        return secrets
    }

    /// 配对 PSK 读取（决策①：PSK 由 App 生成并存 keychain——v2.3.0 配对集成
    /// 接线，替代原 merge-time nil；spawn stdin 注入与 pair_decision 下发同源）。
    /// 返回 nil → `brokerStdinSecrets` fail-closed 不 spawn。**绝不硬编码/伪造
    /// PSK**——占位材料会腐蚀扩展身份派生（确定性 derive 语义）。
    private func pairingPskHex() -> String? {
        guard !vaultUUID.isEmpty else { return nil }
        let keychain = BrowserPairingKeychain()
        guard let key = keychain.load(vaultUUID: vaultUUID) else {
            DiagLog.append("浏览器集成 PSK keychain 读取失败（未启用/项缺失，fail-closed 不 spawn）")
            return nil
        }
        guard key.count == BrowserPairingKeychain.keyLength else {
            DiagLog.append("浏览器集成 PSK keychain 长度非法（\(key.count)B，fail-closed 不 spawn）")
            return nil
        }
        return BrowserPairingKeychain.hexString(from: key)
    }

    /// 锁定 / 退出 / 停用：kill broker（幂等，docs/31 §2.1 killed；会话密钥随
    /// 进程销毁 docs/31 §3.4）。
    ///
    /// R1-3 缓解（裁定书 §1.7 R1-3）：停用/锁定即关闭 DEK 保留——Rust 侧立即
    /// 清零会话内保留的 DEK（`set_dek_retention(false)` → zeroize current_dek），
    /// 与锁态镜像一致（fail-closed：DEK 只在「浏览器集成启用 + 解锁」窗口驻留）。
    /// 覆盖三个调用方：lock() / disableBrowserIntegration() / lockAllForTermination()。
    func stopBrowserBroker() {
        session?.setDekRetention(enabled: false)
        BrowserBroker.kill(process: browserBrokerProcess)
        browserBrokerProcess = nil
        // 配对集成 V：停 broker 同时停 notify 客户端 + 复位 responder + 关挂起
        // 弹框（broker 已死，配对无法完成；超时定时器一并清）。
        brokerNotifyClient?.stop()
        brokerNotifyClient = nil
        browserPairingResponder = RecordingBrowserPairingResponder()
        pendingPairingRequest = nil
        clearPairingTimeout()
        browserBrokerState = .stopped
    }

    /// 配对请求到达（BrokerNotifyClient 读线程经 Task hop 主线程调用；docs/31 §4.2）。
    /// 挂起 120s 超时定时器（契约 §8 裁定 3：超时即拒关框）。
    func submitPendingPairing(_ request: BrowserPairingRequest) {
        pendingPairingRequest = request
        lastPairingDismissal = nil
        startPairingTimeout()
    }

    /// 用户显式批准（docs/31 §5.3：批准才触发 broker 下发 PSK + 公钥）。密钥
    /// 材料不经 App、不进日志——本方法只转发决策元数据（含 request_id 回写）。
    func approvePendingPairing() {
        guard let request = pendingPairingRequest else { return }
        browserPairingResponder.respond(
            BrowserPairingDecision(browser: request.browser, extensionID: request.extensionID,
                                   requestId: request.requestId, approved: true, decidedAt: Date()))
        pendingPairingRequest = nil
        lastPairingDismissal = .approved
        clearPairingTimeout()
    }

    /// 用户拒绝配对（docs/31 §4.2 拒绝路径）。
    func rejectPendingPairing() {
        guard let request = pendingPairingRequest else { return }
        browserPairingResponder.respond(
            BrowserPairingDecision(browser: request.browser, extensionID: request.extensionID,
                                   requestId: request.requestId, approved: false, decidedAt: Date()))
        pendingPairingRequest = nil
        lastPairingDismissal = .rejected
        clearPairingTimeout()
    }

    /// 扩展断连/超时（broker 经 notify.sock 发 pair_cancel，契约 §2.3）→ 关弹框。
    /// request_id 匹配才关（防止迟到的旧取消关掉新请求的框）。
    func cancelPendingPairing(requestId: Int) {
        guard let request = pendingPairingRequest, request.requestId == requestId else { return }
        pendingPairingRequest = nil
        lastPairingDismissal = .cancelled(reason: "扩展断连或配对超时")
        clearPairingTimeout()
    }

    /// 配对弹框挂起超时（120s，契约 §8 裁定 3「超时即拒」）：到期关框。broker
    /// 侧同样 120s 超时并回拒扩展；本侧为兜底（broker 被杀/断连时 pair_cancel
    /// 可能不达，弹框不能永久挂起）。
    private func startPairingTimeout() {
        clearPairingTimeout()
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                guard let self, self.pendingPairingRequest != nil else { return }
                self.pendingPairingRequest = nil
                self.lastPairingDismissal = .cancelled(reason: "配对超时（120 秒）")
            }
        }
        pairingTimeoutWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.pairingTimeoutInterval, execute: work)
    }

    /// 取消未触发的超时任务（决策已出 / 弹框关闭 / broker 停止时）。
    private func clearPairingTimeout() {
        pairingTimeoutWorkItem?.cancel()
        pairingTimeoutWorkItem = nil
    }

    /// 进程退出兜底（AppDelegate.applicationWillTerminate 调用）。
    nonisolated func lockAllForTermination() {
        MainActor.assumeIsolated {
            factory.lockAll()
            // 退出 → kill broker（锁态镜像 docs/31 §2.1；会话密钥随进程销毁）
            stopBrowserBroker()
        }
    }
    // MARK: - 密码强度（非门禁展示用）

    /// 强度估算：走 Rust 工厂版 zxcvbn（纯计算、无会话依赖，建库前
    /// 可用 —— v0.1 的「无会话只能本地粗估」限制已移除）。
    func estimateStrength(_ candidate: String) -> FfiStrengthEstimate? {
        try? factory.strengthEstimate(candidate: candidate)
    }
}
