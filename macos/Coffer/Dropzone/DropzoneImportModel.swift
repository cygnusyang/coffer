// DropzoneImportModel.swift —— 放置区导入向导状态机（S0-S5，docs/19 §3.1 L1 抽取）。
//
// 从 DropzoneImportView 抽出的可测 model（ObservableObject）：S0-S5 状态机 +
// 全部跨组件回落逻辑（onChange 三态停表 + 回落）+ 派生计数。视图降为薄壳
// （只渲染 + 绑定转发）。关键收益（docs/19 §0.1）：IT-12（A-5 广播回落）、
// IT-14/15/18（监视生命周期与停摆）从「走查」升级为「模型单测可覆盖」。
//
// 通用模式（docs/19 §3.4「View 薄壳 + 可测 model」）：
//   ① 状态机/派生/IO 决策全进 ObservableObject model（Foundation + Combine +
//      FFI 纯类型，禁 SwiftUI）；
//   ② AppModel 面收窄为 DropzoneImportContext 协议（extension conform，测试
//      用内存 stub，见 DropzoneImportContext.swift）；
//   ③ 服务类一律注入式（watcher: DirectoryWatching / bookmarkStore /
//      fingerprintStore 由 init 注入，shared 仅生产装配点）；
//   ⑤ 生命周期副作用（onChange/onReceive/onDisappear）的逻辑搬到 model 方法，
//      视图只调。
//
// 视图接线：@EnvironmentObject（AppModel）在 SwiftUI 视图 init 阶段读不到，
// 故 context 经 `attach(context:)` 在 onAppear 延迟接线（生产装配点），
// harness 用 `init(context:watcher:bookmarkStore:fingerprintStore:)` 直装。

import Combine
import Foundation

/// 放置区目录内一个 CSV 候选（S1/S1.5 用）：URL + 元数据指纹态。
struct DropzoneCandidate: Identifiable {
    let url: URL
    /// 元数据指纹（名+大小+mtime）；无法读取为 nil。
    let fingerprint: String?
    /// 是否命中「已导入过」指纹。
    let isImported: Bool
    /// 是否命中「已忽略」指纹。
    let isIgnored: Bool

    var id: URL { url }
}

/// 放置区导入向导状态机（S0-S5，docs/21 §4.2 转移表）。
@MainActor
final class DropzoneImportModel: ObservableObject {
    // MARK: - 状态机（S0-S5，docs/21 §4.2 转移表）

    /// Equatable：harness 断言 `model.step == .waiting` 等（docs/19 §3.3，
    /// 全部关联值类型已 Equatable，编译器合成）。
    enum Step: Equatable {
        /// S0 未授权（首次 / 已失效）：DropzoneAuthStatusView 呈现 .notAuthorized / .stale。
        case unauthorized
        /// S0-E 授权失败（bookmark 写失败/面板异常）：重试回 S0。
        case authFailed(String)
        /// S1 已授权 · 等待新导出（监视中）。
        case waiting
        /// S1.5 文件选择（≥2 候选 或 含已导入过）。
        case pickFile
        /// S2 预检中。
        case prechecking(URL)
        /// S2-E 预检失败（就地错误态，D-7.3）：重试 / 忽略双出口。
        case precheckFailed(URL, String)
        /// S3 预览·去重。
        case preview(FfiDropzonePrecheck, path: String)
        /// S4 导入中（单事务，关闭禁用）。skippedDuplicates = 本次跳过重复数（S5 展示）。
        case importing(path: String, skippedDuplicates: UInt32)
        /// S5 结果页。
        case done(FfiCsvImportResult, path: String, skippedDuplicates: UInt32)
        /// S5-E 导入失败（all-or-nothing 零落库）：回等待 S1。
        case importFailed(path: String, error: String)
    }

    // MARK: - 状态（原视图 @State → @Published，docs/19 §3.1）

    /// S0-S5 状态（视图 switch 渲染 + 绑定转发）。
    @Published var step: Step = .unauthorized
    /// S1.5 候选（非忽略、可触发）。
    @Published var candidates: [DropzoneCandidate] = []
    /// S1.5 当前选中文件。
    @Published var selectedCandidate: URL?
    /// S1 目录内全部候选（含忽略，供「已忽略」区）。
    @Published var directoryCandidates: [DropzoneCandidate] = []
    /// S3 将导入行号集合（D-8.4 即时统计反馈的唯一真相源；默认 = New ∪ Conflict）。
    @Published var includedLineNos: Set<UInt32> = []
    /// S1 副态 caption（回前台但文件未落盘，W-5 / D-7.5 不打断）。
    @Published var waitingHint: String?

    // MARK: - 依赖（docs/19 §3.2/§3.4 注入式）

    /// AppModel 窄面（@EnvironmentObject 由 SwiftUI 持有；视图经 attach 延迟接线）。
    /// 强引用无环：AppModel 不反向持有 model。
    private var context: DropzoneImportContext?
    /// 目录监视窄面（测试注入 FakeWatcher；生产由视图装配 DropzoneDirectoryWatcher）。
    private let watcher: DirectoryWatching
    /// bookmark 存取（S0 授权唯一写点 save + A-3 validate）。
    private let bookmarkStore: DropzoneBookmarkStore
    /// 已导入过/已忽略指纹存取（W-3/W-6）。
    private let fingerprintStore: DropzoneFingerprintStore

    /// 可测装配点（docs/19 §3.3 harness）：窄协议 context + FakeWatcher + 注入式 store。
    /// - Parameters:
    ///   - context: AppModel 窄面（视图经 `attach(context:)` 延迟接线时传 nil）。
    ///   - watcher: 目录监视窄面（测试注入 FakeWatcher）。
    ///   - bookmarkStore: bookmark 存取（测试传 `UserDefaults(suiteName:)` 隔离实例）。
    ///   - fingerprintStore: 指纹存取（同 store 隔离纪律）。
    init(context: DropzoneImportContext? = nil,
         watcher: DirectoryWatching,
         bookmarkStore: DropzoneBookmarkStore,
         fingerprintStore: DropzoneFingerprintStore) {
        self.context = context
        self.watcher = watcher
        self.bookmarkStore = bookmarkStore
        self.fingerprintStore = fingerprintStore
    }

    /// 视图接线：@EnvironmentObject（AppModel）在 onAppear 传入（SwiftUI 视图
    /// init 阶段读不到环境对象）。须在任何状态方法之前调用一次（编程不变量）。
    func attach(context: DropzoneImportContext) {
        self.context = context
    }

    // MARK: - 生命周期（原视图 onChange/onReceive/onDisappear 逻辑，docs/19 §3.4 ⑤）

    /// 进入向导：按授权三态落地。已授权 → S1 并开始监视（进入即补扫）；
    /// 未授权/已失效 → S0（授权即同意，裁定②；失效非静默，D-18.3）。
    func onAppear() {
        switch context?.dropzoneAuthStatus {
        case .authorized:
            step = .waiting
            startWatching()
        case .notAuthorized, .stale, .none:
            step = .unauthorized
        }
        // 测试专用 seam（A-3 自动化前置；testBaseDir / debugDisableTouchID 同族
        // 先例，docs/19 §5.3 lead 批准纪律）：`coffer.debugAuthorizeDropzonePath`
        // 置位且当前 S0 → 走与「选择放置区目录…」按钮**完全相同**的
        // authorize(url:) 路径自动授权。跳过的仅是 NSOpenPanel 用户选择 UI
        // （面板交互 = 用户手势，无法后台化）；目标限定 App 自有容器内目录，
        // 零安全面扩大。失效语义（改名/chmod/删除/重启持久）与真实授权同码路。
        if step == .unauthorized,
           let debugPath = UserDefaults.standard.string(
               forKey: Self.debugAuthorizeDropzonePathKey),
           !debugPath.isEmpty {
            authorize(url: URL(fileURLWithPath: debugPath))
        }
    }

    /// 测试 seam 键名（A-3 自动化）：App 自有容器内目录路径，置位即自动授权。
    nonisolated static let debugAuthorizeDropzonePathKey = "coffer.debugAuthorizeDropzonePath"

    /// W-2 phase 停表（视图 `.onChange(of: model.phase)` 转发）：phase 离开
    /// .unlocked 即停表（fail-closed 双保险，docs/21a §2.2）。
    func handlePhaseChange() {
        if context?.phase != .unlocked { watcher.stop() }
    }

    /// IT-12 A-5 广播回落（视图 `.onChange(of: model.dropzoneBookmark)` 转发）：
    /// 设置页「移除授权」置 nil → 停表（watcher.stop 配对释放安全作用域）+ 回落
    /// S0，防止在已撤销目录上继续监视 / 点「导入 N 条」；S0 重授权（换目录）时
    /// status 仍 .authorized，不受扰。注意 onChange 仅在 bookmark 值变化时触发——
    /// 目录不可达但 bookmark 值未变的 stale 场景由 rescanAndEvaluate 的 validate
    /// 判定回落（S1 补扫），不由此方法覆盖（IT-12 走查 2026-10-16，H-1 收敛）。
    func handleBookmarkChange() {
        switch context?.dropzoneAuthStatus {
        case .authorized:
            break
        case .notAuthorized, .stale, .none:
            watcher.stop()
            step = .unauthorized
        }
    }

    /// W-5 回前台补扫（视图 `.onReceive(didBecomeActiveNotification)` 转发）：
    /// 仅解锁 + S1 等待态触发；未落盘则保持 S1 + 轻提示（D-7.5 不打断不弹窗）。
    func handleDidBecomeActive() {
        guard context?.phase == .unlocked else { return }
        if case .waiting = step { rescanAndEvaluate(foreground: true) }
    }

    /// 视图 onDisappear 转发：防御性停表（结构性拆树之外的双保险，docs/21a §2.2）。
    func onDisappear() {
        watcher.stop()
    }

    // MARK: - S0 授权

    /// S0 授权落地（视图 NSOpenPanel 成功后回调，docs/19 §3.1）：唯一写点
    /// save → context.setDropbookmark 广播 → S1 开始监视。失败就地 S0-E。
    func authorize(url: URL) {
        guard let ctx = context else { return }
        do {
            let bookmark = try bookmarkStore.save(url)
            ctx.setDropzoneBookmark(bookmark)
            step = .waiting
            startWatching()
        } catch {
            step = .authFailed(errorText(error))
        }
    }

    // MARK: - S1 监视

    /// 启动目录监视（仅 S1 已授权态）。进入即补扫一次（docs/21a §2.2 补扫时机①）。
    /// start 失败（授权失效/无法打开）→ 就地 S0-E，不静默（D-18.3）。
    func startWatching() {
        guard case .authorized(let bookmark) = context?.dropzoneAuthStatus else { return }
        do {
            try watcher.start(watching: bookmark.url) { [weak self] in
                // vnode 事件在后台队列触发；跳主队列再判状态（不打断 S1.5/S3/S4）。
                Task { @MainActor in
                    self?.handleWatchEvent()
                }
            }
            handleWatchEvent()
        } catch {
            step = .authFailed(errorText(error))
        }
    }

    /// vnode 事件回调：仅 S1（等待）态响应自动流转；S1.5/S3 不打断当前选择、
    /// S4/S5 入队不打断（W-4，回 S1 后补扫兜底）。
    func handleWatchEvent() {
        guard context?.phase == .unlocked else { return }
        guard case .waiting = step else { return }
        rescanAndEvaluate(foreground: false)
    }

    /// 补扫 + 指纹过滤 → W-3 判多/判已导入过 → S2 / S1.5 / S1。
    /// `foreground` = 回前台触发的补扫（W-5）：无候选时设轻提示 caption。
    func rescanAndEvaluate(foreground: Bool) {
        guard context?.phase == .unlocked, let ctx = context else { return }
        switch ctx.dropzoneAuthStatus {
        case .authorized(let bookmark):
            // 失效检测（A-3 / D-18.3）：目录不可达 → 就地 .stale（回 S0 重新授权）。
            guard bookmarkStore.validate(bookmark) else {
                step = .unauthorized
                return
            }
            let all = dropzoneCandidates()
            directoryCandidates = all
            let fresh = all.filter { !$0.isIgnored }
            if fresh.isEmpty {
                if foreground { waitingHint = "还没看到新导出——请完成 Passwords.app 的保存" }
                step = .waiting
                return
            }
            waitingHint = nil
            if fresh.count >= 2 || fresh.contains(where: { $0.isImported }) {
                candidates = fresh
                selectedCandidate = defaultSelection(fresh)
                step = .pickFile
            } else if let only = fresh.first {
                startPrecheck(only.url)
            }
        case .notAuthorized, .stale:
            step = .unauthorized
        }
    }

    /// 默认选中 = 最新修改时间且未「已导入过」；全为已导入过则无默认（预检禁用）。
    func defaultSelection(_ candidates: [DropzoneCandidate]) -> URL? {
        let fresh = candidates.filter { !$0.isImported }
        let pool = fresh.isEmpty ? candidates : fresh
        return pool.max { mtime($0.url) < mtime($1.url) }?.url
    }

    /// 枚举目录内全部 CSV 候选并附指纹态（名+大小+mtime，S-4 仅元数据）。
    func dropzoneCandidates() -> [DropzoneCandidate] {
        watcher.rescan().map { url in
            let fp = fingerprintStore.fingerprint(for: url)
            return DropzoneCandidate(url: url,
                                     fingerprint: fp,
                                     isImported: fp.map { fingerprintStore.isImported($0) } ?? false,
                                     isIgnored: fp.map { fingerprintStore.isIgnored($0) } ?? false)
        }
    }

    /// 忽略文件（W-6）：落忽略指纹后回 S1，该文件同/跨会话不再自动触发预检。
    func ignoreFile(_ url: URL) {
        if let fp = fingerprintStore.fingerprint(for: url) {
            fingerprintStore.markIgnored(fp)
        }
        step = .waiting
        rescanAndEvaluate(foreground: false)
    }

    /// 取消忽略（S1「已忽略」区）：清忽略指纹后重扫，恢复可检测（W-6）。
    func unignore(_ fingerprint: String) {
        fingerprintStore.removeIgnored(fingerprint)
        rescanAndEvaluate(foreground: false)
    }

    // MARK: - S2 预检

    /// 选定文件 → session.precheckDropzone（core 去重分类，P-4；只读同步调用）。
    func startPrecheck(_ url: URL) {
        step = .prechecking(url)
        let path = url.path
        do {
            let report = try sessionCall { try $0.precheckDropzone(path: path) }
            // 默认 include = New ∪ Conflict（安全默认跳过重复，docs/21 §4.4）。
            includedLineNos = Set(report.rows.filter { $0.category != .duplicate }.map(\.lineNo))
            step = .preview(report, path: path)
        } catch {
            // S2-E 就地错误态：错误文案经 ErrorPresenter（D-12.3），不回显文件内容。
            step = .precheckFailed(url, errorText(error))
        }
    }

    // MARK: - S3 预览·去重

    /// 行选择切换（D-8.4 状态可见可逆）。
    func toggle(_ row: FfiDropzoneRow) {
        if includedLineNos.contains(row.lineNo) {
            includedLineNos.remove(row.lineNo)
        } else {
            includedLineNos.insert(row.lineNo)
        }
    }

    func duplicates(in report: FfiDropzonePrecheck) -> [FfiDropzoneRow] {
        report.rows.filter { $0.category == .duplicate }
    }

    func conflicts(in report: FfiDropzonePrecheck) -> [FfiDropzoneRow] {
        report.rows.filter { $0.category == .conflict }
    }

    /// 全部重复行是否均被选中（S3 菜单 label：全部导入 / 跳过）。
    func allDuplicatesIncluded(in report: FfiDropzonePrecheck) -> Bool {
        let dupes = duplicates(in: report)
        return !dupes.isEmpty && dupes.allSatisfy { includedLineNos.contains($0.lineNo) }
    }

    /// 批量导入全部重复（S3 逃生口，D-8.4：新建不覆盖）。
    func includeAllDuplicates(in report: FfiDropzonePrecheck) {
        for row in duplicates(in: report) { includedLineNos.insert(row.lineNo) }
    }

    /// 批量跳过全部重复（S3 安全默认）。
    func excludeAllDuplicates(in report: FfiDropzonePrecheck) {
        for row in duplicates(in: report) { includedLineNos.remove(row.lineNo) }
    }

    /// S3 三连统计由 includedLineNos 派生（D-8.4 即时更新）：各分类当前被选中
    /// （将导入）的行数；三分类和恒等于「导入 N 条」N（M-1）。
    func includedCount(in report: FfiDropzonePrecheck, of category: FfiDedupCategory) -> Int {
        report.rows.reduce(into: 0) { count, row in
            if row.category == category && includedLineNos.contains(row.lineNo) { count += 1 }
        }
    }

    /// S1.5 选中文件是否「已导入过」（放行提示，docs/21 §4.3-②，用户可刻意重导）。
    var selectedIsImported: Bool {
        guard let sel = selectedCandidate else { return false }
        return candidates.first { $0.url == sel }?.isImported ?? false
    }

    /// D-8.4 VO：徽章 label 含当前态 + 动作（「重复，点按改为导入」）。
    func previewRowLabel(_ row: FfiDropzoneRow) -> String {
        let action = includedLineNos.contains(row.lineNo) ? "点按改为跳过" : "点按改为导入"
        return "\(categoryName(row.category))，\(row.title)，\(action)"
    }

    func categoryName(_ category: FfiDedupCategory) -> String {
        switch category {
        case .new: return "新增"
        case .duplicate: return "重复"
        case .conflict: return "冲突"
        }
    }

    // MARK: - S4 导入

    /// 导入执行中（壳「关闭」禁用，防丢结果页）。
    var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    /// import_dropzone 单事务 all-or-nothing（P-4）：按 includeLineNos 选择集导入，
    /// 失败零落库 + 就地错误回 S1（S5-E）。导入中暂停响应监视事件（W-4 入队不打断）。
    func doImport(report: FfiDropzonePrecheck, path: String) {
        let skipped: UInt32 = UInt32(
            report.rows.filter { $0.category == .duplicate && !includedLineNos.contains($0.lineNo) }.count
        )
        step = .importing(path: path, skippedDuplicates: skipped)
        let session = context?.session
        let include = Array(includedLineNos)
        Task.detached(priority: .userInitiated) { [weak self] in
            // 弱引用在 async 边界前一次性解包（避免在 @Sendable 闭包内引用
            // captured var，Swift 6 下是错误）；导入期间 model 由视图持有。
            guard let self else { return }
            do {
                let result = try session?.importDropzone(path: path, includeLineNos: include)
                await MainActor.run {
                    if let result {
                        self.markImported(path: path)
                        self.step = .done(result, path: path, skippedDuplicates: skipped)
                        self.context?.reloadItems()
                    } else {
                        self.step = .importFailed(path: path, error: "会话不存在。")
                    }
                }
            } catch {
                await MainActor.run {
                    self.step = .importFailed(path: path, error: ErrorPresenter.text(error))
                }
            }
        }
    }

    /// 导入成功后落「已导入过」指纹（S5 前；后续补扫判该文件为已导入过，W-3）。
    func markImported(path: String) {
        let url = URL(fileURLWithPath: path)
        if let fp = fingerprintStore.fingerprint(for: url) {
            fingerprintStore.markImported(fp)
        }
    }

    /// 回等待 S1（S5 返回等待 / S5-E / S3 返回共用）：复位后补扫。
    func backToWaiting() {
        step = .waiting
        rescanAndEvaluate(foreground: false)
    }

    // MARK: - 行元数据（非敏感，S-4）

    /// 文件大小 · 相对修改时间（S1.5 行元数据，非敏感）。
    func fileMeta(_ url: URL) -> String {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
              let size = values.fileSize else { return "" }
        let sizeText = ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
        guard let date = values.contentModificationDate else { return sizeText }
        return "\(sizeText) · \(relativeTime(date))"
    }

    func relativeTime(_ date: Date) -> String {
        let seconds = Int(Date().timeIntervalSince(date))
        if seconds < 60 { return "刚刚" }
        if seconds < 3600 { return "\(seconds / 60) 分钟前" }
        if seconds < 86_400 { return "\(seconds / 3600) 小时前" }
        if Calendar.current.isDateInYesterday(date) { return "昨天" }
        return "\(seconds / 86_400) 天前"
    }

    // MARK: - 辅助

    /// FFI 错误一律走 ErrorPresenter 单源（D-12.3：code 本地化 + 4001/4002/6xxx
    /// 特殊码规范化，且 FfiError.errorDescription 是 String(reflecting:) 调试
    /// 表示，不可直出）；本地错误类型（DropzoneBookmarkError/DropzoneWatchError）
    /// 已实现 errorDescription，直出可操作文案。
    func errorText(_ error: Error) -> String {
        if error is FfiError { return ErrorPresenter.text(error) }
        if let localized = error as? LocalizedError, let message = localized.errorDescription {
            return message
        }
        return ErrorPresenter.text(error)
    }

    func sessionCall<R>(_ action: (VaultSession) throws -> R) throws -> R {
        guard let session = context?.session else {
            throw FfiError.Coffer(code: 1001, message: "会话不存在")
        }
        return try action(session)
    }

    private func mtime(_ url: URL) -> Date {
        (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
            ?? .distantPast
    }
}
