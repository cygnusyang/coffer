// DropzoneImportView.swift —— 放置区导入向导（v2.11.0，docs/21 §4/§5 G4）。
//
// 复用共享壳 ImportWizardShell（M-1 Option A，docs/21 §2 裁定）：S0-S5 状态机
// 全在 content 闭包内自持；`precheckError` Binding 传 nil（壳 alert 不触发，
// 预检失败走就地错误态 S2-E，docs/21 §4.3-③）；`ImportWizardShell.swift`
// 零改动（docs/14 P3 硬约束）。
//
// 流程（docs/21 §4.2）：S0 授权（security-scoped bookmark 持久化，授权即同意
// 裁定②）→ S1 已授权·等待（DispatchSource 监视 + 补扫，仅向导打开期间，裁定⑤）
// → S1.5 文件选择（≥2 候选或含已导入过）→ S2 预检（session.precheckDropzone，
// core 去重分类，P-4）→ S2-E 预检失败（就地错误态）→ S3 预览·去重（DedupCategoryBadge
// 三分类 + D-8.4 批量切换）→ S4 导入（import_dropzone 单事务 all-or-nothing）
// → S5 结果页（删源提示，D-6 只提示不代办）。
//
// R2 纪律（docs/21 §4.6）：明文密码全程只在 core 内存内解析/分类，Swift 只
// 消费 FfiDropzonePrecheck 的非敏感行元数据（title/username/url/category），
// 密码明文不跨 FFI；错误文案经 ErrorPresenter 单源（D-12.3），不回显文件内容
// 只回显文件名/行数；零网络。
//
// 监视生命周期：watcher 在 S1 启动（进入即补扫），onDisappear / onChange(phase)
// 防御性停表防泄漏（docs/21a §2.2 结构性 fail-closed 双保险）；App 回前台补扫
// 经本视图观察 didBecomeActiveNotification（W-5，自我托管不依赖 G6 转发）。

import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// 放置区目录内一个 CSV 候选（S1/S1.5 用）：URL + 元数据指纹态。
private struct DropzoneCandidate: Identifiable {
    let url: URL
    /// 元数据指纹（名+大小+mtime）；无法读取为 nil。
    let fingerprint: String?
    /// 是否命中「已导入过」指纹。
    let isImported: Bool
    /// 是否命中「已忽略」指纹。
    let isIgnored: Bool

    var id: URL { url }
}

struct DropzoneImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    // MARK: - 状态机（S0-S5，docs/21 §4.2 转移表）

    enum Step {
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

    @State private var step: Step = .unauthorized
    /// 目录监视器（@State 引用：跨 body 重建稳定；onDisappear/onChange 停表）。
    @State private var watcher = DropzoneDirectoryWatcher()
    /// S1.5 候选（非忽略、可触发）。
    @State private var candidates: [DropzoneCandidate] = []
    /// S1.5 当前选中文件。
    @State private var selectedCandidate: URL?
    /// S1 目录内全部候选（含忽略，供「已忽略」区）。
    @State private var directoryCandidates: [DropzoneCandidate] = []
    /// S3 将导入行号集合（D-8.4 即时统计反馈的唯一真相源；默认 = New ∪ Conflict）。
    @State private var includedLineNos: Set<UInt32> = []
    /// S1 副态 caption（回前台但文件未落盘，W-5 / D-7.5 不打断）。
    @State private var waitingHint: String?

    /// 导入执行中（壳「关闭」禁用，防丢结果页）。
    private var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    /// 格式配置（docs/21 §4.5 线框 + docs/14 P3 §3；S4/S5 文案逐字对齐 CSV，
    /// ImportView.swift:49,55）。语义死字段逐个注 N/A 及缘由（C-2）。
    static let importFormatConfig = ImportFormatConfig(
        title: "从 macOS 密码 App 导入",
        icon: "lock.doc",
        // N/A：S0 授权 UI 在 content 闭包内自持（不走壳 pickBody，docs/21 裁定 M-1）。
        pickTitle: "",
        pickDescription: "",
        pickButtonLabel: "",
        windowWidth: 640, windowHeight: 600,
        // N/A：precheckError Binding 传 nil，壳 alert 不触发（预检失败走就地错误态 S2-E）。
        precheckErrorAlertTitle: "",
        transactionSemantics: .allOrNothing,
        // S4 文案逐字对齐 CSV（ImportView.swift:53）。
        importingCopy: "正在导入（单事务，全部成功或全部回滚）…",
        failureSuffix: "",
        // S5 单事务行逐字对齐 CSV（ImportView.swift:55）。
        doneFooter: "所有行已在单事务内写入（全部成功或全部回滚）。",
        failureRecovery: .backToPick,
        // N/A：S0 闭包自开 NSOpenPanel（目录选择），不走壳 pickBody 面板。
        canChooseDirectories: false,
        allowedContentTypes: [],
        panelMessage: ""
    )

    // MARK: - Body

    var body: some View {
        ImportWizardShell(
            config: Self.importFormatConfig,
            isImporting: isImporting,
            onClose: { dismiss() },
            // C-1：precheckError Binding 传 nil——壳 alert 不呈现，错误态闭包内自持。
            precheckError: .constant(nil),
            onPrecheckErrorDismiss: {}
        ) {
            switch step {
            case .unauthorized:
                authorizationBody()
            case .authFailed(let error):
                authFailedBody(error)
            case .waiting:
                waitingBody()
            case .pickFile:
                pickFileBody()
            case .prechecking(let url):
                precheckingBody(url)
            case .precheckFailed(let url, let error):
                precheckFailedBody(url, error)
            case .preview(let report, let path):
                previewBody(report, path: path)
            case .importing:
                // C-5：S4 复用 ImportScaffold.importingBody。
                ImportScaffold.importingBody(Self.importFormatConfig.importingCopy)
            case .done(let result, let path, let skipped):
                // C-5：S5 复用 ImportScaffold.doneSkeleton。
                ImportScaffold.doneSkeleton(
                    count: result.importedRows,
                    doneFooter: Self.importFormatConfig.doneFooter,
                    path: path,
                    onDone: { dismiss() }
                ) {
                    doneExtra(result: result, path: path, skippedDuplicates: skipped)
                }
            case .importFailed(let path, let error):
                importFailedBody(path, error)
            }
        }
        .onAppear(perform: onAppear)
        // 锁定 = 监视停摆（fail-closed，裁定③）：phase 离开 .unlocked 即停表
        // （结构性拆树之外的双保险，docs/21a §2.2）。
        .onChange(of: model.phase) {
            if model.phase != .unlocked { watcher.stop() }
        }
        // 授权广播同步（D-18.4 状态广播可达 + docs/21 §5 A-5/RT-09）：设置页
        // 「移除授权」置 nil → 停表（watcher.stop 配对释放安全作用域）+ 回落
        // S0，防止在已撤销目录上继续监视 / 点「导入 N 条」；S0 重授权（换目录）
        // 时 status 仍 .authorized，不受扰。注意 onChange 仅在 bookmark 值变化时
        // 触发——目录不可达但 bookmark 值未变的 stale 场景由 rescanAndEvaluate
        // 的 validate 判定回落（S1 补扫），不由此 onChange 覆盖（IT-12 走查 2026-10-16）。
        .onChange(of: model.dropzoneBookmark) {
            switch model.dropzoneAuthStatus {
            case .authorized:
                break
            case .notAuthorized, .stale:
                watcher.stop()
                step = .unauthorized
            }
        }
        .onDisappear {
            watcher.stop()
        }
        // 回前台补扫（W-5）：用户切去 Passwords.app 导出后切回，检测到即自动
        // 进预检；未落盘则保持 S1 + 轻提示（D-7.5 不打断不弹窗）。
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            guard model.phase == .unlocked else { return }
            if case .waiting = step { rescanAndEvaluate(foreground: true) }
        }
    }

    // MARK: - 生命周期

    /// 进入向导：按授权三态落地。已授权 → S1 并开始监视（进入即补扫）；
    /// 未授权/已失效 → S0（授权即同意，裁定②；失效非静默，D-18.3）。
    private func onAppear() {
        switch model.dropzoneAuthStatus {
        case .authorized:
            step = .waiting
            startWatching()
        case .notAuthorized, .stale:
            step = .unauthorized
        }
    }

    /// 启动目录监视（仅 S1 已授权态）。进入即补扫一次（docs/21a §2.2 补扫时机①）。
    /// start 失败（授权失效/无法打开）→ 就地 S0-E，不静默（D-18.3）。
    private func startWatching() {
        guard case .authorized(let bookmark) = model.dropzoneAuthStatus else { return }
        do {
            try watcher.start(watching: bookmark.url) { [self] in
                // vnode 事件在后台队列触发；跳主队列再判状态（不打断 S1.5/S3/S4）。
                Task { @MainActor in
                    self.handleWatchEvent()
                }
            }
            handleWatchEvent()
        } catch {
            step = .authFailed(errorText(error))
        }
    }

    /// vnode 事件回调：仅 S1（等待）态响应自动流转；S1.5/S3 不打断当前选择、
    /// S4/S5 入队不打断（W-4，回 S1 后补扫兜底）。
    private func handleWatchEvent() {
        guard model.phase == .unlocked else { return }
        guard case .waiting = step else { return }
        rescanAndEvaluate(foreground: false)
    }

    /// 补扫 + 指纹过滤 → W-3 判多/判已导入过 → S2 / S1.5 / S1。
    /// `foreground` = 回前台触发的补扫（W-5）：无候选时设轻提示 caption。
    private func rescanAndEvaluate(foreground: Bool) {
        guard model.phase == .unlocked else { return }
        switch model.dropzoneAuthStatus {
        case .authorized(let bookmark):
            // 失效检测（A-3 / D-18.3）：目录不可达 → 就地 .stale（回 S0 重新授权）。
            guard DropzoneBookmarkStore.shared.validate(bookmark) else {
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
    private func defaultSelection(_ candidates: [DropzoneCandidate]) -> URL? {
        let fresh = candidates.filter { !$0.isImported }
        let pool = fresh.isEmpty ? candidates : fresh
        return pool.max { mtime($0.url) < mtime($1.url) }?.url
    }

    private func mtime(_ url: URL) -> Date {
        (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
            ?? .distantPast
    }

    /// 枚举目录内全部 CSV 候选并附指纹态（名+大小+mtime，S-4 仅元数据）。
    private func dropzoneCandidates() -> [DropzoneCandidate] {
        let store = DropzoneFingerprintStore.shared
        return watcher.rescan().map { url in
            let fp = store.fingerprint(for: url)
            return DropzoneCandidate(url: url,
                                     fingerprint: fp,
                                     isImported: fp.map(store.isImported) ?? false,
                                     isIgnored: fp.map(store.isIgnored) ?? false)
        }
    }

    // MARK: - S0 授权

    /// S0 未授权（首次/已失效）说明卡 + 授权范围声明（D-18.1 五要素常显）。
    private func authorizationBody() -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: Self.importFormatConfig.icon)
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("从 macOS 密码 App 导入你的钥匙串密码")
                .font(.callout)
            Text("这是 macOS 系统密码 App 唯一官方导出方式。选一个放置区目录，把导出文件放进去，剩下的交给 Coffer。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("放置区目录（建议：如 ~/Downloads/coffer-import）")
                .font(.caption)
                .foregroundStyle(.secondary)
            Divider()
            // D-18.2：三态组件（未授权态 / 失效态由 model.dropzoneAuthStatus 派生）。
            DropzoneAuthStatusView(
                status: model.dropzoneAuthStatus,
                setButtonLabel: "选择放置区目录…",
                onSet: pickAndAuthorize
            )
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.08)))
            Spacer()
            // footer：授权范围声明常显（D-18.1，只读/目标路径/用途/零网络/可撤销）。
            Text("授权后 Coffer 将对该目录只读访问，仅用于检测新导出 CSV；本地读取、零网络、可随时在设置中撤销。")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 闭包自开 NSOpenPanel 选目录（canChooseDirectories，目录多选禁，A-1）→
    /// 写 bookmark（唯一写点，DropzoneBookmarkStore.save）→ 授权即同意（裁定②，
    /// 无二次确认弹窗，A-2）→ 直接进 S1 并开始监视。
    private func pickAndAuthorize() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = []
        // 授权范围声明在面板 message 重申（D-18.1）。
        panel.message = "Coffer 将获得对所选目录的只读访问，用于自动检测新的密码导出 CSV。仅本地读取、零网络、可随时在『系统设置 › 隐私与安全性 › 文件与文件夹』或本应用内撤销授权。"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let bookmark = try DropzoneBookmarkStore.shared.save(url)
            model.setDropzoneBookmark(bookmark)
            step = .waiting
            startWatching()
        } catch {
            step = .authFailed(errorText(error))
        }
    }

    /// S0-E 授权失败（就地错误态，重试回 S0）。
    private func authFailedBody(_ error: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("无法设置放置区授权").font(.headline)
            Text(error).font(.callout).foregroundStyle(.secondary)
            Button("重试") { step = .unauthorized }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - S1 等待

    /// S1 已授权 · 等待新导出：目录行 + 三步指引卡 + 监视徽章 + 已忽略区 + footer。
    private func waitingBody() -> some View {
        VStack(alignment: .leading, spacing: 14) {
            directoryLine
            guideCard
            DropzoneWatchStatusBadge(directoryName: authorizedDirectoryName, hint: waitingHint)
            ignoredSection
            Spacer()
            Text("监视仅在向导打开期间进行；关闭后再打开会自动补扫新文件。")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 目录行（D-18.5 使用面路径明示）+ 重新授权（回 S0 换目录，仍走唯一写点）。
    private var directoryLine: some View {
        HStack(spacing: 8) {
            Label(authorizedDirectoryPath, systemImage: "folder")
                .font(.callout)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button("重新授权…") { step = .unauthorized }
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
    }

    /// 三步指引卡（docs/21 §4.1）：Passwords.app 打开按钮 + 手动导出说明。
    private var guideCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("① 打开 macOS 密码 App").font(.callout)
                Spacer()
                Button("打开 macOS 密码 App") { openPasswordsApp() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(!passwordsAppAvailable)
            }
            Text("② 「文件」→「导出所有密码」→ 通过验证（Touch ID / 设备密码）")
                .font(.callout)
            Text("③ 保存位置选此目录 → 存储").font(.callout)
            if passwordsAppAvailable {
                // 苹果强制的人工 + 生物识别步——明示不可代替。
                Text("第②步必须由你手动完成（苹果要求），Coffer 无法代替。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                // J-2：macOS < 14 运行时降级（Passwords.app 不存在）→ 就地提示 + 按钮禁用。
                Label("需要 macOS 14 或更高版本（Passwords.app 不可用）。",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.08)))
    }

    /// macOS < 14 检测（J-2）：Passwords.app 是否存在。
    private var passwordsAppAvailable: Bool {
        FileManager.default.fileExists(atPath: "/System/Applications/Passwords.app")
    }

    /// J-1：无参数纯 URL 唤起（BUG-30 类沙盒坑仅涉 --args 剥离，本路径无参数）。
    private func openPasswordsApp() {
        let url = URL(fileURLWithPath: "/System/Applications/Passwords.app")
        guard NSWorkspace.shared.open(url) else {
            waitingHint = "无法打开 macOS 密码 App，请在访达中手动打开。"
            return
        }
    }

    /// 当前授权目录名/路径（徽章 VO + 目录行展示；.stale 时也可呈现）。
    private var authorizedDirectoryName: String {
        switch model.dropzoneAuthStatus {
        case .authorized(let b), .stale(let b): return b.url.lastPathComponent
        case .notAuthorized: return ""
        }
    }

    private var authorizedDirectoryPath: String {
        switch model.dropzoneAuthStatus {
        case .authorized(let b), .stale(let b): return b.url.path
        case .notAuthorized: return ""
        }
    }

    /// 已忽略区（W-6）：被忽略文件行 + [取消忽略] 清指纹恢复可检测。
    private var ignoredSection: some View {
        let ignored = directoryCandidates.filter { $0.isIgnored }
        guard !ignored.isEmpty else { return AnyView(EmptyView()) }
        return AnyView(
            VStack(alignment: .leading, spacing: 4) {
                Text("已忽略").font(.caption).foregroundStyle(.secondary)
                ForEach(ignored) { candidate in
                    HStack(spacing: 8) {
                        Text(candidate.url.lastPathComponent)
                            .font(.caption)
                            .lineLimit(1)
                        Text("（无法解析，已忽略）")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("取消忽略") {
                            if let fp = candidate.fingerprint {
                                DropzoneFingerprintStore.shared.removeIgnored(fp)
                            }
                            rescanAndEvaluate(foreground: false)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            }
        )
    }

    // MARK: - S1.5 文件选择

    private func pickFileBody() -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("放置区检测到导出文件，选择一个：").font(.headline)
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(candidates) { candidate in
                        candidateRow(candidate)
                    }
                }
            }
            if selectedIsImported {
                // 已导入过但用户仍选 → 放行提示（docs/21 §4.3-②，用户可刻意重导）。
                Text("此文件与上次导入一致，继续将全部作为新增。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            HStack {
                Button("忽略所选（不再提示）") { ignoreSelected() }
                    .buttonStyle(.bordered)
                Spacer()
                Button("预检所选") {
                    if let url = selectedCandidate { startPrecheck(url) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedCandidate == nil)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 候选行：单选 + 文件名 + 大小/时间 + 「新」/「已导入过」徽标。
    private func candidateRow(_ candidate: DropzoneCandidate) -> some View {
        Button {
            selectedCandidate = candidate.url
        } label: {
            HStack(spacing: 8) {
                Image(systemName: selectedCandidate == candidate.url ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selectedCandidate == candidate.url ? Color.accentColor : Color.secondary)
                Text(candidate.url.lastPathComponent)
                    .font(.callout)
                    .lineLimit(1)
                Text(fileMeta(candidate.url))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if candidate.isImported {
                    metaBadge("已导入过", color: .secondary)
                } else {
                    metaBadge("新", color: .blue)
                }
            }
            .padding(6)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(selectedCandidate == candidate.url ? Color.accentColor.opacity(0.12) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(candidate.url.lastPathComponent)\(candidate.isImported ? "，已导入过" : "，新文件")")
    }

    private func metaBadge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.monospacedDigit())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.12)))
            .foregroundStyle(color)
    }

    private var selectedIsImported: Bool {
        guard let sel = selectedCandidate else { return false }
        return candidates.first { $0.url == sel }?.isImported ?? false
    }

    /// 文件大小 · 相对修改时间（S1.5 行元数据，非敏感）。
    private func fileMeta(_ url: URL) -> String {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
              let size = values.fileSize else { return "" }
        let sizeText = ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
        guard let date = values.contentModificationDate else { return sizeText }
        return "\(sizeText) · \(relativeTime(date))"
    }

    private func relativeTime(_ date: Date) -> String {
        let seconds = Int(Date().timeIntervalSince(date))
        if seconds < 60 { return "刚刚" }
        if seconds < 3600 { return "\(seconds / 60) 分钟前" }
        if seconds < 86_400 { return "\(seconds / 3600) 小时前" }
        if Calendar.current.isDateInYesterday(date) { return "昨天" }
        return "\(seconds / 86_400) 天前"
    }

    /// 忽略所选（W-6）：落「已忽略指纹」（名+大小+mtime），该文件不再自动触发。
    private func ignoreSelected() {
        guard let sel = selectedCandidate else { return }
        ignoreFile(sel)
    }

    // MARK: - S2 预检

    /// 选定文件 → session.precheckDropzone（core 去重分类，P-4；只读同步调用）。
    private func startPrecheck(_ url: URL) {
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

    private func precheckingBody(_ url: URL) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在分析 \(url.lastPathComponent)（只读，不写入）…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// S2-E 预检失败（就地错误态 D-7.3）：图标 + 摘要 + 重试/忽略双出口。
    private func precheckFailedBody(_ url: URL, _ error: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("无法解析该文件").font(.headline)
            Text(error).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            ImportScaffold.pathLine(url.path)
            HStack {
                Button("重新预检") { startPrecheck(url) }
                    .buttonStyle(.bordered)
                Spacer()
                Button("忽略此文件（不再提示）") { ignoreFile(url) }
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 忽略文件（W-6）：落忽略指纹后回 S1，该文件同/跨会话不再自动触发预检。
    private func ignoreFile(_ url: URL) {
        if let fp = DropzoneFingerprintStore.shared.fingerprint(for: url) {
            DropzoneFingerprintStore.shared.markIgnored(fp)
        }
        step = .waiting
        rescanAndEvaluate(foreground: false)
    }

    // MARK: - S3 预览·去重

    private func previewBody(_ report: FfiDropzonePrecheck, path: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Text("来源").font(.caption).foregroundStyle(.secondary)
                ImportScaffold.pathLine(path)
                Spacer()
            }
            // statLabel 三连（C-5 复用 ImportScaffold.statLabel）。计数由
            // includedLineNos 派生（D-8.4 切换即时更新，对齐「导入 N 条」按钮：
            // 三连和恒等于 N）。
            HStack(spacing: 24) {
                ImportScaffold.statLabel("新增", includedCount(in: report, of: .new))
                ImportScaffold.statLabel("重复", includedCount(in: report, of: .duplicate))
                ImportScaffold.statLabel("冲突", includedCount(in: report, of: .conflict))
            }
            .font(.callout)

            if report.isEmptyVault {
                // 空库折叠预览（docs/21 §4.3-⑦）：无分类表，单行说明 + 统计。
                Text("密码库为空，全部 \(report.validRows) 条将作为新增导入")
                    .font(.callout)
                Spacer()
            } else {
                if !duplicates(in: report).isEmpty {
                    duplicateSectionHeader(report)
                }
                if !conflicts(in: report).isEmpty {
                    Text("冲突条目（\(report.conflictCount)）——用户名或网址不同，请确认")
                        .font(.callout)
                }
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(report.rows, id: \.lineNo) { row in
                            previewRow(row)
                        }
                    }
                }
                // 安全默认透明化（docs/21 §4.4 冲突区文案）。
                Text("不会覆盖库内已有条目；被跳过的条目可在导入后手动核对")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Button("返回") { backToWaiting() }
                    .buttonStyle(.bordered)
                Spacer()
                Button("导入 \(includedLineNos.count) 条") { doImport(report: report, path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(includedLineNos.isEmpty)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 重复区批量切换（D-8.4：即时统计反馈 + 安全默认跳过 + 逃生口）。
    private func duplicateSectionHeader(_ report: FfiDropzonePrecheck) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("重复条目（\(report.duplicateCount)）").font(.callout)
                Spacer()
                Menu {
                    Button("跳过（默认）") { excludeAllDuplicates(in: report) }
                    Button("全部导入（新建不覆盖）") { includeAllDuplicates(in: report) }
                } label: {
                    Label(allDuplicatesIncluded(in: report) ? "全部导入" : "跳过", systemImage: "chevron.down")
                }
                .controlSize(.small)
            }
            // 逃生口（元数据级去重限制的显式出路，docs/21 §4.4）。
            Text("若某条目密码已更新，可切换『全部导入』（新建不覆盖，不覆盖库内已有条目）")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    /// 预览行：分类徽章 + 标题/用户名/URL（中截断）+ 选择态文本标记（D-13.4
    /// 不依赖颜色）+ 行内切换（D-8.4 状态可见可逆）。
    private func previewRow(_ row: FfiDropzoneRow) -> some View {
        let included = includedLineNos.contains(row.lineNo)
        return Button {
            toggle(row)
        } label: {
            HStack(spacing: 8) {
                DedupCategoryBadge(category: row.category)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(row.title)
                            .font(.caption)
                            .lineLimit(1)
                        if let username = row.username, !username.isEmpty {
                            Text(username)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 8)
                        if let url = row.url {
                            Text(url)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    if let note = row.conflictNote {
                        Text(note)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                // 选择态文本（D-8.4 状态可见；D-13.4 不以颜色为唯一通道）。
                Text(included ? "已选" : "跳过")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(included ? Color.secondary : Color.orange)
                    .frame(width: 44, alignment: .trailing)
            }
            .padding(4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // D-8.4 VO：徽章 label 含当前态 + 动作（「重复，点按改为导入」）。
        .accessibilityLabel(previewRowLabel(row))
    }

    private func previewRowLabel(_ row: FfiDropzoneRow) -> String {
        let action = includedLineNos.contains(row.lineNo) ? "点按改为跳过" : "点按改为导入"
        return "\(categoryName(row.category))，\(row.title)，\(action)"
    }

    private func categoryName(_ category: FfiDedupCategory) -> String {
        switch category {
        case .new: return "新增"
        case .duplicate: return "重复"
        case .conflict: return "冲突"
        }
    }

    private func toggle(_ row: FfiDropzoneRow) {
        if includedLineNos.contains(row.lineNo) {
            includedLineNos.remove(row.lineNo)
        } else {
            includedLineNos.insert(row.lineNo)
        }
    }

    private func duplicates(in report: FfiDropzonePrecheck) -> [FfiDropzoneRow] {
        report.rows.filter { $0.category == .duplicate }
    }

    private func conflicts(in report: FfiDropzonePrecheck) -> [FfiDropzoneRow] {
        report.rows.filter { $0.category == .conflict }
    }

    private func allDuplicatesIncluded(in report: FfiDropzonePrecheck) -> Bool {
        let dupes = duplicates(in: report)
        return !dupes.isEmpty && dupes.allSatisfy { includedLineNos.contains($0.lineNo) }
    }

    private func includeAllDuplicates(in report: FfiDropzonePrecheck) {
        for row in duplicates(in: report) { includedLineNos.insert(row.lineNo) }
    }

    private func excludeAllDuplicates(in report: FfiDropzonePrecheck) {
        for row in duplicates(in: report) { includedLineNos.remove(row.lineNo) }
    }

    /// S3 三连统计由 includedLineNos 派生（D-8.4 即时更新）：各分类当前被选中
    /// （将导入）的行数；三分类和恒等于「导入 N 条」N。
    private func includedCount(in report: FfiDropzonePrecheck, of category: FfiDedupCategory) -> Int {
        report.rows.reduce(into: 0) { count, row in
            if row.category == category && includedLineNos.contains(row.lineNo) { count += 1 }
        }
    }

    // MARK: - S4 导入

    /// import_dropzone 单事务 all-or-nothing（P-4）：按 includeLineNos 选择集导入，
    /// 失败零落库 + 就地错误回 S1（S5-E）。导入中暂停响应监视事件（W-4 入队不打断）。
    private func doImport(report: FfiDropzonePrecheck, path: String) {
        let skipped: UInt32 = UInt32(
            report.rows.filter { $0.category == .duplicate && !includedLineNos.contains($0.lineNo) }.count
        )
        step = .importing(path: path, skippedDuplicates: skipped)
        let session = model.session
        let include = Array(includedLineNos)
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session?.importDropzone(path: path, includeLineNos: include)
                await MainActor.run {
                    if let result {
                        markImported(path: path)
                        step = .done(result, path: path, skippedDuplicates: skipped)
                        model.reloadItems()
                    } else {
                        step = .importFailed(path: path, error: "会话不存在。")
                    }
                }
            } catch {
                await MainActor.run {
                    step = .importFailed(path: path, error: ErrorPresenter.text(error))
                }
            }
        }
    }

    /// 导入成功后落「已导入过」指纹（S5 前；后续补扫判该文件为已导入过，W-3）。
    private func markImported(path: String) {
        let url = URL(fileURLWithPath: path)
        if let fp = DropzoneFingerprintStore.shared.fingerprint(for: url) {
            DropzoneFingerprintStore.shared.markImported(fp)
        }
    }

    /// S5-E 导入失败（all-or-nothing 零落库）：就地错误 + 回等待 S1。
    private func importFailedBody(_ path: String, _ error: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("导入失败").font(.headline)
            Text(error).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            ImportScaffold.pathLine(path)
            Button("返回等待") { backToWaiting() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - S5 结果页

    /// 结果页特有区：删源警示（D-6 只提示不代办，绝无删除按钮）+ 跳过重复统计 +
    /// 逃生口 + 返回等待。
    private func doneExtra(result: FfiCsvImportResult, path: String, skippedDuplicates: UInt32) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(
                "已从放置区导入 \(result.importedRows) 条条目。CSV 含明文密码，仅在本地读取解析、不写入日志、不离开本机（零网络承诺）。建议导入完成后立即在访达中删除源文件。",
                systemImage: "exclamationmark.triangle"
            )
            .font(.callout)
            .foregroundStyle(.orange)
            .multilineTextAlignment(.leading)
            if skippedDuplicates > 0 {
                Text("重复 \(skippedDuplicates) 条被跳过，未改动。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("若某条目密码已更新，可重新导入并切换『全部导入』。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button("返回等待") { backToWaiting() }
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// 回等待 S1（S5 返回等待 / S5-E / S3 返回共用）：复位后补扫。
    private func backToWaiting() {
        step = .waiting
        rescanAndEvaluate(foreground: false)
    }

    // MARK: - 辅助

    /// FFI 错误一律走 ErrorPresenter 单源（D-12.3：code 本地化 + 4001/4002/6xxx
    /// 特殊码规范化，且 FfiError.errorDescription 是 String(reflecting:) 调试
    /// 表示，不可直出）；本地错误类型（DropzoneBookmarkError/DropzoneWatchError）
    /// 已实现 errorDescription，直出可操作文案。
    private func errorText(_ error: Error) -> String {
        if error is FfiError { return ErrorPresenter.text(error) }
        if let localized = error as? LocalizedError, let message = localized.errorDescription {
            return message
        }
        return ErrorPresenter.text(error)
    }

    private func sessionCall<R>(_ action: (VaultSession) throws -> R) throws -> R {
        guard let session = model.session else {
            throw FfiError.Coffer(code: 1001, message: "会话不存在")
        }
        return try action(session)
    }
}
