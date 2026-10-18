// DropzoneImportView.swift —— 放置区导入向导（v2.11.0，docs/21 §4/§5 G4）。
//
// v2.11.0 W1a（docs/19 §3.1 L1 抽取）起降为薄壳：S0-S5 状态机 + 跨组件回落
// 逻辑 + 派生计数全部搬到 DropzoneImportModel（macos/Coffer/Dropzone/
// DropzoneImportModel.swift），本文件只保留视图修饰（ImportWizardShell 壳 /
// 系统面板闭包 / ViewBuilder 渲染面）与绑定转发。通用模式见 model 文件头
// 注释（docs/19 §3.4 ①②③⑤）。
//
// 复用共享壳 ImportWizardShell（M-1 Option A，docs/21 §2 裁定）：`precheckError`
// Binding 传 nil（壳 alert 不触发，预检失败走就地错误态 S2-E，docs/21 §4.3-③）；
// `ImportWizardShell.swift` 零改动（docs/14 P3 硬约束）。
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
// 生命周期：监视在 model 内管理（startWatching/onDisappear/onChange(phase)/
// onChange(bookmark)/didBecomeActive 逻辑均为 model 方法，docs/19 §3.4 ⑤——
// 视图只作 SwiftUI 观察转发）。@EnvironmentObject（AppModel）在 onAppear 经
// importModel.attach(context:) 接线（视图 init 读不到环境对象）。

import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct DropzoneImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// S0-S5 状态机 model（docs/19 §3.1 L1 抽取）：生产装配点装配服务，
    /// context 由 onAppear 经 attach 接线。
    @StateObject
    private var importModel = DropzoneImportModel(
        watcher: DropzoneDirectoryWatcher(),
        bookmarkStore: .shared,
        fingerprintStore: .shared
    )

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
            isImporting: importModel.isImporting,
            onClose: { dismiss() },
            // C-1：precheckError Binding 传 nil——壳 alert 不呈现，错误态闭包内自持。
            precheckError: .constant(nil),
            onPrecheckErrorDismiss: {}
        ) {
            switch importModel.step {
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
        .onAppear {
            // @EnvironmentObject 不可在视图 init 读，onAppear 接线（docs/19 §3.4 ⑤）。
            importModel.attach(context: model)
            importModel.onAppear()
        }
        // 锁定 = 监视停摆（fail-closed，裁定③）：phase 离开 .unlocked 即停表
        // （结构性拆树之外的双保险，docs/21a §2.2）——逻辑在 model.handlePhaseChange。
        .onChange(of: model.phase) {
            importModel.handlePhaseChange()
        }
        // 授权广播同步（D-18.4 状态广播可达 + docs/21 §5 A-5/RT-09）：设置页
        // 「移除授权」置 nil → model.handleBookmarkChange 停表 + 回落 S0。
        .onChange(of: model.dropzoneBookmark) {
            importModel.handleBookmarkChange()
        }
        .onDisappear {
            importModel.onDisappear()
        }
        // 回前台补扫（W-5）：用户切去 Passwords.app 导出后切回，检测到即自动
        // 进预检；未落盘则保持 S1 + 轻提示（D-7.5 不打断不弹窗）——逻辑在
        // model.handleDidBecomeActive。
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            importModel.handleDidBecomeActive()
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
    /// 授权落地交给 model.authorize（唯一写点 save + 广播 + 进 S1 开始监视）。
    /// 授权即同意（裁定②，无二次确认弹窗，A-2）。
    private func pickAndAuthorize() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = []
        // 授权范围声明在面板 message 重申（D-18.1）。
        panel.message = "Coffer 将获得对所选目录的只读访问，用于自动检测新的密码导出 CSV。仅本地读取、零网络、可随时在『系统设置 › 隐私与安全性 › 文件与文件夹』或本应用内撤销授权。"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importModel.authorize(url: url)
    }

    /// S0-E 授权失败（就地错误态，重试回 S0）。
    private func authFailedBody(_ error: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("无法设置放置区授权").font(.headline)
            Text(error).font(.callout).foregroundStyle(.secondary)
            Button("重试") { importModel.step = .unauthorized }
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
            DropzoneWatchStatusBadge(directoryName: authorizedDirectoryName, hint: importModel.waitingHint)
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
            Button("重新授权…") { importModel.step = .unauthorized }
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
        PasswordsAppLauncher.isAvailable
    }

    /// J-1：无参数纯 URL 唤起（BUG-30 类沙盒坑仅涉 --args 剥离，本路径无参数）。
    private func openPasswordsApp() {
        // 共享实现（J-1 seam 与按钮同链）：Support/PasswordsAppLauncher.swift。
        guard PasswordsAppLauncher.open() else {
            importModel.waitingHint = "无法打开 macOS 密码 App，请在访达中手动打开。"
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
        let ignored = importModel.directoryCandidates.filter { $0.isIgnored }
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
                                importModel.unignore(fp)
                            }
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
                    ForEach(importModel.candidates) { candidate in
                        candidateRow(candidate)
                    }
                }
            }
            if importModel.selectedIsImported {
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
                    if let url = importModel.selectedCandidate { importModel.startPrecheck(url) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(importModel.selectedCandidate == nil)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 候选行：单选 + 文件名 + 大小/时间 + 「新」/「已导入过」徽标。
    private func candidateRow(_ candidate: DropzoneCandidate) -> some View {
        Button {
            importModel.selectedCandidate = candidate.url
        } label: {
            HStack(spacing: 8) {
                Image(systemName: importModel.selectedCandidate == candidate.url ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(importModel.selectedCandidate == candidate.url ? Color.accentColor : Color.secondary)
                Text(candidate.url.lastPathComponent)
                    .font(.callout)
                    .lineLimit(1)
                Text(importModel.fileMeta(candidate.url))
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
                    .fill(importModel.selectedCandidate == candidate.url ? Color.accentColor.opacity(0.12) : Color.clear)
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

    /// 忽略所选（W-6）：落「已忽略指纹」（名+大小+mtime），该文件不再自动触发。
    private func ignoreSelected() {
        guard let sel = importModel.selectedCandidate else { return }
        importModel.ignoreFile(sel)
    }

    // MARK: - S2 预检

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
                Button("重新预检") { importModel.startPrecheck(url) }
                    .buttonStyle(.bordered)
                Spacer()
                Button("忽略此文件（不再提示）") { importModel.ignoreFile(url) }
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
            // importModel.includedLineNos 派生（D-8.4 切换即时更新，对齐「导入 N 条」
            // 按钮：三连和恒等于 N）。
            HStack(spacing: 24) {
                ImportScaffold.statLabel("新增", importModel.includedCount(in: report, of: .new))
                ImportScaffold.statLabel("重复", importModel.includedCount(in: report, of: .duplicate))
                ImportScaffold.statLabel("冲突", importModel.includedCount(in: report, of: .conflict))
            }
            .font(.callout)

            if report.isEmptyVault {
                // 空库折叠预览（docs/21 §4.3-⑦）：无分类表，单行说明 + 统计。
                Text("密码库为空，全部 \(report.validRows) 条将作为新增导入")
                    .font(.callout)
                Spacer()
            } else {
                if !importModel.duplicates(in: report).isEmpty {
                    duplicateSectionHeader(report)
                }
                if !importModel.conflicts(in: report).isEmpty {
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
                Button("返回") { importModel.backToWaiting() }
                    .buttonStyle(.bordered)
                Spacer()
                Button("导入 \(importModel.includedLineNos.count) 条") { importModel.doImport(report: report, path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(importModel.includedLineNos.isEmpty)
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
                    Button("跳过（默认）") { importModel.excludeAllDuplicates(in: report) }
                    Button("全部导入（新建不覆盖）") { importModel.includeAllDuplicates(in: report) }
                } label: {
                    Label(importModel.allDuplicatesIncluded(in: report) ? "全部导入" : "跳过", systemImage: "chevron.down")
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
        let included = importModel.includedLineNos.contains(row.lineNo)
        return Button {
            importModel.toggle(row)
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
        .accessibilityLabel(importModel.previewRowLabel(row))
    }

    // MARK: - S4 导入 / S5 结果页

    /// S5-E 导入失败（all-or-nothing 零落库）：就地错误 + 回等待 S1。
    private func importFailedBody(_ path: String, _ error: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
            Text("导入失败").font(.headline)
            Text(error).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            ImportScaffold.pathLine(path)
            Button("返回等待") { importModel.backToWaiting() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

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
            Button("返回等待") { importModel.backToWaiting() }
                .buttonStyle(.bordered)
                .controlSize(.small)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
