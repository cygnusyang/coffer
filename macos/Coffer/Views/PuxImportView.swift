// PuxImportView.swift —— 1PUX 导入向导：选文件 → 预检报告 → 确认导入 → 结果。
//
// 流程（FR-7.1 / 7.4~7.8）：precheck1pux 只读且无解锁门禁（锁定态可预检，
// 但 UI 入口在解锁区——菜单/工具栏均 .disabled(phase != .unlocked)）→
// UI 展示报告 → 用户确认 → import1pux（Rust 1001 门禁，需解锁态）→
// 结果展示 + FR-7.8 数据驱动删源提示（D-6：只提示不代办，绝不提供删除按钮）。
//
// 与 CSV 导入的关键语义差异（文案必须如实）：
//   - 1PUX 导入是**每条目独立事务**——中途失败时已导入条目保留
//     （与 CSV import_csv 单事务 all-or-nothing 相反）。因此导入失败的
//     错误提示必须告知「部分条目可能已导入，重试将重复新建」。
//   - 删源建议 deletionAdvice 由内核对本次导入报告即时组装（D-6），
//     canDelete=true 仅表示零信息损失；是否删源由用户自行决定。

import SwiftUI
import UniformTypeIdentifiers

struct PuxImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    enum Step {
        case pickFile
        case report(FfiPuxPrecheckReport, path: String)
        case importing
        case done(FfiPuxImportResult, path: String)
    }

    @State private var step: Step = .pickFile

    /// 导入失败的错误文案（经 lastErrorMessage → .ffiErrorAlert 呈现）。
    /// 预检失败（未发生任何导入）用本地 alert，回 pickFile 可重试。
    @State private var precheckError: String?

    /// 最近一次预检成功的报告与路径：导入失败后回 report 页重试需要
    /// 重建 .report 状态（每条目独立事务，部分导入已发生，如实呈现）。
    @State private var lastReport: FfiPuxPrecheckReport?
    @State private var lastPath: String?

    /// 导入执行中（关闭按钮此时禁用，防丢结果页；已导入条目不受影响，
    /// 但中途关 sheet 会丢失结果页与删源提示）。
    private var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    /// FR-7.7 抽样核对数据：导入后全量条目随机抽出的样本与总数。
    /// 只保留 title/category 等非敏感字段展示（FR-12.3 类比延伸：
    /// 抽样核对不展示密码/备注正文）；拉取失败保持空 → 结果页静默隐藏。
    @State private var sampledItems: [FfiItemSummary] = []
    @State private var sampledTotalCount: UInt32 = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导入 1Password（.1pux）").font(.headline)
                Spacer()
                // 显式关闭出口（BUG-5 同类修复：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效）。导入执行中禁用——非 all-or-nothing，
                // 中途关 sheet 丢结果页与删源提示，用户无从判断已导入多少。
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isImporting)
            }
            .padding()

            Divider()

            Group {
                switch step {
                case .pickFile:
                    pickFileBody
                case .report(let report, let path):
                    reportBody(report, path: path)
                case .importing:
                    importingBody
                case .done(let result, let path):
                    doneBody(result, path: path)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 560, height: 520)
        .alert("预检失败", isPresented: Binding(
            get: { precheckError != nil },
            set: { if !$0 { precheckError = nil } }
        )) {
            Button("好", role: .cancel) { step = .pickFile }
        } message: {
            Text(precheckError ?? "")
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 选文件

    private var pickFileBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "shippingbox")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("选择 1Password 导出的 .1pux 文件")
                .font(.callout)
            Text("1PUX 是 1Password 官方导出格式（ZIP 归档），导入为每条目独立事务。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择文件…") { pickAndPrecheck() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickAndPrecheck() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        // 1PUX 本质是 ZIP 归档：接受 zip，兜底 .data（与 CSV 流的
        // [.commaSeparatedText, .plainText, .data] 同一兜底策略）
        panel.allowedContentTypes = [.zip, .data]
        panel.message = "选择 1Password 导出的 .1pux 文件"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            // 预检是只读操作且无解锁门禁（锁定态亦可预检），同步调用即可
            let report = try sessionCall { try $0.precheck1pux(path: url.path) }
            lastReport = report
            lastPath = url.path
            step = .report(report, path: url.path)
        } catch {
            precheckError = ErrorPresenter.text(error)
        }
    }

    // MARK: - 预检报告（FR-7.4~7.6）

    private func reportBody(_ report: FfiPuxPrecheckReport, path: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("预检报告").font(.headline)
                Spacer()
                Text(URL(fileURLWithPath: path).lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 24) {
                        statLabel("总条目", report.totalItems)
                        statLabel("可导入", report.importableItems)
                        statLabel("附件数", report.attachmentCount)
                    }
                    .font(.callout)

                    // 条件计数行：为 0 不展示，避免噪音
                    if report.trashedCount > 0 {
                        Text("回收站 \(report.trashedCount) 条")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if report.passwordHistoryDropped > 0 {
                        Text("丢弃密码历史 \(report.passwordHistoryDropped) 条")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    // 类别分布：count 降序取前 5 行，溢出显示「等 M 类」
                    let distribution = report.categoryDistribution
                        .sorted { $0.count > $1.count }
                    if !distribution.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(distribution.prefix(5), id: \.category) { entry in
                                Text("\(entry.category) \(entry.count)")
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.secondary)
                            }
                            if distribution.count > 5 {
                                Text("等 \(distribution.count) 类")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    // 未导入项逐条列出（FR-7.6：不静默丢弃）
                    if !report.notImported.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("未导入 \(report.notImported.count) 条", systemImage: "xmark.circle")
                                .font(.callout)
                                .foregroundStyle(.orange)
                            ForEach(report.notImported, id: \.uuid) { item in
                                HStack(alignment: .top, spacing: 6) {
                                    Text(item.title)
                                        .font(.caption)
                                        .lineLimit(1)
                                    Text(String(item.uuid.suffix(8)))
                                        .font(.caption.monospacedDigit())
                                        .foregroundStyle(.tertiary)
                                    Spacer()
                                }
                                Text(item.reason)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    ForEach(report.warnings, id: \.self) { warning in
                        Label(warning, systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Button("重新选择") { step = .pickFile }
                Spacer()
                Button("导入 \(report.importableItems) 条") { doImport(path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(report.importableItems == 0)
            }
        }
    }

    private func statLabel(_ title: String, _ count: UInt32) -> some View {
        VStack(spacing: 2) {
            Text("\(count)").font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - 导入

    private var importingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            // 如实反映非 all-or-nothing：每条目独立事务，已完成的条目保留
            Text("正在导入（每条目独立事务，已完成的条目保留）…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 导入（需解锁态：锁定态 Rust 返回 1001；写路径 + 附件落盘较慢，
    /// Task.detached 包裹）。失败后回 report 页可重试——但部分导入已
    /// 发生，错误文案必须提示重试将重复新建（内核语义，如实呈现）。
    private func doImport(path: String) {
        step = .importing
        let session = model.session
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session?.import1pux(path: path)

                // FR-7.7 抽样数据：导入为全部新建，导入后全量列表即本次产物。
                // 同 detached 上下文拉取（随 import1pux 的慢路径，不阻塞主线程），
                // Swift 侧随机抽 min(5, count) 条。失败仅记 DiagLog 静默隐藏
                // 抽样区——抽样只是核对辅助，不影响导入成功结论。
                var sampled: [FfiItemSummary] = []
                var totalCount: UInt32 = 0
                if let result, result.importedItems > 0, let session {
                    do {
                        let all = try session.listItems(
                            filter: FfiItemFilter(
                                state: .active, category: nil, offset: nil, limit: nil)
                        )
                        totalCount = UInt32(all.count)
                        sampled = Array(all.shuffled().prefix(min(5, all.count)))
                    } catch {
                        DiagLog.append("1PUX 导入后抽样拉取失败：\(ErrorPresenter.text(error))")
                    }
                }
                // 固化为不可变值再捕获进 MainActor 闭包（Swift 6 并发纪律：
                // 不跨并发域捕获可变 var）
                let finalSampled = sampled
                let finalTotalCount = totalCount

                await MainActor.run {
                    if let result {
                        sampledItems = finalSampled
                        sampledTotalCount = finalTotalCount
                        step = .done(result, path: path)
                        model.reloadItems()
                    } else {
                        // 会话缺失（理论不可达：入口在解锁区）；无导入发生，
                        // 无部分导入提示的必要，回报告页即可
                        step = .report(lastReport ?? FfiPuxPrecheckReport(
                            totalItems: 0, importableItems: 0, categoryDistribution: [],
                            attachmentCount: 0, unknownCategories: [], trashedCount: 0,
                            passwordHistoryDropped: 0, unmappedValueTypes: [],
                            duplicateDocumentIds: [], notImported: [], warnings: []
                        ), path: lastPath ?? path)
                        model.lastErrorMessage = "会话不存在。"
                    }
                }
            } catch {
                await MainActor.run {
                    // 错误纪律：落 DiagLog（与 AppModel / 审计日志同纪律）+
                    // lastErrorMessage → .ffiErrorAlert。附加部分导入提示：
                    // 每条目独立事务，中途失败已导入条目保留，重试会重复新建。
                    DiagLog.append(ErrorPresenter.text(error))
                    model.lastErrorMessage = ErrorPresenter.text(error)
                        + "\n注意：导入为每条目独立事务，部分条目可能已导入，重试将重复新建。"
                    if let lastReport, let lastPath {
                        step = .report(lastReport, path: lastPath)
                    } else {
                        step = .pickFile
                    }
                }
            }
        }
    }

    // MARK: - 结果（FR-7.7 / FR-7.8）

    private func doneBody(_ result: FfiPuxImportResult, path: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导入完成：新建 \(result.importedItems) 条条目")
                .font(.headline)

            // FR-7.7 随机抽样核对：只展示非敏感字段（标题/类别），绝不展示
            // 密码/备注正文（FR-12.3 类比延伸）。空样本（未导入/拉取失败）
            // 静默隐藏；先核对、后决定删源（D-6 只提示不代办）。
            if !sampledItems.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("抽样核对 · 共 \(sampledTotalCount) 条，随机抽 \(sampledItems.count) 条")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(sampledItems) { item in
                        HStack(spacing: 8) {
                            Text(item.title)
                                .font(.caption)
                                .lineLimit(1)
                            Spacer()
                            Text(item.category.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text("可回到主列表核对完整内容")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }

            // FR-7.8 数据驱动删源提示（D-6）：只提示不代办，绝不提供
            // 删除按钮——是否删源由用户在访达自行决定。
            if result.deletionAdvice.canDelete {
                Label("本次导入零信息损失，可安全删除源文件",
                      systemImage: "checkmark.seal")
                    .font(.callout)
                    .foregroundStyle(.green)
                    .multilineTextAlignment(.leading)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Label("建议保留源文件", systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                    ForEach(result.deletionAdvice.blockers, id: \.self) { blocker in
                        Text("· \(blocker)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(result.deletionAdvice.degradedItems, id: \.key) { item in
                        Text("· \(item.key)：\(item.reason)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .multilineTextAlignment(.leading)
            }

            Text(URL(fileURLWithPath: path).path)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .lineLimit(2)
                .truncationMode(.middle)
            Spacer()
            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    // MARK: - 辅助

    private func sessionCall<R>(_ action: (VaultSession) throws -> R) throws -> R {
        guard let session = model.session else {
            throw FfiError.Coffer(code: 1001, message: "会话不存在")
        }
        return try action(session)
    }
}
