// ImportView.swift —— CSV 导入向导：选文件 → 预检报告 → 确认导入 → 结果。
//
// 流程（docs/07 §3）：precheck_csv 只读可反复调用 → UI 展示报告（含警告、
// 未映射列、公式前缀单元格）→ 用户确认 → import_csv 单事务 all-or-nothing
// → 结果展示 + 提示删除明文 CSV 源文件。
//
// v2.9.0 P3：脚手架收敛到共享壳 ImportWizardShell（docs/14 §A P3）。本视图
// 只提供 ImportFormatConfig + 私有报告 body + 状态机内容闭包；壳统一头部/
// 尺寸/选文件/导入中/结果页骨架与预检失败 alert。**事务语义 all-or-nothing
// 逐字保留**（importingCopy / 单事务行 / 无失败追加文案）。

import SwiftUI
import UniformTypeIdentifiers

struct ImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    enum Step {
        case pickFile
        case report(FfiCsvPrecheckReport, path: String)
        case importing
        case done(FfiCsvImportResult, path: String)
    }

    @State private var step: Step = .pickFile
    // 预检失败与导入失败共用本 alert（CSV 与其余格式不同：两路都回选文件，
    // 不经 ffiErrorAlert——保持重构前行为等价）。
    @State private var errorMessage: String?

    /// 导入事务执行中（关闭按钮此时禁用，防丢结果页）。
    private var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    /// CSV 格式配置（docs/14 §A P3 §3 逐字对照表）。
    static let importFormatConfig = ImportFormatConfig(
        // 配置字段是 String 且由 Text(config.x) / Button(config.x) 消费，Text(String)
        // 不查表（设计 24 F6）——所以译文在**产生点**取（§5.4），不在使用点。
        title: String(localized: "导入 CSV（1Password 9 列）"),
        icon: "square.and.arrow.down.on.square",
        pickTitle: String(localized: "选择从 1Password 导出的 CSV 文件"),
        pickDescription: String(localized: "支持 1Password 9 列格式（Title / Website / Username / Password /\nOne-time password / Favorite status / Archived status / Tags / Notes）"),
        pickButtonLabel: String(localized: "选择文件…"),
        windowWidth: 520, windowHeight: 460,
        // FRICT-11（AC-2.10.0-FR-3）：预检失败 alert 标题「预检失败」——与其余
        // 三格式一致，不再误用「导入失败」（预检失败时零落库，用户会误以为数据
        // 已写入一半）。
        precheckErrorAlertTitle: String(localized: "预检失败"),
        transactionSemantics: .allOrNothing,
        importingCopy: String(localized: "正在导入（单事务，全部成功或全部回滚）…"),
        failureSuffix: "",
        doneFooter: String(localized: "所有行已在单事务内写入（全部成功或全部回滚）。"),
        failureRecovery: .backToPick,
        canChooseDirectories: false,
        allowedContentTypes: [.commaSeparatedText, .plainText, .data],
        panelMessage: String(localized: "选择 1Password 导出的 CSV 文件（UTF-8）")
    )

    var body: some View {
        ImportWizardShell(
            config: Self.importFormatConfig,
            isImporting: isImporting,
            onClose: { dismiss() },
            precheckError: $errorMessage,
            onPrecheckErrorDismiss: { step = .pickFile }
        ) {
            switch step {
            case .pickFile:
                ImportScaffold.pickBody(config: Self.importFormatConfig) { pickAndPrecheck() }
            case .report(let report, let path):
                reportBody(report, path: path)
            case .importing:
                ImportScaffold.importingBody(Self.importFormatConfig.importingCopy)
            case .done(let result, let path):
                ImportScaffold.doneSkeleton(
                    count: result.importedRows,
                    doneFooter: Self.importFormatConfig.doneFooter,
                    path: path,
                    onDone: { dismiss() }
                ) {
                    // 特有内容：删源警示（明文密码源文件）
                    Label("该 CSV 含明文密码，建议导入完成后立即删除源文件。",
                          systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.leading)
                }
            }
        }
    }

    // MARK: - 选文件

    private func pickAndPrecheck() {
        let config = Self.importFormatConfig
        let panel = NSOpenPanel()
        panel.canChooseDirectories = config.canChooseDirectories
        panel.canChooseFiles = !config.canChooseDirectories
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = config.allowedContentTypes
        panel.message = config.panelMessage
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            // 预检是只读操作，同步调用即可
            let report = try sessionCall { try $0.precheckCsv(path: url.path) }
            step = .report(report, path: url.path)
        } catch {
            errorMessage = ErrorPresenter.text(error)
        }
    }

    // MARK: - 预检报告

    private func reportBody(_ report: FfiCsvPrecheckReport, path: String) -> some View {
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
                        ImportScaffold.statLabel("数据行", report.totalRows)
                        ImportScaffold.statLabel("可导入", report.validRows)
                        ImportScaffold.statLabel("跳过空行", report.skippedRows.count)
                    }
                    .font(.callout)

                    if !report.rowsWithoutTitle.isEmpty {
                        reportLine(String(localized: "缺标题行（将以「（无标题）」导入）："), report.rowsWithoutTitle)
                    }
                    if !report.rowsWithBadTotp.isEmpty {
                        reportLine(String(localized: "otpauth 解析失败行（值并入备注，不丢数据）："), report.rowsWithBadTotp)
                    }
                    if !report.unmappedColumns.isEmpty {
                        reportLine(String(localized: "未识别列（值并入对应条目备注）："), report.unmappedColumns)
                    }
                    if !report.formulaLikeCells.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("疑似公式前缀单元格（原值保留，仅提醒）", systemImage: "exclamationmark.triangle")
                                .font(.callout)
                                .foregroundStyle(.orange)
                            // 坐标是数据、句式是文案：逐项本地化后再拼接（设计 §5.4
                            // 「拼接串改单串 + 占位符」），分隔符随生效语言。
                            Text(report.formulaLikeCells.prefix(10)
                                .map { String(format: String(localized: "行 %u｜%@"),
                                              $0.row, $0.column) }
                                .joined(separator: CopyListSeparator.semicolon))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    ForEach(report.warnings, id: \.self) { warning in
                        Label(ImportWarningText.text(for: warning), systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Button("重新选择") { step = .pickFile }
                Spacer()
                Button("导入 \(report.validRows) 条") { doImport(path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(report.validRows == 0)
            }
        }
    }

    private func reportLine<Items: Sequence>(_ prefix: String, _ items: Items) -> some View {
        // prefix 是文案（调用点已本地化），items 是数据（行号/列名）——§5.5 分界。
        Text(prefix + " " + items.map { "\($0)" }.joined(separator: CopyListSeparator.comma))
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    // MARK: - 导入

    private func doImport(path: String) {
        step = .importing
        // 导入可能较慢（大量行解密加密），放后台线程执行
        let session = model.session
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session?.importCsv(path: path)
                await MainActor.run {
                    if let result {
                        step = .done(result, path: path)
                        model.reloadItems()
                    } else {
                        errorMessage = String(localized: "会话不存在。")
                    }
                }
            } catch {
                await MainActor.run {
                    errorMessage = ErrorPresenter.text(error)
                }
            }
        }
    }

    // MARK: - 辅助

    private func sessionCall<R>(_ action: (VaultSession) throws -> R) throws -> R {
        guard let session = model.session else {
            throw FfiError.Coffer(code: 1001, message: "会话不存在")
        }
        return try action(session)
    }
}
