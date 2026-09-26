// ImportView.swift —— CSV 导入向导：选文件 → 预检报告 → 确认导入 → 结果。
//
// 流程（docs/07 §3）：precheck_csv 只读可反复调用 → UI 展示报告（含警告、
// 未映射列、公式前缀单元格）→ 用户确认 → import_csv 单事务 all-or-nothing
// → 结果展示 + 提示删除明文 CSV 源文件。

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
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导入 CSV（1Password 9 列）").font(.headline)
                Spacer()
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
                    VStack(spacing: 12) {
                        ProgressView()
                        Text("正在导入（单事务，全部成功或全部回滚）…")
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                case .done(let result, let path):
                    doneBody(result, path: path)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 520, height: 460)
        .alert("导入失败", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("好", role: .cancel) { step = .pickFile }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    // MARK: - 选文件

    private var pickFileBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "square.and.arrow.down.on.square")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("选择从 1Password 导出的 CSV 文件")
                .font(.callout)
            Text("支持 1Password 9 列格式（Title / Website / Username / Password /\nOne-time password / Favorite status / Archived status / Tags / Notes）")
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
        panel.allowedContentTypes = [.commaSeparatedText, .plainText, .data]
        panel.message = "选择 1Password 导出的 CSV 文件（UTF-8）"
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
                        statLabel("数据行", report.totalRows)
                        statLabel("可导入", report.validRows)
                        statLabel("跳过空行", report.skippedRows.count)
                    }
                    .font(.callout)

                    if !report.rowsWithoutTitle.isEmpty {
                        reportLine("缺标题行（将以「（无标题）」导入）：", report.rowsWithoutTitle)
                    }
                    if !report.rowsWithBadTotp.isEmpty {
                        reportLine("otpauth 解析失败行（值并入备注，不丢数据）：", report.rowsWithBadTotp)
                    }
                    if !report.unmappedColumns.isEmpty {
                        reportLine("未识别列（值并入对应条目备注）：", report.unmappedColumns)
                    }
                    if !report.formulaLikeCells.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("疑似公式前缀单元格（原值保留，仅提醒）", systemImage: "exclamationmark.triangle")
                                .font(.callout)
                                .foregroundStyle(.orange)
                            Text(report.formulaLikeCells.prefix(10).map { "行 \($0.row)｜\($0.column)" }
                                .joined(separator: "；"))
                                .font(.caption)
                                .foregroundStyle(.secondary)
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
                Button("导入 \(report.validRows) 条") { doImport(path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(report.validRows == 0)
            }
        }
    }

    private func statLabel(_ title: String, _ count: UInt32) -> some View {
        VStack(spacing: 2) {
            Text("\(count)").font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func statLabel(_ title: String, _ count: Int) -> some View {
        statLabel(title, UInt32(max(0, count)))
    }

    private func reportLine<Items: Sequence>(_ prefix: String, _ items: Items) -> some View {
        Text(prefix + " " + items.map { "\($0)" }.joined(separator: "、"))
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
                        errorMessage = "会话不存在。"
                    }
                }
            } catch {
                await MainActor.run {
                    errorMessage = ErrorPresenter.text(error)
                }
            }
        }
    }

    // MARK: - 结果

    private func doneBody(_ result: FfiCsvImportResult, path: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导入完成：新建 \(result.importedRows) 条条目")
                .font(.headline)
            Text("所有行已在单事务内写入（全部成功或全部回滚）。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Label("该 CSV 含明文密码，建议导入完成后立即删除源文件。", systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
                .multilineTextAlignment(.leading)
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
