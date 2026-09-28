// ExportView.swift —— 导出向导：加密备份（FR-8.1/8.6）+ CSV 明文（FR-8.3/8.4）。
//
// 双入口 segmented Picker：
//   - 加密备份：NSSavePanel 选路径 → 确认页（UI 义务，docs/09
//     §3.1：必须告知「加密归档非明文，但可被暴力破解」）→ 导出 → 结果页。
//   - CSV 明文（T-F）：NSSavePanel 选路径 → 强风险页 → 二次确认 →
//     导出 → 结果页（FR-8.4 / TC-UI-08 / TC-UI-09）。
//
// CSV 双门禁（内核不提供确认门禁，D-11：UI 是唯一防线）：
//   ① 强风险页勾选框「我已知晓风险」——未勾选导出按钮 disabled；
//   ② confirmationDialog 二次确认——仅「确认导出」才调用 exportCsv。
//   未走完双门禁不存在任何调用路径（TC-UI-08 负向验收）。
//   勾选框在流程重置（取消 / 回退 / 出错）时清零，防勾选残留一键通过。
// 底层契约（TC-EXP-08）：exportBackup 挂在 CofferApp 工厂级（非 session），
// 锁定态亦可用；UI 入口放在解锁后的主界面仅是产品选择，不构成门禁。
// Rust 侧导出成功自动打点 meta.last_backup_at，并自动执行一次结构校验
// （FR-8.6）——结果页 verified=false 必须按失败呈现，不得只展示成功数字。
//
// 错误呈现：2003（目标不可写等导出失败）/ 1012 / 5002 经 ErrorPresenter
// 直出 → lastErrorMessage → .ffiErrorAlert（与全仓一致）。
//
// v0.2.0 出口判据①②（docs/09-v0.2实现方案 §3.1）：加密备份导出可用 +
// 备份提醒可触发（提醒评估已接入，T-G：仅备份流导出成功时重评估——
// CSV 导出不打点 last_backup_at，不消横幅）。

import SwiftUI
import UniformTypeIdentifiers

struct ExportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 顶部双入口。
    enum Tab {
        case encrypted
        case csv
    }

    enum Step {
        case pickPath
        case confirm(path: String)
        case exporting
        case done(FfiBackupExportResult)
    }

    /// CSV 明文流状态机（与备份流平行，互不干扰）。
    enum CsvStep {
        case pickPath
        /// 强风险页（双门禁①：勾选框）
        case riskConfirm(path: String)
        case exporting
        case done(FfiCsvExportResult)
    }

    @State private var tab: Tab = .encrypted
    @State private var step: Step = .pickPath

    @State private var csvStep: CsvStep = .pickPath
    /// 双门禁①：风险确认勾选框；流程重置时必须清零
    @State private var csvRiskAcknowledged = false
    /// 双门禁②：confirmationDialog 是否弹出
    @State private var csvShowFinalConfirm = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导出").font(.headline)
                Spacer()
                Picker("", selection: $tab) {
                    Text("加密备份").tag(Tab.encrypted)
                    Text("CSV 明文").tag(Tab.csv)
                }
                .pickerStyle(.segmented)
                .frame(width: 220)
            }
            .padding()

            Divider()

            Group {
                switch tab {
                case .encrypted:
                    switch step {
                    case .pickPath:
                        pickPathBody
                    case .confirm(let path):
                        confirmBody(path: path)
                    case .exporting:
                        exportingBody
                    case .done(let result):
                        doneBody(result)
                    }
                case .csv:
                    switch csvStep {
                    case .pickPath:
                        csvPickPathBody
                    case .riskConfirm(let path):
                        csvRiskConfirmBody(path: path)
                    case .exporting:
                        csvExportingBody
                    case .done(let result):
                        csvDoneBody(result)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 520, height: 420)
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - ① 选路径

    private var pickPathBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "arrow.up.doc")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("将密码库导出为加密备份文件")
                .font(.callout)
            Text("备份是整个库的加密归档，可用于跨设备迁移与灾后恢复。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择导出位置…") { pickPath() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickPath() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = suggestedFileName()
        panel.message = "选择加密备份文件的保存位置"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        step = .confirm(path: url.path)
    }

    /// 建议文件名：Coffer备份-<库名>-<yyyyMMdd>.coffer；库名取不到用固定前缀。
    private func suggestedFileName() -> String {
        let formatter = DateFormatter()
        // 固定 en_US_POSIX：文件名时间戳不受用户日历（佛历/和历等）与数字
        // locale 影响，保证跨环境生成的文件名稳定可读。
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd"
        let stamp = formatter.string(from: Date())
        if model.vaultName.isEmpty {
            return "Coffer备份-\(stamp).coffer"
        }
        return "Coffer备份-\(model.vaultName)-\(stamp).coffer"
    }

    // MARK: - ② 确认页（UI 义务，docs/09 §3.1）

    private func confirmBody(path: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("确认导出").font(.headline)
            Text(URL(fileURLWithPath: path).path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            Label("备份文件为加密归档，非明文，但可被暴力破解，请妥善保管。",
                  systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
            Spacer()
            HStack {
                Button("取消") { step = .pickPath }
                Spacer()
                Button("导出到所选位置") { doExport(path: path) }
                    .buttonStyle(.borderedProminent)
                    // 与上方橙色警示同风格：导出是需谨慎确认的动作
                    .tint(.orange)
                    .disabled(model.isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - ③ 导出中

    private var exportingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在导出加密备份…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 导出（工厂级调用，TC-EXP-08；全库打包可能较慢，放后台线程执行）。
    private func doExport(path: String) {
        guard !model.isBusy else { return }
        step = .exporting
        let factory = model.factory
        let vaultDir = model.baseDir.path
        Task.detached(priority: .userInitiated) {
            do {
                let result = try factory.exportBackup(vaultDir: vaultDir, outPath: path)
                await MainActor.run {
                    step = .done(result)
                    // 备份提醒重评估（FR-8.5，T-G）：Rust 在 exportBackup
                    // 成功路径已打点 meta.last_backup_at，重算后横幅自然消失
                    // （距上次备份不再超期 → shouldSuggestBackup 返回 false）。
                    // 仅备份流接入：CSV 导出不打点 last_backup_at，不应消横幅。
                    model.evaluateBackupReminder()
                }
            } catch {
                await MainActor.run {
                    // 2003 / 1012 / 5002 等经 ErrorPresenter 直出；
                    // 回到选路径页可重试
                    step = .pickPath
                    model.lastErrorMessage = ErrorPresenter.text(error)
                }
            }
        }
    }

    // MARK: - ④ 结果页

    private func doneBody(_ result: FfiBackupExportResult) -> some View {
        VStack(spacing: 16) {
            if result.verified {
                Image(systemName: "checkmark.circle")
                    .font(.system(size: 44))
                    .foregroundStyle(.green)
                Text("导出完成").font(.headline)
            } else {
                // verified=false 按失败呈现（FR-8.6 自检未通过），不得只展示数字
                Image(systemName: "xmark.octagon")
                    .font(.system(size: 44))
                    .foregroundStyle(.red)
                Text("导出后自检未通过").font(.headline)
                Label("备份文件可能不完整或已损坏，请勿依赖该文件，建议重新导出到其他位置。",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.leading)
            }

            HStack(spacing: 24) {
                statLabel("文件数", "\(result.fileCount)")
                statLabel("大小", formatBytes(result.sizeBytes))
            }
            .font(.callout)

            Text(result.filePath)
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

    private func statLabel(_ title: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - CSV 明文（FR-8.3/8.4，T-F）

    // MARK: CSV ① 选路径

    private var csvPickPathBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.plaintext")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("将密码库导出为 CSV 明文文件")
                .font(.callout)
            Text("所有条目（含密码、TOTP 密钥）将以不加密的 CSV 写入磁盘。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择导出位置…") { pickCsvPath() }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickCsvPath() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = suggestedCsvFileName()
        panel.message = "选择 CSV 明文文件的保存位置"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        csvRiskAcknowledged = false
        csvStep = .riskConfirm(path: url.path)
    }

    /// 建议文件名：Coffer导出-<库名>-<yyyyMMdd>.csv；库名取不到用固定前缀。
    private func suggestedCsvFileName() -> String {
        let formatter = DateFormatter()
        // 固定 en_US_POSIX：同备份流纪律，文件名时间戳不受用户日历与
        // 数字 locale 影响，保证跨环境生成的文件名稳定可读。
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd"
        let stamp = formatter.string(from: Date())
        if model.vaultName.isEmpty {
            return "Coffer导出-\(stamp).csv"
        }
        return "Coffer导出-\(model.vaultName)-\(stamp).csv"
    }

    // MARK: CSV ② 强风险页（双门禁①：勾选框）

    private func csvRiskConfirmBody(path: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("高风险操作").font(.headline)
            Text(URL(fileURLWithPath: path).path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            // FR-8.4：必须明示「导出文件为明文，包含全部密码」
            Label("导出文件为明文，包含全部密码。",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout.bold())
                .foregroundStyle(.red)
            Text("所有条目（含密码、TOTP 密钥）将以不加密的 CSV 写入磁盘，任何能读取该文件的程序或人都能获取全部凭据。")
                .font(.callout)
                .foregroundStyle(.orange)
                .multilineTextAlignment(.leading)
            Toggle(isOn: $csvRiskAcknowledged) {
                Text("我已知晓风险，确认导出明文文件")
                    .font(.callout)
            }
            Spacer()
            HStack {
                Button("取消") { csvResetToPickPath() }
                Spacer()
                Button("导出明文文件") {
                    // 双门禁②：勾选通过后才弹二次确认
                    csvShowFinalConfirm = true
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                // 未勾选时导出按钮 disabled（TC-UI-08 门禁①）
                .disabled(!csvRiskAcknowledged || model.isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // 双门禁②：仅「确认导出」才执行；取消留在本页
        .confirmationDialog(
            "再次确认：写出明文 CSV？",
            isPresented: $csvShowFinalConfirm,
            titleVisibility: .visible
        ) {
            Button("确认导出", role: .destructive) { doCsvExport(path: path) }
            Button("取消", role: .cancel) {}
        }
    }

    // MARK: CSV ③ 导出中

    private var csvExportingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在导出 CSV 明文…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// CSV 导出（session 级调用，需解锁态：锁定态返回 1001；错误 2003 导出失败）。
    /// 唯一调用点：双门禁①勾选 + ②confirmationDialog「确认导出」之后（TC-UI-08）。
    private func doCsvExport(path: String) {
        guard let session = model.session, !model.isBusy else { return }
        csvStep = .exporting
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session.exportCsv(outPath: path)
                await MainActor.run {
                    csvStep = .done(result)
                }
            } catch {
                await MainActor.run {
                    // 1001（锁定态）/ 2003（导出失败）等经 ErrorPresenter 直出；
                    // 回到选路径页可重试（勾选框一并重置）
                    csvResetToPickPath()
                    model.lastErrorMessage = ErrorPresenter.text(error)
                }
            }
        }
    }

    // MARK: CSV ④ 结果页（TC-UI-09）

    private func csvDoneBody(_ result: FfiCsvExportResult) -> some View {
        VStack(spacing: 16) {
            // 固定警示：CSV 已落盘为明文，用完即删（TC-UI-09）
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导出完成").font(.headline)
            Label("导出文件为明文，包含全部密码，请立即删除源明文文件。",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout.bold())
                .foregroundStyle(.red)
                .multilineTextAlignment(.leading)

            HStack(spacing: 24) {
                statLabel("写入条数", "\(result.rowCount)")
                statLabel("回收站跳过", "\(result.skippedTrashed)")
            }
            .font(.callout)

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

    /// CSV 流程重置：回选路径页并清零勾选框——防「上次勾选残留导致
    /// 下次一键通过」（TC-UI-08）。
    private func csvResetToPickPath() {
        csvRiskAcknowledged = false
        csvShowFinalConfirm = false
        csvStep = .pickPath
    }

    // MARK: - 辅助

    /// 字节数人类可读格式化（B / KB / MB / GB）。
    private func formatBytes(_ bytes: UInt64) -> String {
        let kb: Double = 1024
        let value = Double(bytes)
        if value < kb { return "\(bytes) B" }
        if value < kb * kb { return String(format: "%.1f KB", value / kb) }
        if value < kb * kb * kb { return String(format: "%.1f MB", value / (kb * kb)) }
        return String(format: "%.2f GB", value / (kb * kb * kb))
    }
}
