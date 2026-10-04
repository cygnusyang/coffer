// ExportView.swift —— 导出向导：加密备份（FR-8.1/8.6）+ CSV 明文（FR-8.3/8.4）
// + 1PUX 明文（FR-8.2/8.4，v0.7.0-T06）。
//
// 三入口 segmented Picker：
//   - 加密备份：NSSavePanel 选路径 → 确认页（UI 义务，docs/09
//     §3.1：必须告知「加密归档非明文，但可被暴力破解」）→ 导出 → 结果页。
//   - CSV 明文（T-F）：NSSavePanel 选路径 → 强风险页 → 二次确认 →
//     导出 → 结果页（FR-8.4 / TC-UI-08 / TC-UI-09）。
//   - 1PUX 明文（T06）：NSSavePanel 选路径 → 强风险页 → 二次确认 →
//     导出 → 结果页（FR-8.2 官方 v3 结构；FR-8.4 明文二次确认适用，
//     docs/22 §2.1.5 裁决 E——1PUX export.data 为解密后的明文 JSON，
//     含全部密码/TOTP secret，与 CSV 同纪律走双门禁）。
//
// CSV / 1PUX 双门禁（内核不提供确认门禁，D-11：UI 是唯一防线）：
//   ① 强风险页勾选框「我已知晓风险」——未勾选导出按钮 disabled；
//   ② confirmationDialog 二次确认——仅「确认导出」才调用 exportCsv /
//     exportOnePux。
//   未走完双门禁不存在任何调用路径（TC-UI-08 负向验收；TC-EXP-16 同纪律）。
//   勾选框在流程重置（取消 / 回退 / 出错）时清零，防勾选残留一键通过。
// 1PUX 导出范围（docs/22 §2.1.7）：Active + Archived 导出，回收站条目不
// 导出（skipped_trashed 计数）；passkey 无桌面 1PUX 承载形态不导出
// （skipped_passkeys 计数，结果页提示用加密备份迁移，§2.1.3）；未知
// FieldType 降级 Text 并入 report.degraded_fields（不静默，§2.1.7）。
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

    /// 顶部三入口。
    enum Tab {
        case encrypted
        case csv
        case pux
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

    /// 1PUX 明文流状态机（与备份/CSV 流平行，互不干扰；FR-8.2，T06）。
    enum PuxStep {
        case pickPath
        /// 强风险页（双门禁①：勾选框）
        case riskConfirm(path: String)
        case exporting
        case done(FfiPuxExportResult)
    }

    @State private var tab: Tab = .encrypted
    @State private var step: Step = .pickPath

    @State private var csvStep: CsvStep = .pickPath
    /// 双门禁①：风险确认勾选框；流程重置时必须清零
    @State private var csvRiskAcknowledged = false
    /// 双门禁②：confirmationDialog 是否弹出
    @State private var csvShowFinalConfirm = false

    @State private var puxStep: PuxStep = .pickPath
    /// 双门禁①：1PUX 风险确认勾选框；流程重置时必须清零（同 CSV 纪律）
    @State private var puxRiskAcknowledged = false
    /// 双门禁②：1PUX confirmationDialog 是否弹出
    @State private var puxShowFinalConfirm = false

    /// 任一导出流执行中（关闭按钮此时禁用，防丢结果页）。
    private var isAnyExporting: Bool {
        if case .exporting = step { return true }
        if case .exporting = csvStep { return true }
        if case .exporting = puxStep { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导出").font(.headline)
                Picker("", selection: $tab) {
                    Text("加密备份").tag(Tab.encrypted)
                    Text("CSV 明文").tag(Tab.csv)
                    Text("1PUX 明文").tag(Tab.pux)
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
                Spacer()
                // 显式关闭出口（BUG-5 同类修复：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效）。导出执行中禁用（结果页会丢，任务
                // 本身不受影响；备份/CSV 均为写目标文件，无中断损坏面）。
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isAnyExporting)
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
                case .pux:
                    switch puxStep {
                    case .pickPath:
                        puxPickPathBody
                    case .riskConfirm(let path):
                        puxRiskConfirmBody(path: path)
                    case .exporting:
                        puxExportingBody
                    case .done(let result):
                        puxDoneBody(result)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 540, height: 460)
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
        let vaultDir = model.vaultDirPath
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

    // MARK: - 1PUX 明文（FR-8.2/8.4，v0.7.0-T06）

    // MARK: 1PUX ① 选路径

    private var puxPickPathBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.text")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("将密码库导出为 1Password 1PUX 明文文件")
                .font(.callout)
            Text("1PUX 是 1Password 官方导出格式，本文件为不加密的明文归档，\n包含全部密码与 TOTP 密钥。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择导出位置…") { pickPuxPath() }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickPuxPath() {
        let panel = NSSavePanel()
        // 1PUX 本质是 ZIP 归档：与加密备份流同用通用 .data 兜底，避免
        // 系统按 content type 追加/替换扩展名——.1pux 非注册 UTType
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = suggestedPuxFileName()
        panel.message = "选择 1PUX 明文文件的保存位置"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        puxRiskAcknowledged = false
        puxStep = .riskConfirm(path: url.path)
    }

    /// 建议文件名：Coffer导出-<库名>-<yyyyMMdd>.1pux；库名取不到用固定前缀。
    private func suggestedPuxFileName() -> String {
        let formatter = DateFormatter()
        // 固定 en_US_POSIX：同备份/CSV 流纪律，文件名时间戳不受用户日历
        // 与数字 locale 影响，保证跨环境生成的文件名稳定可读。
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd"
        let stamp = formatter.string(from: Date())
        if model.vaultName.isEmpty {
            return "Coffer导出-\(stamp).1pux"
        }
        return "Coffer导出-\(model.vaultName)-\(stamp).1pux"
    }

    // MARK: 1PUX ② 强风险页（双门禁①：勾选框；TC-EXP-16）

    private func puxRiskConfirmBody(path: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("高风险操作").font(.headline)
            Text(URL(fileURLWithPath: path).path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            // FR-8.4（裁决 E，docs/22 §2.1.5）：1PUX export.data 为解密后的
            // 明文 JSON，含全部密码/TOTP secret——必须明示明文风险
            Label("导出文件为明文，包含全部密码。",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout.bold())
                .foregroundStyle(.red)
            Text("1PUX 归档为明文 JSON，包含全部密码、TOTP 密钥与附件，任何能读取该文件的程序或人都能获取全部凭据。")
                .font(.callout)
                .foregroundStyle(.orange)
                .multilineTextAlignment(.leading)
            Toggle(isOn: $puxRiskAcknowledged) {
                Text("我已知晓风险，确认导出明文文件")
                    .font(.callout)
            }
            Spacer()
            HStack {
                Button("取消") { puxResetToPickPath() }
                Spacer()
                Button("导出明文文件") {
                    // 双门禁②：勾选通过后才弹二次确认
                    puxShowFinalConfirm = true
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                // 未勾选时导出按钮 disabled（双门禁①）
                .disabled(!puxRiskAcknowledged || model.isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // 双门禁②：仅「确认导出」才执行；取消留在本页
        .confirmationDialog(
            "再次确认：写出明文 1PUX？",
            isPresented: $puxShowFinalConfirm,
            titleVisibility: .visible
        ) {
            Button("确认导出", role: .destructive) { doPuxExport(path: path) }
            Button("取消", role: .cancel) {}
        }
    }

    // MARK: 1PUX ③ 导出中

    private var puxExportingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在导出 1PUX 明文…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 1PUX 导出（session 级调用，需解锁态：锁定态返回 1001；错误 2003
    /// 导出失败 / 6002/6003 只读拒绝，TC-EXP-09/10/11——经 ErrorPresenter
    /// 直出，走既有 6004 风格范式）。
    /// 唯一调用点：双门禁①勾选 + ②confirmationDialog「确认导出」之后。
    private func doPuxExport(path: String) {
        guard let session = model.session, !model.isBusy else { return }
        puxStep = .exporting
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session.exportOnePux(outPath: path)
                await MainActor.run {
                    puxStep = .done(result)
                }
            } catch {
                await MainActor.run {
                    // 1001（锁定态）/ 2003（导出失败）/ 6002/6003（只读拒绝）
                    // 经 ErrorPresenter 直出；回到选路径页可重试（勾选框一并重置）
                    puxResetToPickPath()
                    model.lastErrorMessage = ErrorPresenter.text(error)
                }
            }
        }
    }

    // MARK: 1PUX ④ 结果页（TC-EXP-16 / TC-EXP-17 诚实边界）

    private func puxDoneBody(_ result: FfiPuxExportResult) -> some View {
        VStack(spacing: 14) {
            // 固定警示：1PUX 已落盘为明文，用完即删（同 CSV 纪律）
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导出完成").font(.headline)
            Label("导出文件为明文，包含全部密码，请立即删除源明文文件。",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.callout.bold())
                .foregroundStyle(.red)
                .multilineTextAlignment(.leading)

            HStack(spacing: 20) {
                statLabel("写入条数", "\(result.itemCount)")
                statLabel("附件", "\(result.attachmentCount)")
                statLabel("回收站跳过", "\(result.skippedTrashed)")
                statLabel("Passkey 跳过", "\(result.skippedPasskeys)")
            }
            .font(.callout)

            VStack(alignment: .leading, spacing: 6) {
                // Passkey 不随 1PUX 导出（docs/22 §2.1.3 裁决 C）：显式提示
                // 用加密备份迁移，不静默（skipped_passkeys 计数）
                if result.skippedPasskeys > 0 {
                    Label("Passkey 不随 1PUX 导出，请用加密备份迁移。",
                          systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.leading)
                }
                // 非 SHA-1 TOTP（docs/22 §2.1.4 裁决 D）：报告注明回环降级，
                // 第三方工具按 URI algorithm 参数解读不受影响（不静默）
                if result.report.nonSha1Totp > 0 {
                    Text("非 SHA-1 TOTP \(result.report.nonSha1Totp) 个：经本仓回环按 SHA-1 降级，第三方工具按其算法参数解读不受影响。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
                // 未知 FieldType 降级 Text（docs/22 §2.1.7）：逐项列出不静默
                if !result.report.degradedFields.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("降级为文本的字段 \(result.report.degradedFields.count) 个（无 1P 承载码）：")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(result.report.degradedFields.prefix(5).joined(separator: "、"))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .lineLimit(2)
                        if result.report.degradedFields.count > 5 {
                            Text("等 \(result.report.degradedFields.count) 个")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

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

    /// 1PUX 流程重置：回选路径页并清零勾选框——防「上次勾选残留导致
    /// 下次一键通过」（TC-EXP-16 双门禁①同 CSV 纪律）。
    private func puxResetToPickPath() {
        puxRiskAcknowledged = false
        puxShowFinalConfirm = false
        puxStep = .pickPath
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
