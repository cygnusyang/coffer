// ExportView.swift —— 导出向导：加密备份（FR-8.1/8.6）+ CSV 明文占位（T-F）。
//
// 双入口 segmented Picker：
//   - 加密备份（本任务）：NSSavePanel 选路径 → 确认页（UI 义务，docs/09
//     §3.1：必须告知「加密归档非明文，但可被暴力破解」）→ 导出 → 结果页。
//   - CSV 明文：占位（T-F 接入），本文件不实现任何 CSV 导出逻辑。
//
// 底层契约（TC-EXP-08）：exportBackup 挂在 CofferApp 工厂级（非 session），
// 锁定态亦可用；UI 入口放在解锁后的主界面仅是产品选择，不构成门禁。
// Rust 侧导出成功自动打点 meta.last_backup_at，并自动执行一次结构校验
// （FR-8.6）——结果页 verified=false 必须按失败呈现，不得只展示成功数字。
//
// 错误呈现：2003（目标不可写等导出失败）/ 1012 / 5002 经 ErrorPresenter
// 直出 → lastErrorMessage → .ffiErrorAlert（与全仓一致）。
//
// v0.2.0 出口判据①②（docs/09-v0.2实现方案 §3.1）：加密备份导出可用 +
// 备份提醒可触发（提醒评估 T-G 接入，本文件留调用点注释）。

import SwiftUI
import UniformTypeIdentifiers

struct ExportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 顶部双入口（CSV 明文 tab 为 T-F 占位）。
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

    @State private var tab: Tab = .encrypted
    @State private var step: Step = .pickPath

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
                    // T-F 接入 CSV 明文导出流程（FR-8.x），本任务不做任何实现
                    csvPlaceholderBody
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
                    // T-G 接入：此处调用备份提醒评估（evaluateBackupReminder），
                    // 基于新的 meta.last_backup_at 重算下次提醒时点
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

    // MARK: - CSV 明文占位（T-F）

    private var csvPlaceholderBody: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.plaintext")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("CSV 明文导出尚未开放（T-F 接入）。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
