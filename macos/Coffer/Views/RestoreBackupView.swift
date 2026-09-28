// RestoreBackupView.swift —— 从加密备份恢复（FR-8.1 回环，docs/09 §3.7 T-H）。
//
// 流程（verifyBackup / restoreBackup 均挂 CofferApp 工厂级，恢复无需解锁态，
// 与 ExportView 的 TC-EXP-08 同契约；UI 入口在设置页⑤数据节）：
//   选文件（.coffer）→ verifyBackup 只读校验（2001 非 Coffer 包 / 1005
//   header 畸形 / 1006 版本过新；篡改包在此步检出且**不写库**）→ 确认页
//   （展示校验报告，「开始恢复」需显式确认）→ restoreBackup（1004 = 工作
//   目录已存在同 ID 库 → 专属文案；恢复当前库自身的备份必然命中 1004）→
//   完成页（「好」→ listVaults 按 vaultUuid 匹配恢复产物 → model.openSession
//   → phase = .locked —— 恢复后走 openSession + .locked 是既定设计，不新造
//   恢复向导，LockView 天然承担解锁引导；sheet 树随 MainView 拆除）。
//
// 错误呈现：与全仓一致经 ErrorPresenter → lastErrorMessage → .ffiErrorAlert；
// 错误路径落 DiagLog（与 AppModel / ChangePasswordView 同纪律）。
// 慢调用纪律：verify / restore 用 Task.detached(userInitiated) 包裹，闭包
// 只捕获局部 let（factory、路径字符串），不捕获 self 的可变状态；状态机
// 执行页无按钮，天然防双击（AppModel.isBusy 只读门禁兜底）。

import SwiftUI
import UniformTypeIdentifiers

struct RestoreBackupView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 状态机（与 ExportView / ImportView 的 enum Step 同风格）。
    enum Step {
        case pickFile
        /// 校验中（verifyBackup 只读，失败不写库）
        case verifying(path: String)
        /// 确认页（校验通过后展示报告；1004 等恢复失败回本页可重试）
        case confirm(FfiBackupVerifyReport, path: String)
        /// 恢复中
        case restoring(FfiBackupVerifyReport, path: String)
        /// 完成页（restoredDir = restoreBackup 返回的 <target>/<vault_uuid>）
        case done(FfiBackupVerifyReport, restoredDir: String)
    }

    @State private var step: Step = .pickFile
    /// 恢复产物未能在库列表中匹配（理论不可达）时的降级提示。
    @State private var showHandoffFallback = false

    /// 校验/恢复执行中（关闭按钮此时禁用，防丢结果页）。
    private var isBusyStep: Bool {
        if case .verifying = step { return true }
        if case .restoring = step { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("从备份恢复").font(.headline)
                Spacer()
                // 显式关闭出口（BUG-5 同类修复：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效）。校验/恢复执行中禁用。
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isBusyStep)
            }
            .padding()

            Divider()

            Group {
                switch step {
                case .pickFile:
                    pickFileBody
                case .verifying(let path):
                    verifyingBody(path: path)
                case .confirm(let report, let path):
                    confirmBody(report, path: path)
                case .restoring(let report, let path):
                    restoringBody(report, path: path)
                case .done(let report, let restoredDir):
                    doneBody(report, restoredDir: restoredDir)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 480, height: 360)
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("未找到恢复的库", isPresented: $showHandoffFallback) {
            // 理论不可达分支：恢复成功但枚举不到该库，只能引导重启
            Button("完成", role: .cancel) { dismiss() }
        } message: {
            Text("请重新启动应用后在新库列表中选择。")
        }
    }

    // MARK: - ① 选文件

    private var pickFileBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "arrow.down.doc")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("从加密备份文件恢复密码库")
                .font(.callout)
            Text("恢复将在工作目录中重建该库，需用该库的主密码解锁。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择备份文件…") { pickFile() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        // 与 ExportView 备份流同源：.coffer 归档无独立 UTType，用 .data 兜底
        panel.allowedContentTypes = [.data]
        panel.message = "选择加密备份文件（.coffer）"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        step = .verifying(path: url.path)
        doVerify(path: url.path)
    }

    // MARK: - ② 校验中

    private func verifyingBody(path: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在校验备份文件…")
            Text(URL(fileURLWithPath: path).lastPathComponent)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 只读校验（工厂级）：2001 / 1005 / 1006 在此检出，失败路径绝不写库。
    private func doVerify(path: String) {
        let factory = model.factory
        Task.detached(priority: .userInitiated) {
            do {
                let report = try factory.verifyBackup(backupPath: path)
                await MainActor.run {
                    step = .confirm(report, path: path)
                }
            } catch {
                let errText = ErrorPresenter.text(error)
                await MainActor.run {
                    // 回选文件页可重试（选错文件 / 包损坏均属常见入口错误）
                    step = .pickFile
                    DiagLog.append(errText)
                    model.lastErrorMessage = errText
                }
            }
        }
    }

    // MARK: - ③ 确认页

    private func confirmBody(_ report: FfiBackupVerifyReport, path: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("确认恢复").font(.headline)
            Text(URL(fileURLWithPath: path).lastPathComponent)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            HStack(spacing: 24) {
                statLabel("库 ID", maskedUuid(report.vaultUuid))
                statLabel("格式版本", "\(report.formatVersion)")
                statLabel("文件数", "\(report.fileCount)")
            }
            .font(.callout)
            Label("恢复将在工作目录创建该库；若工作目录已存在相同 ID 的库，恢复将失败。",
                  systemImage: "info.circle")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
            Spacer()
            HStack {
                Button("重新选择") { step = .pickFile }
                Spacer()
                Button("开始恢复") { doRestore(report: report, path: path) }
                    .buttonStyle(.borderedProminent)
                    // 非破坏性操作用普通醒目风格即可；isBusy 门禁兜底
                    .disabled(model.isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - ④ 恢复中

    private func restoringBody(_ report: FfiBackupVerifyReport, path: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在恢复密码库…（解包写入工作目录，请勿退出应用）")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 恢复（工厂级，锁定态亦可用）。1004 = 工作目录已存在同 ID 库（恢复
    /// 当前库自身的备份必然命中），给专属文案；其余错误 ErrorPresenter 直出。
    private func doRestore(report: FfiBackupVerifyReport, path: String) {
        step = .restoring(report, path: path)
        let factory = model.factory
        let targetBaseDir = model.baseDir.path
        Task.detached(priority: .userInitiated) {
            do {
                let restoredDir = try factory.restoreBackup(
                    backupPath: path, targetBaseDir: targetBaseDir)
                await MainActor.run {
                    step = .done(report, restoredDir: restoredDir)
                }
            } catch {
                let errText: String
                if let ffiError = error as? FfiError,
                   case let .Coffer(code, _) = ffiError, code == 1004 {
                    // 专属文案（1004）：解释「同 ID 库已存在」与出路——
                    // 恢复当前库自身的备份即命中此码
                    errText = "错误 1004：该库已存在于工作目录（相同库 ID）。如需覆盖请先删除现有库后再恢复。"
                } else {
                    errText = ErrorPresenter.text(error)
                }
                await MainActor.run {
                    // 回确认页可重试或重新选文件
                    step = .confirm(report, path: path)
                    DiagLog.append(errText)
                    model.lastErrorMessage = errText
                }
            }
        }
    }

    // MARK: - ⑤ 完成页

    private func doneBody(_ report: FfiBackupVerifyReport, restoredDir: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("恢复完成").font(.headline)
            Text("已恢复库 \(maskedUuid(report.vaultUuid))（\(report.fileCount) 个文件）。")
                .font(.callout)
            Label("请用该库的主密码解锁。", systemImage: "lock")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(restoredDir)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .lineLimit(2)
                .truncationMode(.middle)
            Spacer()
            HStack {
                Spacer()
                Button("好") { handoffToRestoredVault(report: report) }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 恢复后引导解锁（既定设计）：先锁定当前会话（清明文状态）→ listVaults
    /// 重新枚举 → 按 vaultUuid 匹配恢复产物（restoredDir 尾段即 <vault_uuid>，
    /// 与 brief.vaultUuid 同源）→ openSession（内部切 phase = .locked，本 sheet
    /// 随 MainView 拆除）→ LockView 承担解锁引导。
    private func handoffToRestoredVault(report: FfiBackupVerifyReport) {
        do {
            let briefs = try model.factory.listVaults(baseDir: model.baseDir.path)
            if let brief = briefs.first(where: { $0.vaultUuid == report.vaultUuid }) {
                // 恢复的是另一个库：必须先锁当前会话——lock() 清 items/details
                // 等明文状态 + clearOnLock（docs/07 §2.4），否则旧库明文残留在
                // AppModel 与 Rust 进程内。lock 后 phase=.locked，openSession
                // 替换会话，LockView 引导输入恢复库的主密码。
                model.lock()
                // 关 sheet（sheet 将随 MainView 拆除，dismiss 保证状态干净）
                dismiss()
                model.openSession(brief)
            } else {
                // 理论不可达：restoreBackup 成功返回即保证 <target>/<uuid> 存在
                showHandoffFallback = true
            }
        } catch {
            // 枚举失败不丢恢复成果：留在完成页可重试「好」
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
        }
    }

    // MARK: - 辅助

    private func statLabel(_ title: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    /// 库 UUID 掩码显示（前 8 位，非敏感字段但不整串展示）。
    private func maskedUuid(_ uuid: String) -> String {
        uuid.prefix(8) + "…"
    }
}
