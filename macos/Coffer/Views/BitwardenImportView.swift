// BitwardenImportView.swift —— Bitwarden JSON 导入向导：选文件 → 预检报告 →
// 确认导入 → 结果（docs/17 §4.2 PK2 / §4.4 PK3）。
//
// 流程：precheck_bitwarden_json 只读且无解锁门禁（锁定态可预检，但 UI 入口
// 在解锁区——菜单/工具栏均 .disabled(phase != .unlocked)）→ UI 展示报告
// （含 passkey 计数与「含密码且含 passkey」证据计数，FR-10.6）→ 用户确认 →
// import_bitwarden_json（Rust 1001 门禁，需解锁态）→ 结果展示。
//
// 与 CSV 导入的关键语义差异（文案必须如实）：
//   - Bitwarden 导入是**每条目独立事务**——中途失败时已导入条目保留
//     （与 CSV import_csv 单事务 all-or-nothing 相反）。因此导入失败的
//     错误提示必须告知「部分条目可能已导入，重试将重复新建」。
//   - 非 ES256 / 坏 passkey 行在预检逐条显式列出（TCB-7，不静默丢弃），
//     导入跳过该行不丢条目。
//
// 可用性声明边界（docs/17 §4.2 TCB-1，防声明越界）：真实 Bitwarden 未加密
// 导出的 encryptedPrivateKey 恒为 EncString 形态（attach key 不随导出解包），
// 当前真实导出实际不可导入——本向导**不声称「Bitwarden passkey 导入可用」**，
// passkey 导入情况一律以预检报告逐行数据为准。

import SwiftUI
import UniformTypeIdentifiers

struct BitwardenImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    enum Step {
        case pickFile
        case report(FfiBwPrecheckReport, path: String)
        case importing
        case done(FfiBwImportResult, path: String)
    }

    @State private var step: Step = .pickFile

    /// 预检失败的错误文案（未发生任何导入）用本地 alert，回 pickFile 可重试。
    @State private var precheckError: String?

    /// 最近一次预检成功的报告与路径：导入失败后回 report 页重试需要
    /// 重建 .report 状态（每条目独立事务，部分导入已发生，如实呈现）。
    @State private var lastReport: FfiBwPrecheckReport?
    @State private var lastPath: String?

    /// 导入执行中（关闭按钮此时禁用，防丢结果页；已导入条目不受影响，
    /// 但中途关 sheet 会丢失结果页）。
    private var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导入 Bitwarden（.json）").font(.headline)
                Spacer()
                // 显式关闭出口（BUG-5 同类修复）：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效。导入执行中禁用——非 all-or-nothing，
                // 中途关 sheet 丢结果页，用户无从判断已导入多少。
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
        .frame(width: 560, height: 560)
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
            Image(systemName: "doc.text")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("选择 Bitwarden 导出的未加密 JSON 文件")
                .font(.callout)
            Text("Bitwarden JSON 是官方导出格式，导入为每条目独立事务。\npasskey（fido2Credentials）导入支持受导出字段形态影响，具体以预检报告为准。")
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
        // Bitwarden 导出为 JSON 文本：接受 json，兜底 .plainText/.data
        panel.allowedContentTypes = [.json, .plainText, .data]
        panel.message = "选择 Bitwarden 导出的未加密 JSON 文件"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            // 预检是只读操作且无解锁门禁（锁定态亦可预检），同步调用即可
            let report = try sessionCall { try $0.precheckBitwardenJson(path: url.path) }
            lastReport = report
            lastPath = url.path
            step = .report(report, path: url.path)
        } catch {
            precheckError = ErrorPresenter.text(error)
        }
    }

    // MARK: - 预检报告

    private func reportBody(_ report: FfiBwPrecheckReport, path: String) -> some View {
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
                        statLabel("Passkey 总数", report.passkeyTotal)
                        statLabel("可导入 Passkey", report.passkeyImportable)
                    }
                    .font(.callout)

                    // FR-10.6 证据计数（D-6）：passkey 挂靠不触碰密码字段，
                    // 预检报告给出「含密码且含 passkey 的条目数」。
                    if report.itemsWithPasswordAndPasskey > 0 {
                        Label("含密码且含 Passkey 的条目 \(report.itemsWithPasswordAndPasskey) 条（密码原样保留）",
                              systemImage: "checkmark.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

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

                    // 非 ES256 passkey 行逐条列出（TCB-7：预检显式列出，不静默丢弃）
                    if !report.nonEs256.isEmpty {
                        failureSection(
                            "非 ES256 Passkey \(report.nonEs256.count) 个（不导入）",
                            failures: report.nonEs256,
                            symbol: "xmark.circle"
                        )
                    }

                    // 其余坏 passkey 行逐条列出（TCB-7：EncString / 坏 credentialId /
                    // 缺 rpId / 负 counter；导入跳过该行不丢条目）
                    if !report.badPasskeys.isEmpty {
                        failureSection(
                            "无法导入的 Passkey \(report.badPasskeys.count) 个（跳过该行，不丢条目）",
                            failures: report.badPasskeys,
                            symbol: "exclamationmark.triangle"
                        )
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

    /// 失败 passkey 行清单（TCB-7 不静默丢弃）：item_title + index +
    /// 结构化 kind + reason + item_id 全量直出，程序判定以 kind 为唯一依据
    /// （L-2，reason 仅供人类阅读）。
    private func failureSection(
        _ title: String,
        failures: [FfiBwPasskeyFailure],
        symbol: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: symbol)
                .font(.callout)
                .foregroundStyle(.orange)
            ForEach(failures, id: \.self) { failure in
                HStack(alignment: .top, spacing: 6) {
                    Text(failure.itemTitle)
                        .font(.caption)
                        .lineLimit(1)
                    Text("#\(failure.index)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.tertiary)
                    Spacer()
                }
                Text("\(Self.kindText(failure.kind))：\(failure.reason)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text("条目 ID \(failure.itemId)")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
        }
    }

    /// 结构化 kind → 人类可读文案（展示用；分类判定以 kind 枚举为准，非文案）。
    private static func kindText(_ kind: FfiBwPasskeyFailureKind) -> String {
        switch kind {
        case .keyAlgorithmMismatch: return "keyAlgorithm 非 ecdsa"
        case .keyCurveMismatch: return "keyCurve 非 p256"
        case .missingRpId: return "缺少 rpId"
        case .invalidCredentialId: return "凭据 ID 非法"
        case .invalidCounter: return "签名计数器非法"
        case .missingPrivateKey: return "缺少私钥字段"
        case .encryptedPrivateKey: return "私钥为加密形态"
        case .unparseablePrivateKey: return "私钥无法解析为 ES256"
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

    /// 导入（需解锁态：锁定态 Rust 返回 1001；写路径较慢，Task.detached
    /// 包裹）。失败后回 report 页可重试——但部分导入已发生，错误文案必须
    /// 提示重试将重复新建（内核语义，如实呈现）。
    private func doImport(path: String) {
        step = .importing
        let session = model.session
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session?.importBitwardenJson(path: path)
                await MainActor.run {
                    if let result {
                        step = .done(result, path: path)
                        model.reloadItems()
                    } else {
                        // 会话缺失（理论不可达：入口在解锁区）；无导入发生，
                        // 无部分导入提示的必要，回报告页即可
                        step = .report(lastReport ?? FfiBwPrecheckReport(
                            totalItems: 0, importableItems: 0,
                            passkeyTotal: 0, passkeyImportable: 0, passkeyItemCount: 0,
                            itemsWithPasswordAndPasskey: 0, nonEs256: [], badPasskeys: [],
                            trashedCount: 0, passwordHistoryDropped: 0, warnings: []
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

    // MARK: - 结果

    private func doneBody(_ result: FfiBwImportResult, path: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导入完成：新建 \(result.importedItems) 条条目")
                .font(.headline)

            // passkey 计数直出本次导入报告（result.report 与导入同管线产出，
            // FR-7.4 所见即所得）；真实导出 encryptedPrivateKey 多为 EncString
            // → passkeyImportable 恒 0，此处自然隐藏，不构成可用性声明。
            if result.report.passkeyImportable > 0 {
                Text("本次导入 Passkey \(result.report.passkeyImportable) 个")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if result.report.itemsWithPasswordAndPasskey > 0 {
                Label("含密码且含 Passkey 的条目 \(result.report.itemsWithPasswordAndPasskey) 条（密码原样保留）",
                      systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
