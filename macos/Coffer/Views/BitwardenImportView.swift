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
//
// v2.9.0 P3：脚手架收敛到共享壳 ImportWizardShell（docs/14 §A P3）。本视图
// 提供 ImportFormatConfig + 私有报告/结果特有 body；per-item 事务语义逐字
// 保留（importingCopy / failureSuffix，失败回报告页可重试）。

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

    /// Bitwarden 格式配置（docs/14 §A P3 §3 逐字对照表）。
    static let importFormatConfig = ImportFormatConfig(
        // 配置字段是 String 且由 Text/Button 消费，不查表（设计 24 F6）→ 译文在产生点取（§5.4）。
        title: String(localized: "导入 Bitwarden（.json）"),
        icon: "doc.text",
        pickTitle: String(localized: "选择 Bitwarden 导出的未加密 JSON 文件"),
        pickDescription: String(localized: "Bitwarden JSON 是官方导出格式，导入为每条目独立事务。\npasskey（fido2Credentials）导入支持受导出字段形态影响，具体以预检报告为准。"),
        pickButtonLabel: String(localized: "选择文件…"),
        windowWidth: 560, windowHeight: 560,
        precheckErrorAlertTitle: String(localized: "预检失败"),
        transactionSemantics: .perItem,
        importingCopy: String(localized: "正在导入（每条目独立事务，已完成的条目保留）…"),
        failureSuffix: String(localized: "\n注意：导入为每条目独立事务，部分条目可能已导入，重试将重复新建。"),
        doneFooter: nil,
        failureRecovery: .backToReport,
        canChooseDirectories: false,
        allowedContentTypes: [.json, .plainText, .data],
        panelMessage: String(localized: "选择 Bitwarden 导出的未加密 JSON 文件")
    )

    var body: some View {
        ImportWizardShell(
            config: Self.importFormatConfig,
            isImporting: isImporting,
            onClose: { dismiss() },
            precheckError: $precheckError,
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
                    count: result.importedItems,
                    doneFooter: Self.importFormatConfig.doneFooter,
                    path: path,
                    onDone: { dismiss() }
                ) {
                    doneExtra(result)
                }
            }
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 选文件

    private func pickAndPrecheck() {
        let config = Self.importFormatConfig
        let panel = NSOpenPanel()
        panel.canChooseDirectories = config.canChooseDirectories
        panel.canChooseFiles = !config.canChooseDirectories
        panel.allowsMultipleSelection = false
        // Bitwarden 导出为 JSON 文本：接受 json，兜底 .plainText/.data
        panel.allowedContentTypes = config.allowedContentTypes
        panel.message = config.panelMessage
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
                        ImportScaffold.statLabel("总条目", report.totalItems)
                        ImportScaffold.statLabel("可导入", report.importableItems)
                        ImportScaffold.statLabel("Passkey 总数", report.passkeyTotal)
                        ImportScaffold.statLabel("可导入 Passkey", report.passkeyImportable)
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

    /// 失败 passkey 行清单（TCB-7 不静默丢弃）：item_title + index +
    /// 结构化 kind + reason + item_id 全量直出，程序判定以 kind 为唯一依据
    /// （L-2，reason 仅供人类阅读）。形态与 1PUX/OPVault 未导入清单不同，
    /// 保持格式私有（不进共享 failureList）。
    /// title 用 LocalizedStringKey 而非 String：Label 的 String 重载**不查表**（设计 24
    /// F6），形参写成 String 会让这行标题「有译文但不生效」；LocalizedStringKey 才会查表，
    /// 且缺键时可正常回退到中文原文（§5.4.1）。
    private func failureSection(
        _ title: LocalizedStringKey,
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
    /// 返回值是**文案**，且被外层插值句 "%@：%@" 拼进句子里——所以必须在返回时
    /// 本地化（设计 24 §5.4「纯函数返回展示串在返回值处翻」）。
    private static func kindText(_ kind: FfiBwPasskeyFailureKind) -> String {
        switch kind {
        case .keyAlgorithmMismatch: return String(localized: "keyAlgorithm 非 ecdsa")
        case .keyCurveMismatch: return String(localized: "keyCurve 非 p256")
        case .missingRpId: return String(localized: "缺少 rpId")
        case .invalidCredentialId: return String(localized: "凭据 ID 非法")
        case .invalidCounter: return String(localized: "签名计数器非法")
        case .missingPrivateKey: return String(localized: "缺少私钥字段")
        case .encryptedPrivateKey: return String(localized: "私钥为加密形态")
        case .unparseablePrivateKey: return String(localized: "私钥无法解析为 ES256")
        }
    }

    // MARK: - 导入

    /// 导入（需解锁态：锁定态 Rust 返回 1001；写路径较慢，Task.detached
    /// 包裹）。失败后回 report 页可重试——但部分导入已发生，错误文案必须
    /// 提示重试将重复新建（内核语义，如实呈现）。恢复方向 = failureRecovery
    /// .backToReport（保留 lastReport，可重试）。
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
                        model.lastErrorMessage = String(localized: "会话不存在。")
                    }
                }
            } catch {
                await MainActor.run {
                    // 错误纪律：落 DiagLog（与 AppModel / 审计日志同纪律）+
                    // lastErrorMessage → .ffiErrorAlert。附加部分导入提示：
                    // 每条目独立事务，中途失败已导入条目保留，重试会重复新建
                    // （failureSuffix 逐字，per-item 必有——AC-2.9.0-P3T-5）。
                    DiagLog.append(ErrorPresenter.text(error))
                    model.lastErrorMessage = ErrorPresenter.text(error)
                        + Self.importFormatConfig.failureSuffix
                    if let lastReport, let lastPath {
                        step = .report(lastReport, path: lastPath)
                    } else {
                        step = .pickFile
                    }
                }
            }
        }
    }

    // MARK: - 结果特有区

    /// 结果页特有区：passkey 计数（壳骨架之外格式私有）。
    private func doneExtra(_ result: FfiBwImportResult) -> some View {
        VStack(spacing: 8) {
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
