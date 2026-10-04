// DiagnosticsView.swift —— 本地诊断信息页（FR-14.4，docs/22 §2.4；docs/23 §1.5 TC-DIAG）。
//
// 数据源：VaultSession.diagnostic_summary()（T03 FFI：条目数 / 附件数 / 库创建时间 /
// 最后备份时间 / 库 UUID 前缀）+ CofferApp.format_version()（库格式版本）+ Bundle 版本。
// **字段集白名单**（TC-DIAG-03）：只呈现计数/时间/uuid 前缀类非敏感字段——结构上
// 不存在明文 / 条目标题 / secret 读路径（非仅 UI 不展示，FFI 侧白名单见
// core/cf-ffi/src/types.rs FfiDiagnosticSummary）。
//
// 状态语义（TC-DIAG-04/06）：
//   - 锁定态 / 无会话 → 条目级诊断数据不可用并明示「需解锁」，不展示条目级数据；
//     库格式版本 / App 版本不依赖会话，恒可展示。
//   - 无库环境 → 诊断面条目数不可用并明示，不展示占位误值。
//   - 0 条目库 → 条目数 = 0（真实值直出）。
// 错误纪律（与 AuditLogView 一致）：错误文案经 ErrorPresenter 直出，
// 落 DiagLog + model.lastErrorMessage → .ffiErrorAlert。

import SwiftUI

struct DiagnosticsView: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 诊断摘要（T03 FFI）；nil = 尚未取到（加载中 / 锁定 / 无库环境）。
    @State private var summary: FfiDiagnosticSummary?
    /// 首次加载进行中标记。
    @State private var isLoading = true

    /// 时间格式化器（static 缓存：DateFormatter 创建开销大）。
    /// 日期为界面本地展示（非跨机器稳定场景），跟随用户当前 Locale / 时区。
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    ProgressView("正在读取…")
                } else {
                    Form {
                        appSection
                        vaultSection
                    }
                    .formStyle(.grouped)
                }
            }
            .navigationTitle("诊断信息")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .frame(width: 440, height: 380)
        .task { await load() }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - ① 应用与库格式（不依赖会话，恒可展示；TC-DIAG-02）

    private var appSection: some View {
        Section("版本") {
            LabeledContent("App 版本", value: Self.appVersion)
            // 库格式版本经 FFI 取内核常量（cf_format::FORMAT_VERSION，T03），
            // 与 header 内逐库 format_version 语义一致；勿在 Swift 侧硬编码。
            LabeledContent("库格式版本", value: model.factory.formatVersion())
        }
    }

    /// Bundle 版本（CFBundleShortVersionString）；非 App bundle 环境（如测试进程）
    /// 取不到 → 「未知」（界面恒有值，不因版本行崩坏诊断页）。
    private static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "未知"
    }

    // MARK: - ② 库诊断摘要（白名单字段；TC-DIAG-01/03/04/06）

    @ViewBuilder
    private var vaultSection: some View {
        if let summary {
            Section("密码库") {
                // 字段集白名单（TC-DIAG-03）：仅计数/时间/前缀类。任何新增
                // 敏感字段（标题/用户名/URL/明文/secret）不得出现在本页。
                LabeledContent("条目数", value: "\(summary.itemCount)")
                LabeledContent("附件数", value: "\(summary.attachmentCount)")
                LabeledContent("库创建时间", value: Self.timestampText(summary.vaultCreatedAt))
                LabeledContent(
                    "最后备份时间",
                    value: summary.lastBackupAt.map(Self.timestampText) ?? "从未备份"
                )
                LabeledContent("库 UUID 前缀", value: summary.vaultUuidPrefix)
            }
        } else {
            Section {
                // TC-DIAG-04/06：锁定 / 无库环境 → 明示「不可用」而非占位误值。
                Label {
                    Text("诊断数据不可用：需解锁密码库后才能读取。")
                } icon: {
                    Image(systemName: "lock")
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("密码库")
            }
        }
    }

    // MARK: - 加载

    private func load() async {
        // 设置页仅在解锁态（phase == .unlocked）可达，session 必非 nil；
        // 防御性 guard 兜底（锁定 / 无库环境，TC-DIAG-04/06）——此时不展示
        // 条目级数据，只保留版本行。
        guard let session = model.session else {
            isLoading = false
            return
        }
        do {
            let fetched = try await Task.detached(priority: .userInitiated) {
                // diagnostic_summary 只读允许面无门禁（TC-DIAG-05）；锁定态 1001。
                try session.diagnosticSummary()
            }.value
            summary = fetched
        } catch {
            // 错误文案 Rust 侧已脱敏，直出并落诊断日志（同 AuditLogView 各错误路径）。
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
        }
        isLoading = false
    }

    // MARK: - 时间格式化

    /// Unix 秒 → 本地展示时间（formatter 为 static 缓存，见上）。
    private static func timestampText(_ unixSeconds: Int64) -> String {
        timestampFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(unixSeconds)))
    }
}
