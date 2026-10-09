// AuditLogView.swift —— 审计日志查看页（FR-12.6，Could 级，T-I）。
//
// 只读语义：本视图只调 `VaultSession.recentAuditEvents(offset:limit:)`
// （本地审计日志分页查询，FR-12.6），不做任何写入。锁定态调用返回
// 1001（需解锁会话）——入口在设置页（仅解锁区可达），View 内仍 guard
// 解锁态兜底。
//
// 事件打点位置（写入语义，注释供 UI 理解，实际打点在 Rust 内核）：
//   事件只由内核动作的成功路径打点——备份导出（FR-8.1）/ 备份恢复 /
//   CSV 导出 / 修改主密码（FR-1.8）/ 条目跨库复制（v0.4）/ 主密码恢复
//   通道（FR-17，v2.5.0：生物识别重置 / 恢复码重置 / 启用恢复码）；
//   打点失败静默（不影响主流程）；备份包内不含「本次导出」这一条事件。
//
// 分页约定（Could 级保持简单）：一次性取最近 200 条（limit = 200，
// Rust 侧已按 (ts DESC, id DESC) 倒序返回，此处不再重排）；不提供
// 「加载更多」，`offset` 参数留接口不接 UI，将来加翻页时再接。
//
// 错误纪律（与 ChangePasswordView 一致）：错误文案经 ErrorPresenter
// 直出，落 DiagLog + model.lastErrorMessage → .ffiErrorAlert。

import SwiftUI

// MARK: - 事件映射（纯函数，便于将来单测）

extension FfiAuditEvent {
    /// 事件中文名（UI 展示用）。
    var displayName: String {
        // 与绑定 enum 全 case 对齐（无 default：Rust 侧新增变体时此处
        // 编译报错，强制补映射，防止新事件静默显示为原始 case 名）。
        switch self {
        case .backupExport: return "导出备份"
        case .backupRestore: return "恢复备份"
        case .csvExport: return "导出 CSV"
        case .puxExport: return "导出 1PUX"
        case .passwordChange: return "修改主密码"
        case .itemCopy: return "跨库复制"
        case .passwordResetByBio: return "生物识别重置主密码"
        case .passwordResetByRecovery: return "恢复码重置主密码"
        case .recoveryCodeEnabled: return "启用恢复码"
        }
    }

    /// 行首图标（SF Symbol）。
    var symbolName: String {
        switch self {
        case .backupExport: return "externaldrive.badge.timemachine"
        case .backupRestore: return "arrow.counterclockwise"
        case .csvExport: return "tablecells"
        case .puxExport: return "shippingbox"
        case .passwordChange: return "key"
        case .itemCopy: return "doc.on.doc"
        case .passwordResetByBio: return "faceid"
        case .passwordResetByRecovery: return "key.fill"
        case .recoveryCodeEnabled: return "qrcode"
        }
    }
}

// MARK: - Identifiable

extension FfiAuditEntry: Identifiable {}

// MARK: - 视图

struct AuditLogView: View {
    @EnvironmentObject
    private var model: AppModel
    /// 关闭出口（macOS sheet 点外部不关闭、无按钮时 Esc 无效，
    /// 必须提供显式关闭按钮——同 ChangePasswordView / RestoreBackupView）。
    @Environment(\.dismiss)
    private var dismiss

    /// 最近审计事件（Rust 已按时间倒序返回，保持原序渲染）。
    @State private var entries: [FfiAuditEntry] = []
    /// 首次加载进行中标记。
    @State private var isLoading = true

    /// 单页上限（Could 级不分页，200 条足够回溯近期操作）。
    private static let pageSize: Int64 = 200

    /// 时间格式化器（static 缓存：DateFormatter 创建开销大，
    /// 每行新建在 200 行重渲染下浪费明显）。
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        // 日期为界面本地展示（非文件名等跨机器稳定场景），
        // 跟随用户当前 Locale / 时区即可，不固定 POSIX 格式。
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    ProgressView("正在加载…")
                } else if entries.isEmpty {
                    emptyState
                } else {
                    eventList
                }
            }
            .navigationTitle("审计日志")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .frame(width: 420, height: 460)
        .task { await loadEvents() }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: 列表与空状态

    private var eventList: some View {
        List {
            ForEach(entries) { entry in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: entry.event.symbolName)
                        .foregroundStyle(.secondary)
                        .frame(width: 22)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.event.displayName)
                        // detail 为非敏感上下文（如条目 UUID），恒 nil 时
                        // 此行不渲染；非 nil 用次要色 caption 展示。
                        if let detail = entry.detail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Text(Self.timestampText(entry.ts))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                .padding(.vertical, 2)
            }
        }
        .listStyle(.inset)
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "list.bullet.rectangle")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("暂无审计事件")
                .font(.headline)
            Text("导出备份、修改主密码等操作会记录在此。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - 加载

    private func loadEvents() async {
        // 设置页仅在解锁态（phase == .unlocked）可达，session 必非 nil；
        // 防御性 guard 兜底（1001 场景不应发生，发生即按错误呈现）。
        guard let session = model.session else {
            isLoading = false
            let errText = "内部错误：审计日志需解锁后查看。"
            DiagLog.append(errText)
            model.lastErrorMessage = errText
            return
        }
        do {
            // 局部捕获页上限，避免 detached 闭包跨 actor 访问 MainActor 静态属性。
            let pageSize = Self.pageSize
            let fetched = try await Task.detached(priority: .userInitiated) {
                // offset 传 nil 从最新取一页；倒序由 Rust 保证，勿再 reverse。
                try session.recentAuditEvents(offset: nil, limit: pageSize)
            }.value
            entries = fetched
        } catch {
            // 错误文案 Rust 侧已脱敏，直出并落诊断日志（同 AppModel 各错误路径）。
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
