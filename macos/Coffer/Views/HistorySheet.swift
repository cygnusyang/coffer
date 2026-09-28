// HistorySheet.swift —— 条目历史版本查看与回滚（FR-2.9，v0.3.0-T05）。
//
// 只读列表 + 显式回滚：Rust 侧 listHistory 已按 version DESC 排好，
// 此处保持原序渲染、不再排序。
//
// 快照明文不跨 FFI 是内核刻意设计（历史快照密文落库，列表接口只回
// version + createdAt 元数据）——本视图只展示版本号与时间，没有内容
// 预览 / diff 能力。这是设计而非缺口；将来做内容级 diff 需内核新增
// 「按 historyUuid 读快照明文」的接口。
//
// 错误码 1012（Trashed / Archived 条目回滚被拒）与入口的关系：详情页
// 对回收站条目整体隐藏「历史版本」section（不给入口优于让用户点了
// 再吃 1012 报错）；sheet 内若会话状态变化仍触发 1012，按下方错误
// 纪律呈现文案。
//
// 错误纪律（与 AuditLogView 一致）：错误文案经 ErrorPresenter 直出，
// 落 DiagLog + model.lastErrorMessage → .ffiErrorAlert。

import SwiftUI

extension FfiHistoryEntry: Identifiable {
    /// FFI 绑定无 `id` 字段，用历史行 UUID 充当列表标识。
    public var id: String { historyUuid }
}

struct HistorySheet: View {
    @EnvironmentObject
    private var model: AppModel
    /// 关闭出口（macOS sheet 点外部不关闭、无按钮时 Esc 无效，
    /// 必须提供显式关闭按钮——同 AuditLogView / ChangePasswordView）。
    @Environment(\.dismiss)
    private var dismiss

    let itemId: String

    /// 历史条目（Rust 已按 version DESC 返回，保持原序渲染）。
    @State private var entries: [FfiHistoryEntry] = []
    /// 首次加载进行中标记。
    @State private var isLoading = true
    /// 回滚执行中标记（防双击：执行中再次点击行直接忽略）。
    @State private var isRestoring = false
    /// 待确认回滚的目标版本（行点击先暂存，弹确认框）。
    @State private var pendingRestore: FfiHistoryEntry?
    @State private var showRestoreConfirm = false

    /// 时间格式化器（static 缓存：DateFormatter 创建开销大，
    /// 每行新建在列表重渲染下浪费明显——同 AuditLogView）。
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
                    historyList
                }
            }
            .navigationTitle("历史版本")
            .toolbar {
                // 关闭按钮挂在 cancellationAction：Esc 生效（BUG-5 纪律）。
                // 只读列表，loading 中不禁用。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
        .frame(width: 460, height: 480)
        .task {
            await loadEntries()
            isLoading = false
        }
        .confirmationDialog(
            "回滚到版本 \(pendingRestore?.version ?? 0)？当前状态会先保存为新版本，之后可再次回滚。",
            isPresented: $showRestoreConfirm,
            titleVisibility: .visible
        ) {
            Button("回滚到版本 \(pendingRestore?.version ?? 0)", role: .destructive) {
                guard let entry = pendingRestore else { return }
                Task { await performRestore(entry) }
            }
            Button("取消", role: .cancel) {}
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 列表与空状态

    private var historyList: some View {
        List {
            ForEach(entries) { entry in
                Button {
                    guard !isRestoring else { return } // 防双击
                    pendingRestore = entry
                    showRestoreConfirm = true
                } label: {
                    HStack {
                        // 快照明文不跨 FFI（见文件头）：只渲染元数据，
                        // 无任何内容预览。
                        Text("版本 \(entry.version)")
                            .font(.headline)
                        Spacer()
                        Text(Self.timestampText(entry.createdAt))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
                .buttonStyle(.plain)
                .disabled(isRestoring)
            }
        }
        .listStyle(.inset)
        .overlay {
            if isRestoring {
                ProgressView("正在回滚…")
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("暂无历史版本")
                .font(.headline)
            Text("每次修改会留存快照。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - 加载与回滚

    private func loadEntries() async {
        guard let session = model.session else {
            // 解锁态下才可达（入口在详情页），防御性 guard 兜底。
            isLoading = false
            let errText = "内部错误：历史版本需解锁后查看。"
            DiagLog.append(errText)
            model.lastErrorMessage = errText
            return
        }
        do {
            let id = itemId
            let fetched = try await Task.detached(priority: .userInitiated) {
                // 倒序由 Rust 保证（version DESC），勿再排序。
                try session.listHistory(itemId: id)
            }.value
            entries = fetched
        } catch {
            // 错误文案 Rust 侧已脱敏，直出并落诊断日志（同 AuditLogView）。
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
        }
    }

    /// 回滚到指定快照：写路径会重加密整条条目（同建库/导入等慢调用，
    /// 走 Task.detached 避免 UI 卡顿——ItemStore 头注释纪律）。
    private func performRestore(_ entry: FfiHistoryEntry) async {
        guard !isRestoring else { return } // 防双击
        isRestoring = true
        defer { isRestoring = false }
        guard let session = model.session else {
            let errText = "内部错误：历史回滚需解锁后操作。"
            DiagLog.append(errText)
            model.lastErrorMessage = errText
            return
        }
        do {
            let id = itemId
            let historyUuid = entry.historyUuid
            try await Task.detached(priority: .userInitiated) {
                try session.restoreHistory(itemId: id, historyUuid: historyUuid)
            }.value
            // 回滚本身会写入一个新版本：刷新详情内容 + 重新拉列表
            // （列表应比回滚前多一条）。
            model.loadSelectedDetails()
            await loadEntries()
        } catch {
            // 1012（Trashed/Archived 被拒）等均直出；列表仍刷新一次，
            // 保证与内核状态一致。
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
            await loadEntries()
        }
    }

    // MARK: - 时间格式化

    /// Unix 秒 → 本地展示时间（formatter 为 static 缓存，见上）。
    private static func timestampText(_ unixSeconds: Int64) -> String {
        timestampFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(unixSeconds)))
    }
}
