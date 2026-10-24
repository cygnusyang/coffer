// TrashView.swift —— 回收站列表：软删条目 + 恢复 / 彻底删除。

import SwiftUI

/// 中列在 sidebarFilter == .trash 时的列表视图。
struct TrashListView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var confirmPurgeAll = false
    /// FW-03（v2.9.0 docs/13 §5 / DESIGN.md D-8.2）：清空回收站聚合反馈文案
    /// （成功 N 条 / 失败 M 条 + 原因）；非 nil 即呈现，不逐条弹窗。
    @State private var purgeResult: String?

    var body: some View {
        List(selection: $model.selectedItemID) {
            ForEach(model.items) { summary in
                HStack {
                    Image(systemName: summary.category.symbolName)
                        .foregroundStyle(.secondary)
                        .frame(width: 22)
                    Text(summary.title)
                        .lineLimit(1)
                    Spacer()
                }
                .tag(summary.uuid)
            }
        }
        .overlay {
            if model.items.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "trash")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("回收站为空").font(.headline)
                    Text("删除的条目会先移入回收站")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("回收站")
        .toolbar {
            ToolbarItem {
                Button {
                    confirmPurgeAll = true
                } label: {
                    Label("清空回收站", systemImage: "trash.slash")
                }
                .disabled(model.items.isEmpty)
            }
        }
        .confirmationDialog(
            "彻底删除回收站中的全部 \(model.items.count) 条条目？此操作不可恢复。",
            isPresented: $confirmPurgeAll,
            titleVisibility: .visible
        ) {
            Button("全部彻底删除", role: .destructive) {
                purgeAll()
            }
            Button("取消", role: .cancel) {}
        }
        // FW-03：聚合反馈一次呈现（D-8.2），替代原先「首错中断 + 静默吞错」。
        .alert("清空回收站", isPresented: Binding(
            get: { purgeResult != nil },
            set: { if !$0 { purgeResult = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(purgeResult ?? "")
        }
    }

    // MARK: - 清空回收站（FW-03 聚合反馈）

    /// D-8.1/D-8.2（FW-03）：批量硬删不中断继续——单条失败记入聚合结果，继续
    /// 清剩余条目；完成后一次呈现「成功 N 条 / 失败 M 条 + 原因」，不逐条弹窗。
    /// 1001 会话失效仍切锁定界面（与 handleFfiError 同语义）但不中断（视图随
    /// phase 切换即将拆除，循环自然以失败聚合收尾）。
    private func purgeAll() {
        var succeeded = 0
        var failures: [(title: String, reason: String)] = []
        for summary in model.items {
            do {
                try model.deleteItem(itemId: summary.uuid, hard: true)
                succeeded += 1
            } catch {
                if case let .Coffer(code, _) = error as? FfiError, code == 1001 {
                    model.handleFfiError(error)
                }
                failures.append((summary.title, ErrorPresenter.text(error)))
            }
        }
        purgeResult = Self.purgeSummaryText(succeeded: succeeded, failures: failures)
    }

    /// 聚合反馈文案（纯函数，D-8.2）：全成功「已彻底删除 N 条」；有失败追加
    /// 失败数与逐条原因。
    /// v2.13.0：三处拼接改为「单串 + 占位符」并在产生点本地化（设计 §5.4）——
    /// 拼接后的 String 到了 View 里只会走 Text(String)，不再查表，晚一步就救不回来。
    static func purgeSummaryText(succeeded: Int, failures: [(title: String, reason: String)]) -> String {
        var text = String(localized: "已彻底删除 \(succeeded) 条")
        if !failures.isEmpty {
            text += String(localized: "，\(failures.count) 条失败")
            for failure in failures {
                text += String(localized: "\n「\(failure.title)」：\(failure.reason)")
            }
        }
        return text
    }
}
