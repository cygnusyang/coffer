// TrashView.swift —— 回收站列表：软删条目 + 恢复 / 彻底删除。

import SwiftUI

/// 中列在 sidebarFilter == .trash 时的列表视图。
struct TrashListView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var confirmPurgeAll = false

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
                for summary in model.items {
                    do {
                        try model.deleteItem(itemId: summary.uuid, hard: true)
                    } catch {
                        model.handleFfiError(error)
                        break
                    }
                }
            }
            Button("取消", role: .cancel) {}
        }
    }
}
