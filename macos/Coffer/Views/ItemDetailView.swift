// ItemDetailView.swift —— 条目详情：字段掩码/显示切换、URL/标签/TOTP 元数据、
// 收藏 / 编辑 / 删除动作。复制按钮在阶段三接入（剪贴板 30s 清除一并实现）。

import SwiftUI

struct ItemDetailView: View {
    @EnvironmentObject
    private var model: AppModel

    let details: FfiItemDetails

    @State private var showEditSheet = false
    @State private var confirmHardDelete = false

    private var isTrashed: Bool {
        if case .trashed = details.state { return true }
        return false
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                fieldSection
                if !details.urls.isEmpty { urlSection }
                if !details.tags.isEmpty { tagSection }
                if let totp = details.totp { totpSection(totp) }
                metaSection
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(details.title)
        .toolbar { toolbarContent }
        .sheet(isPresented: $showEditSheet) {
            ItemEditView(mode: .edit(details))
                .environmentObject(model)
        }
        .confirmationDialog(
            "彻底删除「\(details.title)」？此操作不可恢复。",
            isPresented: $confirmHardDelete,
            titleVisibility: .visible
        ) {
            Button("彻底删除", role: .destructive) {
                tryAction { try model.deleteItem(itemId: details.uuid, hard: true) }
            }
            Button("取消", role: .cancel) {}
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 头部

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: details.category.symbolName)
                    .font(.title2)
                    .foregroundStyle(.tint)
                Text(details.title).font(.title2.bold())
                if details.isFavorite {
                    Image(systemName: "star.fill")
                        .font(.callout)
                        .foregroundStyle(.yellow)
                }
                if isTrashed {
                    Text("回收站")
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(.orange.opacity(0.2)))
                }
            }
            if !details.category.isEditable {
                Label("该类别为只读兜底（v0.1 仅支持登录 / 密码 / 安全笔记 / 信用卡四类编辑）", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - 字段

    @ViewBuilder
    private var fieldSection: some View {
        if !details.fields.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text("字段").font(.headline)
                ForEach(details.fields, id: \.uuid) { field in
                    FieldRowView(itemId: details.uuid, field: field)
                }
            }
        }
    }

    // MARK: - URL / 标签 / TOTP

    private var urlSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("网址").font(.headline)
            ForEach(details.urls, id: \.uuid) { url in
                HStack {
                    Image(systemName: "link").foregroundStyle(.secondary)
                    Text(url.url)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if url.isPrimary {
                        Text("主要").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var tagSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("标签").font(.headline)
            TagChipsView(tags: details.tags)
        }
    }

    private func totpSection(_ totp: FfiTotpDetail) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("一次性密码（TOTP）").font(.headline)
            TotpCodeView(itemId: details.uuid, detail: totp)
        }
    }

    private var metaSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("信息").font(.headline)
            LabeledContent("创建时间", value: Self.timestamp(details.createdAt))
            LabeledContent("修改时间", value: Self.timestamp(details.updatedAt))
            LabeledContent("条目 ID", value: details.uuid)
                .textSelection(.enabled)
        }
        .font(.callout)
    }

    private static func timestamp(_ unixSecs: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(unixSecs))
        return date.formatted(date: .long, time: .shortened)
    }

    // MARK: - 工具栏

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup {
            if !isTrashed {
                Button {
                    tryAction { try model.setFavorite(itemId: details.uuid, favorite: !details.isFavorite) }
                } label: {
                    Label(details.isFavorite ? "取消收藏" : "收藏",
                          systemImage: details.isFavorite ? "star.slash" : "star")
                }
                if details.category.isEditable {
                    Button {
                        showEditSheet = true
                    } label: {
                        Label("编辑", systemImage: "pencil")
                    }
                }
                Button(role: .destructive) {
                    tryAction { try model.deleteItem(itemId: details.uuid, hard: false) }
                } label: {
                    Label("移到回收站", systemImage: "trash")
                }
            } else {
                Button {
                    tryAction { try model.restoreItem(itemId: details.uuid) }
                } label: {
                    Label("恢复", systemImage: "arrow.uturn.backward")
                }
                Button(role: .destructive) {
                    confirmHardDelete = true
                } label: {
                    Label("彻底删除", systemImage: "trash.slash")
                }
            }
        }
    }

    // MARK: - 动作辅助

    private func tryAction(_ action: () throws -> Void) {
        do {
            try action()
        } catch {
            model.handleFfiError(error)
        }
    }
}

// MARK: - 标签流式布局（简易换行 chips）

struct TagChipsView: View {
    let tags: [String]

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 60), alignment: .leading)], alignment: .leading, spacing: 6) {
            ForEach(tags, id: \.self) { tag in
                Text(tag)
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(.quaternary))
            }
        }
    }
}
