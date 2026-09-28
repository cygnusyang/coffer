// ItemDetailView.swift —— 条目详情：字段掩码/显示切换、URL/标签/TOTP 元数据、
// 收藏 / 编辑 / 删除动作、历史版本入口（FR-2.9，回滚见 HistorySheet）。
// 复制按钮在阶段三接入（剪贴板 30s 清除一并实现）。

import SwiftUI

struct ItemDetailView: View {
    @EnvironmentObject
    private var model: AppModel

    let details: FfiItemDetails

    @State private var showEditSheet = false
    @State private var confirmHardDelete = false
    @State private var showHistory = false
    /// 跨库复制 sheet（v0.4 FR-2.10，MB-2）。
    @State private var showCrossCopy = false
    /// 历史版本数（出现时轻量拉一次；失败显示 0 并静默——入口数字
    /// 非关键信息，不弹窗打扰）。
    @State private var historyCount = 0

    private var isTrashed: Bool {
        if case .trashed = details.state { return true }
        return false
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                // FR-9.4 Document 条目（最小形态）：附件是主体内容，
                // 附件区置于字段区之上（判定见 ItemTemplates 扩展）。
                if details.category.placesAttachmentSectionAboveFields {
                    attachmentSection
                }
                fieldSection
                if !details.urls.isEmpty { urlSection }
                if !details.tags.isEmpty { tagSection }
                if let totp = details.totp { totpSection(totp) }
                if !isTrashed { historySection }
                metaSection
                // MA-2 挂载点约定（docs/15 §7 风险 8）：非 Document 条目的
                // 附件区在 body 尾部，与 MB-2 的右键复制菜单（context menu
                // 头部）物理隔离，避免同文件串行接驳冲突。
                if !details.category.placesAttachmentSectionAboveFields {
                    attachmentSection
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(details.title)
        .toolbar { toolbarContent }
        // 跨库复制入口（v0.4 FR-2.10，MB-2）：详情右键菜单，单行挂载——
        // 与 MA-2 附件区物理隔离（docs/15 §7 风险 8 约定）。回收站条目
        // 不出入口（内核 Trashed→Active 语义外的 UI 双保险，§3.2.4-4）。
        .contextMenu {
            if !isTrashed {
                Button {
                    showCrossCopy = true
                } label: {
                    Label("复制到其他库…", systemImage: "doc.on.doc")
                }
            }
        }
        .task {
            refreshHistoryCount()
        }
        .onChange(of: showHistory) {
            // sheet 关闭后刷新计数（回滚会写入新版本，列表 +1）。
            if !showHistory { refreshHistoryCount() }
        }
        .sheet(isPresented: $showHistory) {
            HistorySheet(itemId: details.uuid)
                .environmentObject(model)
        }
        .sheet(isPresented: $showEditSheet) {
            ItemEditView(mode: .edit(details))
                .environmentObject(model)
        }
        .sheet(isPresented: $showCrossCopy) {
            CrossCopySheet(sourceItemId: details.uuid, sourceTitle: details.title)
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

    // MARK: - 附件（FR-9.3 / 9.4，v0.4.0 MA-2）

    /// 附件区（自持状态，经 environmentObject 只读访问 session；docs/15
    /// §6.1 S2 切片：零 AppModel 改动）。
    private var attachmentSection: some View {
        AttachmentSection(itemId: details.uuid)
    }

    // MARK: - 历史版本（FR-2.9）

    // 回收站条目回滚被内核拒绝（错误码 1012），故 trashed 条目整体
    // 不渲染本 section——不给入口优于让用户点了再吃报错。快照明文
    // 不跨 FFI 是内核刻意设计，入口只展示版本数，详见 HistorySheet。

    private var historySection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("历史版本").font(.headline)
            Button("\(historyCount) 个历史版本 ›") {
                showHistory = true
            }
            .buttonStyle(.link)
        }
        .font(.callout)
    }

    /// 轻量计数：listHistory 只回元数据（毫秒级，同 ItemStore CRUD
    /// 纪律直接主线程调用）；失败静默为 0。
    private func refreshHistoryCount() {
        guard let session = model.session else { return }
        historyCount = (try? session.listHistory(itemId: details.uuid).count) ?? 0
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
