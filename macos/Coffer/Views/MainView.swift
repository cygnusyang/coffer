// MainView.swift —— 解锁后的主界面：侧栏（分类筛选）+ 列表（搜索）+ 详情。

import SwiftUI

struct MainView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var newSheetCategory: FfiItemCategory?

    var body: some View {
        NavigationSplitView {
            sidebar
        } content: {
            middleColumn
        } detail: {
            detailPane
        }
        .onAppear {
            model.reloadItems()
            if model.selectedItemID != nil {
                model.loadSelectedDetails()
            }
        }
        .sheet(item: $newSheetCategory) { category in
            ItemEditView(mode: .create(category))
                .environmentObject(model)
        }
    }

    // MARK: - 侧栏

    private var sidebar: some View {
        List(selection: $model.sidebarFilter) {
            Section {
                Label("全部条目", systemImage: "tray.full").tag(SidebarFilter.all)
                Label("收藏", systemImage: "star").tag(SidebarFilter.favorites)
            }
            Section("类别") {
                ForEach(FfiItemCategory.editableCategories, id: \.self) { category in
                    Label(category.displayName, systemImage: category.symbolName)
                        .tag(SidebarFilter.category(category))
                }
            }
            Section {
                Label("回收站", systemImage: "trash").tag(SidebarFilter.trash)
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 180)
    }

    // MARK: - 中列（列表 / 搜索）

    private var middleColumn: some View {
        Group {
            if model.sidebarFilter == .trash {
                TrashListView()
            } else {
                ActiveItemList()
            }
        }
        .frame(minWidth: 300)
        .toolbar {
            ToolbarItemGroup {
                Menu {
                    ForEach(FfiItemCategory.editableCategories, id: \.self) { category in
                        Button {
                            newSheetCategory = category
                        } label: {
                            Label(category.displayName, systemImage: category.symbolName)
                        }
                    }
                } label: {
                    Label("新建", systemImage: "plus")
                }
                Button {
                    model.lock()
                } label: {
                    Label("锁定", systemImage: "lock")
                }
            }
        }
    }

    // MARK: - 详情

    @ViewBuilder
    private var detailPane: some View {
        if let details = model.currentDetails {
            ItemDetailView(details: details)
                .id(details.uuid)
        } else {
            VStack(spacing: 10) {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.system(size: 40))
                    .foregroundStyle(.secondary)
                Text("选择左侧列表中的条目查看详情")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: - 新建条目 sheet 的 category Identifiable 适配

extension FfiItemCategory: Identifiable {
    public var id: String { displayName }
}

// MARK: - 活动条目列表

struct ActiveItemList: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        List(selection: $model.selectedItemID) {
            ForEach(model.items) { summary in
                HStack {
                    Image(systemName: summary.category.symbolName)
                        .foregroundStyle(.tint)
                        .frame(width: 22)
                    Text(summary.title)
                        .lineLimit(1)
                    Spacer()
                    if summary.isFavorite {
                        Image(systemName: "star.fill")
                            .font(.caption)
                            .foregroundStyle(.yellow)
                    }
                }
                .tag(summary.uuid)
            }
        }
        .overlay {
            if model.items.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: model.searchText.isEmpty ? "tray" : "magnifyingglass")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text(model.searchText.isEmpty ? "暂无条目" : "无匹配结果").font(.headline)
                    Text(model.searchText.isEmpty ? "点击工具栏「新建」创建第一个条目" : "换个关键词试试")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "按标题搜索")
        .onChange(of: model.searchText) { _, _ in
            model.reloadItems()
        }
        .navigationTitle(navigationTitleText)
    }

    private var navigationTitleText: String {
        switch model.sidebarFilter {
        case .all: return "全部条目"
        case .favorites: return "收藏"
        case .category(let category): return category.displayName
        case .trash: return "回收站"
        }
    }
}
