// MainView.swift —— 解锁后的主界面：侧栏（分类筛选）+ 列表（搜索）+ 详情。

import SwiftUI

struct MainView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var newSheetCategory: FfiItemCategory?
    @State private var showImport = false
    /// 加密备份导出 sheet（FR-8.1/8.6，T-E）。
    @State private var showExport = false
    /// 统一设置 sheet（docs/09-v0.2实现方案.md §3.7，T06 设置页归位：
    /// 自动锁定 / 剪贴板 / 备份提醒 / 安全 / 数据归位到 SettingsView，
    /// 取代原 autoLockMenu + 安全设置入口）。
    @State private var showSettings = false

    var body: some View {
        NavigationSplitView {
            sidebar
        } content: {
            middleColumn
        } detail: {
            detailPane
        }
        // 备份提醒横幅（FR-8.5，T-G）：挂在 split view 顶部安全区，
        // 不挤压三栏 content（safeAreaInset 标准做法）
        .safeAreaInset(edge: .top) {
            if model.showBackupBanner {
                backupBanner
            }
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

    // MARK: - 备份提醒横幅（FR-8.5，T-G）

    /// 黄色警示横幅：文案统一「距上次备份已超过 N 天」——从未备份时
    /// Rust 侧 lastBackupAt 为 nil 同样返回应提醒，无需区分文案（保持简单）。
    /// 「立即备份」保留横幅显示：导出成功回调（ExportView →
    /// evaluateBackupReminder）基于 Rust 新打点的 last_backup_at 重算，
    /// 横幅自动消失；「暂不」本会话隐藏，下次解锁重评估。
    private var backupBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
            Text("距上次备份已超过 \(model.backupReminderDays) 天，建议备份以防数据丢失")
                .font(.callout)
            Spacer()
            Button("立即备份") {
                showExport = true
            }
            Button("暂不") {
                model.dismissBackupBanner()
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.yellow.opacity(0.15))
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
                // 统一设置入口（docs/09-v0.2实现方案.md §3.7）
                Button {
                    showSettings = true
                } label: {
                    Label("设置", systemImage: "gearshape")
                }
                Button {
                    showImport = true
                } label: {
                    Label("导入 CSV", systemImage: "square.and.arrow.down")
                }
                // 加密备份导出入口（FR-8.1/8.6，T-E；底层契约锁定态可用，
                // UI 入口置于解锁后主界面，TC-EXP-08）
                Button {
                    showExport = true
                } label: {
                    Label("导出", systemImage: "arrow.up.doc")
                }
                Button {
                    model.lock()
                } label: {
                    Label("锁定", systemImage: "lock")
                }
            }
        }
        .sheet(isPresented: $showImport) {
            ImportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showExport) {
            ExportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showSettings) {
            SettingsView()
                .environmentObject(model)
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
