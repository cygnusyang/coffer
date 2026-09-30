// MainView.swift —— 解锁后的主界面：侧栏（分类筛选）+ 列表（搜索）+ 详情。

import SwiftUI

struct MainView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var newSheetCategory: FfiItemCategory?
    // showImport / showExport / showSettings 提升到 AppModel（@Published）：
    // 菜单栏「数据」菜单（⌘I / ⌘E / ⌘,）需要跨视图触发同一 sheet，
    // @State 无法从 commands 访问（验收反馈：菜单里没有导入导出）。

    var body: some View {
        NavigationSplitView {
            sidebar
        } content: {
            middleColumn
        } detail: {
            detailPane
        }
        // 备份提醒横幅（FR-8.5，T-G）：挂在中栏（列表列）顶部——
        // 不挂 NavigationSplitView 顶层：macOS 上 safeAreaInset(.top) 与
        // 窗口工具栏同区，横幅文字与工具栏按钮重叠（验收发现，已修）。
        // onAppear 的 safeAreaInset 见 middleColumn。
        // 备份提醒横幅（FR-8.5）：挂整个窗口右下角（用户裁定：详情区
        // 上方悬浮、最上层，不挤占任何内容区布局；overlay 不入工具栏
        // 区域，无早期 safeAreaInset(.top) 的重叠问题）
        .overlay(alignment: .bottomTrailing) {
            if model.showBackupBanner {
                backupBanner
                    .padding(12)
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
        // 浮动卡片样式（右下角悬浮）：材质底 + 圆角 + 阴影，与列表内容
        // 视觉分层；固定宽度防文案换行错乱。
        VStack(alignment: .leading, spacing: 10) {
            Label("距上次备份已超过 \(model.backupReminderDays) 天，建议备份以防数据丢失",
                  systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
            HStack(spacing: 10) {
                Spacer()
                Button("暂不") {
                    model.dismissBackupBanner()
                }
                Button("立即备份") {
                    model.showExport = true
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(14)
        .frame(width: 380)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(.yellow.opacity(0.4), lineWidth: 1)
        )
        .shadow(color: .black.opacity(0.18), radius: 8, y: 2)
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
                // 安全体检入口（FR-6.2–6.7，v0.3.0-T05 T-D）
                Label("安全体检", systemImage: "cross.case.fill").tag(SidebarFilter.health)
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
            } else if model.sidebarFilter == .health {
                // 安全体检页（FR-6.2–6.7，T-D）：整页视图，不走条目列表
                HealthCheckView()
            } else {
                ActiveItemList()
            }
        }
        .frame(minWidth: 300)
        .toolbar {
            ToolbarItemGroup {
                // 库切换器入口（v0.4 FR-1.2，MB-1）：当前库名 + 下拉，
                // sheet 承载库列表 / 新建库（docs/15 §3.2.1）
                Menu {
                    Button("切换密码库…") { model.showVaultSwitcher = true }
                } label: {
                    Label(model.vaultName.isEmpty ? "密码库" : model.vaultName,
                          systemImage: "vault")
                }
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
                    model.showSettings = true
                } label: {
                    Label("设置", systemImage: "gearshape")
                }
                // 导入入口菜单（v0.3.0-T05 FR-7.1；v0.5.0 PK3 增 Bitwarden 源）：三格式并列
                Menu {
                    Button("CSV…") { model.showImport = true }
                    Button("1Password (.1pux)…") { model.showImportPux = true }
                    Button("Bitwarden (.json)…") { model.showImportBitwarden = true }
                } label: {
                    Label("导入", systemImage: "square.and.arrow.down")
                }
                // 加密备份导出入口（FR-8.1/8.6，T-E；底层契约锁定态可用，
                // UI 入口置于解锁后主界面，TC-EXP-08）
                Button {
                    model.showExport = true
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
        .sheet(isPresented: $model.showImport) {
            ImportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showImportPux) {
            PuxImportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showImportBitwarden) {
            BitwardenImportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showExport) {
            ExportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showSettings) {
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
        // FR-11.2 文案收尾（v0.4 MB-1 并入，docs/15 §3.3.5）：内核 search
        // 即模糊搜索（标题/用户名/网址/标签），仅此提示文案过时
        .searchable(text: $model.searchText, placement: .toolbar,
                    prompt: "搜索标题、用户名、网址、标签")
        .onChange(of: model.searchText) { _, _ in
            model.reloadItems()
        }
        .navigationTitle(navigationTitleText)
        // HK-2/3/4 主窗口局部键（v0.4 MC，docs/15 §3.3.2 r1.4）：以隐藏
        // 按钮 + keyboardShortcut 承载——列表无焦点（如焦点在搜索框）时
        // 同样触发，判据①「搜索 → 回车复制」链路依赖此形态
        .background {
            hotKeyActions
        }
    }

    private var navigationTitleText: String {
        switch model.sidebarFilter {
        case .all: return "全部条目"
        case .favorites: return "收藏"
        case .category(let category): return category.displayName
        case .trash: return "回收站"
        // 防御分支：.health 下中栏渲染 HealthCheckView，本标题不可达。
        case .health: return "安全体检"
        }
    }

    // MARK: - 主窗口局部键（HK-2/3/4，docs/15 §3.3.2 r1.4）

    /// 隐藏快捷键按钮组：⌘U 复制用户名的禁用态由按钮 disabled 承载
    /// （无用户名 = 禁用，快捷键随之失效）；Enter/↑/↓ 恒可用（无选中
    /// 时动作内 guard 兜底）。.hidden() 不移出视图层级，快捷键仍注册。
    private var hotKeyActions: some View {
        Group {
            Button("上移选中") { moveSelection(-1) }
                .keyboardShortcut(.upArrow, modifiers: [])
            Button("下移选中") { moveSelection(1) }
                .keyboardShortcut(.downArrow, modifiers: [])
            Button("复制选中条目密码") { copySelectedPassword() }
                .keyboardShortcut(.defaultAction)
                .disabled(model.currentDetails == nil)
            Button("复制选中条目用户名") { copySelectedUsername() }
                .keyboardShortcut("u", modifiers: .command)
                .disabled(selectedUsername == nil)
        }
        .hidden()
        .accessibilityHidden(true)
    }

    /// 选中条目的用户名值（nil = 无选中 / 无用户名字段 / 值为空——HK-4
    /// 禁用态依据）。用户名为普通字段，值已随详情直出（掩码纪律只约束
    /// Concealed 字段），不经 fieldValue 跨桥。
    private var selectedUsername: String? {
        guard let field = model.currentDetails?.fields.first(where: {
            $0.designation == .username
        }), let value = field.value, !value.isEmpty else { return nil }
        return value
    }

    /// HK-2：结果列表移动选中（相对当前选中 ±offset）。无选中时 ↓ 到
    /// 第一条、↑ 到最后一条（Finder 语义）；越界钳制到两端。
    private func moveSelection(_ offset: Int) {
        let ids = model.items.map(\.uuid)
        guard !ids.isEmpty else { return }
        let next: Int
        switch model.selectedItemID.flatMap({ ids.firstIndex(of: $0) }) {
        case nil:
            next = offset > 0 ? 0 : ids.count - 1
        case let current?:
            next = min(max(current + offset, 0), ids.count - 1)
        }
        model.selectedItemID = ids[next]
    }

    /// HK-3：复制选中条目密码（FR-5.6 序列，docs/15 §3.3.3）：条目含
    /// TOTP（details.totp 非空）才走「密码 → 延迟 → TOTP」序列，否则
    /// 单次自动清除复制（现状）。明文经 fieldValue 随取随用，不落状态。
    private func copySelectedPassword() {
        guard let itemId = model.selectedItemID,
              let details = model.currentDetails,
              let passwordField = details.fields.first(where: {
                  $0.designation == .password
              }) else { return }
        do {
            guard let password = try model.fieldValue(itemId: itemId, fieldId: passwordField.uuid),
                  !password.isEmpty else { return }
            if details.totp != nil {
                // totpProvider 延迟执行取 fresh code；闭包体内访问
                // @MainActor 的 AppModel，经 assumeIsolated 进入——
                // ClipboardManager 保证回调只在主队列触发
                ClipboardManager.shared.copyPasswordThenTotp(password: password) {
                    MainActor.assumeIsolated { try? model.totpCode(itemId: itemId).code }
                }
            } else {
                ClipboardManager.shared.copyWithAutoClear(password)
            }
        } catch {
            // 1001（取值时会话已锁）→ 切回锁定界面；其余 code+message 直出
            model.handleFfiError(error)
        }
    }

    /// HK-4：复制用户名（copyPlain 不自动清除，与 FieldRowView 普通字段
    /// 复制同纪律）。无用户名由按钮禁用态拦截，此处 guard 兜底。
    private func copySelectedUsername() {
        guard let username = selectedUsername else { return }
        ClipboardManager.shared.copyPlain(username)
    }
}
