// MainView.swift —— 解锁后的主界面：侧栏（分类筛选）+ 列表（搜索）+ 详情。

import SwiftUI

struct MainView: View {
    @EnvironmentObject
    private var model: AppModel

    // showImport / showExport / newSheetCategory 提升到 AppModel（@Published）：
    // 菜单栏「数据」菜单（⌘I / ⌘E / ⌘,）与 P7 ⌘N CommandGroup 需要跨视图触发
    // 同一 sheet，@State 无法从 commands 访问（验收反馈：菜单里没有导入导出）。
    // 设置（⌘,）v2.4.1 改独立窗口：不再走 showSettings，经 openWindow(id:
    // "settings") 触发（见 CofferApp 的 Window scene），本视图与菜单共用。
    @Environment(\.openWindow)
    private var openWindow

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
        // P4（v2.9.0）：选择任一列表条目即退出安全体检 destination 回条目详情
        // （跳条目路径 HealthCheckView.jump 已先行清位，此处对程序性选中为 no-op）。
        .onChange(of: model.selectedItemID) { _, _ in
            model.showHealthDestination = false
        }
        .sheet(item: $model.pendingNewCategory) { category in
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
                // 库切换器入口（v0.4 FR-1.2，MB-1）：当前库名 + 下拉，
                // sheet 承载库列表 / 新建库（docs/15 §3.2.1）
                Menu {
                    Button("切换密码库…") { model.showVaultSwitcher = true }
                } label: {
                    Label(model.vaultName.isEmpty ? "密码库" : model.vaultName,
                          systemImage: "archivebox")
                    // 注：SF Symbol 无 "vault"（本机实测 MISSING，无效名渲染为
                    // 空白——多仓库切换入口图标曾空显）；archivebox=「库」箱柜
                    // 隐喻，与锁定态 lock/lock.fill 不混淆。
                }
                // 安全体检入口（v2.9.0 P4，docs/14 §A P4 §2）：主入口，发现性
                // 优先（工具栏）。toggle 语义：点击进入详情区整页体检；再次
                // 点击退出回条目详情（选择任一列表条目同样退出，见下方
                // onChange(of: model.selectedItemID)）。
                Button {
                    model.showHealthDestination.toggle()
                } label: {
                    Label("安全体检", systemImage: "cross.case.fill")
                }
                Menu {
                    ForEach(FfiItemCategory.editableCategories, id: \.self) { category in
                        Button {
                            model.pendingNewCategory = category
                        } label: {
                            Label(category.displayName, systemImage: category.symbolName)
                        }
                    }
                } label: {
                    Label("新建", systemImage: "plus")
                }
                // 统一设置入口（docs/09-v0.2实现方案.md §3.7）
                // v2.4.1：改独立窗口（openWindow id "settings"，左上角红绿灯关闭）
                // M-2（docs/15 §2.4，AC-2.10.0-A1-10）：首启向导置位期间
                // （pendingBioOffer || pendingRecoveryOffer）禁用——与菜单栏
                // 「设置…」同谓词（对齐 phase != .unlocked 纪律），向导内设置
                // 窗结构性不可达，消除并发覆盖路径；向导收口后恢复可开。
                Button {
                    openWindow(id: "settings")
                } label: {
                    Label("设置", systemImage: "gearshape")
                }
                .disabled(model.phase != .unlocked
                          || model.pendingBioOffer || model.pendingRecoveryOffer)
                // 导入入口菜单（v0.3.0-T05 FR-7.1；v0.5.0 PK3 增 Bitwarden 源；
                // v0.7.0-T06 增 OPVault）：四格式并列
                Menu {
                    Button("CSV…") { model.showImport = true }
                    Button("1Password (.1pux)…") { model.showImportPux = true }
                    Button("Bitwarden (.json)…") { model.showImportBitwarden = true }
                    Button("1Password (OPVault)…") { model.showImportOpvault = true }
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
        .sheet(isPresented: $model.showImportOpvault) {
            OpvaultImportView()
                .environmentObject(model)
        }
        .sheet(isPresented: $model.showExport) {
            ExportView()
                .environmentObject(model)
        }
    }

    // MARK: - 详情

    @ViewBuilder
    private var detailPane: some View {
        // P4（v2.9.0）：详情区按优先级渲染——安全体检整页 destination 最优先，
        // 覆盖条目详情与「未选中」占位（docs/14 §A P4 §2）。
        if model.showHealthDestination {
            HealthCheckView()
        } else if let details = model.currentDetails {
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
            // 空态 overlay 分三路（issue #2 + H-1 收窄）：搜索态「无匹配结果」
            // 保持纯文本原样（空态下给按钮会误导为可导入）；双按钮主路径仅
            // 限 `sidebarFilter == .all` 的真·全库空——按收藏/分类筛选出的空
            // 列表，新建/导入的条目不会落在当前筛选下，带按钮会「导入了却
            // 没看到」困惑，只给纯文本提示。
            if model.items.isEmpty {
                if model.searchText.isEmpty {
                    if model.sidebarFilter == .all {
                        emptyVaultPrompt
                    } else {
                        filterEmptyPrompt
                    }
                } else {
                    noMatchPrompt
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
        }
    }

    // MARK: - 空态提示（issue #2）

    /// 真·全库空（sidebarFilter == .all 且无搜索词）空态：图标 + 「暂无
    /// 条目」+ 两条主路径按钮。「新建第一个条目」置 `.login`（与 ⌘N 同
    /// 默认类别，docs/14 P7 §3.1）；「导入已有密码…」为四格式 Menu，与
    /// 工具栏「导入」菜单同源同标签（issue #2 裁定：从 1Password 等来的
    /// 用户点按钮须直接选格式，不得落进 CSV 向导错向）。筛选空 / 搜索态
    /// 分别走 filterEmptyPrompt / noMatchPrompt，不重复此双按钮（H-1）。
    private var emptyVaultPrompt: some View {
        VStack(spacing: 12) {
            Image(systemName: "tray")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("暂无条目").font(.headline)
            HStack(spacing: 10) {
                Button("新建第一个条目") {
                    model.pendingNewCategory = .login
                }
                .buttonStyle(.borderedProminent)
                Menu {
                    Button("CSV…") { model.showImport = true }
                    Button("1Password (.1pux)…") { model.showImportPux = true }
                    Button("Bitwarden (.json)…") { model.showImportBitwarden = true }
                    Button("1Password (OPVault)…") { model.showImportOpvault = true }
                } label: {
                    Text("导入已有密码…")
                }
                .menuStyle(.borderedButton)
            }
        }
    }

    /// 非 .all 筛选（收藏/分类）下列表为空的纯文本提示（H-1 收窄）：双
    /// 按钮主路径只属真·全库空；筛选空时新建/导入的条目不会落在当前筛选
    /// 下，故只给文案不给按钮。「暂无收藏/该分类暂无条目」区分筛选语境；
    /// .trash 不进本视图（TrashListView 独立渲染），.all 空态由
    /// emptyVaultPrompt 接管。
    private var filterEmptyPrompt: some View {
        VStack(spacing: 10) {
            Image(systemName: "tray")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(filterEmptyTitle).font(.headline)
        }
    }

    private var filterEmptyTitle: String {
        switch model.sidebarFilter {
        case .favorites: return "暂无收藏"
        case .category: return "该分类暂无条目"
        case .all, .trash: return "暂无条目"
        }
    }

    /// 搜索「无匹配结果」空态（issue #2：保持原样，不加按钮——搜索态下
    /// 双按钮会误导为「空库可导入」）。
    private var noMatchPrompt: some View {
        VStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("无匹配结果").font(.headline)
            Text("换个关键词试试")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - 主窗口上下文键（↑/↓/Enter，docs/14 §A P7 §2.2；HK-2/3/4 回归）

    /// 隐藏快捷键按钮组：↑/↓/Enter **保留在列表视图层**（D-9.1 上下文键模式，
    /// 不迁 CommandGroup，docs/14 §A P7 §2.2 / B.2 硬约束）。应用级
    /// ⌘N/⌘L/⌘⇧C/⌘U/⌥⇧C 已迁 CofferApp CommandGroup（⌘U 自本组迁出，语义
    /// 与禁用条件不变——HK-4 回归，谓词上收 model.canCopyUsername）：
    ///   - ↑/↓ 移动选中：注册裸方向键为应用级会全局劫持文本编辑/滚动箭头
    ///     （搜索框光标移动、文本区滚动），破坏编辑场景；
    ///   - Enter 默认动作复制密码：应用级 .defaultAction 会与任意 sheet/alert
    ///     的默认按钮（保存/确定）抢回车，编辑 sheet 内触发复制是错误行为；
    ///     判据①「搜索 → 回车复制」链路依赖列表级注册。
    ///   - Enter 禁用谓词与 ⌘⇧C 同源（model.canCopyPassword，REV2-08）——
    ///     secureNote 等无密码字段的条目 Enter 与菜单一致禁用。
    /// .hidden() 不移出视图层级，快捷键仍注册。
    private var hotKeyActions: some View {
        Group {
            Button("上移选中") { moveSelection(-1) }
                .keyboardShortcut(.upArrow, modifiers: [])
            Button("下移选中") { moveSelection(1) }
                .keyboardShortcut(.downArrow, modifiers: [])
            Button("复制选中条目密码") { model.copySelectedPassword() }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canCopyPassword)
        }
        .hidden()
        .accessibilityHidden(true)
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
}
