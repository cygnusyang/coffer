// CofferApp.swift —— 应用入口（@main）。
//
// 命名注意：UniFFI 生成的绑定里已有一个 `CofferApp` 类（Rust 工厂对象），
// 因此本文件的入口结构体命名为 `CofferMainApp`，避免类型名冲突。
//
// v0.4 MC-1（docs/15 §3.3.1 / §3.3.2；选型 docs/research-v0.4-menubar-hotkey.md）：
//   - 菜单栏常驻（FR-13.3）：状态行 + 打开主窗口 + 快速搜索 + 锁定全部 +
//     退出。只放状态与动作，不放文本输入（research §2：.window 样式有键盘
//     焦点缺陷，不采用）。v0.5.0 起由 AppKit NSStatusItem 实现
//     （Platform/StatusItemController.swift；PL-6：macOS 26 MenuBarExtra
//     图标空白，仅占位不渲染）。
//   - 全局快捷键 ⌥⌘P 呼出/聚焦主窗口（FR-4.5 HK-1；注册失败静默降级，
//     见 Platform/HotKeyMonitor.swift）。
//   - 关窗驻留：applicationShouldTerminateAfterLastWindowClosed = false
//     （2026-09-29 用户裁定采纳；不设 LSUIElement，保持常规 App）。

import SwiftUI

@main
struct CofferMainApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self)
    private var appDelegate

    @StateObject
    private var model = AppModel()

    var body: some Scene {
        WindowGroup("Coffer") {
            // AppDelegate.model 接线点：必须在 RootView.onAppear 而非 App.init——
            // @StateObject 在 App.init 阶段尚未安装，访问它会新建临时实例且随即
            // 释放（SwiftUI 运行时警告实证，PL-6 复验打回根因），weak 引用随之
            // 归 nil。onAppear 时 model 是已安装的真实实例；attach 幂等。
            RootView()
                .environmentObject(model)
                .frame(minWidth: 820, minHeight: 540)
                .onAppear { appDelegate.attach(model: model) }
        }
        .windowToolbarStyle(.unified)
        .commands {
            // 「数据」菜单（验收反馈：菜单里没有导入/导出）：与工具栏
            // 触发同一 sheet 状态（AppModel @Published）。锁定态禁用——
            // 导入需解锁态（1001 门禁）、导出/设置入口在主界面（解锁区）。
            CommandMenu("数据") {
                Button("导入 CSV…") { model.showImport = true }
                    .keyboardShortcut("i", modifiers: .command)
                    .disabled(model.phase != .unlocked)
                // 1PUX 导入（v0.3.0-T05 FR-7.1）：import1pux 有 1001 门禁
                // （需解锁态），与 CSV 同纪律禁用于锁定态
                Button("导入 1Password (.1pux)…") { model.showImportPux = true }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .disabled(model.phase != .unlocked)
                // Bitwarden 导入（v0.5.0 PK3）：import_bitwarden_json 有 1001
                // 门禁（需解锁态），与 CSV/1PUX 同纪律禁用于锁定态
                Button("导入 Bitwarden (.json)…") { model.showImportBitwarden = true }
                    .disabled(model.phase != .unlocked)
                Button("导出…") { model.showExport = true }
                    .keyboardShortcut("e", modifiers: .command)
                    .disabled(model.phase != .unlocked)
                Divider()
                Button("设置…") { model.showSettings = true }
                    .keyboardShortcut(",", modifiers: .command)
                    .disabled(model.phase != .unlocked)
            }
        }

        // 菜单栏常驻（FR-13.3）已迁往 Platform/StatusItemController.swift
        // （v0.5.0 PL-6：NSStatusItem 取代 MenuBarExtra，菜单结构与语义一致）。
    }
}

/// 应用生命周期回调：全局快捷键注册（MC-1）+ 关窗驻留 + 主窗口呼出 +
/// 菜单栏常驻（PL-6）+ 退出前锁定全部会话。
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// AppModel 引用（strong）。供退出回调、呼出焦点判定与菜单栏状态行使用
    /// （只读 phase；呼出动作本身不经 AppModel——docs/15 §6.1 S3 切片）。
    ///
    /// 必须 strong：AppDelegate 生命周期 = App 生命周期，AppModel 不反向持有
    /// AppDelegate，无循环。原 weak 实现被 PL-6 复验打穿——App.init 里用未安装
    /// 的 @StateObject 临时实例赋值，实例随即释放，weak 归 nil；接线改由
    /// RootView.onAppear 的 attach(model:) 完成（幂等）。
    private(set) var model: AppModel?

    /// 菜单栏状态项已启动标志（attach 幂等：onAppear 可能重复触发，只启一次）。
    private var statusItemStarted = false

    /// 全局快捷键监视（FR-4.5 HK-1；注册失败静默降级为仅菜单栏入口）。
    private let hotKeyMonitor = HotKeyMonitor()

    /// 菜单栏常驻 NSStatusItem 控制器（v0.5.0 PL-6：NSStatusItem 取代
    /// MenuBarExtra，macOS 26 MenuBarExtra 图标空白）。
    private let statusItemController = StatusItemController()

    /// 接线真实 AppModel 并启动菜单栏常驻（RootView.onAppear 调用；幂等）。
    /// 首次调用同时启动 StatusItemController（PL-6：NSStatusItem 取代
    /// MenuBarExtra）；后续重复 onAppear 仅刷新 model 引用，不重复启动。
    func attach(model: AppModel) {
        self.model = model

        guard !statusItemStarted else { return }
        statusItemStarted = true
        statusItemController.start(model: model) { [weak self] focusText in
            self?.summonMainWindow(focusText: focusText)
        }
    }

    /// 关窗驻留（v0.4 出口判据②，2026-09-29 裁定采纳）：关主窗口后 App
    /// 驻留菜单栏，退出只经菜单「退出」/⌘Q。自动锁定语义不受影响——会话
    /// 按空闲超时/锁屏锁定，与窗口可见性解耦（docs/15 §3.3.1）。
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 全局快捷键注册：失败静默降级（不阻塞启动、不崩溃，菜单栏入口
        // 仍可用），原因与 OSStatus 写诊断日志（HotKeyMonitor 内部处理）。
        // 菜单栏常驻不在此启动：model 此刻尚未接线（@StateObject 未安装，
        // App.init 访问会造临时实例），由 RootView.onAppear 的 attach(model:)
        // 幂等启动（见 attach 与 body 注释）。
        hotKeyMonitor.start { [weak self] action in
            self?.handleHotKeyAction(action)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // 先反注册热键（清理 Carbon 资源）、移除状态栏项，再锁定全部会话
        // 触发 Rust 侧密钥清零（docs/07 R-4）
        hotKeyMonitor.stop()
        statusItemController.stop()
        model?.lockAllForTermination()
    }

    // MARK: - 全局快捷键动作

    private func handleHotKeyAction(_ action: HotKeyAction) {
        switch action {
        case .summonMainWindow:
            summonMainWindow(focusText: true)
        }
    }

    // MARK: - 主窗口呼出（HK-1 与菜单项共用）

    /// 呼出/聚焦主窗口（docs/15 §3.3.2：不经 AppModel）——activate 自身 +
    /// makeKeyAndOrderFront。focusText 时按 phase（只读）判定焦点落点：
    /// 解锁态 → 工具栏搜索框（.searchable）；锁定态 → LockView 主密码输入
    /// 框（判据①「锁定 → 快捷键 → 解锁 → 搜索 → 复制」通路的入口步）。
    /// 已在本 App 前台聚焦且无 sheet 挂载时隐藏窗口（HK-1「显示/隐藏」
    /// 语义；sheet 挂载时不隐藏，避免连 sheet 一起消失）。
    func summonMainWindow(focusText: Bool) {
        guard let window = Self.mainWindow else { return }
        if focusText, window.isKeyWindow, window.attachedSheet == nil {
            window.orderOut(nil)
            return
        }
        // 呼出场景自动 Touch ID 引导（用户 2026-10-03 裁定，docs/08 §7.6）：
        // 窗口确从隐藏恢复（关窗驻留后重新呼出）才考虑——窗口本就可见
        // （自动锁定后直接手点解锁）不自动弹。判定与防重入（同一次锁定态
        // 只弹一次）在 AppModel.maybeAutoPromptBiometric。
        let wasHidden = !window.isVisible
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        if wasHidden {
            model?.maybeAutoPromptBiometric()
        }
        guard focusText else { return }
        scheduleTextInputFocus(window: window)
    }

    /// 聚焦窗口内文本输入控件（有限次重试：窗口刚 order front 时 SwiftUI
    /// 可能尚未布局锁定态的 SecureField / 未创建工具栏搜索框，重试兜底）。
    private func scheduleTextInputFocus(window: NSWindow, remainingAttempts: Int = 5) {
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(80)) { [weak self] in
            guard let self, window.isVisible else { return }
            if self.focusTextInput(in: window) { return }
            if remainingAttempts > 1 {
                self.scheduleTextInputFocus(window: window, remainingAttempts: remainingAttempts - 1)
            }
        }
    }

    /// 按锁定相位聚焦对应输入控件；找到并聚焦成功（或该相位无需聚焦）
    /// 返回 true 停止重试，未找到（相变中/未布局）返回 false 继续重试。
    private func focusTextInput(in window: NSWindow) -> Bool {
        switch model?.phase {
        case .unlocked:
            guard let field = Self.searchField(in: window) else { return false }
            // makeFirstResponder 失败（字段未挂上视图树）→ 继续重试；
            // selectText 全选现有词，直接输入即替换
            guard window.makeFirstResponder(field) else { return false }
            field.selectText(nil)
            return true
        case .locked:
            guard let field = Self.firstEditableTextField(in: window) else { return false }
            return window.makeFirstResponder(field)
        default:
            // noVault / booting / fatal：展示窗口即可，无输入聚焦点
            return true
        }
    }

    /// 工具栏搜索框（MainView .searchable → NSSearchToolbarItem）；
    /// contentView 递归扫描兜底（防 SwiftUI 内部结构变化致 toolbar 路径落空）。
    private static func searchField(in window: NSWindow) -> NSSearchField? {
        if let item = window.toolbar?.items.compactMap({ $0 as? NSSearchToolbarItem }).first {
            return item.searchField
        }
        guard let content = window.contentView else { return nil }
        return firstSubview(of: content, where: { $0 is NSSearchField }) as? NSSearchField
    }

    /// 窗口内第一个可编辑文本控件（锁定态 = LockView 的主密码 SecureField，
    /// 渲染为 NSSecureTextField——NSTextField 子类，走同一扫描）。
    private static func firstEditableTextField(in window: NSWindow) -> NSTextField? {
        guard let content = window.contentView else { return nil }
        return firstSubview(of: content, where: { view in
            guard let field = view as? NSTextField else { return false }
            return field.isEditable && field.isEnabled
        }) as? NSTextField
    }

    /// 深度优先找第一个命中子视图。
    private static func firstSubview(of view: NSView, where predicate: (NSView) -> Bool) -> NSView? {
        if predicate(view) { return view }
        for subview in view.subviews {
            if let hit = firstSubview(of: subview, where: predicate) { return hit }
        }
        return nil
    }

    /// 主窗口定位（SwiftUI WindowGroup 唯一窗口）：排除 NSPanel（状态栏类
    /// 窗口）与 sheet（sheetParent 非空）。关窗驻留后窗口实例仍在
    /// NSApp.windows 中（仅不可见），可直接 makeKeyAndOrderFront 复原。
    private static var mainWindow: NSWindow? {
        NSApp.windows.first { !($0 is NSPanel) && $0.sheetParent == nil }
    }
}
