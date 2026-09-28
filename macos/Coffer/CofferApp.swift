// CofferApp.swift —— 应用入口（@main）。
//
// 命名注意：UniFFI 生成的绑定里已有一个 `CofferApp` 类（Rust 工厂对象），
// 因此本文件的入口结构体命名为 `CofferMainApp`，避免类型名冲突。
//
// v0.4 MC-1（docs/15 §3.3.1 / §3.3.2；选型 docs/research-v0.4-menubar-hotkey.md）：
//   - MenuBarExtra(.menu) 菜单栏常驻（FR-13.3）：状态行 + 打开主窗口 +
//     快速搜索 + 锁定全部 + 退出。只放状态与动作，不放文本输入
//     （research §2：.window 样式有键盘焦点缺陷，不采用）。
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

    init() {
        // AppDelegate.model 接线：applicationWillTerminate 的 lockAll 兜底
        // 此前从未生效（weak model 无人赋值——docs/15 §3.3.1 引用的「兜底
        // lockAll 已有」实为死路径，MC-1 修复）。delegate 由 adaptor 在
        // App init 前创建，此处是唯一赋值点。
        appDelegate.model = model
    }

    var body: some Scene {
        WindowGroup("Coffer") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 820, minHeight: 540)
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
                Button("导出…") { model.showExport = true }
                    .keyboardShortcut("e", modifiers: .command)
                    .disabled(model.phase != .unlocked)
                Divider()
                Button("设置…") { model.showSettings = true }
                    .keyboardShortcut(",", modifiers: .command)
                    .disabled(model.phase != .unlocked)
            }
        }

        // 菜单栏常驻（FR-13.3，docs/15 §3.3.1 菜单项路由表）。S3 切片
        // 纪律（docs/15 §6.1）：只读消费 AppModel + 调既有 API，不新增
        // 不改 AppModel 状态机。
        MenuBarExtra("Coffer", systemImage: menuBarIcon) {
            Section {
                // 状态行（只读）：库名 + 锁定/已解锁（锁定态显式「已锁定」）
                Text(menuStatusLine)
            }
            Divider()
            Button("打开主窗口") { appDelegate.summonMainWindow(focusText: false) }
            // 快速搜索…：呼出/聚焦主窗口搜索框（research §6 判据①落主窗口
            // 聚焦，不建独立面板）；锁定态可用——窗口内先展示解锁页
            Button("快速搜索…") { appDelegate.summonMainWindow(focusText: true) }
                .keyboardShortcut("p", modifiers: [.command, .option])
            Divider()
            Button("锁定全部") {
                // 既有 API 双保险（docs/15 §3.3.1）：factory 全局锁所有会话
                // + model.lock() 清 UI 状态与剪贴板；均幂等，锁定态可用
                model.factory.lockAll()
                model.lock()
            }
            Divider()
            Button("退出 Coffer") { NSApp.terminate(nil) }
        }
        .menuBarExtraStyle(.menu)
    }

    /// 菜单栏状态行文案（只读派生，不改 AppModel）。
    private var menuStatusLine: String {
        switch model.phase {
        case .booting:
            return "正在打开…"
        case .noVault:
            return "未创建密码库"
        case .locked:
            return model.vaultName.isEmpty ? "已锁定" : "\(model.vaultName)（已锁定）"
        case .unlocked:
            return model.vaultName.isEmpty ? "已解锁" : "\(model.vaultName)（已解锁）"
        case .fatal:
            return "启动失败"
        }
    }

    /// 菜单栏图标随锁定相位切换（只读派生）。
    private var menuBarIcon: String {
        model.phase == .unlocked ? "lock.open.square" : "lock.square"
    }
}

/// 应用生命周期回调：全局快捷键注册（MC-1）+ 关窗驻留 + 主窗口呼出 +
/// 退出前锁定全部会话。
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// AppModel 在 App init 时注册自己，供退出回调与呼出焦点判定使用
    /// （只读 phase；呼出动作本身不经 AppModel——docs/15 §6.1 S3 切片）。
    weak var model: AppModel?

    /// 全局快捷键监视（FR-4.5 HK-1；注册失败静默降级为仅菜单栏入口）。
    private let hotKeyMonitor = HotKeyMonitor()

    /// 关窗驻留（v0.4 出口判据②，2026-09-29 裁定采纳）：关主窗口后 App
    /// 驻留菜单栏，退出只经菜单「退出」/⌘Q。自动锁定语义不受影响——会话
    /// 按空闲超时/锁屏锁定，与窗口可见性解耦（docs/15 §3.3.1）。
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 全局快捷键注册：失败静默降级（不阻塞启动、不崩溃，菜单栏入口
        // 仍可用），原因与 OSStatus 写诊断日志（HotKeyMonitor 内部处理）
        hotKeyMonitor.start { [weak self] action in
            self?.handleHotKeyAction(action)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // 先反注册热键（清理 Carbon 资源），再锁定全部会话触发 Rust 侧
        // 密钥清零（docs/07 R-4）
        hotKeyMonitor.stop()
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
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
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
