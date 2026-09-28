// CofferApp.swift —— 应用入口（@main）。
//
// 命名注意：UniFFI 生成的绑定里已有一个 `CofferApp` 类（Rust 工厂对象），
// 因此本文件的入口结构体命名为 `CofferMainApp`，避免类型名冲突。

import SwiftUI

@main
struct CofferMainApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self)
    private var appDelegate

    @StateObject
    private var model = AppModel()

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
                Button("导出…") { model.showExport = true }
                    .keyboardShortcut("e", modifiers: .command)
                    .disabled(model.phase != .unlocked)
                Divider()
                Button("设置…") { model.showSettings = true }
                    .keyboardShortcut(",", modifiers: .command)
                    .disabled(model.phase != .unlocked)
            }
        }
    }
}

/// 应用生命周期回调：退出前通知 AppModel 锁定全部会话。
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// AppModel 在启动后注册自己，供退出回调使用。
    weak var model: AppModel?

    func applicationWillTerminate(_ notification: Notification) {
        // 进程退出兜底：锁定全部会话，触发 Rust 侧密钥清零（docs/07 R-4）。
        model?.lockAllForTermination()
    }
}
