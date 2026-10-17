// ShortcutsSheet.swift —— 键盘快捷键速查面板（v2.9.1，GitLab issue #5）。
//
// 静态只读面板：分组列出应用级与列表级快捷键，供用户自查（快捷键此前
// 无任何速查入口，issue #5 可发现性修复）。内容与 CofferApp.swift 的
// CommandGroup / 内联数据菜单 / HotKeyMonitor 实际注册逐一核对过（实读
// 代码，有出入以代码为准）：
//   - ⌥⌘P 为 HK-1 全局呼出/隐藏主窗口（HotKeyMonitor，非库切换）；
//     库切换无快捷键（仅工具栏按钮触发 showVaultSwitcher）。
//
// 键位核对出处（仅维护期参考，不渲染；锚点用语义位置，行号随改动漂移）：
//   ⌘N/⌘L：CofferApp.swift `CommandGroup(replacing: .newItem)`
//   ⌘⇧C/⌘U/⌥⇧C：CofferApp.swift `CommandGroup(after: .pasteboard)`
//   ⌘I/⌘⇧I/⌘E/⌘,：CofferApp.swift 内联「数据」CommandMenu
//   ↑/↓/Enter：MainView.swift `hotKeyActions`（列表层上下文键，D-9.1）
//   ⌥⌘P：HotKeyMonitor.swift `HotKeyCombination.summonMainWindow`（HK-1）
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showShortcuts)，
// 由帮助菜单「键盘快捷键…」触发。帮助无密级，锁定/解锁态均可打开。
//
// 关闭纪律（与 HistorySheet / AboutUpdateView 一致）：关闭按钮挂
// .cancellationAction（Esc 生效），无按钮时 sheet 点外部不关闭。

import SwiftUI

struct ShortcutsSheet: View {
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("列表操作") {
                    row("上移 / 下移选中", "↑ / ↓")
                    row("复制选中条目密码", "⏎")
                    row("搜索框输入名称后回车直接复制", "⏎")
                }
                Section("条目操作") {
                    row("复制密码", "⌘⇧C")
                    row("复制用户名", "⌘U")
                    row("复制验证码", "⌥⇧C")
                }
                Section("通用") {
                    row("新建条目", "⌘N")
                    row("锁定 Coffer", "⌘L")
                    row("导入 CSV", "⌘I")
                    row("导入 1Password (.1pux)", "⌘⇧I")
                    row("导出", "⌘E")
                    row("设置", "⌘,")
                    row("呼出 / 隐藏主窗口", "⌥⌘P")
                }
            }
            .listStyle(.inset)
            .navigationTitle("键盘快捷键")
            .toolbar {
                // 只读面板关闭语义：「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
        .frame(width: 460, height: 460)
    }

    /// 单行快捷键条目：动作名左对齐 + 键位右对齐等宽字体（对齐 macOS
    /// 快捷键面板两列排版）。
    private func row(_ action: String, _ keys: String) -> some View {
        HStack {
            Text(action)
            Spacer()
            Text(keys)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}
