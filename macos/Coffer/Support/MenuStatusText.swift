// MenuStatusText.swift —— 菜单栏文案纯函数（Foundation-only，可独立单测）。
//
// v2.11.0（2026-10-16 用户裁定）自 StatusItemController.swift 抽出：菜单栏取消
// 永久 disabled 的纯展示状态行（「可用不灰、永久不可用不占位」），状态文案并入
// 可点击的「打开主窗口」项标题。两函数仅依赖 AppPhase + String，零 AppKit/SwiftUI
// 耦合（W1a AppPhase 同模式），harness 只需编译本文件 + AppPhase.swift。
//
// 单一来源不变：statusLine 语义与 v0.4 MC-1 menuStatusLine 一致；
// openTitle 以 statusLine 为单一来源拼接。

import Foundation

/// 菜单栏文案命名空间（纯函数面）。
enum MenuStatusText {

    /// 打开项标题：库名非空且已建库（locked/unlocked）时形如「打开 main（已解锁）」；
    /// booting/noVault/fatal 与库名缺失时退回「打开主窗口」（不展示半生不熟的状态后缀）。
    nonisolated static func openTitle(phase: AppPhase, vaultName: String) -> String {
        guard !vaultName.isEmpty else { return String(localized: "打开主窗口") }
        switch phase {
        case .locked, .unlocked:
            // 骨架 + 占位符，不用 "打开 " + statusLine 拼接：英文语序需整体重排
            // （"Open main (Locked)"），拼接会让译文变成 "Open " 硬贴中文残余。
            // 参数传**已本地化**的 statusLine（本地化发生在 String 产生点，设计 §5.4）。
            return String(localized: "打开 \(statusLine(phase: phase, vaultName: vaultName))")
        default:
            return String(localized: "打开主窗口")
        }
    }

    /// 状态文案（只读派生，语义与 v0.4 MC-1 menuStatusLine 一致；纯函数）。
    nonisolated static func statusLine(phase: AppPhase, vaultName: String) -> String {
        switch phase {
        case .booting:
            return String(localized: "正在打开…")
        case .noVault:
            return String(localized: "未创建密码库")
        case .locked:
            return vaultName.isEmpty
                ? String(localized: "已锁定")
                : String(localized: "\(vaultName)（已锁定）")
        case .unlocked:
            return vaultName.isEmpty
                ? String(localized: "已解锁")
                : String(localized: "\(vaultName)（已解锁）")
        case .fatal:
            return String(localized: "启动失败")
        }
    }
}
