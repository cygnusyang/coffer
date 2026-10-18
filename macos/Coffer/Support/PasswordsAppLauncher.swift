// PasswordsAppLauncher.swift —— macOS「密码」App 唤起助手（J-1 判定点的共享实现）。
//
// 单一实现点：放置区向导 S1 指引卡按钮（DropzoneImportView.openPasswordsApp）
// 与 J-1 自动化测试 seam（AppDelegate --test-open-passwords）共用本助手，
// 保证测试执行的就是产品按钮走的同一条 NSWorkspace 启动链（BUG-30 类沙盒
// 坑判定：无参数纯 URL，LaunchServices 剥离面不存在，但沙盒内启动系统 App
// 的行为须真机实证）。
//
// 可用性检测（J-2 同源）：macOS < 14 无 Passwords.app → 按钮禁用 + 就地提示。

import AppKit
import Foundation

enum PasswordsAppLauncher {
    /// 系统「密码」App 固定路径（macOS 14+）。
    static let appURL = URL(fileURLWithPath: "/System/Applications/Passwords.app")

    /// 当前系统是否提供 Passwords.app（J-2：macOS < 14 降级判定）。
    static var isAvailable: Bool {
        FileManager.default.fileExists(atPath: appURL.path)
    }

    /// 唤起「密码」App；返回是否成功发起（与视图按钮既有语义一致）。
    @discardableResult
    static func open() -> Bool {
        NSWorkspace.shared.open(appURL)
    }
}
