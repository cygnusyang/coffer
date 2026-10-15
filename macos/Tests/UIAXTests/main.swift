// UIAXTests/main.swift —— L3 AX 黑盒驱动器（docs/04-测试与验收/19-UI测试自动化分层设计.md §5）。
//
// 形态（docs/19 §5.1）：swiftc 编译的 AX 可执行（ApplicationServices + AppKit），
// 不做 osascript——AppleScript UI scripting 是 AX 的弱桥，能力与可断言性低于直接
// AXUIElement API，且 TCC 授权对象不同（osascript 进程 vs 本 driver）。
//
// 固定编译输出：macos/build/axdriver/UIAXDriver（tools/build_ax_driver.sh）。
// TCC 按「路径」记录（swiftc 无签名二进制），输出路径必须固定——不能 mktemp，
// 否则每次路径变化授权失效重弹（docs/19 §5.4）。
//
// 能力面（docs/19 §5.5）：子树遍历（AXButton/AXTextField/AXSecureTextField/
// AXStaticText/AXSheet）、按 title/label 查找、kAXEnabledAttribute、窗口枚举、
// kAXPressAction、SetAttributeValue 文本注入。输出一律**机器可读行**（TAB 分隔），
// 供 harness 脚本（W4 run_ui_ax_tests.sh）编排断言。
//
// 子命令（首个参数；目标 App 缺省 = top.cygnusyang.coffer，可用 --pid <n> 覆盖）：
//   trusted                    输出 TRUSTED\t<true|false>（AX 授权探针，spike ⑤）
//   windows                    枚举窗口：WINDOW\t<idx>\t<role>\t<subrole>\t<title>\t<enabled>
//   tree                       全树遍历：E\t<depth>\t<role>\t<subrole>\t<title>\t<desc>\t<value>\t<enabled>
//   find   <query>             按 title/desc/value/placeholder 模糊匹配：
//                              MATCH\t<depth>\t<role>\t<subrole>\t<title>\t<enabled>
//   label  <query>             输出首个匹配的 label：LABEL\t<title>（AXTitle 透传断言，spike ③）
//   press  <query>             对全部匹配元素执行 kAXPressAction：PRESSED\t<count>
//   enabled <query>            输出首个匹配 enabled：ENABLED\t<true|false|missing>
//   type   <query> [--env N]   对首个匹配设置 kAXValueAttribute 文本注入：
//                              TYPED\t<count>；值来源缺省 env COFFER_TEST_PASSWORD（R2：
//                              测试密码绝不进 argv/对话/日志），--env 可换变量名
//
// 安全纪律（R2，docs/19 §10）：
//   - type 的值只经 env 读取，绝不从 argv 取、绝不回显、绝不写日志；
//   - 树 dump / 匹配输出一律净化 AXSecureTextField 的 AXValue（占位 <secure>），
//     防任何路径把密码泄漏进 stdout/日志。
//
// 退出码：0 成功；1 内部错误；3 目标 App 未运行；4 用法错误；5 AX 未授权；6 无匹配。
// 编译：tools/build_ax_driver.sh

import ApplicationServices
import AppKit
import Foundation

// MARK: - 常量

/// L3 目标 App bundle id（docs/19 §5.1 启动顺序第 3 步产物）。
let kTargetBundleID = "top.cygnusyang.coffer"
/// type 子命令缺省密码来源 env（R2：密码只走 env）。
let kDefaultPasswordEnv = "COFFER_TEST_PASSWORD"
/// 树遍历深度上限 / 元素上限，防失控 App 树跑飞。
let kMaxDepth = 24
let kMaxElements = 5000

enum DriverExit: Int32 {
    case ok = 0
    case internalError = 1
    case targetNotRunning = 3
    case usage = 4
    case notTrusted = 5
    case noMatch = 6
}

/// AX 元素快照（遍历收集用，值已按安全规则净化）。
struct AXInfo {
    let element: AXUIElement
    let depth: Int
    let role: String
    let subrole: String
    let title: String
    let desc: String
    let value: String
    let enabled: Bool?
}

// MARK: - AX 工具

/// 读元素属性（失败返回 nil；AX API 对未授权进程返回 kAXErrorAPIDisabled）。
func axAttr(_ el: AXUIElement, _ attr: CFString) -> CFTypeRef? {
    var out: CFTypeRef?
    return AXUIElementCopyAttributeValue(el, attr, &out) == .success ? out : nil
}

func axString(_ el: AXUIElement, _ attr: CFString) -> String? {
    axAttr(el, attr) as? String
}

func axBool(_ el: AXUIElement, _ attr: CFString) -> Bool? {
    axAttr(el, attr) as? Bool
}

/// 安全取文本值：AXSecureTextField 一律净化（R2——secure 字段的 value 可能是掩码后
/// 的明文，绝不外泄）。
func axSafeValue(_ el: AXUIElement, role: String) -> String {
    if role == "AXSecureTextField" { return "<secure>" }
    return axString(el, kAXValueAttribute as CFString) ?? ""
}

func snapshot(_ el: AXUIElement, depth: Int) -> AXInfo {
    let role = axString(el, kAXRoleAttribute as CFString) ?? "?"
    return AXInfo(
        element: el,
        depth: depth,
        role: role,
        subrole: axString(el, kAXSubroleAttribute as CFString) ?? "",
        title: axString(el, kAXTitleAttribute as CFString) ?? "",
        desc: axString(el, kAXDescriptionAttribute as CFString) ?? "",
        value: axSafeValue(el, role: role),
        enabled: axBool(el, kAXEnabledAttribute as CFString)
    )
}

/// 深度优先遍历整棵 AX 树，收集快照（深度/总数双上限）。
/// 从 App 根出发：先挂上 kAXWindowsAttribute 的各窗口，再挂 App 直接子节点
/// （菜单栏）——否则只走到菜单栏，主窗口内容在 windows 下不出现（实测）。
func walk(_ root: AXUIElement, _ collect: (AXInfo) -> Void) {
    var count = 0
    func rec(_ el: AXUIElement, _ depth: Int) {
        guard depth <= kMaxDepth, count < kMaxElements else { return }
        count += 1
        collect(snapshot(el, depth: depth))
        if depth == kMaxDepth { return }
        if let children = axAttr(el, kAXChildrenAttribute as CFString) as? [AXUIElement] {
            for c in children { rec(c, depth + 1) }
        }
    }
    // 窗口先挂（主内容）；再走 App 子节点（菜单栏/其他）。注意窗口本身也可能
    // 在 children 里（部分 App），走两遍不重复收集元素（count 上限兜底）。
    if let wins = axAttr(root, kAXWindowsAttribute as CFString) as? [AXUIElement] {
        for w in wins { rec(w, 1) }
    }
    rec(root, 0)
}

/// 匹配：title / desc / value / placeholder 任一包含 query（大小写不敏感）。
/// AXPlaceholderValue（SecureField 占位「请输入主密码」）一并纳入，保证锁定面锚定。
func matches(_ info: AXInfo, _ query: String) -> Bool {
    let q = query.lowercased()
    let candidates: [String] = [info.title, info.desc, info.value]
        + [(axString(info.element, kAXPlaceholderValueAttribute as CFString) ?? "")]
    return candidates.contains { $0.lowercased().contains(q) }
}

// MARK: - 目标 pid 解析

/// 解析目标 App pid：命令行 --pid 优先；否则按 bundle id 找正在运行的实例。
func resolvePID(arguments: [String]) -> pid_t? {
    if let i = arguments.firstIndex(of: "--pid"), i + 1 < arguments.count,
       let p = pid_t(arguments[i + 1]) {
        return p
    }
    return NSRunningApplication.runningApplications(withBundleIdentifier: kTargetBundleID).first?.processIdentifier
}

// MARK: - 子命令实现

/// 枚举窗口（docs/19 §5.5：kAXWindowsAttribute，排除 sheet/设置窗由 harness 判断）。
func cmdWindows(pid: pid_t) -> Int32 {
    let app = AXUIElementCreateApplication(pid)
    guard let wins = axAttr(app, kAXWindowsAttribute as CFString) as? [AXUIElement] else {
        print("WINDOW\tno-windows")
        return DriverExit.internalError.rawValue
    }
    for (i, w) in wins.enumerated() {
        let s = snapshot(w, depth: 0)
        print("WINDOW\t\(i)\t\(s.role)\t\(s.subrole)\t\(s.title)\t\(s.enabled.map { $0 ? "true" : "false" } ?? "?")")
    }
    return DriverExit.ok.rawValue
}

func cmdTree(pid: pid_t) -> Int32 {
    let app = AXUIElementCreateApplication(pid)
    walk(app) { info in
        print("E\t\(info.depth)\t\(info.role)\t\(info.subrole)\t\(info.title)\t\(info.desc)\t\(info.value)\t\(info.enabled.map { $0 ? "true" : "false" } ?? "?")")
    }
    return DriverExit.ok.rawValue
}

func allMatches(pid: pid_t, query: String) -> [AXInfo] {
    var found: [AXInfo] = []
    let app = AXUIElementCreateApplication(pid)
    walk(app) { info in
        if matches(info, query) { found.append(info) }
    }
    return found
}

func cmdFind(pid: pid_t, query: String) -> Int32 {
    let found = allMatches(pid: pid, query: query)
    for info in found {
        print("MATCH\t\(info.depth)\t\(info.role)\t\(info.subrole)\t\(info.title)\t\(info.enabled.map { $0 ? "true" : "false" } ?? "?")")
    }
    return found.isEmpty ? DriverExit.noMatch.rawValue : DriverExit.ok.rawValue
}

func cmdLabel(pid: pid_t, query: String) -> Int32 {
    guard let first = allMatches(pid: pid, query: query).first else {
        print("LABEL\tmissing")
        return DriverExit.noMatch.rawValue
    }
    print("LABEL\t\(first.title)")
    return DriverExit.ok.rawValue
}

func cmdPress(pid: pid_t, query: String) -> Int32 {
    let found = allMatches(pid: pid, query: query)
    var pressed = 0
    for info in found {
        if AXUIElementPerformAction(info.element, kAXPressAction as CFString) == .success {
            pressed += 1
        }
    }
    print("PRESSED\t\(pressed)")
    return pressed > 0 ? DriverExit.ok.rawValue : DriverExit.noMatch.rawValue
}

func cmdEnabled(pid: pid_t, query: String) -> Int32 {
    guard let first = allMatches(pid: pid, query: query).first else {
        print("ENABLED\tmissing")
        return DriverExit.noMatch.rawValue
    }
    if let en = first.enabled {
        print("ENABLED\t\(en ? "true" : "false")")
        return DriverExit.ok.rawValue
    }
    print("ENABLED\tunknown")
    return DriverExit.ok.rawValue
}

/// 文本注入（docs/19 §5.5：kAXFocusedAttribute + SetAttributeValue）。
/// 值来源：--env 指定的变量；缺省 COFFER_TEST_PASSWORD（R2 密码纪律）。
/// 值只在栈内读写，绝不打印、绝不落日志。
func cmdType(pid: pid_t, query: String, envName: String) -> Int32 {
    guard let secret = ProcessInfo.processInfo.environment[envName], !secret.isEmpty else {
        print("TYPED\t0\tenv-missing:\(envName)")
        return DriverExit.usage.rawValue
    }
    guard let first = allMatches(pid: pid, query: query).first else {
        print("TYPED\t0\tno-match")
        return DriverExit.noMatch.rawValue
    }
    // 先聚焦（SecureField 必须可聚焦才接受值写入），再 SetAttributeValue。
    _ = AXUIElementSetAttributeValue(first.element, kAXFocusedAttribute as CFString, kCFBooleanTrue)
    let err = AXUIElementSetAttributeValue(first.element, kAXValueAttribute as CFString, secret as CFString)
    if err == .success {
        print("TYPED\t1\t\(first.role)")
        return DriverExit.ok.rawValue
    }
    print("TYPED\t0\tax-error:\(err.rawValue)")
    return DriverExit.internalError.rawValue
}

func cmdTrusted() -> Int32 {
    if AXIsProcessTrusted() {
        print("TRUSTED\ttrue")
        return DriverExit.ok.rawValue
    }
    print("TRUSTED\tfalse")
    return DriverExit.notTrusted.rawValue
}

// MARK: - 入口

func usage() -> Int32 {
    print("usage: UIAXDriver <trusted|windows|tree|find|label|press|enabled|type> [args] [--pid <n>]")
    print("  type <query> [--env VAR]   值来源 env（缺省 COFFER_TEST_PASSWORD），绝不进 argv")
    return DriverExit.usage.rawValue
}

let args = CommandLine.arguments
guard args.count >= 2 else { exit(usage()) }

let sub = args[1]
switch sub {
case "trusted":
    exit(cmdTrusted())
case "windows":
    guard let pid = resolvePID(arguments: Array(args.dropFirst(2))) else {
        print("TARGET\tnot-running")
        exit(DriverExit.targetNotRunning.rawValue)
    }
    exit(cmdWindows(pid: pid))
case "tree":
    guard let pid = resolvePID(arguments: Array(args.dropFirst(2))) else {
        print("TARGET\tnot-running")
        exit(DriverExit.targetNotRunning.rawValue)
    }
    exit(cmdTree(pid: pid))
case "find", "label", "press", "enabled":
    guard args.count >= 3 else { exit(usage()) }
    guard let pid = resolvePID(arguments: Array(args.dropFirst(2))) else {
        print("TARGET\tnot-running")
        exit(DriverExit.targetNotRunning.rawValue)
    }
    let query = args[2]
    switch sub {
    case "find": exit(cmdFind(pid: pid, query: query))
    case "label": exit(cmdLabel(pid: pid, query: query))
    case "press": exit(cmdPress(pid: pid, query: query))
    default: exit(cmdEnabled(pid: pid, query: query))
    }
case "type":
    guard args.count >= 3 else { exit(usage()) }
    guard let pid = resolvePID(arguments: Array(args.dropFirst(2))) else {
        print("TARGET\tnot-running")
        exit(DriverExit.targetNotRunning.rawValue)
    }
    let query = args[2]
    var envName = kDefaultPasswordEnv
    if let i = args.firstIndex(of: "--env"), i + 1 < args.count {
        envName = args[i + 1]
    }
    exit(cmdType(pid: pid, query: query, envName: envName))
default:
    exit(usage())
}
