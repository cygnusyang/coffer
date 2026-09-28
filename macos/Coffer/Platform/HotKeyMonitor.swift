// HotKeyMonitor.swift —— 全局快捷键注册/分发（FR-4.5，v0.4 MC-1）。
//
// 机制（docs/research-v0.4-menubar-hotkey.md 选型结论）：手写 Carbon
// RegisterEventHotKey（零第三方依赖、零权限——不需要辅助功能/Input
// Monitoring 授权）。与本项目其余 Swift 面一样无网络框架，维持
// 运行时 0 socket（出口判据②）。
//
// 约束（docs/15 §2.3 / §3.3.2）：
//   - 注册失败静默降级：不抛错、不阻塞启动、不崩溃，仅菜单栏入口
//     仍可用；失败原因与 OSStatus 写诊断日志（DiagLog，只记错误原文）。
//   - 组合安全校验（Sequoia 15.0–15.1 沙盒回归：⌥/⇧-only 注册报
//     -9868）：修饰键必须含 ⌘ 或 ⌃（isRegistrationSafe 纯函数守卫，
//     默认键位 ⌥⌘P 天然满足）。
//   - 本类不做任何具体动作：热键事件经 route（纯函数）映射为
//     HotKeyAction 回调给持有者（AppDelegate），纯函数面独立可测。
//
// 线程契约：start/stop 主线程调用；热键回调由 Carbon 主事件循环派发
// （主线程），跨线程兜底转 main queue 后再回调。

import AppKit
import Carbon.HIToolbox

/// 全局热键动作（docs/15 §3.3.2 路由表的 MC-1 子集）。
enum HotKeyAction: Equatable {
    /// HK-1：全局呼出（默认 ⌥⌘P）→ 主窗口聚焦（锁定态先进解锁页）。
    case summonMainWindow
}

/// 全局快捷键组合（keyCode + NSEvent 修饰键语义，纯数据可单测）。
struct HotKeyCombo: Equatable {
    let keyCode: UInt32
    let modifiers: NSEvent.ModifierFlags

    init(keyCode: UInt32, modifiers: NSEvent.ModifierFlags) {
        self.keyCode = keyCode
        // 只保留四个修饰键位：NSEvent.flags 可能夹带 capsLock/function
        // 等无关位，剔除后 Equatable 比较与 Carbon 映射才稳定。
        self.modifiers = modifiers.intersection([.command, .option, .control, .shift])
    }

    /// 注册安全校验（纯函数）：修饰必须含 ⌘ 或 ⌃——macOS 15.0–15.1
    /// 沙盒内 ⌥/⇧-only 组合注册报 -9868（调研报告 §3 Sequoia 回归）。
    var isRegistrationSafe: Bool {
        modifiers.contains(.command) || modifiers.contains(.control)
    }

    /// Carbon modifier mask（纯函数）：RegisterEventHotKey 的修饰键入参。
    var carbonModifiers: UInt32 {
        var mask: UInt32 = 0
        if modifiers.contains(.command) { mask |= UInt32(cmdKey) }
        if modifiers.contains(.option) { mask |= UInt32(optionKey) }
        if modifiers.contains(.control) { mask |= UInt32(controlKey) }
        if modifiers.contains(.shift) { mask |= UInt32(shiftKey) }
        return mask
    }

    /// NFR-UX-03 默认全局热键（2026-09-29 用户裁定）：⌥⌘P 呼出。
    static let summon = HotKeyCombo(
        keyCode: UInt32(kVK_ANSI_P),
        modifiers: [.option, .command]
    )
}

final class HotKeyMonitor {
    /// 热键路由编号（EventHotKeyID.id）：HK-1 呼出。
    nonisolated static let summonHotKeyID: UInt32 = 1
    /// EventHotKeyID.signature：固定四字标识（'COFR'），仅作事件归属标记。
    private static let hotKeySignature: FourCharCode = 0x434F_4652

    /// Carbon 热键引用（反注册用）。
    private var hotKeyRef: EventHotKeyRef?
    /// 事件处理器引用（卸载用）。
    private var handlerRef: EventHandlerRef?
    /// 动作回调（主线程执行；start 后非 nil，stop 置 nil）。
    private var actionHandler: ((HotKeyAction) -> Void)?

    deinit {
        stop()
    }

    /// 安装事件处理器并注册全部热键。主线程调用。
    /// - Returns: 是否注册成功。false = 已静默降级（原因写诊断日志）：
    ///   App 照常启动，快捷键不生效，菜单栏入口不受影响。
    @discardableResult
    func start(actionHandler: @escaping (HotKeyAction) -> Void) -> Bool {
        self.actionHandler = actionHandler
        // 处理器先装后注册：杜绝「注册成功但事件无人接听」的窗口期。
        guard installEventHandler() else { return false }
        return register(combo: .summon, id: Self.summonHotKeyID)
    }

    /// 反注册热键 + 卸载事件处理器（applicationWillTerminate / deinit 调用；幂等）。
    func stop() {
        if let hotKeyRef {
            UnregisterEventHotKey(hotKeyRef)
            self.hotKeyRef = nil
        }
        if let handlerRef {
            RemoveEventHandler(handlerRef)
            self.handlerRef = nil
        }
        actionHandler = nil
    }

    /// 热键编号 → 动作（纯函数，docs/15 §3.3.2 路由表 MC-1 子集；
    /// 未注册编号返回 nil，防御未知事件）。
    nonisolated static func route(hotKeyID: UInt32) -> HotKeyAction? {
        switch hotKeyID {
        case Self.summonHotKeyID: return .summonMainWindow
        default: return nil
        }
    }

    // MARK: - 注册 / 卸载

    /// 注册单个组合。失败：清引用 + 诊断日志（静默降级语义），返回 false。
    private func register(combo: HotKeyCombo, id: UInt32) -> Bool {
        guard combo.isRegistrationSafe else {
            // 交由调用面兜底（默认键位已满足校验）；此处记录拒绝原因
            Self.logFailure(combo, osStatus: 0,
                            reason: "修饰组合不含 ⌘/⌃（Sequoia 沙盒 -9868 规避校验拒绝）")
            return false
        }
        let hotKeyID = EventHotKeyID(signature: Self.hotKeySignature, id: id)
        var ref: EventHotKeyRef?
        let status = RegisterEventHotKey(
            combo.keyCode, combo.carbonModifiers, hotKeyID,
            GetApplicationEventTarget(), 0, &ref
        )
        guard status == noErr, let ref else {
            // 注册失败常见于组合被其他软件占用（调研报告 §6 风险 5）
            Self.logFailure(combo, osStatus: status, reason: "RegisterEventHotKey 失败")
            return false
        }
        hotKeyRef = ref
        return true
    }

    /// 安装 kEventClassKeyboard/kEventHotKeyPressed 事件处理器（幂等）。
    private func installEventHandler() -> Bool {
        guard handlerRef == nil else { return true }
        var eventType = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard),
            eventKind: UInt32(kEventHotKeyPressed)
        )
        let selfRef = Unmanaged.passUnretained(self).toOpaque()
        var handler: EventHandlerRef?
        let status = InstallEventHandler(
            GetApplicationEventTarget(), Self.eventCallback, 1, &eventType, selfRef, &handler
        )
        guard status == noErr, let handler else {
            DiagLog.append("HotKeyMonitor InstallEventHandler 失败 OSStatus=\(status)")
            return false
        }
        handlerRef = handler
        return true
    }

    /// Carbon C 回调（无捕获静态函数指针）：取出 EventHotKeyID 转发回实例。
    private static let eventCallback: EventHandlerUPP = { _, event, userData in
        guard let event, let userData else { return noErr }
        var hotKeyID = EventHotKeyID()
        let status = GetEventParameter(
            event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID),
            nil, MemoryLayout<EventHotKeyID>.size, nil, &hotKeyID
        )
        guard status == noErr else { return status }
        let monitor = Unmanaged<HotKeyMonitor>.fromOpaque(userData).takeUnretainedValue()
        monitor.dispatch(hotKeyID: hotKeyID.id)
        return noErr
    }

    /// 热键事件 → 动作分发：route 纯函数映射，回调在主线程执行。
    private func dispatch(hotKeyID: UInt32) {
        guard let action = Self.route(hotKeyID: hotKeyID),
              let handler = actionHandler else { return }
        if Thread.isMainThread {
            MainActor.assumeIsolated { handler(action) }
        } else {
            // 线程契约兜底：Carbon 热键应在主事件循环派发，此分支理论不可达
            DispatchQueue.main.async {
                MainActor.assumeIsolated { handler(action) }
            }
        }
    }

    /// 注册失败诊断（DiagLog 纪律：只写错误原文与状态码，无敏感值）。
    private static func logFailure(_ combo: HotKeyCombo, osStatus: OSStatus, reason: String) {
        DiagLog.append(
            "HotKeyMonitor 注册失败：\(reason) keyCode=\(combo.keyCode) "
                + "modifiers=\(combo.modifiers.rawValue) OSStatus=\(osStatus)"
        )
    }
}
