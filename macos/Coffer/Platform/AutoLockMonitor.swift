// AutoLockMonitor.swift —— 自动锁定平台驱动（docs/07 §2.4）。
//
// 两条锁定路径：
//   1. 空闲超时：定时器每 2 s 用 CGEventSource 读取会话级输入空闲秒数，
//      有新输入（空闲 < 5 s）时喂 set_last_activity，然后调 auto_lock_if_expired
//      让 Rust 侧纯函数判定（时间注入，docs/03 §11.2 决策对齐）。
//   2. 系统事件立即锁定（FR-13.6）：锁屏（Darwin 通知 com.apple.screenIsLocked）、
//      休眠 / 屏保（NSWorkspace screensDidSleep/WillSleep）、快速用户切换
//      （sessionDidResignActive）→ 直接 lock()。

import AppKit
import CoreGraphics

@MainActor
final class AutoLockMonitor {
    private weak var model: AppModel?

    private var tickTimer: Timer?
    private var workspaceObservers: [NSObjectProtocol] = []
    private var darwinObserver: NSObjectProtocol?

    /// 输入空闲低于该秒数视为「有活动」，喂 last_activity。
    private static let activityThresholdSecs: Double = 5
    /// 判定节拍（秒）。
    private static let tickInterval: TimeInterval = 2

    func start(model: AppModel) {
        self.model = model

        let timer = Timer(timeInterval: Self.tickInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.tick()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        tickTimer = timer

        let center = NSWorkspace.shared.notificationCenter
        let wsHandler: (Notification) -> Void = { [weak self] _ in
            MainActor.assumeIsolated { self?.lockNow() }
        }
        workspaceObservers.append(center.addObserver(
            forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main,
            using: wsHandler
        ))
        workspaceObservers.append(center.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main,
            using: wsHandler
        ))
        workspaceObservers.append(center.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main,
            using: wsHandler
        ))

        // 锁屏通知：NSWorkspace 无直接「屏幕已锁定」事件，走 Darwin 通知
        darwinObserver = DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"),
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.lockNow() }
        }
    }

    func stop() {
        tickTimer?.invalidate()
        tickTimer = nil
        let center = NSWorkspace.shared.notificationCenter
        workspaceObservers.forEach { center.removeObserver($0) }
        workspaceObservers = []
        if let darwinObserver {
            DistributedNotificationCenter.default().removeObserver(darwinObserver)
        }
        darwinObserver = nil
    }

    // MARK: - 节拍

    private func tick() {
        guard let model, let session = model.session, session.isUnlocked() else { return }

        let now = Int64(Date().timeIntervalSince1970)
        let idle = Self.idleSeconds()

        if idle >= 0 && idle < Self.activityThresholdSecs {
            // 会话级有输入 → 喂活动时间（Rust 侧纯函数判定到期）
            session.setLastActivity(unixSecs: now)
        }
        _ = session.autoLockIfExpired(nowSecs: now)

        if !session.isUnlocked() {
            model.lock()
        }
    }

    /// 系统事件触发的立即锁定。
    private func lockNow() {
        guard let model else { return }
        if let session = model.session, session.isUnlocked() {
            model.lock()
        }
    }

    // MARK: - 空闲检测

    /// 会话级输入空闲秒数；查询失败返回 -1（tick 会跳过喂入，交由 Rust 判定兜底）。
    static func idleSeconds() -> Double {
        guard let anyType = CGEventType(rawValue: ~0) else { return -1 }
        return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyType)
    }
}
