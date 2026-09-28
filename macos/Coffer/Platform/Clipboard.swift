// Clipboard.swift —— 剪贴板写入 + 五档可配置自动清除（FR-4.6 / FR-4.7 / FR-14.2）。
//
// 机制（docs/03 §10.3；FR-14.2 档位 10 / 30 / 60 / 120 / 从不）：
//   1. 写入 NSPasteboard，记录当时的 changeCount；
//   2. 轮询（1 s）：changeCount 未变 → 到点后清空剪贴板；
//      changeCount 已变（用户在此期间复制了别的内容）→ 放弃清除，
//      绝不误清用户后来的数据。
//   3. 多次复制：取消旧定时任务，只保留最近一次；
//   4. 会话锁定（AppModel.lock() → clearOnLock()）：取消待执行清除，
//      且若剪贴板仍是我们写入的敏感内容则立即清空。
//   5. 档位 0（从不）：跳过定时调度（绝不能 asyncAfter(0) 立即清空），
//      但保留 changeCount 记录——锁定时 clearOnLock 仍能清掉我们写入
//      的敏感内容。清除时长只作用于定时路径，不影响锁定兜底。
//   6. TOTP 验证码复制不走本类定时清除（FR-5.5 例外，TotpCodeView 用
//      copyPlain），本类改动不影响该例外路径。

import AppKit

final class ClipboardManager {
    static let shared = ClipboardManager()

    /// UserDefaults key（与 AppModel.clipboardClearSecs 共用，FR-14.2）。
    static let clearSecsDefaultsKey = "clipboard_clear_secs"

    /// 明文在剪贴板的存活时间（秒）。0 = 从不清除（FR-14.2 档位之一）。
    /// 初始值从 UserDefaults 读取；无值或非法 → 回退 Rust 侧默认
    /// （defaultClipboardClearSecs，当前 30，勿在 Swift 侧硬编码）。
    private(set) var clearAfterSeconds: TimeInterval

    private var clearWorkItem: DispatchWorkItem?
    private var writtenChangeCount: Int = -1

    private init() {
        self.clearAfterSeconds = TimeInterval(Self.loadStoredClearSecs())
    }

    /// 从 UserDefaults 读档位（AppModel 初始化与本类初始化共用同一校验
    /// 规则，保证两侧初始值一致）：
    ///   - 键不存在或值非法（不在 {0, 10, 30, 60, 120}）→ 回退 Rust 默认；
    ///   - 注意 integer(forKey:) 对「键不存在」也返回 0，而 0 恰是合法档位
    ///     （从不），故必须用 object(forKey:) 区分「未配置」与「显式从不」。
    nonisolated static func loadStoredClearSecs() -> Int {
        guard let stored = UserDefaults.standard.object(forKey: clearSecsDefaultsKey) as? Int else {
            return Int(defaultClipboardClearSecs())
        }
        return isValidClearSecs(stored) ? stored : Int(defaultClipboardClearSecs())
    }

    /// 档位校验：0（从不）或 Rust 侧定义的档位之一。
    /// 档位表经 FFI 取（clipboardClearTiers），与 Rust 校验同一来源，勿硬编码。
    nonisolated static func isValidClearSecs(_ secs: Int) -> Bool {
        secs == 0 || clipboardClearTiers().contains(Int64(secs))
    }

    /// 复制文本到剪贴板并按当前档位安排自动清除。
    /// - Parameter value: 明文（密码 / TOTP 验证码 / 其他敏感字段值）
    func copyWithAutoClear(_ value: String) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        writtenChangeCount = pasteboard.changeCount
        scheduleClear()
    }

    /// 普通复制（非敏感内容：用户名 / 网址 / TOTP 验证码等，
    /// 不安排自动清除；FR-5.5：TOTP 验证码 30/60 s 内会失效轮换，不清除）。
    func copyPlain(_ value: String) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// 运行时改档（AppModel.clipboardClearSecs.didSet 调用，FR-14.2）：
    /// 更新档位；若已有待执行清除任务则取消并按新间隔重排（新值 0 = 从不
    /// → 只取消、不重排）。无待执行任务时改档对下一次复制即生效。
    /// 非法值直接忽略（保持旧档位）——入口只有 AppModel 设置页，此处
    /// 兜底防非法值经其他路径进入。
    func updateClearInterval(secs: Int) {
        guard Self.isValidClearSecs(secs) else { return }
        clearAfterSeconds = TimeInterval(secs)
        guard clearWorkItem != nil else { return }
        clearWorkItem?.cancel()
        clearWorkItem = nil
        guard secs > 0 else { return }
        schedulePendingClear()
    }

    /// 会话锁定时的剪贴板处置（AppModel.lock() 调用）：
    ///   1. 取消待执行的定时清除任务；
    ///   2. 若剪贴板仍是我们写入的敏感内容（changeCount 未被用户后续复制
    ///      顶掉），立即清空 —— 锁定时刻剪贴板里可能还有密码，立即清比
    ///      等定时到点更安全。
    /// 用户在此期间已复制自己的内容则不动剪贴板，与定时清除同一条纪律：
    /// 绝不误清用户数据（changeCount 守卫）。
    func clearOnLock() {
        clearWorkItem?.cancel()
        clearWorkItem = nil
        guard writtenChangeCount != -1 else { return }
        let pasteboard = NSPasteboard.general
        if pasteboard.changeCount == writtenChangeCount {
            pasteboard.clearContents()
        }
        writtenChangeCount = -1
    }

    /// 按当前档位调度定时清除。
    private func scheduleClear() {
        clearWorkItem?.cancel()
        clearWorkItem = nil
        // 0（从不）：跳过调度。writtenChangeCount 保留，锁定兜底仍有效。
        guard clearAfterSeconds > 0 else { return }
        schedulePendingClear()
    }

    /// 以当前 writtenChangeCount 挂一个到点清除任务（首次调度 / 改档重排共用）。
    private func schedulePendingClear() {
        let written = writtenChangeCount
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let pasteboard = NSPasteboard.general
            // changeCount 不变 = 用户没有复制过别的内容，安全清空；
            // 变了 = 剪贴板已是用户自己的内容，绝不误清。
            if pasteboard.changeCount == written {
                pasteboard.clearContents()
            }
            self.writtenChangeCount = -1
            self.clearWorkItem = nil
        }
        clearWorkItem = work
        DispatchQueue.main.asyncAfter(
            deadline: .now() + clearAfterSeconds,
            execute: work
        )
    }
}
