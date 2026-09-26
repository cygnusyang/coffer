// Clipboard.swift —— 剪贴板写入 + 30 秒自动清除（FR-4.6 / FR-4.7）。
//
// 机制（docs/03 §10.3）：
//   1. 写入 NSPasteboard，记录当时的 changeCount；
//   2. 轮询（1 s）：changeCount 未变 → 30 s 到点后清空剪贴板；
//      changeCount 已变（用户在此期间复制了别的内容）→ 放弃清除，
//      绝不误清用户后来的数据。
//   3. 多次复制：取消旧定时任务，只保留最近一次。

import AppKit

final class ClipboardManager {
    static let shared = ClipboardManager()

    /// 明文在剪贴板的存活时间（秒）。
    static let clearAfterSeconds: TimeInterval = 30

    private var clearWorkItem: DispatchWorkItem?
    private var writtenChangeCount: Int = -1

    private init() {}

    /// 复制文本到剪贴板并安排 30 秒后自动清除。
    /// - Parameter value: 明文（密码 / TOTP 验证码 / 其他敏感字段值）
    func copyWithAutoClear(_ value: String) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        writtenChangeCount = pasteboard.changeCount
        scheduleClear()
    }

    /// 普通复制（非敏感内容：用户名 / 网址等，不安排自动清除）。
    func copyPlain(_ value: String) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// 取消待执行的清除（如会话锁定后不再需要）。
    func cancelPendingClear() {
        clearWorkItem?.cancel()
        clearWorkItem = nil
    }

    private func scheduleClear() {
        clearWorkItem?.cancel()
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
            deadline: .now() + Self.clearAfterSeconds,
            execute: work
        )
    }
}
