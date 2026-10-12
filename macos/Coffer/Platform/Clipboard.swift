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
//   7. FR-5.6 序列复制（copyPasswordThenTotp，v0.4）：密码照走本类定时
//      清除；延迟 totpDelaySecs(clearSecs:) 后复制 TOTP 验证码（copyPlain，
//      FR-5.5 不清除）。交接语义：TOTP 落盘即改变 changeCount → 密码的
//      pending 清除被守卫放弃（先交接后到点，延迟恒 < 清除档）；锁定
//      （clearOnLock）取消 pending TOTP 复制；延迟窗口内用户写入剪贴板
//      则写入路径守卫取消 TOTP 复制（绝不覆写用户内容）；再次调用重置序列。

import AppKit

final class ClipboardManager {
    static let shared = ClipboardManager()

    /// UserDefaults key（与 AppModel.clipboardClearSecs 共用，FR-14.2）。
    static let clearSecsDefaultsKey = "clipboard_clear_secs"

    /// FR-5.6 TOTP 取码延迟默认值（秒）：30 s 及以上清除档下密码清除前
    /// 完成交接、TOTP 30 s 周期内剩余有效期 ≥ 22 s。已裁定 8 s 默认
    ///（2026-09-29），非用户可配置（docs/15 §3.3.3）。
    private static let defaultTotpDelaySecs: TimeInterval = 8

    /// 明文在剪贴板的存活时间（秒）。0 = 从不清除（FR-14.2 档位之一）。
    /// 初始值从 UserDefaults 读取；无值或非法 → 回退 Rust 侧默认
    /// （defaultClipboardClearSecs，当前 30，勿在 Swift 侧硬编码）。
    private(set) var clearAfterSeconds: TimeInterval

    private var clearWorkItem: DispatchWorkItem?
    /// pending 清除任务是否为「用户档位驱动」类型（REV-DEV-01 分槽）：
    /// true = 档位任务（随用户档位重排）；false = 显式时长任务（恢复码固定
    /// 30s，FR-17.2——改档**不得**取消/重排它）。与 clearWorkItem 成对维护。
    private var isClearTierDriven = false
    /// FR-5.6：pending 的 TOTP 延迟取码任务（nil = 无序列进行中）。
    private var totpWorkItem: DispatchWorkItem?
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

    /// changeCount 守卫（纯函数）：剪贴板 changeCount 与我们写入时一致
    /// （用户没有复制过别的内容）才为真。清除路径据此「绝不误清用户数据」；
    /// FR-5.6 写入路径据此「绝不覆写用户内容」（TOTP 交接前复核）+「交接
    /// 天然完成」（TOTP 落盘 → changeCount 变 → 密码的 pending 清除被
    /// 放弃）。writtenChangeCount 哨兵 -1 的前置 guard 在调用面
    /// （clearOnLock），此处对不一致一律拒绝。
    nonisolated static func clipboardUnchanged(currentChangeCount: Int, writtenChangeCount: Int) -> Bool {
        currentChangeCount == writtenChangeCount
    }

    /// FR-5.6 TOTP 取码延迟（纯函数）：延迟必须落在密码清除到点**之前**
    /// ——TOTP 先落盘改变 changeCount，密码的 pending 清除才被守卫放弃。
    ///   - 10 s 档：min(8, 10/2) = 5 s；
    ///   - 30 s 及以上：min(8, clear/2) = 8 s（默认值）；
    ///   - 0（从不）：恒 8 s（无清除到点可交接，仅固定延迟取 fresh code；
    ///     密码副本由 TOTP 落盘顶掉，此后按 FR-5.5 不清除）。
    nonisolated static func totpDelaySecs(clearSecs: TimeInterval) -> TimeInterval {
        guard clearSecs > 0 else { return Self.defaultTotpDelaySecs }
        return min(Self.defaultTotpDelaySecs, clearSecs / 2)
    }

    /// 复制文本到剪贴板并按当前档位安排自动清除（委托给显式时长版，传当前档位）。
    /// 经 isClearTierDriven = true 标记为档位任务：改档时随新档位重排（FR-14.2）。
    /// - Parameter value: 明文（密码 / TOTP 验证码 / 其他敏感字段值）
    func copyWithAutoClear(_ value: String) {
        copyWithAutoClear(value, clearSecs: clearAfterSeconds, isTierDriven: true)
    }

    /// 复制文本到剪贴板并按**显式时长**安排自动清除（P5-A / FR-17.2）。本次
    /// 复制以 `clearSecs` 覆盖用户档位调度清除；changeCount 守卫与
    /// `schedulePendingClear` 同纪律（清除任务闭包内**局部捕获**写入时
    /// changeCount，不依赖单例槽位）；`clearOnLock` 覆盖（经单例槽位记录本次
    /// 写入，锁定时若仍为本内容即清）。
    ///
    /// **REV-DEV-01 分槽**：经 isTierDriven = false 标记为显式时长任务，改档
    /// （updateClearInterval）**不**取消/重排它——恢复码固定 30s 不受用户档位
    /// 影响（FR-17.2，AC-2.9.0-P5-9）。仅下一次复制（最新覆盖）或 clearOnLock
    /// 会终结它。
    /// - Parameters:
    ///   - value: 明文（密码 / 恢复码 / 其他敏感字段值）
    ///   - clearSecs: 本次清除时长（秒）。> 0 走定时清除；== 0 视作「本次
    ///     不清除定时路径」但保留锁定兜底（与档位 0 同语义，勿 asyncAfter(0)）。
    func copyWithAutoClear(_ value: String, clearSecs: TimeInterval) {
        copyWithAutoClear(value, clearSecs: clearSecs, isTierDriven: false)
    }

    /// 复制 + 按给定时长安排清除的内部实现（REV-DEV-01 统一入口）：
    /// `isTierDriven` 决定改档时该 pending 任务是否随新档位重排（true）还是
    /// 原样保留至自己到点（false，恢复码固定 30s 场景）。
    private func copyWithAutoClear(_ value: String, clearSecs: TimeInterval, isTierDriven: Bool) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        writtenChangeCount = pasteboard.changeCount
        schedulePendingClear(clearAfter: clearSecs, isTierDriven: isTierDriven)
    }

    /// 普通复制（非敏感内容：用户名 / 网址 / TOTP 验证码等，
    /// 不安排自动清除；FR-5.5：TOTP 验证码 30/60 s 内会失效轮换，不清除）。
    func copyPlain(_ value: String) {
        guard !value.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// FR-5.6 序列复制：复制密码（走现有自动清除定时器）→ 延迟
    /// totpDelaySecs(clearSecs:) 后复制 TOTP 验证码（走 copyPlain，
    /// FR-5.5 不安排清除）。取码延迟执行（TOTP 30 s 周期内 fresh code）。
    ///
    /// 延迟期间的取消/交接条件：
    ///   - 锁定（clearOnLock）→ 取消 pending TOTP 复制（密码副本仍按
    ///     既有 changeCount 守卫处置）；
    ///   - 再次调用本方法 → 取消旧序列，只保留最近一次（与定时清除同纪律）；
    ///   - 延迟窗口内用户写入剪贴板（复制自己的内容，含 HK-4）→ 写入路径
    ///     守卫（clipboardUnchanged）取消 TOTP 复制——验证码绝不覆写用户
    ///     内容（M-1：与清除路径「绝不误清」同一守卫两侧对称）；
    ///   - TOTP 落盘 → changeCount 改变 → 密码的 pending 清除被守卫放弃
    ///     （延迟恒 < 清除档，交接先于到点，见 totpDelaySecs）。
    ///
    /// - Parameter totpProvider: 取码回调，主队列延迟执行（本类保证只在
    ///   主队列触发）；返回 nil/空 = 取码失败，跳过 TOTP 复制（诊断日志
    ///   留痕，不打扰用户）。回调体内访问 @MainActor 的 AppModel 时由
    ///   调用面以 MainActor.assumeIsolated 包裹。
    func copyPasswordThenTotp(password: String, totpProvider: @escaping () -> String?) {
        guard !password.isEmpty else { return }
        // ① 密码先行：armed 自动清除 + changeCount 记录（既有纪律原样，
        //    与 FR-5.5 例外路径共存：密码副本 armed、TOTP 副本不 armed）
        copyWithAutoClear(password)
        // ② 重置旧序列（只保留最近一次）
        totpWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.totpWorkItem = nil
            // 本工作项经 DispatchQueue.main.asyncAfter 派发，恒在主队列
            // 执行；totpProvider 闭包体内或需访问 @MainActor 状态，故经
            // assumeIsolated 进入（off-main 属违约，trap 快败优于静默错序）
            guard let code = MainActor.assumeIsolated({ totpProvider() }),
                  !code.isEmpty else {
                DiagLog.append("FR-5.6 TOTP 取码失败/为空，跳过验证码复制")
                return
            }
            // 写入路径守卫（M-1 修复，与清除路径「绝不误清用户数据」对称）：
            // 延迟窗口内用户复制了自己的内容（含 HK-4 ⌘U）→ changeCount
            // 已变，取消 TOTP 复制——验证码绝不覆写用户内容。
            guard Self.clipboardUnchanged(
                currentChangeCount: NSPasteboard.general.changeCount,
                writtenChangeCount: writtenChangeCount
            ) else {
                DiagLog.append("FR-5.6 TOTP 复制取消：延迟窗口内剪贴板已被用户写入顶掉（changeCount 守卫）")
                return
            }
            self.copyPlain(code)
        }
        totpWorkItem = work
        DispatchQueue.main.asyncAfter(
            deadline: .now() + Self.totpDelaySecs(clearSecs: clearAfterSeconds),
            execute: work
        )
    }

    /// 运行时改档（AppModel.clipboardClearSecs.didSet 调用，FR-14.2）：
    /// 更新档位；若已有待执行的**档位驱动**清除任务则取消并按新间隔重排
    /// （新值 0 = 从不 → 只取消、不重排，由 schedulePendingClear 的
    /// delay <= 0 分支处理）。
    ///
    /// **REV-DEV-01 分槽**：显式时长任务（恢复码固定 30s，isClearTierDriven
    /// == false）**不**在此重排/取消——改档绝不破坏 FR-17.2 固定 30s 契约。
    /// 无待执行任务时改档对下一次复制即生效。非法值直接忽略（保持旧档位）
    /// ——入口只有 AppModel 设置页，此处兜底防非法值经其他路径进入。
    func updateClearInterval(secs: Int) {
        guard Self.isValidClearSecs(secs) else { return }
        clearAfterSeconds = TimeInterval(secs)
        // 只重排档位驱动的 pending 任务；isClearTierDriven 与 clearWorkItem
        // 成对维护，true 时必非 nil（无需再判 clearWorkItem）。
        guard isClearTierDriven else { return }
        schedulePendingClear(clearAfter: clearAfterSeconds, isTierDriven: true)
    }

    /// 会话锁定时的剪贴板处置（AppModel.lock() 调用）：
    ///   1. 取消待执行的定时清除任务；
    ///   2. 若剪贴板仍是我们写入的敏感内容（changeCount 未被用户后续复制
    ///      顶掉），立即清空 —— 锁定时刻剪贴板里可能还有密码，立即清比
    ///      等定时到点更安全。
    /// 用户在此期间已复制自己的内容则不动剪贴板，与定时清除同一条纪律：
    /// 绝不误清用户数据（changeCount 守卫）。
    func clearOnLock() {
        // FR-5.6：锁定即取消 pending TOTP 序列复制（会话已锁，验证码不该
        // 再落剪贴板）；密码副本按 clearWrittenIfUnchanged 既有守卫处置。
        totpWorkItem?.cancel()
        totpWorkItem = nil
        clearWorkItem?.cancel()
        clearWorkItem = nil
        // 不变式维护：clearWorkItem 已 nil，档位旗标同步复位（否则锁定后
        // 改档会误重排出 written = -1 的空任务）。
        isClearTierDriven = false
        clearWrittenIfUnchanged()
    }

    /// P6 —— verify 步进板清除（clearOnLock 的公开子集，供恢复码验证步调用）。
    /// 语义：clipboardUnchanged 校验通过则清板 + 复位 writtenChangeCount；不触碰
    /// TOTP 序列（pending TOTP 复制与定时清除任务均不取消——到点任务经
    /// schedulePendingClear 闭包内的 written 局部捕获 + changeCount 守卫自然失效）。
    func clearWrittenIfUnchanged() {
        guard writtenChangeCount != -1 else { return }
        let pasteboard = NSPasteboard.general
        if Self.clipboardUnchanged(currentChangeCount: pasteboard.changeCount,
                            writtenChangeCount: writtenChangeCount) {
            pasteboard.clearContents()
        }
        writtenChangeCount = -1
    }

    /// 以当前 writtenChangeCount 挂一个到点清除任务（首次调度 / 改档重排 /
    /// 显式时长覆盖共用）。`delay <= 0`（档位 0「从不」）→ 只取消待执行任务、
    /// 不重排——writtenChangeCount 保留，锁定兜底仍有效（勿 asyncAfter(0)）。
    ///
    /// `isTierDriven` 随任务成对记入 isClearTierDriven，供 updateClearInterval
    /// 判断改档是否重排（REV-DEV-01：显式时长任务不受改档影响）。
    private func schedulePendingClear(clearAfter delay: TimeInterval, isTierDriven: Bool) {
        clearWorkItem?.cancel()
        clearWorkItem = nil
        // 不变式：isClearTierDriven == true ⇔ clearWorkItem 非 nil（档位驱动）。
        // delay <= 0（「从不」）不挂任务 → 旗标必须复位 false，否则后续改档会
        // 误把「从不」档下的旧写入重排清除（原行为：无 pending 任务即不动）。
        guard delay > 0 else {
            self.isClearTierDriven = false
            return
        }
        self.isClearTierDriven = isTierDriven
        let written = writtenChangeCount
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let pasteboard = NSPasteboard.general
            // changeCount 不变 = 用户没有复制过别的内容，安全清空；
            // 变了 = 剪贴板已是用户自己的内容（或 FR-5.6 TOTP 已交接落盘），
            // 绝不误清。守卫判定收敛到纯函数 clipboardUnchanged（独立可测）。
            if Self.clipboardUnchanged(currentChangeCount: pasteboard.changeCount,
                                writtenChangeCount: written) {
                pasteboard.clearContents()
            }
            self.writtenChangeCount = -1
            self.clearWorkItem = nil
            self.isClearTierDriven = false
        }
        clearWorkItem = work
        DispatchQueue.main.asyncAfter(
            deadline: .now() + delay,
            execute: work
        )
    }

    deinit {
        // 契约兜底（FR-5.6 取消条件之一）：单例常态下不会走到
        totpWorkItem?.cancel()
        clearWorkItem?.cancel()
    }
}
