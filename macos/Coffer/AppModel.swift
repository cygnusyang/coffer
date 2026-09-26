// AppModel.swift —— 应用全局状态（@MainActor ObservableObject）。
//
// 职责（docs/07 §2.4）：
//   - 持有 FFI 工厂（CofferApp）与当前 VaultSession 引用
//   - appPhase 状态机：booting → noVault / locked → unlocked
//   - 建库 / 解锁 / 锁定的异步编排（Argon2id 慢调用用 Task.detached 包裹）
//
// 明文纪律（docs/07 §2.4 / §4.2；docs/08 §7.4）：
//   - 主密码只作为方法参数传入，不落任何 @State / @Published 属性
//   - 明文字段值只在取值那一刻经 FFI 取回，用完即弃，不进本模型
//   - K_bio（bio unwrap-key）同纪律：Keychain 取回即用，不落任何属性

import AppKit
import Foundation
import LocalAuthentication
import SwiftUI

/// 应用阶段状态机。
enum AppPhase: Equatable {
    /// 启动中：枚举工作目录里的库。
    case booting
    /// 工作目录没有库：进入建库流程。
    case noVault
    /// 已有库但处于锁定态。
    case locked
    /// 已解锁，进入条目管理。
    case unlocked
    /// 不可恢复的启动失败（列出原因，引导用户检查环境）。
    case fatal(String)
}

@MainActor
final class AppModel: ObservableObject {
    // MARK: - Published 状态

    @Published var phase: AppPhase = .booting
    @Published private(set) var vaultName: String = ""
    /// 当前库 UUID 文本（Keychain bio 项的 account，docs/08 §3.2；非密钥材料）。
    @Published private(set) var vaultUUID: String = ""
    /// 最近一次可呈现的错误文案（code+message 直出，见 ErrorPresenter）。
    @Published var lastErrorMessage: String?
    /// 慢调用（建库 / 解锁 / 导入）进行中标记，用于禁用按钮。
    @Published private(set) var isBusy = false

    /// 建库成功后的可选「启用 Touch ID」步骤标记（docs/08 §4.1 建库可选启用）。
    /// 建库成功时置位（仅 Touch ID 设备）；用户在首次解锁后的引导 sheet 中
    /// 完成或跳过后清除。无 Touch ID 设备恒 false——v0.1 建库流程零变化
    /// （docs/08 §9 T04 验收①）。
    @Published var pendingBioOffer = false

    // MARK: 条目列表 / 详情状态（T05 阶段二）

    /// 当前过滤 + 搜索下的条目摘要列表。
    @Published var items: [FfiItemSummary] = []
    /// 侧栏过滤条件（变更即重载列表）。
    @Published var sidebarFilter: SidebarFilter = .all {
        didSet { guard oldValue != sidebarFilter else { return }; reloadItems() }
    }
    /// 标题搜索词（非空时走 search 接口）。
    @Published var searchText: String = ""
    /// 当前选中条目 ID。
    @Published var selectedItemID: String? {
        didSet { guard oldValue != selectedItemID else { return }; loadSelectedDetails() }
    }
    /// 选中条目的完整详情（Concealed 值已掩码）。
    @Published var currentDetails: FfiItemDetails?

    // MARK: 自动锁定配置（T05 阶段四）

    /// 空闲自动锁定分钟数（0 = 从不）。默认 5 分钟（FR-12.1）。
    @Published var autoLockMinutes: Int = AppModel.loadAutoLockMinutes() {
        didSet {
            // 0（从不）落盘为 -1，与「从未配置」区分
            UserDefaults.standard.set(autoLockMinutes == 0 ? -1 : autoLockMinutes,
                                      forKey: Self.autoLockDefaultsKey)
            applyIdleTimeout()
        }
    }

    /// 从 UserDefaults 读已保存档位（nonisolated，供属性默认值使用）。
    nonisolated private static func loadAutoLockMinutes() -> Int {
        let stored = UserDefaults.standard.integer(forKey: "autoLockMinutes")
        // 未配置（键不存在时 integer 返回 0）→ 默认 5 分钟；-1 = 用户选了「从不」
        switch stored {
        case 0: return 5
        case -1: return 0
        default: return autoLockOptions.contains(stored) ? stored : 5
        }
    }
    /// 可选档位：1 / 5 / 15 / 30 分钟、从不。
    nonisolated static let autoLockOptions: [Int] = [1, 5, 15, 30, 0]
    nonisolated static let autoLockDefaultsKey = "autoLockMinutes"
    /// 自动锁定平台驱动（锁屏 / 休眠 / 屏保立即锁定 + 空闲喂入）。
    private var lockMonitor: AutoLockMonitor?

    // MARK: - FFI 对象

    /// Rust 侧应用工厂（库的枚举 / 创建 / 打开注册表）。
    let factory: CofferApp
    /// 当前打开的库会话；noVault 阶段为 nil。
    private(set) var session: VaultSession?

    // MARK: - 路径

    /// 库工作目录（沙盒内 Documents/Coffer）。
    let baseDir: URL

    private var terminateObserver: NSObjectProtocol?

    // MARK: - 生命周期

    nonisolated init() {
        // 注意：AppModel 是 @MainActor，但 Swift 5 模式下 @StateObject
        // 初始化发生在主线程，这里的非隔离初始化只做确定性、无 IO 副作用的装配。
        self.factory = CofferApp()

        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
        self.baseDir = documents.appendingPathComponent("Coffer", isDirectory: true)
    }

    /// 启动入口（RootView.onAppear 调用）：建目录 + 枚举已有库 + 启动自动锁定监视。
    func bootstrap() {
        // 幂等：仅在 booting 阶段执行一次。
        guard phase == .booting else { return }
        try? FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        // 自动锁定监视（持弱引用，无循环）
        let monitor = AutoLockMonitor()
        monitor.start(model: self)
        lockMonitor = monitor

        do {
            let briefs = try factory.listVaults(baseDir: baseDir.path)
                .sorted { $0.createdAt < $1.createdAt } // 最早创建者优先（Q-2：UI 只做单库）
            if let brief = briefs.last {
                openSession(brief)
            } else {
                phase = .noVault
            }
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
    }

    // MARK: - 会话管理

    private func openSession(_ brief: FfiVaultBrief) {
        do {
            let opened = try factory.openVault(baseDir: baseDir.path, vaultUuid: brief.vaultUuid)
            session = opened
            vaultName = brief.displayName
            vaultUUID = brief.vaultUuid
            applyIdleTimeout()
            phase = .locked
            refreshTouchIDStatus()
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
    }

    // MARK: - 建库

    /// 创建库（zxcvbn 门禁在 Rust 侧，score < 3 → 错误码 1010）。
    /// Argon2id 256 MiB 档位派生耗时约 0.5–1 s，用 Task.detached 包裹避免卡主线程。
    func createVault(name: String, password: String) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        let factory = self.factory
        let dir = self.baseDir.path
        do {
            let brief = try await Task.detached(priority: .userInitiated) {
                try factory.createVault(baseDir: dir, name: name, password: password)
            }.value
            openSession(brief)
            // 建库成功 → 首次解锁后提供可选「启用 Touch ID」步骤（docs/08 §4.1）。
            // 仅 Touch ID 设备置位；无 Touch ID 机器不置位，v0.1 流程零变化。
            // 注意：enable 需解锁态（Rust 1001 门禁），故引导 sheet 挂在
            // 首次解锁完成后（RootView），而非建库成功即刻。
            pendingBioOffer = isTouchIDSupported
        } catch {
            lastErrorMessage = ErrorPresenter.text(error)
        }
    }

    // MARK: - 解锁 / 锁定

    /// 解锁（Argon2id 慢调用，Task.detached 包裹）。
    /// 密码只作为参数传入：拷贝进 Task 闭包使用后即弃，不落任何属性。
    func unlock(password: String) async {
        guard let session, !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let target = session
            let info = try await Task.detached(priority: .userInitiated) {
                try target.unlock(password: password)
            }.value
            vaultName = info.displayName
            applyIdleTimeout()
            phase = .unlocked
        } catch {
            lastErrorMessage = ErrorPresenter.text(error)
        }
    }

    /// 手动锁定：清零 Rust 侧密钥，回到锁定态，并清空 UI 侧条目状态。
    func lock() {
        session?.lock()
        // 锁定时刻剪贴板里可能仍有刚复制的密码：立即清空（clearOnLock
        // 沿用 changeCount 纪律，用户已复制自己的内容则不动剪贴板）。
        ClipboardManager.shared.clearOnLock()
        // 锁定即清空已解密数据的 UI 状态（docs/07 §2.4：锁定后清空已取回明文状态）
        items = []
        currentDetails = nil
        selectedItemID = nil
        searchText = ""
        phase = session != nil ? .locked : .noVault
        refreshTouchIDStatus()
    }

    /// 把当前超时配置应用到会话（0 或负数 = 禁用自动锁定）。
    private func applyIdleTimeout() {
        guard let session else { return }
        let secs = autoLockMinutes > 0 ? Int64(autoLockMinutes) * 60 : 0
        session.setIdleTimeoutSecs(secs: secs)
    }

    // MARK: - Touch ID 解锁（docs/08 §7.2 / §7.4 / §8）

    /// Touch ID 通道状态（openSession / lock 时刷新；enable/disable 后由
    /// 设置页再触发刷新）。三态定义与组合规则见 Support/TouchIDStatus.swift
    /// （docs/08 §9 T04 验收②：组合逻辑为纯函数，独立单测）。
    @Published private(set) var touchIDStatus: TouchIDStatus = .disabled

    /// 降级验证开关（docs/08 §9 T04 验收①）：强制视为「无 Touch ID 设备」，
    /// 验证全 UI 降级路径（设置入口隐藏 / LockView 无按钮 / 建库步骤不出现）。
    /// 用法：`defaults write app.coffer.Coffer debugDisableTouchID -bool true`
    /// 后重启 App；`-bool false` / `defaults delete` 恢复。
    nonisolated static let debugDisableTouchIDKey = "debugDisableTouchID"

    /// 当前设备是否支持生物识别（LAContext 只检测不弹窗，docs/08 §8 第一行）。
    /// false 时 UI 应整体隐藏 Touch ID 入口（LockView 按钮 / 设置入口 / 建库步骤）。
    var isTouchIDSupported: Bool {
        if UserDefaults.standard.bool(forKey: Self.debugDisableTouchIDKey) {
            return false
        }
        return BiometricKeychain.isBiometricsAvailable()
    }

    /// 刷新三态：纯读操作（header 布尔 + Keychain 属性查询），无密钥操作。
    /// 组合逻辑委托 TouchIDStatus.resolve 纯函数（docs/08 §9 T04 验收②）。
    /// 注意：biometryCurrentSet 失效后 Keychain 项通常仍「存在」（读取才失败），
    /// 因此 stale 终判以 unlockWithTouchID 的 read 失败为准（docs/08 §4.1）。
    func refreshTouchIDStatus() {
        guard let session, !vaultUUID.isEmpty else {
            touchIDStatus = .disabled
            return
        }
        touchIDStatus = TouchIDStatus.resolve(
            headerWrapAvailable: session.hasBiometricWrap(),
            keychainItemExists: BiometricKeychain().itemExists(vaultUUID: vaultUUID)
        )
    }

    /// Touch ID 解锁（docs/08 §7.2 时序）：
    /// LAContext 认证 → Keychain 读 K_bio → FFI unlockWithBiometric →
    /// 与主密码解锁完全相同的收尾（D-5：一次 Touch ID 换一次 DEK 解封）。
    ///
    /// K_bio 纪律（§7.4）：取回即用——K_bio 只作局部变量捕获进 Task 闭包，
    /// 用完即弃，不落任何 @Published / 不进全局状态（与主密码同纪律）。
    /// isBusy 互斥与主密码解锁共用。
    func unlockWithTouchID() async {
        guard let session, !isBusy, phase == .locked else { return }

        // 前置门禁（Swift 侧先行判定，避免无谓跨桥；Rust 侧同语义兜底 4001，D-8）：
        // ① header 未启用 bio 封装（available=false → Rust 会回 4001）；
        // ② 设备无 Touch ID / 未录入指纹（canEvaluatePolicy=false → 4001）。
        guard session.hasBiometricWrap(), BiometricKeychain.isBiometricsAvailable() else {
            lastErrorMessage = ErrorPresenter.text(TouchIDError.unavailable)
            return
        }

        isBusy = true
        defer { isBusy = false }

        do {
            // ① 弹 Touch ID 认证（主线程触发，LAContext UI 纪律，docs/08 §7.4）
            let context = LAContext()
            try await Self.authenticateWithBiometrics(context: context)

            // ② 认证通过 → 同一 context 读 K_bio（不再二次弹窗）。
            //    读取失败（项不存在 / biometryCurrentSet 失效）→ 4002 降级（§4.1）：
            //    不改 header、不删项——用户主密码解锁后可在设置页「重新启用」。
            let kBio = try BiometricKeychain().read(vaultUUID: vaultUUID, context: context)

            // ③ 后半段走 FFI：open(K_bio, aad) → DEK → SubKeys → ItemStore。
            //    K_bio 拷贝进 Task 闭包，本函数返回后局部变量即弃。
            //    AEAD open 失败（K_bio 不匹配 / 篡改）→ Rust 统一 1002（D-8）。
            let target = session
            let info = try await Task.detached(priority: .userInitiated) {
                try target.unlockWithBiometric(kBio: kBio)
            }.value

            // ④ 状态机切换：与主密码解锁同收尾（锁定/自动锁定路径零新增，D-5）
            vaultName = info.displayName
            applyIdleTimeout()
            phase = .unlocked
        } catch {
            // ErrorPresenter 分派：TouchIDError / BiometricKeychainError /
            // FfiError（1002 / 4001 / 5999）各自语义化呈现
            lastErrorMessage = ErrorPresenter.text(error)
            // 4002（凭据失效）后刷新状态行，让设置页/LockView 与实际一致
            refreshTouchIDStatus()
        }
    }

    /// 启用 Touch ID 解锁（docs/08 §4.1 enable 流程，T04 设置页与建库可选
    /// 步骤共用编排）。D-6：enable 需主密码重新验证——Rust 侧 recover_dek
    /// 校验密码并解出 DEK（错 → 1002），密码不落任何属性。
    ///
    /// 顺序裁定 D-9：**先 Keychain 后 header**——
    ///   ① Rust CSPRNG 生成 K_bio（32B）；
    ///   ② Keychain 写入（失败 → 直接报错，header 未动，无半启用态）；
    ///   ③ FFI enableBiometric（失败 → 补偿删除 Keychain 项，不留孤儿半启用态；
    ///     孤儿项本身危害 ≈ 0，但补偿使幂等重试路径更干净）。
    ///
    /// - Parameter password: 主密码（仅作参数传入，用后即弃，不落状态）。
    /// - Returns: 是否启用成功（调用方据此关闭对话框）。
    @discardableResult
    func enableTouchID(password: String) async -> Bool {
        guard let session, !isBusy, phase == .unlocked,
              isTouchIDSupported, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let factory = self.factory
        let uuid = vaultUUID
        do {
            // ① K_bio：Rust CSPRNG 随机 32B（docs/08 D-3；非 DEK、非派生物）
            let kBio = try factory.newBiometricUnwrapKey()
            // ② 先 Keychain（D-9）：biometryCurrentSet 门禁，ThisDeviceOnly
            try BiometricKeychain().save(key: kBio, vaultUUID: uuid, requireBiometry: true)
            // ③ 后 header：recover_dek(password) → seal → 原子重写（慢调用，
            //    Argon2id 约 1s，Task.detached 包裹）。K_bio 拷贝进 Task 闭包，
            //    本函数返回后局部变量即弃（docs/08 R-2 同纪律）。
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.enableBiometric(password: password, kBio: kBio)
            }.value
            refreshTouchIDStatus()
            return true
        } catch {
            // 失败补偿（docs/08 §4.1）：删除刚写入的 Keychain 项（幂等），
            // header 保持原样（Rust 失败时不重写文件）。密码错 1002 与
            // Keychain 失败均经 ErrorPresenter 呈现（T04 验收③）。
            _ = try? BiometricKeychain().delete(vaultUUID: uuid)
            lastErrorMessage = ErrorPresenter.text(error)
            refreshTouchIDStatus()
            return false
        }
    }

    /// 关闭 Touch ID 解锁（docs/08 §4.1 disable 流程）。D-9 反向：
    /// **先删 Keychain 再改 header**——Keychain 删除幂等；header 写失败时
    /// 功能实际已失效（项已删），报非致命错误、可重试。
    ///
    /// - Returns: 是否关闭成功。
    @discardableResult
    func disableTouchID() async -> Bool {
        guard let session, !isBusy, phase == .unlocked, !vaultUUID.isEmpty else {
            return false
        }
        isBusy = true
        defer { isBusy = false }

        let uuid = vaultUUID
        // ① 先删 Keychain（D-9 反向；幂等）
        do {
            try BiometricKeychain().delete(vaultUUID: uuid)
        } catch {
            // 删除失败属系统层异常：header 未动，功能未关，可重试
            lastErrorMessage = ErrorPresenter.text(error)
            return false
        }
        // ② 后 header：原子重写 → 禁用态（幂等）
        do {
            let target = session
            try await Task.detached(priority: .userInitiated) {
                try target.disableBiometric()
            }.value
            refreshTouchIDStatus()
            return true
        } catch {
            // header 写失败：非致命（docs/08 §8）——Keychain 已删，Touch ID
            // 解锁实际已不可用；header 残留密文无泄露面，可重试关闭
            lastErrorMessage = ErrorPresenter.text(error)
            refreshTouchIDStatus()
            return false
        }
    }

    /// LAContext 生物识别认证（evaluatePolicy 的 async 包装）。
    /// 取消 / 失败 / 不可用一律 → 4001 文案（docs/08 §7.2：LA 失败显示 4001）。
    private static func authenticateWithBiometrics(context: LAContext) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "解锁 Coffer"
            ) { success, error in
                if success {
                    continuation.resume()
                } else {
                    // 保留系统错误信息用于调试日志；用户面统一 4001 文案
                    NSLog("Coffer TouchID evaluatePolicy 失败: \(String(describing: error))")
                    continuation.resume(throwing: TouchIDError.unavailable)
                }
            }
        }
    }

    /// 进程退出兜底（AppDelegate.applicationWillTerminate 调用）。
    nonisolated func lockAllForTermination() {
        MainActor.assumeIsolated {
            factory.lockAll()
        }
    }

    // MARK: - 密码强度（非门禁展示用）

    /// 强度估算：走 Rust 工厂版 zxcvbn（纯计算、无会话依赖，建库前
    /// 可用 —— v0.1 的「无会话只能本地粗估」限制已移除）。
    func estimateStrength(_ candidate: String) -> FfiStrengthEstimate? {
        try? factory.strengthEstimate(candidate: candidate)
    }
}
