// AutoPromptBiometric.swift —— 启动自动 Touch ID 引导判定（纯函数）。
//
// 用户 2026-10-03 口头裁定（feat）：启动 Coffer 后，若工作目录仅一个密码库
// 且 Touch ID 通道可用（touchIDStatus == .enabled，内含设备支持），则不经点击
// 直接弹指纹认证框——单库用户启动 → 一次授权 → 直达主界面。
//
// 判定抽为纯函数（无 IO / 无 Keychain 依赖），独立单测——参照
// TouchIDStatus.resolve 纪律（docs/08 §9 T04 验收②）。AppModel.bootstrap
// 末尾接线（docs/08 §7.6 启动自动引导时序）。

/// 启动自动引导判定纯函数命名空间。
enum AutoPromptBiometric {
    /// 是否在启动时自动弹 Touch ID 认证框。
    ///
    /// 条件（全部满足才弹，docs/08 §7.6）：
    ///   - `vaultCount == 1`：工作目录仅一个密码库（单库用户免选择）
    ///   - `isSupported`：设备支持生物识别（`BiometricKeychain.isBiometricsAvailable()`，
    ///     canEvaluatePolicy 无 UI 副作用）
    ///   - `status == .enabled`：Touch ID 通道已启用（header available ∧ Keychain
    ///     项存在；.enabled 已隐含 headerWrapAvailable，此处 isSupported 独立
    ///     再查设备支持——双保险）
    ///
    /// 不满足 → 静默回退到锁定页手点解锁（启动零打扰）。
    static func shouldAutoPromptBiometric(
        vaultCount: Int,
        isSupported: Bool,
        status: TouchIDStatus
    ) -> Bool {
        vaultCount == 1 && isSupported && status == .enabled
    }
}
