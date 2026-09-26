// TouchIDStatus.swift —— Touch ID 通道三态（docs/08 §4 / §7.5 / §8）。
//
// 三态组合逻辑抽为纯函数（docs/08 §9 T04 验收②）：判定只依赖三个布尔信号，
// 无 IO / 无 FFI / 无 Keychain 依赖，可独立单测（macos/Tests/TouchIDStatusTests）。
//
// 信号语义（docs/08 §3.1）：
//   - header.biometric_wrap.available = 「用户意图开启」（持久意愿，Rust 侧）
//   - Keychain 项存在性 = 「实际可用」信号（Swift 侧）。注意：指纹集变更后
//     项通常仍「存在」但不可读，stale 终判以 unlockWithTouchID 的 read 失败
//     为准（docs/08 §4.1）；此处 existence 仅是设置页状态行的近实时信号。

/// Touch ID 通道三态（docs/08 §7.5 状态行 / §8 降级矩阵）。
enum TouchIDStatus: Equatable {
    /// 功能未启用（header available=false，或无打开的库会话）
    case disabled
    /// header available=true 且 Keychain 项存在：可用
    case enabled
    /// header available=true 但 Keychain 项缺失/失效（BioStale）：
    /// 需主密码解锁后「重新启用」（docs/08 §4.1）
    case stale

    /// 三态判定纯函数（docs/08 §9 T04 验收②）。
    ///
    /// 组合规则（docs/08 §8 降级矩阵）：
    ///   - 无会话 / header 未启用 → disabled（Keychain 项残留不影响判定，
    ///     孤儿项危害 ≈ 0，见 docs/08 §4.1 顺序裁定）
    ///   - header 启用 ∧ Keychain 项存在 → enabled
    ///   - header 启用 ∧ Keychain 项缺失 → stale（BioStale）
    ///
    /// - Parameters:
    ///   - headerWrapAvailable: `session.hasBiometricWrap()`——header
    ///     `biometric_wrap.available`
    ///   - keychainItemExists: `BiometricKeychain.itemExists(vaultUUID:)`
    ///   - sessionOpen: 是否有打开的库会话（AppModel.session != nil）
    static func resolve(
        headerWrapAvailable: Bool,
        keychainItemExists: Bool,
        sessionOpen: Bool = true
    ) -> TouchIDStatus {
        guard sessionOpen, headerWrapAvailable else { return .disabled }
        return keychainItemExists ? .enabled : .stale
    }

    /// 状态行短文案（docs/08 §7.5 状态行）。
    var label: String {
        switch self {
        case .disabled: return "已停用"
        case .enabled: return "已启用"
        case .stale: return "凭据已失效（需重新启用）"
        }
    }
}
