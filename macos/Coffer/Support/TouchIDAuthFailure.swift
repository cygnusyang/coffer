// TouchIDAuthFailure.swift —— Touch ID 解锁失败瞬时/持久分道（PL-7）。
//
// 2026-10-03 用户反馈（docs/KNOWN-ISSUES.md PL-7，lead 登记）：长时间空闲 →
// 自动锁定 → 回来后 Touch ID 报 4002「凭据已失效（可能因指纹变更）」只能主
// 密码解锁。根因：`BiometricKeychain.read` 返回 errSecAuthFailed（-25293）有
// 两类成因——
//   - 持久：指纹集变更（biometryCurrentSet 失效）→ 现行 4002 + stale 正确
//   - 瞬时：系统锁屏 / 刚唤醒传感器未就绪 / biometry lockout（无人应答的
//     自动弹框超时可能累计触发）→ 不应判死
// 判别信号 = 失败瞬间 `isBiometricsAvailable()`（LAContext.canEvaluatePolicy，
// 只检测不弹窗）：false（含 lockout / 未就绪）→ 瞬时；true（canEvaluatePolicy
// 通过，物理可用，read 仍失败）→ 持久。
//
// 判定抽成纯函数（docs/08 §9 T04 纯函数纪律）：无 IO / 无 FFI / 无 Keychain
// 依赖，独立单测（tools/run_touchid_auth_failure_tests.sh）。

/// Touch ID 解锁失败后的凭据判定：瞬时（系统/传感器临时不可用）vs 持久
/// （指纹集变更等）。仅 `.authFailed`（errSecAuthFailed）需要分道；
/// `.itemNotFound` 恒为持久失效（docs/08 §4.1），不经本判定。
enum TouchIDAuthFailure: Equatable {
    /// 瞬时不可用：不置 stale、touchIDStatus 保持不变，按钮保留可再点，
    /// 呈现温和文案（TouchIDError.transientUnavailable）
    case transient
    /// 持久失效：4002 + 置 touchIDStatus = .stale 终判（docs/08 §4.1 语义不变）
    case persistent

    /// 瞬时/持久分道纯函数。
    ///
    /// - Parameter biometryAvailable: 失败瞬间 `BiometricKeychain
    ///   .isBiometricsAvailable()` 的结果。false → .transient（传感器未就绪 /
    ///   biometry lockout / 刚唤醒）；true → .persistent（指纹集变更场景项
    ///   物理仍在，canEvaluatePolicy 通过，read 才失败）。
    static func disposition(biometryAvailable: Bool) -> TouchIDAuthFailure {
        biometryAvailable ? .persistent : .transient
    }
}
