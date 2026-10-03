// TouchIDError.swift —— Touch ID 专属错误 + 解锁错误呈现分道。
//
// 2026-10-03 自 ErrorPresenter.swift 拆出独立文件（PL-5）：TouchIDError 无
// FfiError/CoreBindings 依赖，与呈现分道 TouchIDUnlockPresentation.resolve
// 共居，使解锁错误分道可独立单测（tools/run_touchid_error_presentation_tests.sh）；
// ErrorPresenter.swift 保留 FfiError 映射，经同模块引用本文件的 TouchIDError。

import Foundation

/// Touch ID 专属错误（docs/08 §4.1 / §8）——仅 Swift 侧产生。
enum TouchIDError: Error, Equatable {
    /// 4001：生物识别不可用（无硬件 / 未录入指纹 / 认证取消或失败 / header 未启用）
    case unavailable
    /// 4002：生物识别凭据已失效（指纹集变更 / Keychain 项不可读）
    case stale
    /// Swift-only（无错误码，docs/17 §5 冻结零新增）：瞬时不可用——传感器
    /// 未就绪 / biometry lockout / 系统刚唤醒，非持久失效（PL-7）。温和文案，
    /// LockView 按钮保留可再点，不置 stale。
    case transientUnavailable

    /// 规范化中文文案（docs/08 T03 验收②）。
    var userText: String {
        switch self {
        case .unavailable:
            return "错误 4001：生物识别解锁不可用（设备不支持或认证未通过），请使用主密码解锁。"
        case .stale:
            return "错误 4002：生物识别凭据已失效（可能因指纹变更），请使用主密码解锁后在设置中重新启用 Touch ID。"
        case .transientUnavailable:
            // PL-7（2026-10-03 用户反馈）：瞬时判定用静态温和文案，不加错误
            // 码（M-5：静态文案，不回显外部输入；docs/17 §5 冻结零新增）
            return "Touch ID 暂时不可用，请稍后重试或使用主密码解锁。"
        }
    }
}

/// Touch ID 解锁错误的呈现分道（AppModel.unlockWithTouchID 与
/// CrossCopySheet.unlockWithBiometric 共用，docs/08 §7.3/§7.6；PL-5 修复使
/// CrossCopySheet 与主解锁路径错误呈现一致）。
enum TouchIDUnlockPresentation: Equatable {
    /// 静默不弹（用户取消认证，取消 ≠ 失败）
    case silent
    /// 呈现指定文案
    case text(String)
    /// 非本函数可判定的错误（unexpected / invalidKeyLength / FfiError / 其他）
    /// ——调用方回退 ErrorPresenter.text（本文件零 CoreBindings 依赖，
    /// 无法判定 FfiError）
    case fallback

    /// 把 Touch ID 解锁错误映射为呈现分道（纯函数，独立单测）：
    ///   - `.userCanceled` → `.silent`（取消静默，两路径一致）
    ///   - `.itemNotFound` → `.text(4002)`（项不存在 = 持久失效）
    ///   - `.authFailed` → 按失败瞬间 `biometryAvailable` 分道（PL-7）：
    ///     瞬时 → `.text(温和文案)`；持久 → `.text(4002)`
    ///   - 其余（unexpected / invalidKeyLength / FfiError / TouchIDError）→
    ///     `.fallback`（调用方回退 ErrorPresenter.text）
    ///
    /// - Parameters:
    ///   - error: `BiometricKeychain().read` / FFI 抛出的解锁错误
    ///   - biometryAvailable: 失败瞬间 `BiometricKeychain.isBiometricsAvailable()`
    static func resolve(error: Error, biometryAvailable: Bool) -> TouchIDUnlockPresentation {
        switch error {
        case BiometricKeychainError.userCanceled:
            return .silent
        case BiometricKeychainError.itemNotFound:
            return .text(TouchIDError.stale.userText)
        case BiometricKeychainError.authFailed:
            switch TouchIDAuthFailure.disposition(biometryAvailable: biometryAvailable) {
            case .transient:
                return .text(TouchIDError.transientUnavailable.userText)
            case .persistent:
                return .text(TouchIDError.stale.userText)
            }
        default:
            return .fallback
        }
    }
}
