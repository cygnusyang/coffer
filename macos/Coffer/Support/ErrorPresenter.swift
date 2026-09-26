// ErrorPresenter.swift —— FFI 错误呈现。
//
// 纪律（T05 任务书）：FfiError 的 code + message **直出**给用户，不吞不改
// （错误文案已在 Rust 层脱敏，docs/07 §4.1）。
// 例外（docs/08 T03）：4001/4002 在 docs/03 §12 错误码表中有跨层固定语义，
// 用规范化中文文案呈现；其中 4002 仅由 Swift 侧产生（docs/08 C-6：Rust 不产生 4002）。

import Foundation
import SwiftUI

/// Touch ID 专属错误（docs/08 §4.1 / §8）——仅 Swift 侧产生。
enum TouchIDError: Error, Equatable {
    /// 4001：生物识别不可用（无硬件 / 未录入指纹 / 认证取消或失败 / header 未启用）
    case unavailable
    /// 4002：生物识别凭据已失效（指纹集变更 / Keychain 项不可读）
    case stale

    /// 规范化中文文案（docs/08 T03 验收②）。
    var userText: String {
        switch self {
        case .unavailable:
            return "错误 4001：生物识别解锁不可用（设备不支持或认证未通过），请使用主密码解锁。"
        case .stale:
            return "错误 4002：生物识别凭据已失效（可能因指纹变更），请使用主密码解锁后在设置中重新启用 Touch ID。"
        }
    }
}

enum ErrorPresenter {
    /// 把任意 Error 转为可展示文本；FfiError 原样透出 code 与 message。
    static func text(_ error: Error) -> String {
        switch error {
        case let ffiError as FfiError:
            return text(of: ffiError)
        case let touchIDError as TouchIDError:
            return touchIDError.userText
        case let keychainError as BiometricKeychainError:
            return text(of: keychainError)
        default:
            return String(describing: error)
        }
    }

    private static func text(of error: FfiError) -> String {
        switch error {
        case let .Coffer(code, message):
            switch code {
            case 4001:
                // 跨层固定语义（docs/03 §12 / docs/08 D-8）：available=false 时调用 bio 解锁
                return TouchIDError.unavailable.userText
            case 4002:
                // Rust 不产生 4002（docs/08 C-6）；此分支仅为防御性兜底
                return TouchIDError.stale.userText
            default:
                // 业务错误：code + message 直出（Rust 层已脱敏）
                return "错误 \(code)：\(message)"
            }
        case let .InternalPanic(message):
            // panic 兜底（码 5999）：脱敏摘要直出
            return "内部错误（5999）：\(message)"
        }
    }

    private static func text(of error: BiometricKeychainError) -> String {
        switch error {
        case .itemNotFound, .authFailed:
            // docs/08 §4.1：认证通过后的 Keychain 读取失败（项不存在 /
            // biometryCurrentSet 失效）→ 凭据失效降级，引导主密码 + 重新启用
            return TouchIDError.stale.userText
        case .invalidKeyLength:
            return "内部错误：生物识别密钥长度非法。"
        case .unexpected(let status):
            return "错误 4001：生物识别解锁不可用（Keychain 异常 \(status)），请使用主密码解锁。"
        }
    }
}

// MARK: - 错误弹窗 ViewModifier

/// 统一错误弹窗：绑定 `lastErrorMessage`，非 nil 时展示、关闭时清空。
struct FfiErrorAlert: ViewModifier {
    @Binding
    var errorMessage: String?

    func body(content: Content) -> some View {
        content.alert(
            "操作失败",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )
        ) {
            Button("好", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }
}

extension View {
    /// 挂载 FFI 错误弹窗；`message` 通常绑定 `AppModel.lastErrorMessage`。
    func ffiErrorAlert(_ message: Binding<String?>) -> some View {
        modifier(FfiErrorAlert(errorMessage: message))
    }
}
