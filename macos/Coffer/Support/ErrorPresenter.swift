// ErrorPresenter.swift —— FFI 错误呈现。
//
// 纪律（T05 任务书）：FfiError 的 code + message **直出**给用户，不吞不改
// （错误文案已在 Rust 层脱敏，docs/07 §4.1）。
// 例外（docs/08 T03）：4001/4002 在 docs/03 §12 错误码表中有跨层固定语义，
// 用规范化中文文案呈现；其中 4002 仅由 Swift 侧产生（docs/08 C-6：Rust 不产生 4002）。
//
// TouchIDError 枚举与解锁错误呈现分道 TouchIDUnlockPresentation 已拆至
// Support/TouchIDError.swift（2026-10-03 PL-5，零 CoreBindings 依赖以独立单测）；
// 本文件经同模块引用。

import Foundation
import SwiftUI

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
        case let activationError as LicenseActivationError:
            // 激活失败统一 6001「序列号无效」（docs/03 §14.9 / FR-15.6）
            return activationError.userText
        case let updateError as UpdatePasswordError:
            // 更新密码 fail-closed 前置（缺密码字段 / 空新密码）——防御性
            // 兜底直出可操作文案（正常流程 UI 已隐藏/禁用入口，见 UpdatePasswordSheet）
            return updateError.errorDescription ?? "无法更新密码。"
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
                // 6xxx 许可域（docs/03 §12/§14.5）：按 code 直出规范化文案
                // （6001 统一序列号无效——FR-15.6 不可区分；6002/6003 拆分引导）。
                // 纯函数映射见 Support/LicenseError.swift（零 CoreBindings 可单测，
                // 签名为 Int——FFI 侧 code 为 UInt16，边界处转换）。
                if let licenseText = LicenseErrorText.text(forCode: Int(code)) {
                    return licenseText
                }
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
        case .userCanceled:
            // 用户取消认证不是失败（reviewer HIGH 处置，docs/08 §7.3/§7.6）：
            // 不弹吓人错误框。空串 = 不呈现；unlockWithTouchID 的 catch 对该
            // case 显式跳过 lastErrorMessage（空串也会弹空白框，故调用侧不写入）。
            return ""
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
                // 空串视为无错误（BiometricKeychainError.userCanceled → ""，不弹
                // 空白框兜底；见 text(of:) 注释），仅非空错误文案才呈现。
                get: { (errorMessage ?? "").isEmpty == false },
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
