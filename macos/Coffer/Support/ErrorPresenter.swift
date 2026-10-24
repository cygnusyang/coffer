// ErrorPresenter.swift —— FFI 错误呈现。
//
// 纪律（v2.13.0 D-10 收口，docs/03-功能设计/24 §7）：**按 code 出文案，载荷降为日志**。
// 用户只看码文案（CoreErrorText / LicenseErrorText / TouchIDError），原始 message 只进
// DiagLog——否则英文界面必然混入 Rust 侧中文载荷（「corrupted container: KDF 参数非法：…」）。
// 契约回到 core/cf-ffi/src/error.rs:60 注释的原意（message 供日志，UI 按 code 本地化）。
// 例外（docs/08 T03）：4001/4002 在 docs/03 §12 错误码表中有跨层固定语义，
// 用规范化中文文案呈现；其中 4002 仅由 Swift 侧产生（docs/08 C-6：Rust 不产生 4002）。
// 未知码仍直出 code + 载荷（可诊断性优先于语言纯度，设计 §7.5）。
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
            return updateError.errorDescription ?? String(localized: "无法更新密码。")
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
                // 1xxx–5xxx 业务码：查表出文案，载荷降为诊断日志（设计 §7.5：载荷
                // 不得进入任何用户可见串）。纯函数映射见 CoreErrorText.swift。
                if let coreText = CoreErrorText.text(forCode: Int(code)) {
                    DiagLog.append("FFI 错误 \(code) 原始载荷：\(message)")
                    return coreText
                }
                // 未知码兜底：带原始载荷直出（此时可诊断性优先于语言纯度）。
                // 码按 String 插值（%@）而非 %lld——Int 插值会走千位分组，
                // 1005 会显示成「1,005」（实测），错误码不该被本地化改写。
                return String(localized: "错误 \(String(code))：\(message)")
            }
        case let .InternalPanic(message):
            // panic 兜底（码 5999）：用户看码文案，脱敏摘要进日志（设计 §7.5）
            DiagLog.append("FFI panic 原始载荷：\(message)")
            return CoreErrorText.internalPanic
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
            return String(localized: "内部错误：生物识别密钥长度非法。")
        case .unexpected(let status):
            // OSStatus 按 String 插值：-25300 若走 %lld 会显示成「-25,300」（实测）
            return String(localized: "错误 4001：生物识别解锁不可用（Keychain 异常 \(String(status))），请使用主密码解锁。")
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
