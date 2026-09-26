// ErrorPresenter.swift —— FFI 错误呈现。
//
// 纪律（T05 任务书）：FfiError 的 code + message **直出**给用户，不吞不改
// （错误文案已在 Rust 层脱敏，docs/07 §4.1）。

import Foundation
import SwiftUI

enum ErrorPresenter {
    /// 把任意 Error 转为可展示文本；FfiError 原样透出 code 与 message。
    static func text(_ error: Error) -> String {
        if let ffiError = error as? FfiError {
            return text(of: ffiError)
        }
        return String(describing: error)
    }

    private static func text(of error: FfiError) -> String {
        switch error {
        case let .Coffer(code, message):
            // 业务错误：code + message 直出（Rust 层已脱敏）
            return "错误 \(code)：\(message)"
        case let .InternalPanic(message):
            // panic 兜底（码 5999）：脱敏摘要直出
            return "内部错误（5999）：\(message)"
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
