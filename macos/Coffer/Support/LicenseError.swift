// LicenseError.swift —— 许可域错误呈现（FR-15，docs/03 §12 6xxx 段 / §14.5）。
//
// 6xxx 文案映射抽为纯函数（对齐 TouchIDError 先例，PL-5）：零 CoreBindings
// 依赖，可独立单测（tools/run_license_status_tests.sh）；ErrorPresenter 按
// code 直出（既有结构，docs/07 §2.3「UI 按 code 本地化，不解析 message」）。
//
// 文案纪律（docs/03 §14.5）：
//   - 6001 刻意合并序列号验证的全部失败原因（格式 / 签名 / 他机 / 版本
//     不支持）同码同文案——FR-15.6 不可区分纪律，文案不得区分失败原因；
//   - 6002 / 6003 刻意拆分（到期只读 vs 异常退化），属 UX 引导需要：
//     6002 引导去激活（正常路径），6003 提示异常退化（引导重启 / 重装，
//     仍异常再联系支持）；
//   - 6004 许可信息存储暂不可用（§14.8 失败模式，视情况重试）。

import Foundation

/// 激活错误（docs/03 §14.9 activate「任何失败统一 6001」）：单 case、零细节，
/// 保证不可区分（FR-15.6）。
enum LicenseActivationError: Error, Equatable {
    /// 序列号无效（6001）。不携带失败原因字段——不可区分纪律。
    case serialInvalid

    /// 激活错误文案（6001，docs/03 §12）。纯函数——视图与 ErrorPresenter 共用，
    /// 可独立单测（本文件零 CoreBindings 依赖）。文案单一来源取
    /// `LicenseErrorText.serialInvalid`（6001 恒在映射中，不做 ?? 兜底——
    /// 兜底是死代码，reviewer LOW-2）。
    var userText: String {
        LicenseErrorText.serialInvalid
    }
}

/// 6xxx 错误文案映射（纯函数，docs/03 §12 6xxx 段 / §14.5）。
enum LicenseErrorText {
    /// 6001 统一文案（单一来源）：序列号验证的全部失败原因合并为同一文案
    /// （FR-15.6 不可区分纪律）。`text(forCode: 6001)` 映射与
    /// `LicenseActivationError.userText` 均经此常量取文案，杜绝重复字面量。
    static let serialInvalid = "序列号无效"

    /// 6xxx 码 → 规范化中文文案；非 6xxx 返回 nil（调用方走默认直出）。
    static func text(forCode code: Int) -> String? {
        switch code {
        case 6001:
            // 统一文案、零细节：不区分格式 / 签名 / 他机 / 版本（FR-15.6）
            return serialInvalid
        case 6002:
            // 试用到期只读：引导去激活（正常路径，§14.5）
            return "试用期已结束，当前处于只读模式。激活后可恢复写入。"
        case 6003:
            // 门禁异常退化：引导重启 / 重装，仍异常再联系支持（§14.5）
            return "当前许可状态不允许此操作。许可状态异常已进入只读保护，请重启应用后重试；若问题持续，请重装应用或联系支持。"
        case 6004:
            // 许可信息存储暂不可用（§14.8）：可稍后重试
            return "许可信息存储暂不可用，请稍后重试。"
        default:
            return nil
        }
    }
}
