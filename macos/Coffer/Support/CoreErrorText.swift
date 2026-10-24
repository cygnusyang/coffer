// CoreErrorText.swift —— 核心（FFI）错误码 → 用户可见文案（v2.13.0，设计 24 §7）。
//
// 为什么按码而不是按载荷（D-10 方案 A）：Rust 侧 CfError 的 Display 是英文、载荷
// 大量是中文（cf-crypto「KDF 参数非法：…」等），中英混排直出会在英文界面留下中文；
// 且中英混排的句子既不可读也不可译。故「用户看码文案、载荷进日志」，
// 契约回到 core/cf-ffi/src/error.rs:60 注释的原意（日志用 message，UI 按 code 本地化）。
//
// 与 Support/LicenseError.swift 同型（零 CoreBindings 依赖，可独立单测，
// tools/run_core_error_text_tests.sh）：ErrorPresenter 先问许可域（6xxx），
// 再问本表（1xxx–5xxx + panic 5999），都查不到才兜底直出 code + 载荷。
//
// 文案纪律：
//   - 键 = 中文原文（D-6），值 = 英文译文，落在 Resources/Localization/en/40-errors.strings。
//   - 文案不暴露载荷细节：1002 必须同时覆盖「密码错」与「头/清单篡改」（FR-1.4
//     不可区分），不得暗示具体原因；1005（文件损坏）与 1002 是两个码，不合并。
//   - 4001 / 4002 不在本表：它们由 ErrorPresenter 走 docs/08 T03 冻结的
//     TouchIDError 文案（含「错误 4001：…」前缀），改口径会动冻结文案。
//   - 6xxx 不在本表：归 LicenseErrorText（6001 不可区分纪律 FR-15.6）。
//   - 本表只给 text(forCode:)：未知码「是否展示载荷」的判定就是 text == nil，
//     不再另设 showsRawDetail（两条真值来源会漂移）。

import Foundation

/// 核心错误码文案映射（纯函数，可独立单测）。
enum CoreErrorText {
    /// 5999 统一文案（单一来源）：InternalPanic 的用户面。
    /// `text(forCode: 5999)` 与 ErrorPresenter 的 panic 分支均经此常量取文案，
    /// 杜绝重复字面量与 `??` 死兜底（对齐 LicenseErrorText.serialInvalid 先例）。
    static let internalPanic = String(localized: "内部错误，请重试；若持续出现请查看诊断信息。")

    /// 1xxx–5xxx 业务码 → 用户可见文案（已本地化）。
    ///
    /// - Returns: 映射域内返回文案；非映射域（6xxx 许可域 / 未知码 / 4001 / 4002）
    ///   返回 nil，由 ErrorPresenter 兜底（许可域先查、未知码直出载荷）。
    static func text(forCode code: Int) -> String? {
        switch code {
        // 1xxx 密码库 / 条目
        case 1001:
            return String(localized: "密码库已锁定，请先解锁。")
        case 1002:
            // FR-1.4 不可区分：密码错与头部篡改同码同文案（docs/03 §12）
            return String(localized: "解锁失败：主密码错误或数据已损坏。")
        case 1003:
            return String(localized: "找不到该密码库。")
        case 1004:
            return String(localized: "该密码库已存在。")
        case 1005:
            // 与 1002 分列：文件损坏 ≠ 凭据错，处置不同（换备份 vs 重输密码）
            return String(localized: "密码库文件已损坏，无法读取。")
        case 1006:
            return String(localized: "密码库格式版本高于当前应用支持的版本，请升级 Coffer。")
        case 1007:
            return String(localized: "密钥派生失败，请重试。")
        case 1008:
            return String(localized: "加解密失败，请重试。")
        case 1009:
            return String(localized: "读写密码库文件失败，请检查磁盘空间与权限。")
        case 1010:
            return String(localized: "主密码强度不足，请使用更长或更复杂的密码。")
        case 1011:
            return String(localized: "条目不存在，可能已被删除。")
        case 1012:
            return String(localized: "输入校验未通过，请检查后重试。")
        // 2xxx 导入 / 导出
        case 2001:
            return String(localized: "无法识别该导入文件的来源格式。")
        case 2002:
            return String(localized: "导入失败。")
        case 2003:
            return String(localized: "导出失败。")
        // 3xxx TOTP
        case 3001:
            return String(localized: "动态验证码生成失败。")
        // 4xxx 生物识别（4001 / 4002 见文件头：走 docs/08 T03 冻结文案）
        case 4003:
            return String(localized: "恢复码功能不可用。")
        // 5xxx 通用 IO / panic 兜底
        case 5001:
            return String(localized: "文件读写失败，请检查路径与权限。")
        case 5002:
            return String(localized: "参数无效。")
        case 5999:
            // InternalPanic 的用户面（载荷只进日志）：先给可重试动作，再指向诊断页
            return internalPanic
        default:
            return nil
        }
    }
}
