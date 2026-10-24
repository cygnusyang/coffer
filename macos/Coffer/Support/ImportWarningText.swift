// ImportWarningText.swift —— 导入告警「码 + 参数」→ 用户可见文案（BUG-35 第一阶段）。
//
// 背景：放置区 / CSV 预检的告警此前由 core 以**中文整句**直出（「第 2 行：缺失 Title…」），
// 经 FFI 原样进 Label(warning)，英文界面必现中文（v2.13.0 多语言留的显式非目标）。
// 现在 core 只产出结构化字符串「码 + 参数」（core/cf-importer/src/warning.rs），
// 句子在这里按码本地化。
//
// 三条纪律（同 CoreErrorText / LicenseError 先例）：
//   1. **键 = 中文原文**（D-6）：8 条中文与 Rust 侧旧直出句逐字一致——改一句要同时动
//      本文件与 Resources/Localization/en/20-ui-b.strings，否则中文界面文案会漂移。
//   2. **未识别的码 / 旧格式字符串原样返回**（含参数个数不符）：Bitwarden / 1PUX /
//      OPVault 的告警是 BUG-35 第二阶段，迁移过渡期必须照旧可读，不能因解码失败丢句，
//      更不能把裸码（csv.xxx）显示给用户。
//   3. **参数是数据不是文案**：不做任何拼接/前处理，插值位置与 Rust 原句一致；
//      参数只承载行号、列名、计数等非敏感值（R2，core 侧保证不带凭据）。
//
// 解码规则与 Rust `warning::decode` 严格对称：分隔符是未转义的竖线，参数内的竖线与
// 反斜杠各由一个反斜杠转义；其它「反斜杠 + 字符」与孤立尾部反斜杠原样保留（non-lossy）。

import Foundation
/// 导入告警码 → 本地化文案（纯函数，零 FFI 依赖，可独立单测：
/// tools/run_import_warning_text_tests.sh）。
enum ImportWarningText {
    /// 已知告警码，与 `core/cf-importer/src/warning.rs` 的 `CODES` 一一对应。
    enum Code: String, CaseIterable {
        /// 第 N 行缺失 Title，导入时以兜底标题替代（参数：行号、兜底标题）。
        case missingTitle = "csv.missing_title"
        /// 第 N 行 One-time password 无法解析，原始值并入备注（参数：行号）。
        case totpUnparsed = "csv.totp_unparsed"
        /// 第 N 行某列值不是 true/false，按 false 处理（参数：行号、列名）。
        case boolInvalid = "csv.bool_invalid"
        /// 第 N 行数据比表头多若干列，多出的非空值并入备注（参数：行号、多出列数）。
        case extraColumns = "csv.extra_columns"
        /// 第 N 行某列值以公式前缀字符开头，导出 CSV 时会被转义（参数：行号、列名）。
        case formulaPrefix = "csv.formula_prefix"
        /// 检测到重复标题，导入全部新建、不做去重（参数：重复标题数、涉及行数）。
        case duplicateTitles = "csv.duplicate_titles"
        /// 丢弃若干条密码历史（历史表语义不同构，FR-2.9）（参数：丢弃条数）。
        case passwordHistoryDropped = "csv.password_history_dropped"
        /// 第 N 行 One-time password 无法解析（附脱敏原因）（参数：行号、原因）。
        case totpUnparsedDetail = "csv.totp_unparsed_detail"
    }

    /// 把 core 产出的告警串渲染成当前语言的文案。
    ///
    /// - Parameter raw: FFI 传回的告警串（码 + 参数，或第二阶段的旧中文整句）。
    /// - Returns: 已知码返回本地化文案；未知码 / 参数个数不符 / 非本格式时原样返回
    ///   `raw`（向后兼容：旧告警仍可读，旧码不露裸码）。
    static func text(for raw: String) -> String {
        var fields = split(raw)
        guard !fields.isEmpty else { return raw }
        let rawCode = fields.removeFirst()
        guard let code = Code(rawValue: rawCode) else { return raw }
        let params = fields

        switch code {
        case .missingTitle:
            guard params.count == 2 else { return raw }
            return String(localized: "第 \(params[0]) 行：缺失 Title，导入时以「\(params[1])」兜底")

        case .totpUnparsed:
            guard params.count == 1 else { return raw }
            return String(localized: "第 \(params[0]) 行：One-time password 无法解析，原始值已并入备注，该行仍导入")

        case .boolInvalid:
            guard params.count == 2 else { return raw }
            return String(localized: "第 \(params[0]) 行：\(params[1]) 值不是 true/false，按 false 处理")

        case .extraColumns:
            guard params.count == 2 else { return raw }
            return String(localized: "第 \(params[0]) 行：数据比表头多 \(params[1]) 列，多出的非空值已并入备注")

        case .formulaPrefix:
            guard params.count == 2 else { return raw }
            return String(localized: "第 \(params[0]) 行：列「\(params[1])」的值以公式前缀字符（= + - @ Tab）开头，若导出为 CSV 时将被转义（导入保留原值）")

        case .duplicateTitles:
            guard params.count == 2 else { return raw }
            return String(localized: "检测到 \(params[0]) 个重复标题（涉及 \(params[1]) 行），导入将全部新建，不做去重")

        case .passwordHistoryDropped:
            guard params.count == 1 else { return raw }
            return String(localized: "丢弃 \(params[0]) 条密码历史（cf 历史表语义不同构，FR-2.9）")

        case .totpUnparsedDetail:
            guard params.count == 2 else { return raw }
            return String(localized: "第 \(params[0]) 行：One-time password 无法解析（\(params[1])），原始值已并入备注，该行仍导入")
        }
    }

    // MARK: - 解码（与 core/cf-importer/src/warning.rs 对称）

    /// 按未转义的竖线切分并逐字段反转义。
    private static func split(_ raw: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var escaping = false

        for character in raw {
            if escaping {
                current.append("\\")
                current.append(character)
                escaping = false
            } else if character == "\\" {
                escaping = true
            } else if character == "|" {
                fields.append(unescape(current))
                current = ""
            } else {
                current.append(character)
            }
        }
        if escaping { current.append("\\") }
        fields.append(unescape(current))
        return fields
    }

    /// 反转义单个字段：只还原竖线与反斜杠；其它转义序列与孤立尾部反斜杠原样保留。
    private static func unescape(_ field: String) -> String {
        var out = ""
        var pendingEscape = false

        for character in field {
            if pendingEscape {
                if character == "|" || character == "\\" {
                    out.append(character)
                } else {
                    out.append("\\")
                    out.append(character)
                }
                pendingEscape = false
            } else if character == "\\" {
                pendingEscape = true
            } else {
                out.append(character)
            }
        }
        if pendingEscape { out.append("\\") }
        return out
    }
}
