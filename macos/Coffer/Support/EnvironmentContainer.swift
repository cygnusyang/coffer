// EnvironmentContainer.swift —— 环境容器（Environment）识别与 NAME 校验辅助
// （docs/36 §5.2 App 通道，v2.8.0）。
//
// 环境容器 = SecureNote 条目 + 保留标签 coffer:environment（ENV_TAG，与
// core/cf-mcp/src/provider/coffer.rs:63 同源）；字段 = NAME/VALUE 对，MCP
// inject_environment 把容器全部字段名当环境变量名注入子进程 env（docs/36 §0）。
//
// 校验实现裁决（D-36.6）：Swift 本地复刻 is_valid_env_name 而非 FFI 导出——
// 规则冻结且 ~6 行，FFI 导出需提 pub(crate) + 破坏 cf-mcp → 下依赖方向；
// 漂移风险低（规则冻结 + 注入侧防御性跳过兜底，App 校验是提前告知不阻断）。

import Foundation

enum EnvironmentContainer {
    /// 环境容器保留标签（与 core/cf-mcp/src/provider/coffer.rs:63 ENV_TAG 同源）。
    static let tag = "coffer:environment"

    /// 是否为环境容器条目：tags 含保留标签即判定。ItemEditView 编辑模式与
    /// ItemDetailView 均已持有 details.tags，检测零额外 FFI 调用（docs/36 §5.2）。
    static func isEnvContainer(_ tags: [String]) -> Bool {
        tags.contains(tag)
    }

    /// 环境变量名合法性：`[A-Za-z_][A-Za-z0-9_]*`（Swift 本地复刻
    /// core/cf-mcp/src/provider/mod.rs:107 is_valid_env_name，同源）。
    ///
    /// 空串 / 首字符非 ASCII 字母或下划线 / 后续含 ASCII 字母数字下划线之外
    /// 的字符 → false。非 ASCII（如中文）不合法——MCP 注入侧防御性跳过兜底，
    /// App 校验是提前告知，不阻断保存（D-36.6 / §5.2）。
    static func isValidEnvName(_ name: String) -> Bool {
        var chars = name.unicodeScalars.makeIterator()
        guard let first = chars.next() else { return false }
        guard first == "_" || isAsciiAlphabetic(first) else { return false }
        while let scalar = chars.next() {
            if scalar != "_" && !isAsciiAlphanumeric(scalar) { return false }
        }
        return true
    }

    /// ASCII 字母（a-z / A-Z）。
    private static func isAsciiAlphabetic(_ scalar: Unicode.Scalar) -> Bool {
        (scalar.value >= 0x41 && scalar.value <= 0x5A)
            || (scalar.value >= 0x61 && scalar.value <= 0x7A)
    }

    /// ASCII 字母或数字。
    private static func isAsciiAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        isAsciiAlphabetic(scalar) || (scalar.value >= 0x30 && scalar.value <= 0x39)
    }
}
