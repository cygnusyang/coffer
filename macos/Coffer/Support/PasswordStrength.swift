// PasswordStrength.swift —— 密码强度展示辅助。
//
// 权威校验是 Rust 侧 zxcvbn（建库门禁 score < 3 拒绝，错误码 1010）。
// 本文件只提供两个用途：
//   1. 有会话时优先使用 AppModel.estimateStrength（Rust zxcvbn）；
//   2. 无会话（首次建库）时用本地粗估兜底，UI 明确标注“本地预估”。

import Foundation

enum PasswordStrength {
    /// 本地粗略预估分（0–4）。非 zxcvbn，仅首次建库无会话时兜底。
    static func localScore(_ password: String) -> Int {
        var score = 0
        let length = password.count
        if length >= 10 { score += 1 }
        if length >= 16 { score += 1 }

        var classes = 0
        if password.contains(where: { $0.isLowercase }) { classes += 1 }
        if password.contains(where: { $0.isUppercase }) { classes += 1 }
        if password.contains(where: { $0.isNumber }) { classes += 1 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }) { classes += 1 }
        score += max(0, classes - 2)

        return min(4, max(0, score))
    }

    /// 强度中文标签（zxcvbn 0–4 与本地粗估共用）。
    static func label(_ score: Int) -> String {
        let labels = ["极弱", "弱", "一般", "强", "极强"]
        let index = min(4, max(0, score))
        return labels[index]
    }

    /// 强度对应的颜色（红 → 绿）。
    static func color(_ score: Int) -> String {
        // 返回 SF 色名，由 UI 转 Color
        switch score {
        case 0: return "red"
        case 1: return "orange"
        case 2: return "yellow"
        case 3: return "green"
        default: return "mint"
        }
    }
}
