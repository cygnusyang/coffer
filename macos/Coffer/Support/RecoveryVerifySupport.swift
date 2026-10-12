import Foundation

/// 恢复码抄写验证步纯函数支持（P6，AC-2.9.0-P6-3/4/5）。
///
/// 自 RecoveryCodeSetupSheet 抽出为无依赖顶层命名空间（v2.9.0 发版轮基层
/// 测试化）：View 文件依赖 SwiftUI/AppModel 无法单文件编译进测试目标，
/// 纯函数外置后可进 swiftc 选编单测。行为逐字不变，仅位置搬移。
enum RecoveryVerifySupport {
    /// 恢复码词数（BIP39-12 恒为 12；从 code 派生以便自证与防御，不硬编码）。
    static func recoveryWordCount(_ code: String) -> Int {
        code.split(whereSeparator: \.isWhitespace).count
    }

    /// 词输入归一化（纯函数，AC-2.9.0-P6-5）：小写 + 折叠连续空格 + trim；
    /// 比较时大小写不敏感（接受用户误输大写）。
    static func normalizeRecoveryWord(_ input: String) -> String {
        input.lowercased()
            .split(whereSeparator: \.isWhitespace)
            .joined(separator: " ")
    }

    /// 确认门（AC-2.9.0-P6-4）：三输入均非空才可提交。
    /// 语义保持原实现（raw isEmpty 门，不改判空口径）：纯空格串可提交，
    /// 由比对步归一化兜出 mismatch——行为与抽取前逐字一致。
    static func canSubmitVerify(_ inputs: [String]) -> Bool {
        !inputs.isEmpty && inputs.allSatisfy { !$0.isEmpty }
    }

    /// 从恢复码词序列中随机抽 `count` 个不同位置（1-based，升序便于展示）。
    /// 实例内固定由调用方持有结果保证（仅「重新生成」后重抽）；
    /// 纯函数面（AC-2.9.0-P6-3：3 个不同位置 / regenerate 重抽）。
    static func randomVerifyPositions(wordCount: Int, count: Int = 3) -> [Int] {
        guard wordCount >= count else {
            // 防御分支：词数 < 抽取个数（正常 BIP39-12 恒 12 词不可达）→ 返回
            // 全部位置；wordCount <= 0 → 空（Array(1...0) 下界越上界在 Swift
            // 会 trap，显式避让，scratch 自证实锤）。
            guard wordCount > 0 else { return [] }
            return Array(1...wordCount)
        }
        return (0..<wordCount).shuffled().prefix(count).sorted().map { $0 + 1 }
    }
}
