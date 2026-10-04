// GeneratorDefaults.swift —— 密码生成器默认参数（FR-14.3，docs/22 §2.4；docs/23 §1.4 TC-GEN）。
//
// 存储范式（对齐 AppModel 既有偏好，docs/22 §2.4）：UserDefaults key
// `generatorDefaultsV1` 存 JSON Data（Codable）——随机字符六字段
// （FfiPasswordGenOptions 镜像）+ 密码短语四字段（FfiPassphraseOptions 镜像）。
// **零核心变更**：cf_audit::generate_password / generate_passphrase 纯函数
// 不变，本文件只做「存档值的读写与校验」，生成本身仍在既有入口。
//
// 校验对齐内核（TC-GEN-03，与 generate_password 1012 Validation 同语义）：
//   - 随机字符：长度 8..=100、至少启用一个字符集（数字/小写/大写/符号）；
//   - 密码短语：词数 3..=10、分隔符 1..=3 个可打印字符
//     （ASCII 图形字符或空格，对齐 cf-audit::passphrase::is_printable）。
// 缺失 / 损坏偏好一律回退内置默认，绝不崩溃（TC-GEN-04）。
//
// 测试：macos/Tests/GeneratorDefaultsTests/main.swift
// （TC-GEN-01/03/04/05，驱动见 tools/run_generator_defaults_tests.sh）。

import Foundation

/// 生成器默认参数存档（FR-14.3）。字段镜像 FfiPasswordGenOptions /
/// FfiPassphraseOptions；纯数据（Codable + Equatable），便于独立单测。
struct GeneratorDefaults: Codable, Equatable {
    // 随机字符（对应 FfiPasswordGenOptions）
    var length: UInt32
    var numbers: Bool
    var lowercaseLetters: Bool
    var uppercaseLetters: Bool
    var symbols: Bool
    var excludeSimilarCharacters: Bool

    // 密码短语（对应 FfiPassphraseOptions）
    var wordCount: UInt32
    var separator: String
    var capitalize: Bool
    var numberSuffix: Bool

    /// 内置默认（对齐 ItemEditView 生成器初始状态）：长度 20、
    /// 数字/小写/大写开、符号关、排除易混淆开；词数 5、连字符分隔、
    /// 词首大写、末尾追加数字。TC-GEN-04 回退基准。
    static let builtin = GeneratorDefaults(
        length: 20,
        numbers: true,
        lowercaseLetters: true,
        uppercaseLetters: true,
        symbols: false,
        excludeSimilarCharacters: true,
        wordCount: 5,
        separator: "-",
        capitalize: true,
        numberSuffix: true
    )

    /// UserDefaults 键（docs/22 §2.4 定名 `generatorDefaultsV1`）。
    static let defaultsKey = "generatorDefaultsV1"

    /// 校验（TC-GEN-03，对齐 cf-audit 内核约束；见文件头注释）。
    /// 非法参数必须被「另存为默认」拒绝、不落盘。
    var isValid: Bool {
        let lengthOk = (8...100).contains(Int(length))
        let charsetOk = numbers || lowercaseLetters || uppercaseLetters || symbols
        let wordsOk = (3...10).contains(Int(wordCount))
        let scalars = separator.unicodeScalars
        let sepOk = (1...3).contains(scalars.count) && scalars.allSatisfy(Self.isPrintableScalar)
        return lengthOk && charsetOk && wordsOk && sepOk
    }

    /// 从 UserDefaults 读档（TC-GEN-02/04）：键不存在 / 解码失败 /
    /// 校验不过 → 回退内置默认（损坏偏好不崩溃）。
    static func load() -> GeneratorDefaults {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let decoded = try? JSONDecoder().decode(GeneratorDefaults.self, from: data),
              decoded.isValid else {
            return builtin
        }
        return decoded
    }

    /// 写档（TC-GEN-01/05）：仅校验通过才落盘；非法参数返回 false 不写
    /// （TC-GEN-03）。成功返回 true。
    @discardableResult
    func save() -> Bool {
        guard isValid,
              let data = try? JSONEncoder().encode(self) else { return false }
        UserDefaults.standard.set(data, forKey: Self.defaultsKey)
        return true
    }

    /// 可打印字符判定（对齐 cf-audit::passphrase::is_printable：
    /// ASCII 图形字符 0x21...0x7E，或空格 0x20）。
    private static func isPrintableScalar(_ scalar: UnicodeScalar) -> Bool {
        (0x21...0x7E).contains(scalar.value) || scalar.value == 0x20
    }
}

// MARK: - FFI 形态（生成器面板预填钩子，TC-GEN-01）

extension GeneratorDefaults {
    /// FfiPasswordGenOptions 形态（ItemEditView 生成器预填 / 试生成用）。
    var genOptions: FfiPasswordGenOptions {
        FfiPasswordGenOptions(
            length: length,
            numbers: numbers,
            lowercaseLetters: lowercaseLetters,
            uppercaseLetters: uppercaseLetters,
            symbols: symbols,
            excludeSimilarCharacters: excludeSimilarCharacters
        )
    }

    /// FfiPassphraseOptions 形态。
    var passphraseOptions: FfiPassphraseOptions {
        FfiPassphraseOptions(
            wordCount: wordCount,
            separator: separator,
            capitalize: capitalize,
            numberSuffix: numberSuffix
        )
    }
}
