// CoreErrorTextTests —— 核心错误码 → 文案映射（v2.13.0 设计 24 §7.4 / D-10）。
//
// 被测单元 Support/CoreErrorText.swift 是零依赖纯函数（同 LicenseErrorText 先例），
// 可独立编译：不装配 app bundle 时 String(localized:) 回落 key 本身（中文原文）并
// **照常代入插值**（已实测：zh 键回退 / en 命中 / ja 回落 dev region 三条路径都格式化），
// 因此这里断言的是「中文原文」——这正是 AC-L10N-10「现有测试断言不变」的依据。
//
// 判据（表驱动，逐码断言精确文案）：
//   1. 每个映射码的文案**逐字等于**期望原文——只断言「非空」是假绿：把 1009 写成
//      5002 的文案照样通过，而用户会看到「参数无效」而不是「读写密码库文件失败」；
//   2. 20 条文案两两不等（防止复制粘贴串行）；
//   3. 非映射域返回 nil（6xxx 归 LicenseErrorText、4001/4002 归 TouchIDError、
//      未知码走 ErrorPresenter 兜底）——否则会出现两份同码文案；
//   4. 5999 常量与查表结果同源（单一来源纪律）。
//
// 期望表来源：core/cf-domain/src/error.rs:208-234 的 25 个变体，扣掉 4001/4002
// （TouchIDError 冻结文案）与 6xxx（许可域），得 19 条业务码；再加 panic 5999 = 20。

import Foundation

var failures = 0
var checks = 0

func expect(_ condition: Bool, _ label: String) {
    checks += 1
    if !condition {
        failures += 1
        print("FAIL  \(label)")
    }
}

// MARK: - 期望表（码 → 中文原文，逐字）

let expected: [(code: Int, text: String)] = [
    (1001, "密码库已锁定，请先解锁。"),
    (1002, "解锁失败：主密码错误或数据已损坏。"),
    (1003, "找不到该密码库。"),
    (1004, "该密码库已存在。"),
    (1005, "密码库文件已损坏，无法读取。"),
    (1006, "密码库格式版本高于当前应用支持的版本，请升级 Coffer。"),
    (1007, "密钥派生失败，请重试。"),
    (1008, "加解密失败，请重试。"),
    (1009, "读写密码库文件失败，请检查磁盘空间与权限。"),
    (1010, "主密码强度不足，请使用更长或更复杂的密码。"),
    (1011, "条目不存在，可能已被删除。"),
    (1012, "输入校验未通过，请检查后重试。"),
    (2001, "无法识别该导入文件的来源格式。"),
    (2002, "导入失败。"),
    (2003, "导出失败。"),
    (3001, "动态验证码生成失败。"),
    (4003, "恢复码功能不可用。"),
    (5001, "文件读写失败，请检查路径与权限。"),
    (5002, "参数无效。"),
    (5999, "内部错误，请重试；若持续出现请查看诊断信息。"),
]

// MARK: - 1. 逐码：文案逐字相等

for row in expected {
    let got = CoreErrorText.text(forCode: row.code)
    expect(got == row.text, "码 \(row.code) 文案应为「\(row.text)」，实得「\(got ?? "<nil>")」")
}

// MARK: - 2. 映射集合与条数（派生自 Rust 侧变体数，不自证）

// 25 个 CfError 变体 − 4001/4002（TouchIDError 持有）− 6xxx 四条（LicenseErrorText 持有）= 19
// 再加 FfiError.InternalPanic 的 5999 = 20。
let expectedCount = 25 - 2 - 4 + 1
expect(expected.count == expectedCount,
       "期望表应覆盖 \(expectedCount) 个码（Rust 25 变体 − 4001/4002 − 6xxx + panic）")

// MARK: - 3. 20 条两两不等（复制粘贴串行的护栏）

var seenText: [String: Int] = [:]
for row in expected {
    if let other = seenText[row.text] {
        expect(false, "码 \(row.code) 与 \(other) 用了同一条文案「\(row.text)」")
    }
    seenText[row.text] = row.code
}

// MARK: - 4. 非映射域必须返回 nil（职责边界）

for code in [4001, 4002, 6001, 6002, 6003, 6004, 5998, 0, -1, 9999] {
    expect(CoreErrorText.text(forCode: code) == nil, "码 \(code) 不属于本表，应返回 nil")
}

// MARK: - 5. 关键契约（语义护栏，文案若改仍需满足）

// 1002 必须同时覆盖「密码错」与「头篡改」→ 文案不得暗示单一原因（FR-1.4 不可区分）
let unlock = CoreErrorText.text(forCode: 1002) ?? ""
expect(unlock.contains("主密码") && unlock.contains("数据"),
       "1002 文案须同时提到主密码与数据（不可区分纪律）")
expect(!unlock.contains("篡改"), "1002 文案不得出现「篡改」等具体原因")

// 1005（文件损坏）与 1002（凭据错）是两个码、两套文案，不合并
expect(CoreErrorText.text(forCode: 1005) != unlock, "1005 与 1002 必须是不同文案")

// 5999 单一来源：常量与查表结果逐字相等
expect(CoreErrorText.text(forCode: 5999) == CoreErrorText.internalPanic,
       "5999 查表结果须与 internalPanic 常量逐字相等（单一来源）")

// MARK: - 汇总

print("----")
print("\(checks - failures) passed / \(failures) failed")
if failures > 0 {
    print("ALL RED")
    exit(1)
}
print("ALL GREEN")
