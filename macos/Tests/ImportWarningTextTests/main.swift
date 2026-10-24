// ImportWarningTextTests —— 导入告警「码 + 参数」→ 文案（BUG-35 第一阶段）。
//
// 被测单元 Support/ImportWarningText.swift 是零依赖纯函数（同 CoreErrorTextTests 纪律）：
// 不装配 app bundle 时 String(localized:) 回落 key 本身（中文原文）并**照常代入插值**，
// 因此这里断言的是「中文原文」（中文界面口径），英文译文由 tools/check_l10n.sh 的
// G1–G5 校验（占位符数量/类型一致），两侧分工不重叠。
//
// 判据：
//   1. 8 条码的文案**逐字等于** Rust 侧旧直出句（含参数代入后的整句）——只断言「非空」
//      是假绿：码与参数串位（行号写到列名位置）照样通过；
//   2. 参数里的分隔符 / 反斜杠按 Rust warning::encode 的转义规则还原；
//   3. 未知码 / 旧中文整句 / 参数个数不符 **原样返回**（绝不显示裸码、不显示半截文案）；
//   4. 码表条数与 Rust CODES 一致（漏码会让该条告警回落成裸码）。

import Foundation

var failures = 0
var checks = 0

func expect(_ condition: Bool, _ label: String) {
    checks += 1
    if !condition {
        failures += 1
        print("FAIL  " + label)
    }
}

/// 断言「原始告警串 → 期望文案」，失败时把两侧原文都打出来（串位时一眼看出）。
func expectText(_ raw: String, _ expected: String, _ label: String) {
    let actual = ImportWarningText.text(for: raw)
    expect(actual == expected, label + "：期望「" + expected + "」实际「" + actual + "」")
}

// MARK: - 1. 8 条码 → 逐字文案

expectText("csv.missing_title|2|（无标题）", "第 2 行：缺失 Title，导入时以「（无标题）」兜底", "缺 Title 兜底")
expectText("csv.totp_unparsed|3", "第 3 行：One-time password 无法解析，原始值已并入备注，该行仍导入", "放置区 OTP 失败（无原因）")
expectText("csv.bool_invalid|4|Favorite status", "第 4 行：Favorite status 值不是 true/false，按 false 处理", "非法 bool")
expectText("csv.extra_columns|5|2", "第 5 行：数据比表头多 2 列，多出的非空值已并入备注", "多余列")
expectText("csv.formula_prefix|6|username", "第 6 行：列「username」的值以公式前缀字符（= + - @ Tab）开头，若导出为 CSV 时将被转义（导入保留原值）", "公式前缀")
expectText("csv.duplicate_titles|1|3", "检测到 1 个重复标题（涉及 3 行），导入将全部新建，不做去重", "重复标题")
expectText("csv.password_history_dropped|4", "丢弃 4 条密码历史（cf 历史表语义不同构，FR-2.9）", "密码历史丢弃")
expectText("csv.totp_unparsed_detail|7|period 参数无效", "第 7 行：One-time password 无法解析（period 参数无效），原始值已并入备注，该行仍导入", "CSV 预检 OTP 失败（带原因）")

// MARK: - 2. 转义还原（与 Rust warning::encode 对称）

// 参数内含竖线：encode 产出 a\|b，解码须还原为 a|b
expectText(
    "csv.bool_invalid|8|a\\|b",
    "第 8 行：a|b 值不是 true/false，按 false 处理",
    "参数含分隔符")
// 参数内含反斜杠：encode 产出 c\\d，解码须还原为 c\d
expectText(
    "csv.bool_invalid|9|c\\\\d",
    "第 9 行：c\\d 值不是 true/false，按 false 处理",
    "参数含反斜杠")
// 非预期转义（反斜杠 + 普通字符）原样保留，不吞字符
expectText(
    "csv.bool_invalid|10|x\\y",
    "第 10 行：x\\y 值不是 true/false，按 false 处理",
    "非预期转义原样保留")

// MARK: - 3. 原样返回（向后兼容）

let legacy = "第 2 行：缺失 Title，导入时以「（无标题）」兜底"
expect(ImportWarningText.text(for: legacy) == legacy, "旧中文整句原样返回（第二阶段迁移期）")
expect(
    ImportWarningText.text(for: "csv.unknown_code|1") == "csv.unknown_code|1",
    "未知码原样返回（不丢句）")
expect(
    ImportWarningText.text(for: "csv.missing_title|2") == "csv.missing_title|2",
    "参数个数不符原样返回（不显示半截文案）")
expect(ImportWarningText.text(for: "") == "", "空串原样返回")

// MARK: - 4. 码表条数（与 core CODES 一致）

expect(ImportWarningText.Code.allCases.count == 8, "码表须为 8 条（与 core CODES 对齐）")

print("ImportWarningTextTests: " + String(checks) + " checks, " + String(failures) + " failures")
if failures > 0 { exit(1) }
