// HelpCenterContentTests/main.swift —— 帮助中心正文完整性断言（v2.10.1，
// docs/19 §5 转写回归点）。
//
// 目标判据（docs/03-功能设计/19-帮助文档.md §5「正文文案源」+ §8 验收要点）：
//   九章正文 = 11 个 HelpSection（§5.4「键盘快捷键」含 3 个 Section：列表操作 /
//   条目操作 / 通用，章节标题为 List 分组语义不单独成 Section）——本文件把每个
//   Section 的标题与条目数断言为常量，HelpCenterContent 转写回归即红。
//   正文措辞 / 键位 / 入口路径逐条 1:1（§5 转写约定），内容不在此重复断言
//   （避免与正文重复维护；标题 + 条目数锚定结构，措辞由人工/审查对照）。
//
// 被测单元 macos/Coffer/Views/HelpCenterContent.swift（struct HelpSection +
// enum HelpCenterContent，纯 Foundation，无 AppKit/SwiftUI 依赖）——与
// MenuIconGeometryTests 同模式，可进 swiftc 选编单测。
//
// 先红后绿自检：删/加任一 Section 或改条目数，对应断言即红——本套件是
// docs/19 §5 结构的回归哨兵。

import Foundation

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(name)")
    } else {
        failures.append("\(name) \(detail)")
        print("FAIL  \(name)  \(detail)")
    }
}

// MARK: - docs/19 §5 结构断言（标题顺序 + 条目数）

// 章节标题（含 §5.4 三组）与对应条目数——与 docs/19 §5.1~§5.9 逐一对应。
let expected: [(title: String, rows: Int)] = [
    ("欢迎使用 Coffer", 2),
    ("开始使用", 3),
    ("日常操作", 5),
    ("列表操作", 3),
    ("条目操作", 3),
    ("通用", 7),
    ("备份与恢复", 3),
    ("安全", 3),
    ("MCP / Agent 协作", 1),
    ("常见问题", 4),
    ("故障排查", 3),
]

let sections = HelpCenterContent.sections

check("Section 总数 = 11（九章，§5.4 拆 3 组）", sections.count == expected.count,
      "实得 \(sections.count)")

do {
    // 标题顺序与 docs/19 §5 一致
    let actualTitles = sections.map(\.title)
    let expectedTitles = expected.map(\.title)
    check("标题顺序 = §5 章节顺序", actualTitles == expectedTitles,
          "实得 \(actualTitles)")
}

do {
    // 标题唯一（List 以 title 作 id，重复即 SwiftUI 冲突）
    let titles = sections.map(\.title)
    check("标题唯一（List id 前提）", Set(titles).count == titles.count)
}

do {
    // 各 Section 条目数 = §5 对应小节条目数
    var allMatch = true
    var mismatch: [String] = []
    for (i, exp) in expected.enumerated() {
        let act = sections[i].rows.count
        if act != exp.rows {
            allMatch = false
            mismatch.append("\(exp.title): 期望 \(exp.rows) 实得 \(act)")
        }
    }
    check("各 Section 条目数 = §5 对应条目数", allMatch, mismatch.joined(separator: "; "))
}

do {
    // 空行守卫：任何 Section 不得有空白/空串条目（List 渲染脏数据防线）
    let hasEmpty = sections.contains { $0.rows.contains { $0.trimmingCharacters(in: .whitespaces).isEmpty } }
    check("无空串 / 纯空白条目", !hasEmpty)
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
