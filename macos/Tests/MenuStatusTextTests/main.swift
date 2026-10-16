// MenuStatusTextTests/main.swift —— 菜单栏文案纯函数单元测试（v2.11.0，
// 2026-10-16 用户裁定回归哨兵）。
//
// 目标判据（本文件顶注即规格）：
//   §1 openTitle——状态文案并入可点击打开项：库名非空且 locked/unlocked 时
//      「打开 <库名>（已锁定/已解锁）」；booting/noVault/fatal 与库名缺失一律
//      退回「打开主窗口」（不展示半生不熟的状态后缀）。
//   §2 statusLine——v0.4 MC-1 五相文案回归（自 StatusItemController 抽出，
//      零语义变化，抽出即红若回归）。
//
// 被测单元 macos/Coffer/Support/MenuStatusText.swift（enum MenuStatusText，
// Foundation-only）+ macos/Coffer/AppPhase.swift（纯 Foundation，W1a 独立文件）
// —— 同 RecoveryVerifySupport / MenuIconGeometry 模式，可进 swiftc 选编单测。
//
// 先红后绿自检：把 openTitle 退回「booting/noVault 也带状态后缀」或把 statusLine
// 五相文案改错任一处，本套件必红。

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

// MARK: - §1 openTitle（状态并入打开项标题）

check("unlocked+main → 打开 main（已解锁）",
      MenuStatusText.openTitle(phase: .unlocked, vaultName: "main") == "打开 main（已解锁）")
check("locked+main → 打开 main（已锁定）",
      MenuStatusText.openTitle(phase: .locked, vaultName: "main") == "打开 main（已锁定）")
check("unlocked+空库名 → 打开主窗口（不展示无库名状态后缀）",
      MenuStatusText.openTitle(phase: .unlocked, vaultName: "") == "打开主窗口")
check("locked+空库名 → 打开主窗口",
      MenuStatusText.openTitle(phase: .locked, vaultName: "") == "打开主窗口")
check("booting+main → 打开主窗口（booting 不带后缀）",
      MenuStatusText.openTitle(phase: .booting, vaultName: "main") == "打开主窗口")
check("noVault → 打开主窗口",
      MenuStatusText.openTitle(phase: .noVault, vaultName: "") == "打开主窗口")
check("fatal → 打开主窗口",
      MenuStatusText.openTitle(phase: .fatal("x"), vaultName: "main") == "打开主窗口")

// MARK: - §2 statusLine 五相文案回归（抽出零语义变化）

check("statusLine booting → 正在打开…",
      MenuStatusText.statusLine(phase: .booting, vaultName: "") == "正在打开…")
check("statusLine noVault → 未创建密码库",
      MenuStatusText.statusLine(phase: .noVault, vaultName: "") == "未创建密码库")
check("statusLine locked+空 → 已锁定",
      MenuStatusText.statusLine(phase: .locked, vaultName: "") == "已锁定")
check("statusLine locked+main → main（已锁定）",
      MenuStatusText.statusLine(phase: .locked, vaultName: "main") == "main（已锁定）")
check("statusLine unlocked+空 → 已解锁",
      MenuStatusText.statusLine(phase: .unlocked, vaultName: "") == "已解锁")
check("statusLine unlocked+main → main（已解锁）",
      MenuStatusText.statusLine(phase: .unlocked, vaultName: "main") == "main（已解锁）")
check("statusLine fatal → 启动失败",
      MenuStatusText.statusLine(phase: .fatal("x"), vaultName: "") == "启动失败")

// MARK: - 汇总

print("----")
print("\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    print("ALL RED:\n" + failures.map { "  - \($0)" }.joined(separator: "\n"))
    exit(1)
}
print("ALL GREEN")
