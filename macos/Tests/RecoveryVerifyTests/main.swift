// RecoveryVerifyTests/main.swift —— 恢复码抄写验证步纯函数单元测试（v2.9.0 基层测试化）。
//
// 目标判据（docs/04-测试与验收/11-v2.9.0验收判据骨架.md §6 P6）：
//   纯函数已外置 macos/Coffer/Support/RecoveryVerifySupport.swift（enum
//   RecoveryVerifySupport，四个 static 纯函数，无依赖——不含 SwiftUI/AppModel，
//   可进 swiftc 选编单测）。行为逐字保持 RecoveryCodeSetupSheet 抽取前实现。
//
// AC 映射表：
//   AC-2.9.0-P6-3  randomVerifyPositions —— 12 词抽 3（恰 3 / 互异 / 1-based /
//                  升序 / 均在 1...12）；防御分支（wordCount=2 → [1,2]；
//                  wordCount=0 → [] 不 trap）；随机性面（循环 ≥200 次出现 ≥2
//                  种不同组合，证明非恒定输出）；count 参数化（wordCount=5, count=3）。
//   AC-2.9.0-P6-4  canSubmitVerify —— 空数组 false / 含空串 false / 全非空 true；
//                  原语义保持：纯空格串 " " 属「非空 raw」→ true（抽取时有意保留，
//                  由比对步 normalize 归一化兜出 mismatch，勿当 bug 修）。
//   AC-2.9.0-P6-5  normalizeRecoveryWord —— 小写 / 折叠连续空格 / trim /
//                  制表符换行按空白折叠 / 全空白 → 空串。
//   recoveryWordCount —— 12 词码 → 12；多空格分隔仍 12；空串 → 0。
//
// 先红后绿自检（对每条断言反问「生产代码退回修复前行为会不会红」）：
//   - wordCount=0 → [] 不 trap：锁 Array(1...0) 越界 trap 避让（scratch 自证实锤
//     过——直接 Array(1...0) 在 Swift 会崩溃，退回应红/崩）；
//   - 随机性 ≥2 组合：锁「恒返回固定位置」的假随机回归；
//   - 纯空格 → true：锁「被『修正』成判空」的语义漂移（这是有意保留的原行为）。
//
// 诚实边界（必须留真机，本测试不覆盖）：
//   - UI 呈现/交互路径：verify 步视图渲染、输入框非掩码、无「返回查看」入口、
//     错误就地橙色提示、清空输入保步、重新生成就地确认行、按钮禁用态；
//   - 抄写反馈视觉（「已复制（30 秒后自动清除）」提示形态）；
//   - 恢复码整体流程（intro → showCode → verify → confirm → enable）与
//     剪贴板死数据粘贴断言（后者归 ClipboardSlotTests / 真机核销）。
//
// 驱动：tools/run_recovery_verify_tests.sh（swiftc 直编 RecoveryVerifySupport.swift
// + 本文件，无 FFI / 无绑定 / 无 libcf_ffi.a，任何环境可跑，不设 SKIP 路径）。

import Foundation

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

/// 断言位置数组满足「抽 count 个、互不相同、1-based、升序、全部落在 1...wordCount」。
func validPositions(_ positions: [Int], count: Int, wordCount: Int) -> Bool {
    positions.count == count
        && Set(positions).count == positions.count          // 互不相同
        && positions == positions.sorted()                   // 升序
        && positions.allSatisfy { (1...wordCount).contains($0) }  // 1-based 且在界内
}

// MARK: - 真实 BIP39-12 样例（12 个标准词，恒用于词数/归一化面）

let bip39TwelveWords = "abandon ability able about above absent absorb abstract absurd abuse access accident"

// MARK: - AC-2.9.0-P6-3 randomVerifyPositions（词位抽取）

let twelveDraw = RecoveryVerifySupport.randomVerifyPositions(wordCount: 12)
check("TC-RV-01", "12 词抽 3 → 恰 3 个、互异、1-based、升序、均在 1...12",
      validPositions(twelveDraw, count: 3, wordCount: 12),
      "实际 \(twelveDraw)")

let twoDraw = RecoveryVerifySupport.randomVerifyPositions(wordCount: 2)
check("TC-RV-02", "防御分支：wordCount=2（< count）→ 恰全部位置 [1,2]",
      twoDraw == [1, 2], "实际 \(twoDraw)")

// wordCount=0 → [] 且不 trap（Array(1...0) 下界越上界在 Swift 会 trap；显式避让）。
// 若回归为未避让版本，本行直接崩溃 → 测试红（先红后绿锁点 1）。
let zeroDraw = RecoveryVerifySupport.randomVerifyPositions(wordCount: 0)
check("TC-RV-03", "防御分支：wordCount=0 → [] 且不 trap（Array(1...0) 避让）",
      zeroDraw.isEmpty, "实际 \(zeroDraw)")

let fiveDraw = RecoveryVerifySupport.randomVerifyPositions(wordCount: 5, count: 3)
check("TC-RV-04", "count 参数化：wordCount=5, count=3 → 3 个互异升序位置",
      validPositions(fiveDraw, count: 3, wordCount: 5), "实际 \(fiveDraw)")

// 随机性面：循环 ≥200 次收集结果组合，断言出现 ≥2 种不同组合（证明非恒定输出）。
// 诚实边界：不断言单次「重抽必不同」——随机的诚实边界（碰巧重复合法），只锁恒常。
// 12 选 3 = 220 种组合，200 次采样全同的概率 ≈ 0（先红后绿锁点 2）。
var observedCombos: Set<[Int]> = []
for _ in 0..<200 {
    observedCombos.insert(RecoveryVerifySupport.randomVerifyPositions(wordCount: 12))
}
check("TC-RV-05", "随机性：200 次抽 3 出现 ≥2 种不同组合（非恒定输出）",
      observedCombos.count >= 2, "仅观察到 \(observedCombos.count) 种组合")

// MARK: - AC-2.9.0-P6-4 canSubmitVerify（确认门）

check("TC-RV-06", "空数组 → false", !RecoveryVerifySupport.canSubmitVerify([]))
check("TC-RV-07", "含空串 → false",
      !RecoveryVerifySupport.canSubmitVerify(["abandon", "", "accident"]))
check("TC-RV-08", "三输入均非空 → true",
      RecoveryVerifySupport.canSubmitVerify(["abandon", "ability", "accident"]))

// 原语义保持：纯空格串属「非空 raw」→ true（抽取时有意保留，raw isEmpty 门，
// 不判空白；由比对步 normalize 归一化兜出 mismatch——勿当 bug 修正。先红后绿锁点 3）。
check("TC-RV-09", "纯空格串 ' ' 属非空 raw → true（原语义保持，比对步归一化兜 mismatch）",
      RecoveryVerifySupport.canSubmitVerify([" ", "abandon", "accident"]))

// MARK: - AC-2.9.0-P6-5 normalizeRecoveryWord（输入归一化）

check("TC-RV-10", "大写 → 小写（大小写不敏感）",
      RecoveryVerifySupport.normalizeRecoveryWord("ABANDON") == "abandon")
check("TC-RV-11", "多连续空格折叠为单空格",
      RecoveryVerifySupport.normalizeRecoveryWord("  HeLLo    WoRLD  ") == "hello world")
check("TC-RV-12", "前后空白 trim",
      RecoveryVerifySupport.normalizeRecoveryWord("   abandon   ") == "abandon")
check("TC-RV-13", "制表符/换行按空白折叠",
      RecoveryVerifySupport.normalizeRecoveryWord("Hello\tWorld\nFoo") == "hello world foo")
check("TC-RV-14", "全空白串 → 空串",
      RecoveryVerifySupport.normalizeRecoveryWord(" \t\n ") == "")

// MARK: - recoveryWordCount（词数派生）

check("TC-RV-15", "12 词码 → 12", RecoveryVerifySupport.recoveryWordCount(bip39TwelveWords) == 12)
check("TC-RV-16", "多空格分隔仍 12",
      RecoveryVerifySupport.recoveryWordCount(
        "abandon   ability  able about above absent absorb abstract absurd abuse access   accident") == 12)
check("TC-RV-17", "空串 → 0", RecoveryVerifySupport.recoveryWordCount("") == 0)

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
