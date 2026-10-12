// ClipboardSlotTests/main.swift —— 剪贴板分槽/守卫行为单元测试（v2.9.0 基层测试化）。
//
// 目标判据（docs/04-测试与验收/11-v2.9.0验收判据骨架.md §5.1 P5-A + REV-DEV-01）：
//   驱动**真实 NSPasteboard + 真实 DispatchQueue.main 定时器**（ClipboardManager
//   单例，非 mock）；显式 clearSecs 传 0.5~0.8s 短时长控制总运行时长（≈6.5s）。
//   被测单元：macos/Coffer/Platform/Clipboard.swift（copyWithAutoClear(_:clearSecs:)
//   显式时长版 / updateClearInterval 分槽 / clearOnLock / changeCount 守卫）。
//
// AC 映射表：
//   TC-SLOT-1  AC-2.9.0-P5-6  changeCount 守卫：30s 内用户顶掉 → 绝不误清。
//   TC-SLOT-2  AC-2.9.0-P5-7  只留最近：A→B 连续复制，B 存活至 B 到点，A 任务被取消。
//   TC-SLOT-3  AC-2.9.0-P5-8  clearOnLock 覆盖：复制后锁定立即清空；反段：用户顶掉
//                             后锁定不动用户内容。
//   TC-SLOT-4  AC-2.9.0-P5-2  显式 0：不立即清（勿 asyncAfter(0)）→ clearOnLock 兜底清。
//   TC-SLOT-5  REV-DEV-01 分槽核心：显式时长任务不被改档取消（FR-17.2 固定 30s 契约
//                             的短时长代理，改档 0.8s 任务仍在 0.8s 清）。
//   TC-SLOT-6  REV-DEV-01 加固缺口：「从不」档语义复制不被改档误清（不产生误清任务）。
//   TC-SLOT-7  AC-2.9.0-P5-9  显式覆盖档位：档位「从不」仍按入参 0.5s 清。
//
// REV-DEV-01 用例的「先红后绿」自检（b4cd8c7 分槽修复回归锁）：
//   - TC-SLOT-5 退回修复前（updateClearInterval 单槽重排，无 isClearTierDriven
//     分槽）→ 0.8s 显式任务被改档重排到 10s → 1.2s 时内容仍在 → 红。当前实现绿。
//   - TC-SLOT-6 锁「从不」复制（clearSecs:0）改档不产生误清任务；这是分槽修复前的
//     缺陷行为（「从不」档旧写入被改档重排误清）的回归锁。
//
//   注意：改档步用 **secs: 10（合法档位）** 而非 lead 初稿的 secs: 1——合法档位集为
//   {0,10,30,60,120}（isValidClearSecs），secs:1 非法 → updateClearInterval 在
//   isValidClearSecs 处直接 return（连 isClearTierDriven 分支都不进），测试退化为
//   空转（改档根本没发生），退回修复前也照样绿——假回归锁。用合法档位才真正压到
//   分槽分支（先红后绿硬约束 #4 自检修正，已向 lead 说明）。
//
// 诚实边界（必须留真机，本测试不覆盖）：
//   - UI 呈现/交互路径：复制按钮、反馈提示形态、sheet 关闭后任务到点、锁定流程。
//   - 30s 真实时序（本测试以 0.5~0.8s 短时长代理时长面，契约面同构）。
//   - AC-2.9.0-P5-6/P5-8 的 30s 窗口长竞态（真机 30s 窗口内用户顶掉）。
//
// 环境自恢复（照抄 ClipboardTierTests 纪律）：测试后恢复剪贴板原内容（无则清空）。
// 用例间隔离：每条用例以自身写入的 changeCount 为基准；结束时 pending 任务均已到点
// 触发或经 clearOnLock 取消——不留跨用例的悬挂 clearWorkItem / writtenChangeCount。
//
// 驱动：tools/run_clipboard_slot_tests.sh（swiftc 直编 CoreBindings 绑定 +
// Platform/Clipboard.swift + Support/DiagLog.swift + 本文件 + libcf_ffi.a）。

import AppKit

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0
var inconclusive = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

/// 主线程 runloop 等待：驱动 main queue 上的 asyncAfter 定时任务真实触发。
func wait(_ seconds: TimeInterval) {
    RunLoop.main.run(until: Date().addingTimeInterval(seconds))
}

func pasteboardString() -> String? {
    NSPasteboard.general.string(forType: .string)
}

/// 「期望剪贴板已空」断言：nil → PASS；仍为本 payload → FAIL（未清除）；
/// 其它非空 → 外部剪贴板活动干扰（测试进程与用户共用系统剪贴板）→ INCONCLUSIVE，
/// 不算 fail（诚实边界，不把环境竞态误判为产品缺陷）。
func checkCleared(_ tc: String, _ name: String, ourPayload: String) {
    let now = pasteboardString()
    if now == nil {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else if now == ourPayload {
        failures.append("\(tc) \(name) 仍为 payload（未清除）")
        print("FAIL  \(tc)  \(name)  仍为 payload（未清除）")
    } else {
        inconclusive += 1
        print("INCONCLUSIVE  \(tc)  \(name)  等待期间剪贴板被外部内容顶掉（现为 \(now!)）")
    }
}

/// 「期望剪贴板仍为本 payload」断言：== payload → PASS；nil → FAIL（被意外清除）；
/// 其它非空 → 外部干扰 → INCONCLUSIVE。
func checkRemains(_ tc: String, _ name: String, payload: String) {
    let now = pasteboardString()
    if now == payload {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else if now == nil {
        failures.append("\(tc) \(name) 被意外清除")
        print("FAIL  \(tc)  \(name)  被意外清除")
    } else {
        inconclusive += 1
        print("INCONCLUSIVE  \(tc)  \(name)  等待期间剪贴板被外部内容顶掉（现为 \(now!)）")
    }
}

// MARK: - 环境保存（测试后恢复）

let clip = ClipboardManager.shared
let originalClipboard = pasteboardString()

// MARK: - TC-SLOT-1：changeCount 守卫（AC-2.9.0-P5-6）

clip.copyWithAutoClear("coffer-slot-1-secret", clearSecs: 0.6)
// 模拟用户随后复制了自己的内容（changeCount 顶掉我们的记录）
NSPasteboard.general.clearContents()
NSPasteboard.general.setString("user-own-content-1", forType: .string)
wait(1.0)   // 越过 0.6s 任务到点
checkRemains("TC-SLOT-1", "AC-2.9.0-P5-6 到点但用户已顶掉 → 绝不误清",
             payload: "user-own-content-1")

// MARK: - TC-SLOT-2：只留最近（AC-2.9.0-P5-7）

// A 先复制（0.8s 到点）；隔 0.2s B 再复制（0.8s 到点）→ 首个理论到点是 A（t≈0.8）。
// A 的未到点任务被 schedulePendingClear 的 cancel() 取消；即便未取消，changeCount
// 守卫也会拒绝 A 清除 B（双保险）。诚实注记：经公开 API 可观察的是「B 存活 + B
// 到点清」两端，「A 被取消」与守卫在此场景互为冗余（守卫单点也足以兜住）。
clip.copyWithAutoClear("coffer-slot-2a", clearSecs: 0.8)   // A：t≈0 写，到点 t≈0.8
wait(0.2)
clip.copyWithAutoClear("coffer-slot-2b", clearSecs: 0.8)   // B：t≈0.2 写，到点 t≈1.0
wait(0.6)   // → t≈0.8，A 的理论到点已过，B 必须仍在
checkRemains("TC-SLOT-2", "AC-2.9.0-P5-7 A 到点后 B 仍在（A 任务已取消/守卫拒绝）",
             payload: "coffer-slot-2b")
wait(0.3)   // → t≈1.1，B 的理论到点（1.0）已过
checkCleared("TC-SLOT-2", "AC-2.9.0-P5-7 B 到点后清除（只留最近调度）",
             ourPayload: "coffer-slot-2b")

// MARK: - TC-SLOT-3：clearOnLock 覆盖（AC-2.9.0-P5-8）

clip.copyWithAutoClear("coffer-slot-3-secret", clearSecs: 60)
clip.clearOnLock()
checkCleared("TC-SLOT-3", "AC-2.9.0-P5-8 复制后锁定 → 立即清空（60s 任务被取消）",
             ourPayload: "coffer-slot-3-secret")

// 反段：复制后用户顶掉内容 → clearOnLock 守卫不动用户内容
clip.copyWithAutoClear("coffer-slot-3-secret", clearSecs: 60)
NSPasteboard.general.clearContents()
NSPasteboard.general.setString("user-own-content-3", forType: .string)
clip.clearOnLock()
checkRemains("TC-SLOT-3", "AC-2.9.0-P5-8 反段：锁定守卫不动用户顶掉的内容",
             payload: "user-own-content-3")

// MARK: - TC-SLOT-4：显式 0（AC-2.9.0-P5-2，勿 asyncAfter(0)）

clip.copyWithAutoClear("coffer-slot-4-never", clearSecs: 0)
wait(1.0)
checkRemains("TC-SLOT-4", "AC-2.9.0-P5-2 显式 0 不立即清（无 asyncAfter(0) 立清）",
             payload: "coffer-slot-4-never")
clip.clearOnLock()
checkCleared("TC-SLOT-4", "AC-2.9.0-P5-2 显式 0 保留锁定兜底（clearOnLock 清）",
             ourPayload: "coffer-slot-4-never")

// MARK: - TC-SLOT-5：REV-DEV-01 分槽核心（显式任务不被改档取消）

// FR-17.2：恢复码固定 30s 清除不受用户档位影响。短时长代理：显式 0.8s 任务挂起时
// 改档到 10s，显式任务必须不被取消/重排，仍按自己的 0.8s 到点清除。
// 退回修复前（无 isClearTierDriven 分槽，updateClearInterval 单槽重排）→ 0.8s 任务
// 被重排到 10s → 1.2s 时内容仍在 → 本断言红。当前实现绿。
clip.copyWithAutoClear("coffer-slot-5-explicit", clearSecs: 0.8)
clip.updateClearInterval(secs: 10)   // 改档（合法档位，见文件头注：secs:1 非法=空转）
wait(1.2)
checkCleared("TC-SLOT-5", "REV-DEV-01 显式任务不被改档取消（0.8s 到点清除）",
             ourPayload: "coffer-slot-5-explicit")

// MARK: - TC-SLOT-6：REV-DEV-01 加固缺口（「从不」语义不被改档误清）

// 「从不」档语义复制（clearSecs:0，不挂任务、无 asyncAfter(0)）后改档：不得产生
// 误清任务（分槽修复前的缺陷行为——「从不」档旧写入被改档重排误清）。1.4s 后内容
// 必须仍在。当前实现：updateClearInterval 经 isClearTierDriven(false) 直接 return，
// 不重排，内容存活。
clip.copyWithAutoClear("coffer-slot-6-never", clearSecs: 0)
clip.updateClearInterval(secs: 10)   // 改档（合法档位）
wait(1.4)
checkRemains("TC-SLOT-6", "REV-DEV-01 「从不」复制不被改档误清（不产生误清任务）",
             payload: "coffer-slot-6-never")
clip.clearOnLock()   // 清理复位（清掉本用例测试内容，writtenChangeCount 归 -1）

// MARK: - TC-SLOT-7：显式覆盖档位（AC-2.9.0-P5-9）

// 用户档位 = 从不（0）→ 恢复码复制仍按入参 0.5s 清（D-3.2：入参覆盖档位，与档位解耦）。
clip.updateClearInterval(secs: 0)   // 用户档位「从不」
clip.copyWithAutoClear("coffer-slot-7", clearSecs: 0.5)
wait(0.9)
checkCleared("TC-SLOT-7", "AC-2.9.0-P5-9 档位「从不」仍按入参 0.5s 清",
             ourPayload: "coffer-slot-7")

// MARK: - 清理（用户要求：测试数据全部清掉）

NSPasteboard.general.clearContents()
if let originalClipboard {
    NSPasteboard.general.setString(originalClipboard, forType: .string)
    print("CLEANUP  剪贴板原内容已还原")
} else {
    print("CLEANUP  剪贴板已清空（原为空）")
}
// 注：本组用例全部走显式 clearSecs（不读用户档位），updateClearInterval 只改单例
// 进程内 clearAfterSeconds、不写 UserDefaults（写盘在 AppModel.clipboardClearSecs
// didSet，测试未触碰），故无需恢复 UserDefaults 档位原值。

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed / \(inconclusive) inconclusive")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
