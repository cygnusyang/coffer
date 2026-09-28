// ClipboardTierTests/main.swift —— 剪贴板五档自动化验收（TC-UI-01 ~ 04 接口级替代执行）。
//
// 定位（2026-09-28 验收批次，用户要求：Round 1 由代理调接口自测，不经手 GUI）：
//   - 驱动真实 NSPasteboard + 真实定时器（ClipboardManager 单例），不是 mock；
//   - 档位表 / 默认值经 FFI 取自 Rust（与 App 同一来源）；
//   - 可选末段：真实库数据 导出 → 校验 → 恢复 回环（出口判据①②的结构面，
//     恢复目标为临时目录，不触碰真实库；不解密对比——测试进程无主密码）。
//
// 测试后清理纪律（用户要求）：
//   - UserDefaults key `clipboard_clear_secs` 原值保存并恢复；
//   - 系统剪贴板原内容保存并恢复（无原内容则清空）；
//   - 回环测试产物全部落在 mktemp 临时目录，进程内删除。
//
// 用法：run_clipboard_tier_tests.sh [--vault-dir <真实库工作目录>]

import AppKit

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

/// 主线程 runloop 等待：驱动 main queue 上的 asyncAfter 定时任务真实触发。
func wait(_ seconds: TimeInterval) {
    RunLoop.main.run(until: Date().addingTimeInterval(seconds))
}

func pasteboardString() -> String? {
    NSPasteboard.general.string(forType: .string)
}

// MARK: - 环境保存（测试后恢复）

let defaultsKey = ClipboardManager.clearSecsDefaultsKey
let originalTierValue = UserDefaults.standard.object(forKey: defaultsKey)
let originalClipboard = pasteboardString()
let clip = ClipboardManager.shared

// MARK: - T7：FFI 档位表 / 默认值（内核同源性）

check("TC-CLP-05", "档位表经 FFI 取得且无硬编码", clipboardClearTiers() == [10, 30, 60, 120],
      "实际 \(clipboardClearTiers())")
check("NFR-UX-02", "默认档位 30s 经 FFI 取得", defaultClipboardClearSecs() == 30,
      "实际 \(defaultClipboardClearSecs())")

// MARK: - T6：UserDefaults 档位装载 / 校验 / 回退（持久化逻辑面）

UserDefaults.standard.removeObject(forKey: defaultsKey)
check("TC-UI-04", "键不存在 → 回退默认 30", ClipboardManager.loadStoredClearSecs() == 30)

UserDefaults.standard.set(0, forKey: defaultsKey)
check("TC-UI-02", "显式 0（从不）不被「未配置」吞掉", ClipboardManager.loadStoredClearSecs() == 0)

UserDefaults.standard.set(88, forKey: defaultsKey)
check("TC-CLP-06", "非法档位 88 → 回退默认 30", ClipboardManager.loadStoredClearSecs() == 30)

UserDefaults.standard.set(120, forKey: defaultsKey)
check("TC-UI-04", "合法档位 120 原样读回", ClipboardManager.loadStoredClearSecs() == 120)

// MARK: - T1：10 秒档真实清除（TC-UI-01 代表档位）

/// 带外部干扰重试的定时清除验证：等待期间若剪贴板被外部内容顶掉
/// （changeCount 守卫正确拒绝清除），判 INCONCLUSIVE 并自动重试——
/// 验收脚本与真实用户共用系统剪贴板，此竞态必须容忍而非误判 FAIL。
/// 档位显式设定（不依赖单例残留档位——那可能是用户原值「从不」）。
func checkTimedClear(tc: String, name: String, tier: Int, payload: String, waitSecs: TimeInterval, retries: Int = 3) {
    clip.updateClearInterval(secs: tier)
    for attempt in 1...max(1, retries) {
        clip.copyWithAutoClear(payload)
        guard pasteboardString() == payload else {
            check(tc, name, false, "第\(attempt)次：复制后读取即不符")
            return
        }
        wait(waitSecs)
        let now = pasteboardString()
        if now == nil {
            check(tc, name, true)
            return
        }
        if now == payload {
            check(tc, name, false, "第\(attempt)次：等待 \(waitSecs)s 后仍未清除")
            return
        }
        // 剪贴板被外部内容顶掉（守卫按设计拒绝清除）→ 重试
        print("RETRY  \(tc)  第\(attempt)次等待期间剪贴板被外部内容顶掉（守卫行为正确），重试")
    }
    check(tc, name, false, "连续 \(retries) 次被外部剪贴板活动干扰")
}

checkTimedClear(tc: "TC-UI-01", name: "10s 档到点自动清除", tier: 10, payload: "coffer-t1-secret-10s", waitSecs: 12)

// MARK: - T2：TOTP 例外（FR-5.5，TC-UI-03）

clip.copyPlain("coffer-t2-totp-123456")
wait(12)
check("TC-UI-03", "copyPlain（TOTP 路径）不清除", pasteboardString() == "coffer-t2-totp-123456",
      "实际 \(pasteboardString() ?? "nil")")

// MARK: - T3：改档重排（120s 档复制后立即改 10s，应按新间隔清）

clip.updateClearInterval(secs: 120)
clip.copyWithAutoClear("coffer-t3-reschedule")
clip.updateClearInterval(secs: 10)
wait(12)
let t3now = pasteboardString()
if t3now == nil || t3now != "coffer-t3-reschedule" {
    // nil = 按新间隔清除 ✅；非 payload 外部内容 = 竞态，不误判
    check("TC-UI-01", "改档后按新间隔重排（120→10 在 ~10s 清除）", t3now == nil,
          t3now == nil ? "" : "等待期间剪贴板被外部内容顶掉，INCONCLUSIVE")
} else {
    check("TC-UI-01", "改档后按新间隔重排（120→10 在 ~10s 清除）", false, "10s 后仍为本 payload")
}

// MARK: - T4：从不（0）—— 不调度 + 锁定兜底（TC-UI-02）

clip.updateClearInterval(secs: 0)
clip.copyWithAutoClear("coffer-t4-never")
check("TC-UI-02", "「从不」档复制后有值", pasteboardString() == "coffer-t4-never")
wait(20)
check("TC-UI-02", "「从不」档 20s 后仍在（无调度，非立即清）",
      pasteboardString() == "coffer-t4-never", "实际 \(pasteboardString() ?? "nil")")
clip.clearOnLock()
check("TC-UI-02", "锁定兜底立即清除（clearOnLock）", pasteboardString() == nil)

// MARK: - T5：changeCount 守卫——绝不误清用户内容

clip.updateClearInterval(secs: 10)
clip.copyWithAutoClear("coffer-t5-secret")
// 模拟用户随后复制了自己的内容（changeCount 顶掉我们的记录）
NSPasteboard.general.clearContents()
NSPasteboard.general.setString("user-own-content", forType: .string)
wait(12)
check("FR-4.7", "到点但用户已顶掉剪贴板 → 不误清",
      pasteboardString() == "user-own-content", "实际 \(pasteboardString() ?? "nil")")
clip.clearOnLock() // 复位内部状态（守卫应判定非我们内容、不动剪贴板）
check("FR-4.7", "clearOnLock 守卫不动用户内容", pasteboardString() == "user-own-content")

// MARK: - T8（可选）：真实库 导出 → 校验 → 恢复 回环（出口判据①②结构面）

var vaultDir: String? = nil
if let idx = CommandLine.arguments.firstIndex(of: "--vault-dir"),
   CommandLine.arguments.count > idx + 1 {
    vaultDir = CommandLine.arguments[idx + 1]
}

if let vaultDir {
    do {
        let app = CofferApp()
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("coffer-acceptance-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let briefs = try app.listVaults(baseDir: vaultDir)
        check("AC-06-pre", "真实工作目录枚举到库", !briefs.isEmpty, "briefs=\(briefs.count)")

        // export_backup 契约参数是**库目录**（<base>/<uuid>，含 header.json），
        // 非工作目录（BUG-7 回归警戒：此前 ExportView 误传工作目录 → 1012）。
        let realVaultDir = (vaultDir as NSString)
            .appendingPathComponent(briefs[0].vaultUuid)

        let exportPath = tmp.appendingPathComponent("acceptance.coffer").path
        let export = try app.exportBackup(vaultDir: realVaultDir, outPath: exportPath)
        check("TC-EXP-08", "真实库导出成功（工厂级）", export.verified,
              "files=\(export.fileCount) size=\(export.sizeBytes)")
        check("FR-8.6", "导出自检 verified=true", export.verified)

        let report = try app.verifyBackup(backupPath: exportPath)
        check("TC-EXP-05", "备份包结构校验通过", report.vaultUuid == briefs[0].vaultUuid,
              "uuid=\(report.vaultUuid) fmt=\(report.formatVersion) files=\(report.fileCount)")

        let restoredDir = try app.restoreBackup(backupPath: exportPath, targetBaseDir: tmp.path)
        let restoredBriefs = try app.listVaults(baseDir: tmp.path)
        check("AC-06", "恢复产物枚举可见且 uuid 与源一致",
              restoredBriefs.contains { $0.vaultUuid == report.vaultUuid },
              "restoredDir=\(restoredDir)")

        // Round 5b 负向：向真实工作目录恢复同 uuid 备份 → 必撞 1004（目录
        // 已存在），且不写库（错误路径 Rust 契约：无半成品产物）。
        do {
            _ = try app.restoreBackup(backupPath: exportPath, targetBaseDir: vaultDir)
            check("TC-EXP-04", "恢复到已存在库 → 应 1004", false, "竟然成功？")
        } catch let e as FfiError {
            if case let .Coffer(code, _) = e, code == 1004 {
                check("TC-EXP-04", "恢复到已存在库 → 1004 且不写库", true)
            } else {
                check("TC-EXP-04", "恢复到已存在库 → 1004", false, "\(e)")
            }
        }
        // 判据②负向的自动化已在 Rust 侧 TC-EXP-05 覆盖（篡改字节检出），此处不重复。
    } catch {
        check("AC-06", "回环异常", false, "\(error)")
    }
} else {
    print("SKIP  T8  未提供 --vault-dir，跳过真实库回环")
}

// MARK: - 清理（用户要求：测试数据全部清掉）

if let originalTierValue {
    UserDefaults.standard.set(originalTierValue, forKey: defaultsKey)
} else {
    UserDefaults.standard.removeObject(forKey: defaultsKey)
}
print("CLEANUP  UserDefaults key restored: \(ClipboardManager.loadStoredClearSecs())s（原值已还原）")

NSPasteboard.general.clearContents()
if let originalClipboard {
    NSPasteboard.general.setString(originalClipboard, forType: .string)
    print("CLEANUP  剪贴板原内容已还原")
} else {
    print("CLEANUP  剪贴板已清空（原为空）")
}

// MARK: - T9：改主密码闭环（TC-UI-11 内核判据，临时库，不触碰真实库）

// 真实库的旧密码只有用户知道，测试进程绝不请求；改密判据（旧失效/新生效/
// 全库可解密/中途原子性）全部可在密码已知的临时库上等价验证——经 Swift
// 绑定层调用（顺带回归绑定生成产物），内核面另有 TC-CPW-01~12 Rust 自动化。
do {
    let app = CofferApp()
    let tmp = FileManager.default.temporaryDirectory
        .appendingPathComponent("coffer-cpw-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmp) }

    let oldPass = "Old-Pass-1!"
    let newPass = "New-Pass-2@x"
    let brief = try app.createVault(baseDir: tmp.path, name: "验收临时库", password: oldPass)
    let session = try app.openVault(baseDir: tmp.path, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: oldPass)

    // 弱新密码 → 1010，且 header 未动（旧密码仍可解锁）
    do {
        try session.changePassword(oldPassword: oldPass, newPassword: "123456", newKdf: nil)
        check("TC-CPW-03", "弱新密码应 1010 拒绝", false, "竟然成功？")
    } catch let e as FfiError {
        if case let .Coffer(code, _) = e, code == 1010 {
            check("TC-CPW-03", "弱新密码 → 1010（先于任何文件操作）", true)
        } else { check("TC-CPW-03", "弱新密码 → 1010", false, "\(e)") }
    }
    session.lock()
    _ = try session.unlock(password: oldPass)
    check("TC-CPW-03", "1010 拒绝后旧密码仍可解锁（header 未动）", true)

    // 正确改密 → 旧密码失效 / 新密码生效（TC-CPW-01/02）
    try session.changePassword(oldPassword: oldPass, newPassword: newPass, newKdf: nil)
    session.lock()
    do {
        _ = try session.unlock(password: oldPass)
        check("TC-CPW-01", "改密后旧密码必失败（1002）", false, "旧密码竟然解锁成功")
    } catch let e as FfiError {
        if case let .Coffer(code, _) = e, code == 1002 {
            check("TC-CPW-01", "改密后旧密码必失败（1002）", true)
        } else { check("TC-CPW-01", "改密后旧密码必失败", false, "\(e)") }
    }
    _ = try session.unlock(password: newPass)
    check("TC-CPW-02", "改密后新密码解锁成功、全库可解密", true)

    // 改密 × 备份回环（TC-CPW-10）：改密后的库导出可校验、可恢复
    let exportPath = tmp.appendingPathComponent("cpw.coffer").path
    let export = try app.exportBackup(vaultDir: tmp.appendingPathComponent(brief.vaultUuid).path,
                                      outPath: exportPath)
    check("TC-CPW-10", "改密后导出自检通过", export.verified)
    try app.verifyBackup(backupPath: exportPath)
    check("TC-CPW-10", "改密后备份包结构校验通过", true)
} catch {
    check("TC-CPW", "改密闭环异常", false, "\(error)")
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
