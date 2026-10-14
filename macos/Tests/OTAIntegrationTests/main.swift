// OTAIntegrationTests/main.swift —— OTA 链路可自动化部分的集成测试（任务 #70 第一层）。
//
// 锁定的契约（docs/35 §6.4 r0.4）：helper 子进程「等待 → 备份 → 替换 → relaunch
// gate → result 握手」全流程，用**真实签名产物**（macos/build/Coffer.app，含
// embedded.provisionprofile）做载荷——把 helper 契约绑定到真实 bundle 结构上。
//
// 为什么绕开 open(1)（BUG-29 后唯一真实启动路径）：open 的 LaunchServices 提交在
// 沙盒 App 内是静默 no-op、继承沙盒风险只能真机定谳（BUG-29 核销判据）。CI 能做的
// 是**直接 exec helper 可执行文件**测其契约。本 harness 编译 helper 测试构建（无
// -D COFFER_UPDATER_PRODUCTION，锚读 env COFFER_UPDATER_TEST_ANCHOR）并直接 exec；
// relaunch 用 COFFER_UPDATER_TEST_FAKE_RELAUNCH 桩隔离（真 open relaunch 归真机
// 核销，docs/01 BUG-29 判据）。
//
// 现场隔离：全部临时目录，不走 /Applications、不碰用户真实密码库。
//   dstApp   = 真实产物 ditto 副本（当前 App，低版本）
//   newApp   = 真实产物另一副本：Info.plist 版本改写 99.99.99 + **重签保 DR** →
//              ditto 打 zip → 解压模拟「下载→prepare」产物（newAppPath）
//   backup/result/relaunch.log 均在临时目录；pid = 已退出进程（立即通过等待窗）
//
// 前置（缺失显式 SKIP，不算 fail）：签名产物存在 + Apple Development 签名身份存在
// + 测试构建 helper 二进制存在（tools/run_ota_integration_tests.sh 编译注入）。
//
// 编译运行：tools/run_ota_integration_tests.sh

import Foundation
import Darwin

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0
var skipped = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

func skip(_ tc: String, _ name: String, _ reason: String) {
    skipped += 1
    print("SKIP  \(tc)  \(name)  \(reason)")
}

// MARK: - 子进程辅助（同步跑 + 收 stdout/stderr；非 0 不自动抛错——由断言判定）

struct ProcResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

@discardableResult
func runProcess(_ executable: String, args: [String],
                env: [String: String] = [:]) throws -> ProcResult {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executable)
    p.arguments = args
    var fullEnv = ProcessInfo.processInfo.environment
    for (key, value) in env { fullEnv[key] = value }
    p.environment = fullEnv
    let out = Pipe()
    let err = Pipe()
    p.standardOutput = out
    p.standardError = err
    try p.run()
    p.waitUntilExit()
    let outData = out.fileHandleForReading.readDataToEndOfFile()
    let errData = err.fileHandleForReading.readDataToEndOfFile()
    return ProcResult(
        status: p.terminationStatus,
        stdout: String(data: outData, encoding: .utf8) ?? "",
        stderr: String(data: errData, encoding: .utf8) ?? "")
}

// MARK: - 现场辅助

/// 读 .app 的 CFBundleShortVersionString（nil = 不可读）。
func appVersion(_ app: URL) -> String? {
    let plist = app.appendingPathComponent("Contents/Info.plist").path
    guard let r = try? runProcess("/usr/libexec/PlistBuddy",
                                  args: ["-c", "Print :CFBundleShortVersionString", plist]),
          r.status == 0 else { return nil }
    return r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Apple Development 签名身份 SHA-1 hash（重签新包保 DR 用；缺身份 → nil）。
func signingIdentity() -> String? {
    guard let r = try? runProcess("/usr/bin/security",
                                  args: ["find-identity", "-v", "-p", "codesigning"]),
          r.status == 0 else { return nil }
    for line in r.stdout.split(separator: "\n") where line.contains("Apple Development") {
        let parts = line.split(separator: " ")
        if parts.count >= 2 { return String(parts[1]) }
    }
    return nil
}

/// 已退出进程的 pid（kill(pid,0) → ESRCH）——helper 等待窗立即通过（不空等 30s）。
func deadPID() -> Int32 {
    let s = Process()
    s.executableURL = URL(fileURLWithPath: "/bin/sleep")
    s.arguments = ["0.05"]
    try? s.run()
    s.waitUntilExit()
    return s.processIdentifier
}

/// 写 helper 安装配置 JSON（5 字段，契约 §6.4 r0.4）。
func writeConfig(_ configPath: String, newApp: String, currentApp: String,
                 backup: String, result: String, pid: Int32) throws {
    let obj: [String: Any] = [
        "newAppPath": newApp,
        "currentAppPath": currentApp,
        "backupPath": backup,
        "resultFilePath": result,
        "pid": pid,
    ]
    let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
    try data.write(to: URL(fileURLWithPath: configPath))
}

/// 解析 helper result JSON；返回 (success, code, message) 三元组。
func readResult(_ path: String) -> (Bool, Int, String)? {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let success = obj["success"] as? Bool,
          let code = obj["code"] as? Int,
          let message = obj["message"] as? String else { return nil }
    return (success, code, message)
}

// MARK: - BUG-30 固定路径兜底（helper 端推导同一路径）

/// 真实用户家目录（getpwuid 用户数据库，与 helper 端 realUserHomeDirectory 同源——
/// 不读 HOME env，沙盒 App 的 HOME 指向容器 Data，读它会把路径算到双层容器目录）。
func realUserHome() -> String {
    if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
        return String(cString: dir)
    }
    return NSHomeDirectory()
}

/// helper 固定路径兜底 config 的确定性路径（与 Installer/main.swift fixedConfigPath
/// 同源）：$HOME/Library/Containers/top.cygnusyang.coffer/Data/tmp/
/// coffer-ota-pending-config.json。零传播假设——不依赖任何参数/env 传递。
func fixedConfigPath() -> String {
    realUserHome()
        + "/Library/Containers/top.cygnusyang.coffer/Data/tmp/coffer-ota-pending-config.json"
}

/// best-effort 移除固定路径 config（测试隔离：清掉可能残留的真实 App/前场固定 config，
/// 让 TC-INT-01/02 的 argv 取参路径确定性地生效；只删这一个固定文件，绝不碰其它）。
func removeFixedConfigIfPresent() {
    try? FileManager.default.removeItem(atPath: fixedConfigPath())
}

// MARK: - 前置（SKIP 条件）

let artifactPath = ProcessInfo.processInfo.environment["COFFER_UPDATE_ARTIFACT_PATH"] ?? ""
let helperBin = ProcessInfo.processInfo.environment["COFFER_OTA_HELPER_BIN"] ?? ""

func missingPrereq(_ tc: String, _ reason: String) -> Bool {
    check(tc, "前置检查（\(reason)）", false, "前置缺失，本用例 SKIP")
    skip(tc, "（前置缺失）", reason)
    return true
}

// MARK: - TC-INT-01 成功路径：等待→备份→替换→relaunch gate→result 握手（真实产物）

do {
    guard !artifactPath.isEmpty, FileManager.default.fileExists(atPath: artifactPath) else {
        _ = missingPrereq("TC-INT-01", "缺真实签名产物 macos/build/Coffer.app（先跑 build_macos_app.sh）")
        failures.removeAll()  // 前置缺失按 SKIP 计，不算 fail
        skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }
    guard !helperBin.isEmpty, FileManager.default.fileExists(atPath: helperBin) else {
        skip("TC-INT-01", "（前置缺失）", "缺测试构建 helper 二进制（run_ota_integration_tests.sh 编译注入）")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }
    guard let identity = signingIdentity() else {
        skip("TC-INT-01", "（前置缺失）", "缺 Apple Development 签名身份（载荷重签保 DR 依赖）")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    let fm = FileManager.default
    let tmpRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-int-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tmpRoot) }

    // ---- dstApp（当前 App：真实产物副本，低版本）----
    let dstDir = tmpRoot.appendingPathComponent("dst")
    try fm.createDirectory(at: dstDir, withIntermediateDirectories: true)
    let dstApp = dstDir.appendingPathComponent("Coffer.app")
    try runProcess("/usr/bin/ditto", args: [artifactPath, dstApp.path])
    guard let originalVersion = appVersion(dstApp), !originalVersion.isEmpty else {
        check("TC-INT-01", "dstApp 版本可读（前置 sanity）", false, "无法读取副本版本")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / \(failures.count) failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    // ---- newApp：另一副本 + 版本改写 99.99.99 + 重签（保 DR/entitlements/profile）----
    let newBuildDir = tmpRoot.appendingPathComponent("newbuild")
    try fm.createDirectory(at: newBuildDir, withIntermediateDirectories: true)
    let newBuildApp = newBuildDir.appendingPathComponent("Coffer.app")
    try runProcess("/usr/bin/ditto", args: [artifactPath, newBuildApp.path])
    let newBuildPlist = newBuildApp.appendingPathComponent("Contents/Info.plist").path
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleShortVersionString 99.99.99", newBuildPlist])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleVersion 999999", newBuildPlist])
    let resign = try runProcess("/usr/bin/codesign",
                                args: ["--force", "--sign", identity,
                                       "--preserve-metadata=entitlements,requirements,flags",
                                       newBuildApp.path])
    check("TC-INT-01", "newApp 版本改写后重签成功（保 DR，载荷合法性前提）",
          resign.status == 0, "exit=\(resign.status) stderr=\(resign.stderr)")
    let verifyResign = try runProcess("/usr/bin/codesign",
                                      args: ["--verify", "--strict", newBuildApp.path])
    check("TC-INT-01", "重签后 codesign --verify --strict 通过",
          verifyResign.status == 0, verifyResign.stderr)

    // 打 zip → 解压：模拟「下载 → prepare 解压」后的产物（newAppPath）
    let zipPath = tmpRoot.appendingPathComponent("new.zip")
    try runProcess("/usr/bin/ditto", args: ["-c", "-k", "--keepParent", newBuildApp.path, zipPath.path])
    let stageDir = tmpRoot.appendingPathComponent("stage")
    try fm.createDirectory(at: stageDir, withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: ["-x", "-k", zipPath.path, stageDir.path])
    let newApp = stageDir.appendingPathComponent("Coffer.app")
    check("TC-INT-01", "解压产物存在且版本 99.99.99",
          fm.fileExists(atPath: newApp.path) && appVersion(newApp) == "99.99.99",
          "version=\(appVersion(newApp) ?? "nil")")

    // ---- 配置 + 跑 helper ----
    let backupPath = tmpRoot.appendingPathComponent("backup/Coffer.app").path
    let resultPath = tmpRoot.appendingPathComponent("result.json").path
    let relaunchLog = tmpRoot.appendingPathComponent("relaunch.log").path
    let configPath = tmpRoot.appendingPathComponent("config.json").path
    try writeConfig(configPath, newApp: newApp.path, currentApp: dstApp.path,
                    backup: backupPath, result: resultPath, pid: deadPID())

    let helperEnv = [
        "COFFER_UPDATER_TEST_ANCHOR": dstApp.path,
        "COFFER_UPDATER_TEST_FAKE_RELAUNCH": relaunchLog,
        // BUG-30 取参隔离：置空 kill 掉环境里可能残留的 COFFER_UPDATER_CONFIG +
        // 清固定路径 config → 本场确定性走 argv 源（TC-INT-03 专测固定路径源）。
        "COFFER_UPDATER_CONFIG": "",
    ]
    removeFixedConfigIfPresent()
    let helper = try runProcess(helperBin, args: ["--config", configPath], env: helperEnv)

    // ---- 断言：退出 → 替换 → relaunch gate → result 握手全流程 ----
    check("TC-INT-01", "helper exit 0（等待→备份→替换→relaunch→result 全流程）",
          helper.status == 0,
          "exit=\(helper.status) stderr=\(helper.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
    if let result = readResult(resultPath) {
        check("TC-INT-01", "result.json success=true", result.0, "\(result)")
        check("TC-INT-01", "result.json code=0", result.1 == 0, "\(result)")
    } else {
        check("TC-INT-01", "result.json 可解析且字段齐全", false, "无法读取/解析 result")
    }
    check("TC-INT-01", "目标 dstApp 已被替换（版本=99.99.99）",
          appVersion(dstApp) == "99.99.99", "actual=\(appVersion(dstApp) ?? "nil")")
    let backupApp = URL(fileURLWithPath: backupPath)
    let backupVersion = appVersion(backupApp)
    check("TC-INT-01", "备份存在", fm.fileExists(atPath: backupPath))
    check("TC-INT-01", "备份为旧版本（\(originalVersion)）", backupVersion == originalVersion,
          "backup=\(backupVersion ?? "nil")")
    if let logData = try? String(contentsOf: URL(fileURLWithPath: relaunchLog), encoding: .utf8) {
        check("TC-INT-01", "relaunch gate 通过：fake 桩记录目标 dstApp（open 被隔离）",
              logData.contains(dstApp.path), "log=\(logData.trimmingCharacters(in: .whitespacesAndNewlines))")
    } else {
        check("TC-INT-01", "relaunch gate 通过：fake 桩记录目标 dstApp（open 被隔离）",
              false, "relaunch.log 缺失")
    }

    // BUG-29 后续 A：helper 文件日志（/tmp/coffer-update.log）——argv 首行落盘
    // 是现场「helper 没被拉起 vs 被拉起但 args 丢失 exit 4」的分诊关键（统一日志
    // 曾整体失效，诊断只能靠文件落盘）。断言文件里含本场唯一 configPath 的
    // 「coffer-update 启动 … argv=…」行。contains 语义 + 每场唯一路径：跨场并发
    // append（多 helper 实例 O_APPEND 行写）时仍能定位本场，不依赖末行。
    let fileLogPath = "/tmp/coffer-update.log"
    if let logText = try? String(contentsOfFile: fileLogPath, encoding: .utf8) {
        let argvLine = logText.split(separator: "\n").first {
            $0.hasPrefix("coffer-update 启动") && $0.contains(configPath)
        }
        check("TC-INT-01", "helper 文件日志首行含本场 argv（--config <路径> 已送达）",
              argvLine != nil, "log=\(fileLogPath)")
    } else {
        check("TC-INT-01", "helper 文件日志首行含本场 argv（--config <路径> 已送达）",
              false, "无法读取 \(fileLogPath)")
    }
}

// MARK: - TC-INT-02 负面：真实产物改版本但**不重签**（签名封存破坏）→ 载荷 DR 拒装 exit 2

// 证明 TC-INT-01 的重签是载荷合法性的必要前提：真实产物上 C-1 载荷门（静态验签
// DR + profile）在集成面同样强制——改版本不重签的包绝不能过。
do {
    let fm = FileManager.default
    guard FileManager.default.fileExists(atPath: artifactPath),
          FileManager.default.fileExists(atPath: helperBin) else {
        skip("TC-INT-02", "（前置缺失）", "签名产物或 helper 缺失（同 TC-INT-01 前置）")
        failures.removeAll()
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }
    let tmpRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-int-neg-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tmpRoot) }

    // 损坏载荷：真实产物副本 + 版本改写，**不重签**（签名封存失效）
    let brokenDir = tmpRoot.appendingPathComponent("broken")
    try fm.createDirectory(at: brokenDir, withIntermediateDirectories: true)
    let brokenApp = brokenDir.appendingPathComponent("Coffer.app")
    try runProcess("/usr/bin/ditto", args: [artifactPath, brokenApp.path])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleShortVersionString 99.99.99",
                          brokenApp.appendingPathComponent("Contents/Info.plist").path])

    // 目标：真实产物另一副本（原版本）
    let dst2Dir = tmpRoot.appendingPathComponent("dst2")
    try fm.createDirectory(at: dst2Dir, withIntermediateDirectories: true)
    let dst2App = dst2Dir.appendingPathComponent("Coffer.app")
    try runProcess("/usr/bin/ditto", args: [artifactPath, dst2App.path])
    let dst2Original = appVersion(dst2App) ?? ""

    let backup2 = tmpRoot.appendingPathComponent("backup2/Coffer.app").path
    let result2 = tmpRoot.appendingPathComponent("result2.json").path
    let config2 = tmpRoot.appendingPathComponent("config2.json").path
    try writeConfig(config2, newApp: brokenApp.path, currentApp: dst2App.path,
                    backup: backup2, result: result2, pid: deadPID())

    removeFixedConfigIfPresent()
    let helper2 = try runProcess(helperBin, args: ["--config", config2],
                                 env: ["COFFER_UPDATER_TEST_ANCHOR": dst2App.path,
                                       // BUG-30 取参隔离（同 TC-INT-01）：确定性走 argv 源
                                       "COFFER_UPDATER_CONFIG": ""])
    check("TC-INT-02", "未重签载荷（真实产物改版本）→ helper exit 2（载荷 DR 拒装）",
          helper2.status == 2, "exit=\(helper2.status) stderr=\(helper2.stderr)")
    if let result = readResult(result2) {
        check("TC-INT-02", "result.json success=false", !result.0, "\(result)")
        check("TC-INT-02", "result.json code=2", result.1 == 2, "\(result)")
    } else {
        check("TC-INT-02", "result.json 可解析且字段齐全", false, "无法读取/解析 result")
    }
    check("TC-INT-02", "拒装后目标未被改动（版本仍 \(dst2Original)）",
          appVersion(dst2App) == dst2Original,
          "actual=\(appVersion(dst2App) ?? "nil")")
    check("TC-INT-02", "拒装后无备份产生（载荷门在任何修改前）",
          !fm.fileExists(atPath: backup2))
}

// MARK: - TC-INT-03 BUG-30 固定路径取参兜底（写固定名 config → exec helper 不带 argv）

// BUG-30 定谳（真机现场）：沙盒 App 经 open(1) 发起 helper 时 --args 被 LaunchServices
// 剥掉（argv 空 + exit 4）。修复 = 三层冗余取参：env → 固定路径 → argv。本用例验证
// 中间层（零传播假设的兜底核心）：把 config 写固定名
// coffer-ota-pending-config.json 到容器 tmp（helper 经 getpwuid 推导同一路径），
// **不带 argv**（模拟 --args 被剥掉的最坏场景）exec helper → 必须成功消费完整替换
// 流程。同时断言：log 记录「取参来源：固定路径」+ helper 消费后删除固定 config
// （顺手修：一次性临时产物不留陈）。
do {
    let fm = FileManager.default
    guard FileManager.default.fileExists(atPath: artifactPath),
          FileManager.default.fileExists(atPath: helperBin) else {
        skip("TC-INT-03", "（前置缺失）", "签名产物或 helper 缺失（同 TC-INT-01 前置）")
        failures.removeAll()
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }
    guard let identity = signingIdentity() else {
        skip("TC-INT-03", "（前置缺失）", "缺 Apple Development 签名身份（载荷重签保 DR 依赖）")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    let tmpRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-int-fixed-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tmpRoot) }

    // ---- dstApp（当前 App：真实产物副本）----
    let dstApp = tmpRoot.appendingPathComponent("dst/Coffer.app")
    try fm.createDirectory(at: dstApp.deletingLastPathComponent(), withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: [artifactPath, dstApp.path])
    guard let originalVersion = appVersion(dstApp), !originalVersion.isEmpty else {
        check("TC-INT-03", "dstApp 版本可读（前置 sanity）", false, "无法读取副本版本")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / \(failures.count) failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    // ---- newApp：版本改写 99.99.99 + 重签保 DR（同 TC-INT-01）----
    let newBuildApp = tmpRoot.appendingPathComponent("newbuild/Coffer.app")
    try fm.createDirectory(at: newBuildApp.deletingLastPathComponent(), withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: [artifactPath, newBuildApp.path])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleShortVersionString 99.99.99",
                          newBuildApp.appendingPathComponent("Contents/Info.plist").path])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleVersion 999999",
                          newBuildApp.appendingPathComponent("Contents/Info.plist").path])
    let resign = try runProcess("/usr/bin/codesign",
                                args: ["--force", "--sign", identity,
                                       "--preserve-metadata=entitlements,requirements,flags",
                                       newBuildApp.path])
    check("TC-INT-03", "newApp 重签成功（保 DR，载荷合法性前提）",
          resign.status == 0, "exit=\(resign.status) stderr=\(resign.stderr)")
    let zipPath = tmpRoot.appendingPathComponent("new.zip")
    try runProcess("/usr/bin/ditto", args: ["-c", "-k", "--keepParent", newBuildApp.path, zipPath.path])
    let stageDir = tmpRoot.appendingPathComponent("stage")
    try fm.createDirectory(at: stageDir, withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: ["-x", "-k", zipPath.path, stageDir.path])
    let newApp = stageDir.appendingPathComponent("Coffer.app")
    check("TC-INT-03", "解压产物版本 99.99.99",
          fm.fileExists(atPath: newApp.path) && appVersion(newApp) == "99.99.99",
          "version=\(appVersion(newApp) ?? "nil")")

    // ---- 写固定路径 config（容器 tmp，helper 无沙盒可读）+ exec helper 不带 argv ----
    let fixedPath = fixedConfigPath()
    let fixedDir = URL(fileURLWithPath: fixedPath).deletingLastPathComponent()
    try fm.createDirectory(at: fixedDir, withIntermediateDirectories: true)
    defer {
        // 只清本场固定 config 文件；tmp 目录若因我们创建而空，一并 best-effort 移除。
        try? fm.removeItem(atPath: fixedPath)
        if (try? fm.contentsOfDirectory(atPath: fixedDir.path))?.isEmpty == true {
            try? fm.removeItem(at: fixedDir)
        }
    }
    let backupPath = tmpRoot.appendingPathComponent("backup/Coffer.app").path
    let resultPath = tmpRoot.appendingPathComponent("result-fixed.json").path
    let relaunchLog = tmpRoot.appendingPathComponent("relaunch-fixed.log").path
    try writeConfig(fixedPath, newApp: newApp.path, currentApp: dstApp.path,
                    backup: backupPath, result: resultPath, pid: deadPID())

    // 不带 argv（模拟沙盒 open 剥 --args 的最坏场景）；env COFFER_UPDATER_CONFIG
    // 置空杀外部残留 → 本场必然走固定路径源。
    let helper3 = try runProcess(helperBin, args: [],
                                 env: ["COFFER_UPDATER_TEST_ANCHOR": dstApp.path,
                                       "COFFER_UPDATER_TEST_FAKE_RELAUNCH": relaunchLog,
                                       "COFFER_UPDATER_CONFIG": ""])

    check("TC-INT-03", "不带 argv exec helper → 固定路径兜底取参，全流程 exit 0",
          helper3.status == 0,
          "exit=\(helper3.status) stderr=\(helper3.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
    if let result = readResult(resultPath) {
        check("TC-INT-03", "result.json success=true（固定路径 config 的 resultFilePath 生效）",
              result.0, "\(result)")
        check("TC-INT-03", "result.json code=0", result.1 == 0, "\(result)")
    } else {
        check("TC-INT-03", "result.json 可解析且字段齐全", false, "无法读取/解析 result")
    }
    check("TC-INT-03", "目标 dstApp 已被替换（版本=99.99.99）",
          appVersion(dstApp) == "99.99.99", "actual=\(appVersion(dstApp) ?? "nil")")
    let backupFixed = URL(fileURLWithPath: backupPath)
    check("TC-INT-03", "备份为旧版本（\(originalVersion)）",
          fm.fileExists(atPath: backupPath) && appVersion(backupFixed) == originalVersion,
          "backup=\(appVersion(backupFixed) ?? "nil")")
    if let logData = try? String(contentsOf: URL(fileURLWithPath: relaunchLog), encoding: .utf8) {
        check("TC-INT-03", "relaunch gate 通过：fake 桩记录目标 dstApp",
              logData.contains(dstApp.path), "log=\(logData.trimmingCharacters(in: .whitespacesAndNewlines))")
    } else {
        check("TC-INT-03", "relaunch gate 通过：fake 桩记录目标 dstApp", false, "relaunch.log 缺失")
    }

    // 取参来源留痕（文件日志首行 argv 语义 + 本场来源行）：含「取参来源：固定路径」
    // 且路径为本场 fixedPath（唯一串，跨场并发 append 仍可定位本场）。
    let fileLogPath = "/tmp/coffer-update.log"
    if let logText = try? String(contentsOfFile: fileLogPath, encoding: .utf8) {
        let sourceLine = logText.split(separator: "\n").first { $0.contains("取参来源：固定路径") && $0.contains(fixedPath) }
        check("TC-INT-03", "文件日志记录取参来源 = 固定路径（三层冗余优先级生效）",
              sourceLine != nil, "log=\(fileLogPath)")
    } else {
        check("TC-INT-03", "文件日志记录取参来源 = 固定路径（三层冗余优先级生效）",
              false, "无法读取 \(fileLogPath)")
    }
    // 顺手修：helper 消费后删除固定 config（一次性临时产物不留陈）。
    check("TC-INT-03", "helper 消费后删除固定 config（顺手修：不留陈）",
          !fm.fileExists(atPath: fixedPath))
}

// MARK: - TC-INT-04 BUG-31 带 quarantine 载荷全流程（Gatekeeper 拒启防线）

// BUG-31 真机定谳（第四次复测）：沙盒 App 自身网络下载的产物带 com.apple.quarantine
// （macOS 26 对沙盒 App 下载打 provenance+quarantine）→ Gatekeeper 对「quarantine +
// 开发证书」新 App 拒启 → helper relaunch open exit 1 → 回滚旧版。修复 = helper 在
// verifyPayload 后、backupAndReplace 前递归剥 quarantine。本用例：newApp 副本打
// quarantine（xattr -w 测试值）→ exec helper → 断言替换成功 + relaunch gate 通过 +
// 替换后目标无 quarantine + 文件日志含「已剥除隔离标记」（证明剥隔离步骤真实执行）。
// 前置：同 TC-INT-01（签名产物 + helper + Apple Development 身份，供重签保 DR）。
do {
    let fm = FileManager.default
    guard FileManager.default.fileExists(atPath: artifactPath),
          FileManager.default.fileExists(atPath: helperBin) else {
        skip("TC-INT-04", "（前置缺失）", "签名产物或 helper 缺失（同 TC-INT-01 前置）")
        failures.removeAll()
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }
    guard let identity = signingIdentity() else {
        skip("TC-INT-04", "（前置缺失）", "缺 Apple Development 签名身份（载荷重签保 DR 依赖）")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / 0 failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    let tmpRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-int-quar-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tmpRoot) }

    // ---- dstApp（当前 App：真实产物副本）----
    let dstApp = tmpRoot.appendingPathComponent("dst/Coffer.app")
    try fm.createDirectory(at: dstApp.deletingLastPathComponent(), withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: [artifactPath, dstApp.path])
    guard let originalVersion = appVersion(dstApp), !originalVersion.isEmpty else {
        check("TC-INT-04", "dstApp 版本可读（前置 sanity）", false, "无法读取副本版本")
        failures = []; skipped = 1
        print("--------------------------------------------------")
        print("结果：\(passCount) passed / \(failures.count) failed / \(skipped) skipped")
        print("ALL GREEN")
        exit(0)
    }

    // ---- newApp：版本改写 99.99.99 + 重签保 DR（同 TC-INT-01）----
    let newBuildApp = tmpRoot.appendingPathComponent("newbuild/Coffer.app")
    try fm.createDirectory(at: newBuildApp.deletingLastPathComponent(), withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: [artifactPath, newBuildApp.path])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleShortVersionString 99.99.99",
                          newBuildApp.appendingPathComponent("Contents/Info.plist").path])
    try runProcess("/usr/libexec/PlistBuddy",
                   args: ["-c", "Set :CFBundleVersion 999999",
                          newBuildApp.appendingPathComponent("Contents/Info.plist").path])
    let resign = try runProcess("/usr/bin/codesign",
                                args: ["--force", "--sign", identity,
                                       "--preserve-metadata=entitlements,requirements,flags",
                                       newBuildApp.path])
    check("TC-INT-04", "newApp 重签成功（保 DR，载荷合法性前提）",
          resign.status == 0, "exit=\(resign.status) stderr=\(resign.stderr)")
    let zipPath = tmpRoot.appendingPathComponent("new.zip")
    try runProcess("/usr/bin/ditto", args: ["-c", "-k", "--keepParent", newBuildApp.path, zipPath.path])
    let stageDir = tmpRoot.appendingPathComponent("stage")
    try fm.createDirectory(at: stageDir, withIntermediateDirectories: true)
    try runProcess("/usr/bin/ditto", args: ["-x", "-k", zipPath.path, stageDir.path])
    let newApp = stageDir.appendingPathComponent("Coffer.app")
    check("TC-INT-04", "解压产物版本 99.99.99",
          fm.fileExists(atPath: newApp.path) && appVersion(newApp) == "99.99.99",
          "version=\(appVersion(newApp) ?? "nil")")

    // ---- BUG-31：给 newApp 打 quarantine（模拟沙盒 App 网络下载残留；普通用户可写，
    //      spike 实证）+ 确认真实存在（sanity：让「已剥除」断言有可剥对象）----
    let quarantineValue = "0286;00000000;Coffer;"
    let setQuar = try runProcess("/usr/bin/xattr",
                                 args: ["-w", "com.apple.quarantine", quarantineValue, newApp.path])
    check("TC-INT-04", "newApp 打 quarantine 成功（BUG-31 场景构造前提）",
          setQuar.status == 0, "exit=\(setQuar.status) stderr=\(setQuar.stderr)")
    let readQuar = try runProcess("/usr/bin/xattr",
                                  args: ["-p", "com.apple.quarantine", newApp.path])
    check("TC-INT-04", "quarantine 属性真实存在（sanity，strip 有可剥对象）",
          readQuar.status == 0 && readQuar.stdout.contains(quarantineValue),
          "exit=\(readQuar.status) out=\(readQuar.stdout)")

    // ---- 配置 + 跑 helper（argv 取参源，env 隔离同 TC-INT-01）----
    let backupPath = tmpRoot.appendingPathComponent("backup/Coffer.app").path
    let resultPath = tmpRoot.appendingPathComponent("result-quar.json").path
    let relaunchLog = tmpRoot.appendingPathComponent("relaunch-quar.log").path
    let configPath = tmpRoot.appendingPathComponent("config-quar.json").path
    try writeConfig(configPath, newApp: newApp.path, currentApp: dstApp.path,
                    backup: backupPath, result: resultPath, pid: deadPID())
    removeFixedConfigIfPresent()
    let helper4 = try runProcess(helperBin, args: ["--config", configPath],
                                 env: ["COFFER_UPDATER_TEST_ANCHOR": dstApp.path,
                                       "COFFER_UPDATER_TEST_FAKE_RELAUNCH": relaunchLog,
                                       "COFFER_UPDATER_CONFIG": ""])

    // ---- 断言：替换 → relaunch gate → result 全流程 + quarantine 已剥 ----
    check("TC-INT-04", "带 quarantine 载荷 → helper exit 0（剥隔离→备份→替换→relaunch→result）",
          helper4.status == 0,
          "exit=\(helper4.status) stderr=\(helper4.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
    if let result = readResult(resultPath) {
        check("TC-INT-04", "result.json success=true", result.0, "\(result)")
        check("TC-INT-04", "result.json code=0", result.1 == 0, "\(result)")
    } else {
        check("TC-INT-04", "result.json 可解析且字段齐全", false, "无法读取/解析 result")
    }
    check("TC-INT-04", "目标 dstApp 已被替换（版本=99.99.99）",
          appVersion(dstApp) == "99.99.99", "actual=\(appVersion(dstApp) ?? "nil")")
    let backupQuar = URL(fileURLWithPath: backupPath)
    check("TC-INT-04", "备份为旧版本（\(originalVersion)）",
          fm.fileExists(atPath: backupPath) && appVersion(backupQuar) == originalVersion,
          "backup=\(appVersion(backupQuar) ?? "nil")")
    if let logData = try? String(contentsOf: URL(fileURLWithPath: relaunchLog), encoding: .utf8) {
        check("TC-INT-04", "relaunch gate 通过：fake 桩记录目标 dstApp（open 被隔离）",
              logData.contains(dstApp.path), "log=\(logData.trimmingCharacters(in: .whitespacesAndNewlines))")
    } else {
        check("TC-INT-04", "relaunch gate 通过：fake 桩记录目标 dstApp（open 被隔离）",
              false, "relaunch.log 缺失")
    }
    // 替换后目标（即被剥隔离的新包 move 到位）无 quarantine——strip 随 move 生效。
    let targetQuar = try runProcess("/usr/bin/xattr",
                                    args: ["-p", "com.apple.quarantine", dstApp.path])
    check("TC-INT-04", "替换后目标无 quarantine（剥隔离随 move 生效）",
          targetQuar.status != 0, "exit=\(targetQuar.status) out=\(targetQuar.stdout)")

    // 文件日志留痕：剥隔离步骤真实执行（含本场 newApp 唯一路径，跨场并发可定位）。
    let fileLogPath = "/tmp/coffer-update.log"
    if let logText = try? String(contentsOfFile: fileLogPath, encoding: .utf8) {
        let stripLine = logText.split(separator: "\n").first {
            $0.contains("已剥除隔离标记") && $0.contains(newApp.path)
        }
        check("TC-INT-04", "文件日志记录「已剥除隔离标记」+ 本场 newApp 路径",
              stripLine != nil, "log=\(fileLogPath)")
    } else {
        check("TC-INT-04", "文件日志记录「已剥除隔离标记」+ 本场 newApp 路径",
              false, "无法读取 \(fileLogPath)")
    }
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed / \(skipped) skipped")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
