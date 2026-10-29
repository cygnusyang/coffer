// main.swift —— MCP 注册 helper（CofferMcpHelper.app，v2.11.0 起，v2.12.0 多工具）。
//
// 形态：嵌入式**非沙盒** helper，装配为嵌套 .app bundle
// Contents/Helpers/CofferMcpHelper.app（open/LaunchServices 只认 bundle——D-6
// 先例）。沙盒 App 无法直接 exec 用户 CLI（process-exec 拒绝）也无法读写真实
// 家目录配置（HOME 重映射容器）——经 open 拉起本 helper 代劳（BUG-30 /
// OTA CofferUpdater 生产实证的逃生通道）。
//
// 职责（单一直线，非通用执行器）：把 App 设置页的注册/检测/移除/探测委托执行——
//   register 模式（upsert）：按 target 定义（McpAgentTarget）resolve 目标 CLI →
//     若既有同名条目则先 spawn 移除命令 → spawn 注册命令（argv 数组直传，**无
//     shell 拼接**）→ 读回目标配置文件 confirm 条目存在且 vaultDir 为目标值 → 写 result。
//   check 模式：只读目标配置文件 → 写 result（不改任何文件）。
//   remove 模式：resolve 目标 CLI → spawn 移除命令 → 读回 confirm 条目已消失 →
//     写 result（开关 OFF 自动移除，best-effort）。
//   probe 模式：遍历 autoRegisterTargets 探测 CLI 是否可执行 → 写 result
//     （installedTargets；不写任何配置）。
// 不做网络、不碰 Keychain、不读秘密材料；config 全程无密码字段（R2）。
//
// 安全（lead 裁定硬约束，v2.12.0 沿用并扩展到多 target）：
//   - 命令结构单源（McpAgentTarget / McpRegisterSpec，App/helper 共享编译），
//     config 只传**值**（mode/target/vaultDir/cofferBinaryPath/resultPath）；
//     **禁止 shell 字符串拼接**，Process spawn 用 argv 数组；
//   - CLI 名只来自 McpAgentTarget.cliName（枚举固定值），且 resolve 前过
//     isSafeCLIName 白名单（兜底 login shell 命令为固定字面量，不接受外部拼接）；
//   - coffer 二进制路径双重校验：路径须含 .app/Contents/Helpers/ 段（纯校验，
//     RegisterRequest.isExpectedHelperPath）+ spawn 前 isExecutableFile 存在性
//     （IO 第二道）——防其他进程投喂恶意 config 注册任意命令；
//   - config/result 落容器 tmp 固定名（BUG-30 同款），config 消费后删除。
//
// 调用协议（App 侧 McpRegistrar 组 A 写）：
//   CofferMcpHelper.app 经 /usr/bin/open -n <helper> --args <args> 拉起（open
//   会剥 --args，故用 BUG-30 三层取参兜底）：
//     env COFFER_MCP_REGISTER_CONFIG=<路径> → 固定路径（容器 tmp 固定名）→ argv --config
//   成败经 result 文件握手（open 无法 waitpid，实证；App 侧轮询 ≤15s）。
//
// 退出码：
//   0 成功（含 check 未注册——registered=false 是有效结论）
//   1 操作失败（result 已写，App 按 code 映射文案）
//   4 用法/配置错误（config 不可解析且 resultPath 未知，无法写 result）

import Darwin
import Foundation

// MARK: - 常量

/// 沙盒 App 容器 bundle id（固定路径推导用；与 App 侧容器 tmp 同一目录，BUG-30）。
private let containerBundleID = "top.cygnusyang.coffer"

/// 固定名 config 文件名（App 写容器 tmp 固定名；helper 推导同一路径读取）。
private let fixedConfigFileName = "coffer-mcp-register-config.json"

/// 固定名 result 文件名（check 模式未指定 resultPath 时的默认落点）。
private let fixedResultFileName = "coffer-mcp-register-result.json"

/// 目标 CLI 注册/移除命令超时（秒）——CLI 首次启动/网络异常时避免挂死。
private let spawnTimeout: TimeInterval = 20

/// login shell command -v 兜底解析超时（秒）。
private let resolveCLITimeout: TimeInterval = 10

/// probe 模式下单个目标的 CLI 解析超时（秒）：3 家最坏 6s，远小于 App 侧 15s
/// 轮询总预算（dev-review M3）。
private let probeResolveTimeout: TimeInterval = 2

/// 轮询间隔（秒）。
private let pollInterval: TimeInterval = 0.2

// MARK: - 真实主目录（BUG-30：getpwuid，**不**读 HOME env——open 传播沙盒 App 的
// HOME=容器 Data，读它会算到错误的双层容器目录）

func realUserHomeDirectory() -> String {
    if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
        return String(cString: dir)
    }
    return NSHomeDirectory()
}

/// 登录 shell 绝对路径（getpwuid pw_shell，CLI 兜底解析用）。
func loginShellPath() -> String? {
    guard let pw = getpwuid(getuid()), let shell = pw.pointee.pw_shell else { return nil }
    let path = String(cString: shell)
    return path.isEmpty ? nil : path
}

/// 容器 tmp 目录：$HOME/Library/Containers/<bundle>/Data/tmp（App 沙盒
/// FileManager.default.temporaryDirectory 解析到的同一目录——零传播假设）。
func containerTmpDirectory() -> String {
    realUserHomeDirectory() + "/Library/Containers/\(containerBundleID)/Data/tmp"
}

/// 固定路径 config：容器 tmp 固定名（BUG-30 三层取参第二源，兜底核心）。
func fixedConfigPath() -> String {
    containerTmpDirectory() + "/" + fixedConfigFileName
}

/// 默认 result 路径：容器 tmp 固定名（App 侧 McpRegistrar 与 helper 双侧硬编码同一路径；
/// config 未显式给 resultPath 时的兜底落点）。
func defaultResultPath() -> String {
    containerTmpDirectory() + "/" + fixedResultFileName
}

// MARK: - 日志（BUG-29 后续纪律：open 拉起进程 stderr 无人接，文件落盘为现场第一诊断入口）

private let fileLogPath = "/tmp/coffer-mcp-register.log"
private let fileLogMaxBytes: off_t = 1_000_000

func log(_ message: String) {
    let line = message + "\n"
    if let data = line.data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
    appendToFileLog(line)
}

private func appendToFileLog(_ line: String) {
    guard let data = line.data(using: .utf8) else { return }
    let fd = open(fileLogPath, O_WRONLY | O_APPEND | O_CREAT, 0o644)
    guard fd >= 0 else { return }
    defer { close(fd) }
    var st = stat()
    if fstat(fd, &st) == 0, st.st_size > fileLogMaxBytes {
        ftruncate(fd, 0)
    }
    data.withUnsafeBytes { buf in
        guard let base = buf.baseAddress else { return }
        _ = write(fd, base, buf.count)
    }
}

// MARK: - result 文件（契约类型 McpRegisterResult / ResultCode 在共享文件
// RegisterRequest.swift，App 与 helper 两侧同构；这里只写不定义）

/// 写 result 文件（best-effort：失败只记 stderr，不改变退出码；App 侧轮询超时兜底）。
func writeResultFile(at path: String, success: Bool, code: ResultCode, message: String, registered: Bool,
                     vaultDir: String?, installedTargets: [String]? = nil, target: String? = nil) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let payload = McpRegisterResult(success: success, code: code, message: message, registered: registered,
                                    vaultDir: vaultDir, installedTargets: installedTargets, target: target)
    guard let data = try? encoder.encode(payload) else {
        log("result 文件编码失败: \(path)")
        return
    }
    let url = URL(fileURLWithPath: path)
    do {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
        log("result 已写: \(path)")
    } catch {
        log("result 文件写入失败（\(path)）: \(error)")
    }
}

// MARK: - 参数解析（仅 --config <路径>；缺参/未知参 → nil）

func parseArguments(_ arguments: [String]) -> String? {
    var configPath: String?
    var iterator = arguments.makeIterator()
    while let flag = iterator.next() {
        switch flag {
        case "--config":
            guard let value = iterator.next(), !value.isEmpty else { return nil }
            configPath = value
        default:
            return nil
        }
    }
    return configPath
}

// MARK: - 三层冗余取参（BUG-30：env → 固定路径 → argv）

func resolveConfigPath(arguments: [String]) -> String? {
    // 1. env
    let fromEnv = ProcessInfo.processInfo.environment["COFFER_MCP_REGISTER_CONFIG"] ?? ""
    if !fromEnv.isEmpty {
        log("取参来源：env COFFER_MCP_REGISTER_CONFIG=\(fromEnv)")
        return fromEnv
    }
    // 2. 固定路径（容器 tmp）
    let fixed = fixedConfigPath()
    if FileManager.default.fileExists(atPath: fixed) {
        log("取参来源：固定路径 \(fixed)")
        return fixed
    }
    // 3. argv --config
    if let fromArgs = parseArguments(arguments) {
        log("取参来源：argv --config \(fromArgs)")
        return fromArgs
    }
    log("取参失败：env / 固定路径 / argv 三源皆无（BUG-30 场景）")
    return nil
}

// MARK: - 配置读取与校验

enum LoadError: Error {
    case message(String)
}

/// 读取并校验 config；成功返回请求，失败返回 LoadError。校验走
/// McpRegisterRequest.validate()（纯函数，RegisterRequest.swift）。
func loadConfig(from path: String) -> Result<McpRegisterRequest, LoadError> {
    let fm = FileManager.default
    guard fm.fileExists(atPath: path) else {
        return .failure(.message("配置文件不存在: \(path)"))
    }
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let request = try JSONDecoder().decode(McpRegisterRequest.self, from: data)
        if let error = request.validate() {
            return .failure(.message("config 校验失败: \(error.rawValue)"))
        }
        return .success(request)
    } catch {
        return .failure(.message("配置解析失败: \(error)"))
    }
}

// MARK: - 目标 CLI resolve

/// CLI 名白名单（来自 McpAgentTarget.cliName 的固定值；兜底 login shell 命令
/// 由它拼装，因此必须先过白名单——防止任何外部输入进入命令字面量）。
func isSafeCLIName(_ name: String) -> Bool {
    guard !name.isEmpty, name.count <= 32 else { return false }
    return name.allSatisfy { character in
        guard character.isASCII else { return false }
        return character.isLetter || character.isNumber || character == "-" || character == "_"
    }
}

/// 解析目标 CLI 绝对路径。顺序：家目录固定候选 → 常见系统候选 → ChatGPT App 候选 → login shell
/// command -v <name>（PATH 兜底，命令为固定字面量）。全部落空 → nil。
func resolveCLIPath(named name: String, shellTimeout: TimeInterval = resolveCLITimeout) -> String? {
    guard isSafeCLIName(name) else {
        log("CLI 名不合法（拒绝拼装兜底命令）: \(name)")
        return nil
    }
    let candidates = CLIPathCandidates.paths(named: name, homeDirectory: realUserHomeDirectory())
    if let candidate = CLIPathCandidates.firstExecutable(in: candidates, isExecutable: {
        FileManager.default.isExecutableFile(atPath: $0)
    }) {
        log("\(name) 命中固定候选: \(candidate)")
        return candidate
    }
    // 兜底：login shell command -v <name>（固定字面量，name 已过白名单）。
    guard let shell = loginShellPath(), !shell.isEmpty else {
        log("\(name) 未命中：无登录 shell 可解析 PATH")
        return nil
    }
    let result = runProcess(executablePath: shell, arguments: ["-lc", "command -v " + name], timeout: shellTimeout)
    guard !result.timedOut, result.status == 0 else {
        log("\(name) 未命中：login shell command -v 失败（status=\(result.status) timedOut=\(result.timedOut)）")
        return nil
    }
    let path = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard path.hasPrefix("/"), !path.contains("\n"),
          FileManager.default.isExecutableFile(atPath: path) else {
        log("\(name) 未命中：command -v 输出不可执行（\(path)）")
        return nil
    }
    log("\(name) 经 login shell 解析: \(path)")
    return path
}

// MARK: - 子进程 PATH（#1：脚本型 CLI 的解释器不在 helper 的 PATH 里）

/// 读 CLI 首行 shebang（IO：前 512 字节足够覆盖 shebang 行）；不可读 / 非文本 → nil。
func shebangLine(atPath path: String) -> String? {
    guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
    defer { try? handle.close() }
    guard let data = try? handle.read(upToCount: 512),
          let text = String(data: data, encoding: .utf8) else { return nil }
    return text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        .first.map(String.init)
}

/// 目标 CLI spawn 环境：继承当前 env，PATH 前置其 shebang 解释器目录。
///
/// #1 修复点：helper 继承的是 App 经过 open 传下来的**精简 PATH**，脚本型 CLI
/// （`#!/usr/bin/env node`）会因找不到解释器 127；这里按 CLI 首行解析出解释器
/// 名称，复用 resolveCLIPath 拿绝对路径，把其所在目录前置进子进程 PATH。原生
/// 二进制（无 shebang / 绝对路径解释器）不受影响，PATH 仅补系统默认兜底。
func cliSpawnEnvironment(executablePath: String) -> [String: String] {
    var environment = ProcessInfo.processInfo.environment
    var prepend: [String] = []
    if let line = shebangLine(atPath: executablePath),
       let interpreter = SpawnEnvironment.envInterpreterName(fromShebangLine: line) {
        if let interpreterPath = resolveCLIPath(named: interpreter) {
            prepend.append((interpreterPath as NSString).deletingLastPathComponent)
            log("解释器 \(interpreter) 命中: \(interpreterPath)（PATH 前置其目录）")
        } else {
            log("解释器 \(interpreter) 未解析到绝对路径（PATH 走系统默认兜底）")
        }
    }
    environment["PATH"] = SpawnEnvironment.commandPATH(current: environment["PATH"],
                                                       prepending: prepend)
    return environment
}

// MARK: - 进程 spawn（argv 数组直传，超时 terminate）

/// spawn 结果（status<0 表示 spawn 本身失败；output 合并 stdout/stderr）。
struct SpawnResult {
    let status: Int32
    let timedOut: Bool
    let output: String
}

/// 以 argv 数组直传 spawn（**无 shell 拼接**——config 里的 vaultDir / 二进制路径
/// 永远只是 argv 元素，路径含空格/引号安全）。超时 → terminate 后返回 timedOut=true。
func runProcess(executablePath: String, arguments: [String], timeout: TimeInterval,
                environment: [String: String]? = nil) -> SpawnResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executablePath)
    process.arguments = arguments
    if let environment { process.environment = environment }
    let outPipe = Pipe()
    let errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return SpawnResult(status: -1, timedOut: false, output: "spawn 失败: \(error)")
    }
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning, Date() < deadline {
        Thread.sleep(forTimeInterval: pollInterval)
    }
    if process.isRunning {
        process.terminate()
        process.waitUntilExit()
        return SpawnResult(status: process.terminationStatus, timedOut: true, output: "")
    }
    process.waitUntilExit()
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    let outText = String(data: outData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let errText = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let output = [outText, errText].filter { !$0.isEmpty }.joined(separator: "\n")
    return SpawnResult(status: process.terminationStatus, timedOut: false, output: output)
}

// MARK: - 目标配置文件读取（遍历 target.configPaths 全部候选）

/// 读目标配置并解析注册态（**遍历全部候选**，dev-review M1）。
///
/// CodeBuddy 有 3 条候选路径（工具自身演进期可能并存多份），只看第一个存在者会
/// 漏掉真正写了注册项的那份。因此逐个解析：
///   - 任一候选 registered == true → 立即返回该条（含 vaultDir）；
///   - 候选全部解析成功但均未注册 → (registered:false, vaultDir:nil)；
///   - 有候选文件但全部不可解析（读取失败 / 非 UTF-8 / JSON 损坏）→ nil
///     （check 模式落 checkFailed）；
///   - 无任何候选文件 → (false, nil)（干净状态，不是错误）。
func readRegisteredState(target: McpAgentTarget) -> (registered: Bool, vaultDir: String?)? {
    guard target.configFormat != .none else { return (false, nil) }
    let allCandidates = target.configPaths(home: realUserHomeDirectory())
    let candidates = allCandidates.filter { FileManager.default.fileExists(atPath: $0) }
    guard !candidates.isEmpty else {
        log("\(target.displayName) 无配置文件（未注册）：\(allCandidates.joined(separator: ", "))")
        return (false, nil)
    }
    var parsedAny = false
    for path in candidates {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard let text = String(data: data, encoding: .utf8) else {
                log("\(target.displayName) 配置非 UTF-8 文本（跳过）: \(path)")
                continue
            }
            if target.configFormat == .json, (try? JSONSerialization.jsonObject(with: data)) == nil {
                log("\(target.displayName) 配置 JSON 不可解析（跳过）: \(path)")
                continue
            }
            parsedAny = true
            let state = target.parseRegisteredVaultDir(text: text)
            log("\(target.displayName) 候选注册态：registered=\(state.registered) vaultDir=\(state.vaultDir ?? "<nil>") 落点=\(path)")
            if state.registered { return state }
        } catch {
            log("\(target.displayName) 配置读取失败（跳过）（\(path)）: \(error)")
            continue
        }
    }
    // 有候选但一个都解析不了 = 状态未知（不能谎报「未注册」）。
    guard parsedAny else { return nil }
    return (false, nil)
}

/// 手动清理提示串（错误文案用；argv 形状硬编码且无值，可直接展示）。
func manualCleanupHint(target: McpAgentTarget) -> String {
    guard let cliName = target.cliName, let args = target.removeArgs() else {
        return "请手动编辑配置文件移除 coffer 条目。"
    }
    return "可在终端运行 " + ([cliName] + args).joined(separator: " ") + " 手动清理。"
}

// MARK: - 执行模式

/// 移除目标注册项（target.removeArgs() 固定形状，无值注入）。
/// 返回 nil = 移除成功（读回确认 coffer 条目已消失）；非 nil = 失败 result
/// （含超时 / 退出码 / 读回仍在 / 读回不可判定四类）。register upsert 清理旧条目
/// 与 remove 模式共用。
func runRemove(target: McpAgentTarget, cliPath: String) -> McpRegisterResult? {
    guard let args = target.removeArgs() else {
        return McpRegisterResult(success: false, code: .targetUnsupported,
                                 message: "\(target.displayName) 不支持自动移除注册项，请手动编辑配置文件。",
                                 registered: false, vaultDir: nil)
    }
    let hint = manualCleanupHint(target: target)
    log("spawn \(target.displayName) 移除命令（argv 直传，固定形状）")
    let result = runProcess(executablePath: cliPath, arguments: args, timeout: spawnTimeout,
                            environment: cliSpawnEnvironment(executablePath: cliPath))
    if result.timedOut {
        log("\(target.displayName) 移除命令超时（\(Int(spawnTimeout))s）")
        return McpRegisterResult(success: false, code: .claudeTimeout,
                                 message: "移除失败：\(target.displayName) 移除命令超时（超过 \(Int(spawnTimeout)) 秒）。" + hint,
                                 registered: false, vaultDir: nil)
    }
    guard result.status == 0 else {
        let detail = result.output.isEmpty ? "" : "（\(result.output.prefix(300))）"
        log("\(target.displayName) 移除命令失败 status=\(result.status)\(detail)")
        return McpRegisterResult(success: false, code: .claudeRemoveFailed,
                                 message: "移除失败：\(target.displayName) 返回错误（退出码 \(result.status)）。" + hint,
                                 registered: false, vaultDir: nil)
    }
    // 读回确认：coffer 条目应已消失。
    guard let readBack = readRegisteredState(target: target), !readBack.registered else {
        log("\(target.displayName) 报告成功但读回 coffer 条目仍存在")
        return McpRegisterResult(success: false, code: .claudeRemoveFailed,
                                 message: "移除失败：\(target.displayName) 报告成功但 coffer 条目仍存在。" + hint,
                                 registered: false, vaultDir: nil)
    }
    log("移除成功（读回确认：\(target.displayName) 无 coffer 条目）")
    return nil
}

/// register 模式（upsert）：按 target 校验 → resolve CLI → 校验 coffer 二进制存在
/// → 既有同名条目先移除 → spawn add（超时）→ 读回 confirm（条目存在 + vaultDir 为
/// 目标值）→ result。
func performRegister(config: McpRegisterRequest) -> McpRegisterResult {
    let target = config.resolvedTarget
    guard let vaultDir = config.vaultDir, !vaultDir.isEmpty else {
        return McpRegisterResult(success: false, code: .configInvalid,
                                 message: "注册失败：缺少 vault 目录配置。", registered: false, vaultDir: nil)
    }
    guard let cofferBinary = config.cofferBinaryPath else {
        return McpRegisterResult(success: false, code: .configInvalid,
                                 message: "注册失败：缺少 coffer 二进制路径配置。", registered: false, vaultDir: nil)
    }
    // IO 第二道校验：路径形状已过（RegisterRequest.validate），再验可执行存在。
    guard FileManager.default.isExecutableFile(atPath: cofferBinary) else {
        log("coffer 二进制不存在/不可执行: \(cofferBinary)")
        return McpRegisterResult(success: false, code: .cofferBinaryInvalid,
                                 message: "注册失败：未找到 coffer 可执行文件。", registered: false, vaultDir: nil)
    }
    // 目标分派：copy-only 目标没有自动注册面（只能复制配置，docs/23 §4.1）。
    guard target.isAutoRegister, let cliName = target.cliName,
          let addArgs = target.addArgs(vaultDir: vaultDir, cofferBinaryPath: cofferBinary) else {
        log("\(target.displayName) 不支持自动注册（copy-only）")
        return McpRegisterResult(success: false, code: .targetUnsupported,
                                 message: "注册失败：\(target.displayName) 不支持自动注册，请用「复制配置」手动添加。",
                                 registered: false, vaultDir: nil)
    }
    guard let cliPath = resolveCLIPath(named: cliName) else {
        return McpRegisterResult(success: false, code: .claudeNotFound,
                                 message: "注册失败：未找到 \(target.displayName) CLI（\(cliName)）。请先安装 \(target.displayName)，或用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    // upsert：同名 add 跳过不覆盖 = 旧 COFFER_VAULT_DIR 残留陷阱，换库后 vault dir
    // 必须刷新；已存在条目 → 先移除再 add。
    if let existing = readRegisteredState(target: target), existing.registered {
        log("检测到既有 coffer 条目（vaultDir=\(existing.vaultDir ?? "<nil>")），upsert：先移除再注册")
        if let failure = runRemove(target: target, cliPath: cliPath) {
            return failure
        }
    }
    // 命令结构单源（McpAgentTarget，App/helper 共享编译），argv 数组直传（无 shell
    // 拼接）；config 只传 vaultDir/二进制两个值，argv 不经 config 传递（无注入面）。
    log("spawn \(target.displayName) 注册命令（argv 直传，vaultDir=\(vaultDir)）")
    let result = runProcess(executablePath: cliPath, arguments: addArgs, timeout: spawnTimeout,
                            environment: cliSpawnEnvironment(executablePath: cliPath))
    if result.timedOut {
        log("\(target.displayName) 注册命令超时（\(Int(spawnTimeout))s）")
        return McpRegisterResult(success: false, code: .claudeTimeout,
                                 message: "注册失败：\(target.displayName) 注册命令超时（超过 \(Int(spawnTimeout)) 秒）。请重试或用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    guard result.status == 0 else {
        let detail = result.output.isEmpty ? "" : "（\(result.output.prefix(300))）"
        log("\(target.displayName) 注册命令失败 status=\(result.status)\(detail)")
        return McpRegisterResult(success: false, code: .claudeAddFailed,
                                 message: "注册失败：\(target.displayName) 返回错误（退出码 \(result.status)）。请用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    // 读回 confirm（read-back 失败 = 注册失败态，UI 显式）。
    guard let readBack = readRegisteredState(target: target), readBack.registered else {
        log("\(target.displayName) 报告成功但读回配置无 coffer 条目")
        return McpRegisterResult(success: false, code: .notRegistered,
                                 message: "注册失败：\(target.displayName) 报告成功但未在其配置中找到 coffer 条目。请用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    // vaultDir 必须为目标值（upsert 后若读回目录与当前不一致 = 注册未生效，仍残留
    // 旧目录——正是要防的陷阱）。
    guard readBack.vaultDir == vaultDir else {
        log("注册未生效：读回 vaultDir=\(readBack.vaultDir ?? "<nil>") != 目标 \(vaultDir)")
        return McpRegisterResult(success: false, code: .claudeAddFailed,
                                 message: "注册失败：\(target.displayName) 报告成功但密码库目录未刷新（可能为历史残留）。请用「复制注册命令」手动注册。",
                                 registered: true, vaultDir: readBack.vaultDir)
    }
    log("注册成功（读回 confirm：\(target.displayName) 存在 coffer 条目且 vaultDir=\(vaultDir)）")
    return McpRegisterResult(success: true, code: .ok,
                             message: "已注册到 \(target.displayName)。",
                             registered: true, vaultDir: readBack.vaultDir)
}

/// check 模式：只读目标配置文件（按 target.configPaths 首个存在者解析）。
func performCheck(target: McpAgentTarget) -> McpRegisterResult {
    guard target.configFormat != .none else {
        // copy-only 目标无自动注册面：恒「未注册」，UI 只渲染复制入口。
        return McpRegisterResult(success: true, code: .ok,
                                 message: "\(target.displayName) 不支持自动注册（仅提供复制配置）。",
                                 registered: false, vaultDir: nil)
    }
    guard let read = readRegisteredState(target: target) else {
        return McpRegisterResult(success: false, code: .checkFailed,
                                 message: "检查注册状态失败：无法读取 \(target.displayName) 配置文件。",
                                 registered: false, vaultDir: nil)
    }
    if read.registered {
        return McpRegisterResult(success: true, code: .ok,
                                 message: "已注册到 \(target.displayName)。",
                                 registered: true, vaultDir: read.vaultDir)
    }
    return McpRegisterResult(success: true, code: .ok,
                             message: "未注册到 \(target.displayName)。",
                             registered: false, vaultDir: nil)
}

/// remove 模式（开关 OFF 自动移除，best-effort）：resolve 目标 CLI → spawn 移除
/// 命令 → 读回 confirm → result。
func performRemove(target: McpAgentTarget) -> McpRegisterResult {
    guard target.isAutoRegister, let cliName = target.cliName, target.removeArgs() != nil else {
        return McpRegisterResult(success: false, code: .targetUnsupported,
                                 message: "\(target.displayName) 不支持自动移除注册项，请手动编辑配置文件。",
                                 registered: false, vaultDir: nil)
    }
    guard let cliPath = resolveCLIPath(named: cliName) else {
        return McpRegisterResult(success: false, code: .claudeNotFound,
                                 message: "移除失败：未找到 \(target.displayName) CLI（\(cliName)）。" + manualCleanupHint(target: target),
                                 registered: false, vaultDir: nil)
    }
    if let failure = runRemove(target: target, cliPath: cliPath) {
        return failure
    }
    return McpRegisterResult(success: true, code: .ok,
                             message: "已停用（已从 \(target.displayName) 移除 coffer 注册项）。",
                             registered: false, vaultDir: nil)
}

/// probe 模式：「重新检测」——遍历可自动注册目标，CLI 可执行者计入 installedTargets。
/// 只读探测，不改任何配置（docs/23 D-18：检测入口恒可用）。
func performProbe() -> McpRegisterResult {
    var installed: [String] = []
    for target in McpAgentTarget.autoRegisterTargets {
        guard let cliName = target.cliName else { continue }
        if resolveCLIPath(named: cliName, shellTimeout: probeResolveTimeout) != nil {
            installed.append(target.rawValue)
        }
    }
    let total = McpAgentTarget.autoRegisterTargets.count
    log("probe 完成：\(installed.count)/\(total)（\(installed.joined(separator: ","))）")
    return McpRegisterResult(success: true, code: .ok,
                             message: "已检测本机 AI 工具：\(installed.count)/\(total) 个可自动注册。",
                             registered: false, vaultDir: nil, installedTargets: installed)
}

// MARK: - 退出码与主流程

enum ExitCode {
    static let success: Int32 = 0
    static let operationFailed: Int32 = 1
    static let usageError: Int32 = 4
}

func run(arguments: [String]) -> Int32 {
    log("coffer-mcp-register 启动 pid=\(getpid()) argv=\(arguments.map { "\"\($0)\"" }.joined(separator: " "))")

    // 1. 三层冗余取参（BUG-30：env → 固定路径 → argv）
    guard let configPath = resolveConfigPath(arguments: arguments) else {
        log("取参失败：三源皆无，exit 4")
        return ExitCode.usageError
    }

    // 2. 读配置 + 校验（McpRegisterRequest.validate，纯函数）
    let request: McpRegisterRequest
    switch loadConfig(from: configPath) {
    case .success(let loaded):
        request = loaded
        // 固定名 config 是一次性临时产物：消费即删（防下下场误读/容器 tmp 积陈；
        // App 侧下次写前也会先删旧，双保险）。失败静默。
        if configPath == fixedConfigPath() {
            try? FileManager.default.removeItem(atPath: configPath)
            log("已删除固定路径 config: \(configPath)")
        }
    case .failure(let error):
        log("配置加载失败（\(configPath)）: \(error)")
        return ExitCode.usageError
    }

    let resultPath = request.resultPath.isEmpty ? defaultResultPath() : request.resultPath
    let target = request.resolvedTarget
    log("模式=\(request.mode.rawValue) 目标=\(target.rawValue)（\(target.displayName)）")

    // 3. 按模式执行（目标分派）
    let result: McpRegisterResult
    switch request.mode {
    case .register:
        result = performRegister(config: request)
    case .check:
        result = performCheck(target: target)
    case .remove:
        result = performRemove(target: target)
    case .probe:
        result = performProbe()
    }

    // 4. 写 result → 按成功/失败退出。回显本次实际执行的目标（dev-review H1 新鲜度
    // 判据）：probe 写固定 "probe"，其余写 resolvedTarget.rawValue——App 侧据此
    // 丢弃取消后残留的陈旧 result。
    let echoedTarget = request.mode == .probe ? McpRegisterResult.probeEchoTarget : target.rawValue
    writeResultFile(at: resultPath, success: result.success, code: result.code, message: result.message,
                    registered: result.registered, vaultDir: result.vaultDir,
                    installedTargets: result.installedTargets, target: echoedTarget)
    return result.success ? ExitCode.success : ExitCode.operationFailed
}

// 入口（main.swift 顶层代码，swiftc 直编，无需 -parse-as-library）
let exitCode = run(arguments: Array(CommandLine.arguments.dropFirst()))
log("coffer-mcp-register 退出 exit=\(exitCode)")
exit(exitCode)
