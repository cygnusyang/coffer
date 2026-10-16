// main.swift —— MCP 一键注册 helper（CofferMcpHelper.app，v2.11.0，lead 裁定）。
//
// 形态：嵌入式**非沙盒** helper，装配为嵌套 .app bundle
// Contents/Helpers/CofferMcpHelper.app（open/LaunchServices 只认 bundle——D-6
// 先例）。沙盒 App 无法直接 exec `~/.local/bin/claude`（process-exec 拒绝）也无法
// 读写真实 ~/.claude.json（HOME 重映射容器）——经 open 拉起本 helper 代劳（BUG-30 /
// OTA CofferUpdater 生产实证的逃生通道）。
//
// 职责（单一直线，非通用执行器）：把 App 设置页开关的注册/检测委托执行——
//   register 模式：resolve claude CLI → spawn `claude mcp add coffer --scope user
//     -e COFFER_VAULT_DIR=<dir> -- <coffer二进制> mcp --provider coffer`
//     （argv 数组直传，**无 shell 拼接**）→ 读回 ~/.claude.json 顶层 mcpServers
//     confirm coffer 键 → 写 result JSON。
//   check 模式：只读 ~/.claude.json 顶层 mcpServers 的 coffer 键 → 写 result JSON。
// 不做网络、不碰 Keychain、不读秘密材料；config 全程无密码字段（R2）。
//
// 安全（lead 裁定硬约束）：
//   - 命令结构单源（McpRegisterSpec，App/helper 共享编译），config 只传**值**
//     （mode/vaultDir/cofferBinaryPath/resultPath）；**禁止 shell 字符串拼接**，
//     Process spawn 用 argv 数组；
//   - coffer 二进制路径双重校验：路径须含 `.app/Contents/Helpers/` 段（纯校验，
//     RegisterRequest.isExpectedHelperPath）+ spawn 前 isExecutableFile 存在性
//     （IO 第二道）——防其他进程投喂恶意 config 注册任意命令；
//   - config/result 落容器 tmp 固定名（BUG-30 同款），config 消费后删除。
//
// 调用协议（App 侧 McpRegistrar 组 A 写）：
//   CofferMcpHelper.app 经 `/usr/bin/open -n <helper> --args <args>` 拉起（open
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

/// claude mcp add 超时（秒）——claude CLI 首次启动/网络异常时避免挂死。
private let spawnTimeout: TimeInterval = 20

/// login shell `command -v claude` 兜底解析超时（秒）。
private let resolveClaudeTimeout: TimeInterval = 10

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

/// 登录 shell 绝对路径（getpwuid pw_shell，claude 兜底解析用）。
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
func writeResultFile(at path: String, success: Bool, code: ResultCode, message: String, registered: Bool, vaultDir: String?) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard let data = try? encoder.encode(McpRegisterResult(success: success, code: code, message: message,
                                                           registered: registered, vaultDir: vaultDir)) else {
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

// MARK: - 参数解析（仅 `--config <路径>`；缺参/未知参 → nil）

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

// MARK: - claude CLI resolve

/// 常见安装路径候选（先于 login shell 解析——无 shell 依赖、快、零拼接）。
private let claudeCandidatePaths = [
    "/usr/local/bin/claude",
    "/opt/homebrew/bin/claude",
    "/usr/bin/claude",
]

/// 解析 claude CLI 绝对路径。顺序：家目录固定候选 → 常见系统候选 → login shell
/// `command -v claude`（PATH 兜底）。全部落空 → nil（claudeNotFound）。
func resolveClaudePath() -> String? {
    var candidates = [
        realUserHomeDirectory() + "/.local/bin/claude",
    ]
    candidates.append(contentsOf: claudeCandidatePaths)
    for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
        log("claude 命中固定候选: \(candidate)")
        return candidate
    }
    // 兜底：login shell `command -v claude`（固定字面量命令，非 config 拼接）。
    guard let shell = loginShellPath(), !shell.isEmpty else {
        log("claude 未命中：无登录 shell 可解析 PATH")
        return nil
    }
    let result = runProcess(executablePath: shell, arguments: ["-lc", "command -v claude"], timeout: resolveClaudeTimeout)
    guard !result.timedOut, result.status == 0 else {
        log("claude 未命中：login shell `command -v claude` 失败（status=\(result.status) timedOut=\(result.timedOut)）")
        return nil
    }
    let path = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !path.isEmpty, FileManager.default.isExecutableFile(atPath: path) else {
        log("claude 未命中：command -v 输出不可执行（\(path)）")
        return nil
    }
    log("claude 经 login shell 解析: \(path)")
    return path
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
func runProcess(executablePath: String, arguments: [String], timeout: TimeInterval) -> SpawnResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executablePath)
    process.arguments = arguments
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

// MARK: - ~/.claude.json 读取（顶层 mcpServers 的 coffer 键）

/// 真实家目录下的 ~/.claude.json 路径（helper 非沙盒可读用户文件）。
func claudeConfigPath() -> String {
    realUserHomeDirectory() + "/.claude.json"
}

/// 从顶层 mcpServers 提取 coffer 条目（读回 confirm / check 共用）。
/// 返回 nil = 未注册（键不存在）；found 携带已注册条目的 COFFER_VAULT_DIR（可 nil）。
func readRegisteredCoffer() -> (found: Bool, vaultDir: String?)? {
    let path = claudeConfigPath()
    guard FileManager.default.fileExists(atPath: path) else {
        log("~/.claude.json 不存在（未注册）: \(path)")
        return (false, nil)
    }
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = root["mcpServers"] as? [String: Any] else {
            log("~/.claude.json 无顶层 mcpServers 或根结构异常")
            return nil
        }
        guard let entry = servers["coffer"] as? [String: Any] else {
            log("顶层 mcpServers 无 coffer 键（未注册）")
            return (false, nil)
        }
        let env = entry["env"] as? [String: Any]
        let vaultDir = env?["COFFER_VAULT_DIR"] as? String
        log("顶层 mcpServers 命中 coffer 键（vaultDir=\(vaultDir ?? "<nil>")）")
        return (true, vaultDir)
    } catch {
        log("~/.claude.json 读取/解析失败: \(error)")
        return nil
    }
}

// MARK: - 执行模式

/// register 模式：resolve claude → 校验 coffer 二进制存在 → spawn add（超时）→
/// 读回 confirm → result。
func performRegister(config: McpRegisterRequest) -> McpRegisterResult {
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
    guard let claudePath = resolveClaudePath() else {
        return McpRegisterResult(success: false, code: .claudeNotFound,
                                 message: "注册失败：未找到 Claude Code CLI（claude）。请先安装 Claude Code，或用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    // 命令结构单源（McpRegisterSpec，App/helper 共享编译），argv 数组直传（无 shell
    // 拼接）；config 只传 vaultDir/二进制两个值，argv 不经 config 传递（无注入面）。
    let args = McpRegisterSpec.commandArgs(vaultDir: vaultDir, cofferBinaryPath: cofferBinary)
    log("spawn claude mcp add（argv 直传，vaultDir=\(vaultDir)）")
    let result = runProcess(executablePath: claudePath, arguments: Array(args.dropFirst()), timeout: spawnTimeout)
    if result.timedOut {
        log("claude mcp add 超时（\(Int(spawnTimeout))s）")
        return McpRegisterResult(success: false, code: .claudeTimeout,
                                 message: "注册失败：claude 注册命令超时（超过 \(Int(spawnTimeout)) 秒）。请重试或用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    guard result.status == 0 else {
        let detail = result.output.isEmpty ? "" : "（\(result.output.prefix(300))）"
        log("claude mcp add 失败 status=\(result.status)\(detail)")
        return McpRegisterResult(success: false, code: .claudeAddFailed,
                                 message: "注册失败：claude 返回错误（退出码 \(result.status)）。请用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    // 读回 confirm（lead 裁定：read-back 失败 = 注册失败态，UI 显式）。
    guard let readBack = readRegisteredCoffer(), readBack.found else {
        log("claude 报告成功但读回 ~/.claude.json 无 coffer 键（config 异常）")
        return McpRegisterResult(success: false, code: .notRegistered,
                                 message: "注册失败：claude 报告成功但未在 ~/.claude.json 找到 coffer 条目。请用「复制注册命令」手动注册。",
                                 registered: false, vaultDir: nil)
    }
    log("注册成功（读回 confirm：mcpServers.coffer 存在）")
    return McpRegisterResult(success: true, code: .ok,
                             message: "已注册到 Claude Code（全局，scope user）。",
                             registered: true, vaultDir: readBack.vaultDir)
}

/// check 模式：只读 ~/.claude.json 顶层 mcpServers 的 coffer 键。
func performCheck() -> McpRegisterResult {
    guard let read = readRegisteredCoffer() else {
        return McpRegisterResult(success: false, code: .checkFailed,
                                 message: "检查注册状态失败：无法读取 ~/.claude.json。",
                                 registered: false, vaultDir: nil)
    }
    if read.found {
        return McpRegisterResult(success: true, code: .ok,
                                 message: "已注册到 Claude Code。",
                                 registered: true, vaultDir: read.vaultDir)
    }
    return McpRegisterResult(success: true, code: .ok,
                             message: "未注册到 Claude Code。",
                             registered: false, vaultDir: nil)
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

    // 3. 按模式执行
    let result: McpRegisterResult
    switch request.mode {
    case .register:
        result = performRegister(config: request)
    case .check:
        result = performCheck()
    }

    // 4. 写 result → 按成功/失败退出
    writeResultFile(at: resultPath, success: result.success, code: result.code, message: result.message,
                    registered: result.registered, vaultDir: result.vaultDir)
    return result.success ? ExitCode.success : ExitCode.operationFailed
}

// 入口（main.swift 顶层代码，swiftc 直编，无需 -parse-as-library）
let exitCode = run(arguments: Array(CommandLine.arguments.dropFirst()))
log("coffer-mcp-register 退出 exit=\(exitCode)")
exit(exitCode)
