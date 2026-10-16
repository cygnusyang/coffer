// McpRegistrar.swift —— MCP 一键注册协调器（App 侧，v2.11.0，lead 裁定）。
//
// 职责：设置页「启用 MCP 服务器」开关 ON（provider == .coffer）时代用户执行
// 注册到 Claude Code。沙盒 App 无法直接 exec `~/.local/bin/claude`
// （process-exec 拒绝）也无法读写真实 ~/.claude.json（HOME 重映射容器）——
// 经 /usr/bin/open 拉起嵌入式**非沙盒** helper（Contents/Helpers/
// CofferMcpHelper.app）代劳（BUG-30 逃生通道，OTA CofferUpdater 生产实证）。
//
// 协议（lead 裁定 + BUG-30 三层冗余取参）：
//   - config 写容器 tmp **固定名**（McpRegisterRequest；沙盒 temporaryDirectory
//     = 容器 Data/tmp，与 helper getpwuid 推导同一路径，零传播假设）；
//   - open -n <helper> --args（open 会剥 --args——BUG-30 实证——靠固定路径 +
//     env 注入双兜底）；
//   - 轮询 result 文件（容器 tmp 固定名）≤15s，读后删除；config 同步清（防
//     串场 + 容器 tmp 不积陈）；
//   - 结构化错误码（ResultCode）→ 用户可读文案（errorMessage(for:)）。
// R2：config/result 全程无密码字段（注册链无密码 env，解锁走 MCP 托管）。
//
// 可测边界：纯函数（openLaunchArgs / configEnvironment / encodeRequest /
// decodeResult / errorMessage / request / helperBundleURL）在 standalone 单测
// （tools/run_mcp_registrar_tests.sh）；IO（写 config / open 启动 / 轮询）薄封装
// 归装配产物 + 真机验证，按项目测试纪律不在此测。

import Foundation

/// 注册/检测协调器（单例静态纯函数 + 实例 IO 方法）。
final class McpRegistrar {
    // MARK: - 常量

    /// 固定名 config 文件名（BUG-30：App 写容器 tmp 固定名，helper 推导同一路径）。
    static let configFileName = "coffer-mcp-register-config.json"
    /// 固定名 result 文件名（helper 写、App 轮询同一路径）。
    static let resultFileName = "coffer-mcp-register-result.json"
    /// 轮询 result 的硬超时（秒）——helper 无响应即按失败兜底（resultWriteFailed）。
    static let resultPollTimeout: TimeInterval = 15
    /// 轮询间隔（秒）。
    static let resultPollInterval: TimeInterval = 0.25
    /// 三层取参 env 键（与 helper resolveConfigPath 一致，单源）。
    static let configEnvironmentKey = "COFFER_MCP_REGISTER_CONFIG"

    // MARK: - 路径（纯函数 / 常量）

    /// 嵌入式 helper bundle 路径（build 脚本 3.7 装配到 Contents/Helpers/）。
    static func helperBundleURL(appBundle: URL = Bundle.main.bundleURL) -> URL {
        appBundle.appendingPathComponent("Contents/Helpers/CofferMcpHelper.app")
    }

    /// 固定名 config URL（容器 tmp；与 helper fixedConfigPath 同一目录）。
    static var fixedConfigURL: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(configFileName)
    }

    /// 固定名 result URL（容器 tmp；helper defaultResultPath 兜底同一路径）。
    static var fixedResultURL: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(resultFileName)
    }

    // MARK: - 纯函数（standalone 单测覆盖）

    /// open(1) 启动参数构造（BUG-29/30 同款）：`-n <helper> --args <args>`。
    /// `-n` 开新实例（防复用旧命令行）；`--args` 之后透传给 helper argv。
    static func openLaunchArgs(helper: URL, args: [String]) -> [String] {
        ["-n", helper.path, "--args"] + args
    }

    /// 从 launcher args 提取 config 路径注入环境（三层取参第一源；open(1) 传播自身
    /// env 给被拉起的 helper）。args 无 `--config` → nil。纯函数供测试断言。
    static func configEnvironment(from args: [String]) -> [String: String]? {
        guard let index = args.firstIndex(of: "--config"),
              args.indices.contains(index + 1) else { return nil }
        return [configEnvironmentKey: args[index + 1]]
    }

    /// 构造 register 配置请求（固定名 result 落点）。纯函数供测试断言 schema。
    static func request(mode: McpRegisterRequest.Mode, vaultDir: String?, cofferBinaryPath: String?) -> McpRegisterRequest {
        McpRegisterRequest(mode: mode, vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath,
                           resultPath: fixedResultURL.path)
    }

    /// 配置 JSON（sortedKeys 确定性序列化，与 helper 解码 schema 同构）。
    static func encodeRequest(_ request: McpRegisterRequest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(request)
    }

    /// 解析 helper 写回的 result JSON（契约类型 RegisterRequest.swift）。
    static func decodeResult(_ data: Data) throws -> McpRegisterResult {
        try JSONDecoder().decode(McpRegisterResult.self, from: data)
    }

    /// 结构化错误码 → 用户可读文案（设置页展示；fail-closed 缺省兜底）。
    static func errorMessage(for code: ResultCode) -> String {
        switch code {
        case .ok:
            return "已注册到 Claude Code（全局）。"
        case .configInvalid:
            return "注册失败：配置不完整，请重新打开设置页重试。"
        case .cofferBinaryInvalid:
            return "注册失败：未找到 coffer 可执行文件，请重新安装后重试。"
        case .claudeNotFound:
            return "注册失败：未找到 Claude Code（claude）。请先安装 Claude Code，或用「复制注册命令」手动注册。"
        case .claudeTimeout:
            return "注册失败：claude 注册命令超时。请重试，或用「复制注册命令」手动注册。"
        case .claudeAddFailed:
            return "注册失败：claude 返回错误。请用「复制注册命令」手动注册。"
        case .claudeRemoveFailed:
            return "注册失败：无法清理旧的 coffer 注册项。请用「复制注册命令」手动注册。"
        case .notRegistered:
            return "注册失败：claude 报告成功但未确认到已注册条目。请用「复制注册命令」手动注册。"
        case .checkFailed:
            return "检查注册状态失败：无法读取 Claude Code 配置。"
        case .resultWriteFailed:
            return "注册未完成：辅助进程未在限定时间内返回结果，请重试。"
        }
    }

    /// 移除语境错误码 → 用户可读文案（开关 OFF 自动移除失败时展示，lead 裁定
    /// 「已停用，但需手动清理注册项」引导）。与 errorMessage(for:)（注册语境）
    /// 分离：同一 code 在两套语义下文案不同（如 claudeNotFound 在注册=可重试，
    /// 在移除=只能手动清理）。
    static func removeErrorMessage(for code: ResultCode) -> String {
        switch code {
        case .ok:
            return "已停用（已从 Claude Code 移除 coffer 注册项）。"
        case .claudeNotFound:
            return "未找到 Claude Code（claude），无法自动移除。可在终端运行 claude mcp remove coffer 手动清理。"
        case .claudeTimeout:
            return "自动移除超时。可在终端运行 claude mcp remove coffer 手动清理。"
        case .claudeRemoveFailed:
            return "未能从 Claude Code 移除 coffer 注册项。可在终端运行 claude mcp remove coffer 手动清理。"
        case .checkFailed:
            return "无法读取 Claude Code 配置确认移除结果。可在终端运行 claude mcp remove coffer 手动清理。"
        case .resultWriteFailed:
            return "移除未完成（辅助进程未在限定时间内返回结果）。可在终端运行 claude mcp remove coffer 手动清理。"
        default:
            return "已停用，但需手动清理注册项：在终端运行 claude mcp remove coffer。"
        }
    }

    /// 轮询截止时间（纯函数，供测试断言超时预算）。
    static func resultPollDeadline(from now: Date = Date()) -> Date {
        now.addingTimeInterval(resultPollTimeout)
    }

    // MARK: - 显式错误（App 侧基础设施失败；helper 已处理失败走 result.success=false）

    enum RegistrarError: Error, LocalizedError {
        case helperMissing
        case configWriteFailed(String)
        case helperLaunchFailed(String)
        case resultTimeout

        var errorDescription: String? {
            switch self {
            case .helperMissing:
                return "注册失败：未找到注册辅助程序，请重新安装 Coffer 后重试。"
            case .configWriteFailed(let detail):
                return "注册失败：无法写入注册配置（\(detail)）。"
            case .helperLaunchFailed(let detail):
                return "注册失败：无法启动注册辅助进程（\(detail)）。"
            case .resultTimeout:
                return "注册未完成：辅助进程未在限定时间内返回结果，请重试。"
            }
        }
    }

    // MARK: - IO 薄封装（App 调用面）

    /// 执行注册：写 config → open 启动 helper → 轮询 result（≤15s）→ 清理 →
    /// 返回结果（success=false = helper 已处理的失败，视图按 code 映射文案）。
    func register(vaultDir: String, cofferBinaryPath: String,
                  helperURL: URL = McpRegistrar.helperBundleURL()) async throws -> McpRegisterResult {
        try await run(mode: .register, vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath, helperURL: helperURL)
    }

    /// 检测注册状态（check 模式）：只读真实 ~/.claude.json 顶层 mcpServers。
    /// 设置页 onAppear / 冷启动异步调用；缓存态由视图持有。
    func checkRegistered(helperURL: URL = McpRegistrar.helperBundleURL()) async throws -> McpRegisterResult {
        try await run(mode: .check, vaultDir: nil, cofferBinaryPath: nil, helperURL: helperURL)
    }

    /// 执行移除（remove 模式）：开关 OFF 自动移除 coffer 注册项（lead 裁定，
    /// best-effort——失败不阻塞 OFF 本身，经 result.code 回写，UI 显示
    /// 「已停用，需手动清理」引导）。
    func remove(helperURL: URL = McpRegistrar.helperBundleURL()) async throws -> McpRegisterResult {
        try await run(mode: .remove, vaultDir: nil, cofferBinaryPath: nil, helperURL: helperURL)
    }

    /// 通用执行（register/check 共用管线）。
    private func run(mode: McpRegisterRequest.Mode, vaultDir: String?, cofferBinaryPath: String?,
                     helperURL: URL) async throws -> McpRegisterResult {
        let fm = FileManager.default
        guard fm.fileExists(atPath: helperURL.path) else {
            throw RegistrarError.helperMissing
        }
        let request = Self.request(mode: mode, vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath)
        let configURL = Self.fixedConfigURL
        let resultURL = Self.fixedResultURL

        // 防串场：上一场残留（未消费/未清理）先清，保证 helper 读到本场 config。
        try? fm.removeItem(at: configURL)
        try? fm.removeItem(at: resultURL)

        // 写 config（原子落盘）。
        do {
            try Self.encodeRequest(request).write(to: configURL, options: .atomic)
        } catch {
            throw RegistrarError.configWriteFailed("\(error)")
        }

        // open 启动 helper（同步提交即返回；成败经 result 文件握手——open 无法
        // waitpid，实证）。启动失败 → 清理残留 + 显式抛错。
        let configArgs = ["--config", configURL.path]
        do {
            try Self.launchViaOpen(helper: helperURL, args: configArgs)
        } catch {
            try? fm.removeItem(at: configURL)
            throw error
        }

        // 轮询 result（≤15s）。
        let deadline = Self.resultPollDeadline()
        while Date() < deadline {
            if fm.fileExists(atPath: resultURL.path) {
                do {
                    let data = try Data(contentsOf: resultURL)
                    let result = try Self.decodeResult(data)
                    try? fm.removeItem(at: resultURL)
                    try? fm.removeItem(at: configURL)
                    return result
                } catch {
                    // result 部分写入/损坏：继续轮询到截止（helper 会重写完整文件）。
                    DiagLog.append("McpRegistrar：result 解析失败继续轮询: \(error)")
                }
            }
            try await Task.sleep(nanoseconds: UInt64(Self.resultPollInterval * 1_000_000_000))
        }
        // 超时兜底：清理残留 + 显式失败（App 侧无法知道 helper 是否成功）。
        try? fm.removeItem(at: resultURL)
        try? fm.removeItem(at: configURL)
        throw RegistrarError.resultTimeout
    }

    /// 生产启动器（open(1) 同步跑，模型对齐 OTAInstaller.launchViaOpen）：主路径
    /// `/usr/bin/open -n <helper> --args <args>` + env 注入 config 路径（三层取参
    /// 第一源，open 传播自身 env）。退出码非 0 或 stderr 有内容 → 显式抛错。
    /// open 只承接自身启动错误；helper 运行期诊断靠 result 文件 / log show。
    static func launchViaOpen(helper: URL, args: [String]) throws {
        guard FileManager.default.fileExists(atPath: helper.path) else {
            throw RegistrarError.helperMissing
        }
        let openArgs = openLaunchArgs(helper: helper, args: args)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = openArgs
        if let configEnv = configEnvironment(from: args) {
            var env = ProcessInfo.processInfo.environment
            for (key, value) in configEnv { env[key] = value }
            process.environment = env
        }
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            throw RegistrarError.helperLaunchFailed("\(error)")
        }
        process.waitUntilExit()
        let detail = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let status = process.terminationStatus
        guard status == 0 && detail.isEmpty else {
            let suffix = detail.isEmpty ? "（无 stderr 输出）" : "：\(detail)"
            throw RegistrarError.helperLaunchFailed("open 启动注册辅助进程失败（exit \(status)）\(suffix)")
        }
    }
}
