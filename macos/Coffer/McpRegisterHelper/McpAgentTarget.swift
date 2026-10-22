// McpRegisterHelper/McpAgentTarget.swift —— AI 工具（target）维度定义**单源**
// （docs/23 v2.12.0 §3.1 / §11.2；纯数据 + 纯函数，无 IO / 无进程）。
//
// 概念纪律（docs/23 §3.1）：target 与 provider 是两个**正交**维度——本类型只回答
// 「谁被登记为 MCP 客户端」，不含任何数据源信息；数据源恒由
// 「coffer mcp --provider coffer」表达。用户可见文案不出现英文 rawValue，只写
// displayName（工具官方名）。
//
// 编译进两个 target（build 脚本：helper 目录 glob 自动包含；App SOURCES 显式追加
// McpAgentTarget.swift）：App 侧 UI / McpRegistrar 用它表达目标，helper 用它分派
// 命令与配置读取——同一份定义，避免 App/helper 两侧漂移。
//
// 安全契约（沿用 McpRegisterSpec 纪律）：
//   - 命令形状**硬编码在本文件**，vaultDir / cofferBinaryPath 永远只作为 argv
//     元素或配置值出现，绝不参与命令拼接；
//   - 只有「复制给用户粘贴」的展示串（copyCommand）才做 shell / JSON 转义，且两种
//     通道分开处理、不混用（docs/23 REV-10）；
//   - 配置读取只取 COFFER_VAULT_DIR 一个值用于比对，不落日志（§11.4 安全面）。

import Foundation

/// AI 工具（MCP 客户端）目标。
///
/// 两个分组（docs/23 §4.1）：
///   - autoRegisterTargets：可由 helper 代执行 CLI 注册（Claude Code / CodeBuddy /
///     Codex），App 侧按 target 持有独立注册态；
///   - copyOnlyTargets：无稳定自动注册面，只提供「复制配置」入口。
enum McpAgentTarget: String, CaseIterable, Codable, Equatable {
    case claudeCode = "claude-code"
    case codeBuddy = "codebuddy"
    case codex = "codex"
    case geminiCLI = "gemini-cli"
    case cursor
    case vscode
    case windsurf
    case zed

    /// 可自动注册的目标（主组行序：Claude Code → CodeBuddy → Codex，固定不重排）。
    static let autoRegisterTargets: [Self] = [.claudeCode, .codeBuddy, .codex]

    /// 仅提供复制入口的目标（折叠组固定 5 家：docs/23 §5.2 计数口径）。
    static let copyOnlyTargets: [Self] = [.geminiCLI, .cursor, .vscode, .windsurf, .zed]

    /// vault 目录 env 键（注册值仅两项之一；R2：不含任何密码 env）。
    static let vaultDirEnvironmentKey = "COFFER_VAULT_DIR"

    /// 配置文件格式（决定读回解析方式；copy-only 无配置面）。
    enum ConfigFormat: String, Codable, Equatable {
        case json
        case toml
        case none
    }

    /// 用户可见工具名（只写官方名，不嵌英文 rawValue）。
    var displayName: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .codeBuddy: return "CodeBuddy"
        case .codex: return "Codex"
        case .geminiCLI: return "Gemini CLI"
        case .cursor: return "Cursor"
        case .vscode: return "VS Code"
        case .windsurf: return "Windsurf"
        case .zed: return "Zed"
        }
    }

    /// 是否属于可自动注册分组（决定 UI 是开关行还是复制行）。
    var isAutoRegister: Bool {
        Self.autoRegisterTargets.contains(self)
    }

    /// 目标 CLI 可执行名（探测信号）；copy-only 目标无 CLI → nil。
    var cliName: String? {
        switch self {
        case .claudeCode: return "claude"
        case .codeBuddy: return "codebuddy"
        case .codex: return "codex"
        case .geminiCLI, .cursor, .vscode, .windsurf, .zed: return nil
        }
    }

    /// 注册落点的配置文件格式。
    var configFormat: ConfigFormat {
        switch self {
        case .claudeCode, .codeBuddy: return .json
        case .codex: return .toml
        case .geminiCLI, .cursor, .vscode, .windsurf, .zed: return .none
        }
    }

    /// 注册落点候选绝对路径（**按优先级**；多候选时取第一个存在的）。
    ///
    /// CodeBuddy 三条候选覆盖其配置路径演进；都不存在时由 codebuddy mcp add 自行
    /// 创建。copy-only 目标无落点 → 空数组。
    func configPaths(home: String) -> [String] {
        switch self {
        case .claudeCode:
            return [home + "/.claude.json"]
        case .codeBuddy:
            return [
                home + "/.codebuddy/mcp.json",
                home + "/.codebuddy/.mcp.json",
                home + "/.codebuddy.json",
            ]
        case .codex:
            return [home + "/.codex/config.toml"]
        case .geminiCLI, .cursor, .vscode, .windsurf, .zed:
            return []
        }
    }

    // MARK: - 配置读回（纯函数：文本 → 注册态）

    /// 解析配置文本，返回是否注册 + 已注册条目的 COFFER_VAULT_DIR。
    ///
    /// JSON：读顶层 mcpServers.coffer.env.COFFER_VAULT_DIR（与
    /// claude mcp add --scope user / CodeBuddy mcp.json 落点一致）。
    /// TOML：[mcp_servers.coffer]（或其 .env 子表）存在即已注册，env 表下取
    /// COFFER_VAULT_DIR（行扫描，不引第三方 TOML 依赖）。
    ///
    /// 文本不可解析 / 结构不符 → (false, nil)；「文件读不到」由调用方（helper）
    /// 以 IO 层错误表达（checkFailed）。
    func parseRegisteredVaultDir(text: String) -> (registered: Bool, vaultDir: String?) {
        switch configFormat {
        case .json:
            return Self.parseJSONRegisteredVaultDir(text: text)
        case .toml:
            return Self.parseTOMLRegisteredVaultDir(text: text)
        case .none:
            return (false, nil)
        }
    }

    private static func parseJSONRegisteredVaultDir(text: String) -> (registered: Bool, vaultDir: String?) {
        guard let data = text.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = root["mcpServers"] as? [String: Any] else {
            return (false, nil)
        }
        guard let entry = servers[McpRegisterSpec.serverName] as? [String: Any] else {
            return (false, nil)
        }
        let env = entry["env"] as? [String: Any]
        return (true, env?[Self.vaultDirEnvironmentKey] as? String)
    }

    /// TOML 行扫描：只认 [mcp_servers.coffer] / [mcp_servers.coffer.env] 两张表。
    /// 不处理多行字符串（注册值恒为单行路径），也不解析其余键。
    private static func parseTOMLRegisteredVaultDir(text: String) -> (registered: Bool, vaultDir: String?) {
        let serverTable = "mcp_servers." + McpRegisterSpec.serverName
        let envTable = serverTable + ".env"
        var registered = false
        var vaultDir: String?
        var inEnvTable = false
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                guard let close = line.firstIndex(of: "]") else { continue }
                let section = String(line[line.index(after: line.startIndex)..<close])
                inEnvTable = section == envTable
                if section == serverTable || inEnvTable { registered = true }
                continue
            }
            guard inEnvTable, let separator = line.firstIndex(of: "=") else { continue }
            let key = line[line.startIndex..<separator].trimmingCharacters(in: .whitespaces)
            guard key == Self.vaultDirEnvironmentKey else { continue }
            vaultDir = parseTOMLString(String(line[line.index(after: separator)...]))
        }
        return (registered, vaultDir)
    }

    /// TOML 值 → 字符串：基本字符串（"…"，处理 \\ 与 \" 转义）或字面量字符串（'…'）。
    private static func parseTOMLString(_ rawValue: String) -> String? {
        let value = rawValue.trimmingCharacters(in: .whitespaces)
        guard let quote = value.first else { return nil }
        if quote == "'" {
            let body = value.dropFirst()
            guard let end = body.firstIndex(of: "'") else { return nil }
            return String(body[body.startIndex..<end])
        }
        guard quote == "\"" else {
            // 裸值（非标准 TOML，容错）：取到空白或注释为止。
            let body = value.prefix { !$0.isWhitespace && $0 != "#" }
            return body.isEmpty ? nil : String(body)
        }
        var result = ""
        var escaped = false
        for character in value.dropFirst() {
            if escaped {
                switch character {
                case "n": result.append("\n")
                case "t": result.append("\t")
                case "r": result.append("\r")
                case "\"": result.append("\"")
                case "\\": result.append("\\")
                default: result.append(character)
                }
                escaped = false
                continue
            }
            if character == "\\" {
                escaped = true
                continue
            }
            if character == "\"" { return result }
            result.append(character)
        }
        // 引号未闭合：视为不可解析。
        return nil
    }

    // MARK: - 自动注册命令（argv 数组，**不经 shell**）

    /// 目标 CLI 之后的 argv（helper spawn 用）；nil = 该目标不支持自动注册。
    ///
    /// 形状硬编码：vaultDir / cofferBinaryPath 只作为独立 argv 元素出现，因此路径
    /// 含空格 / 引号 / 中文时无需任何转义（docs/23 REV-10 进程启动通道）。
    func addArgs(vaultDir: String, cofferBinaryPath: String) -> [String]? {
        switch self {
        case .claudeCode, .codeBuddy:
            // 与 McpRegisterSpec 同一构造函数（App 侧展示串 / 测试断言同源）。
            return McpRegisterSpec.commandArgs(vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath)
        case .codex:
            return [
                "mcp", "add", McpRegisterSpec.serverName,
                "--env", "\(Self.vaultDirEnvironmentKey)=\(vaultDir)",
                "--",
                cofferBinaryPath,
                "mcp", "--provider", McpRegisterSpec.serverName,
            ]
        case .geminiCLI, .cursor, .vscode, .windsurf, .zed:
            return nil
        }
    }

    /// 移除命令 argv（无任何值注入）；nil = 该目标不支持自动移除。
    func removeArgs() -> [String]? {
        switch self {
        case .claudeCode, .codeBuddy:
            return McpRegisterSpec.removeCommandArgs()
        case .codex:
            return ["mcp", "remove", McpRegisterSpec.serverName]
        case .geminiCLI, .cursor, .vscode, .windsurf, .zed:
            return nil
        }
    }

    // MARK: - 复制命令（展示串：唯一做 shell / JSON 转义的通道）

    /// 复制给用户粘贴的注册命令 / 配置片段。
    ///
    /// 通道纪律（docs/23 REV-10）：shell 命令逐 token 单引号转义；JSON 片段交给
    /// JSON 编码器逐值转义（不手拼转义字符）。两者不混用——JSON 片段内不出现
    /// shell 引号，shell 命令内不出现 JSON 转义。
    ///
    /// 返回值语义：自动注册目标 = 完整 shell 命令；Cursor / VS Code = 带
    /// --add-mcp 的 shell 命令；Windsurf / Zed = 含外层键（mcpServers /
    /// context_servers）的可粘贴 JSON 片段。
    func copyCommand(vaultDir: String, cofferBinaryPath: String) -> String {
        switch self {
        case .geminiCLI:
            let tokens = [
                "gemini", "mcp", "add", McpRegisterSpec.serverName,
                cofferBinaryPath, "mcp", "--provider", McpRegisterSpec.serverName,
                "-s", "user",
                "-e", "\(Self.vaultDirEnvironmentKey)=\(vaultDir)",
            ]
            return tokens.map(Self.shellQuoted).joined(separator: " ")
        case .cursor:
            let object = Self.jsonObject([("name", Self.jsonQuoted(McpRegisterSpec.serverName))]
                + Self.entryFields(command: cofferBinaryPath, vaultDir: vaultDir, leading: []))
            return "cursor --add-mcp " + Self.shellQuoted(object)
        case .vscode:
            let object = Self.jsonObject([
                ("name", Self.jsonQuoted(McpRegisterSpec.serverName)),
                ("type", Self.jsonQuoted("stdio")),
            ] + Self.entryFields(command: cofferBinaryPath, vaultDir: vaultDir, leading: []))
            return "code --add-mcp " + Self.shellQuoted(object)
        case .windsurf:
            let entry = Self.jsonObject(Self.entryFields(command: cofferBinaryPath, vaultDir: vaultDir, leading: []))
            return Self.jsonObject([("mcpServers", Self.jsonObject([(McpRegisterSpec.serverName, entry)]))])
        case .zed:
            let entry = Self.jsonObject(Self.entryFields(command: cofferBinaryPath, vaultDir: vaultDir,
                                                         leading: [("source", Self.jsonQuoted("custom"))]))
            return Self.jsonObject([("context_servers", Self.jsonObject([(McpRegisterSpec.serverName, entry)]))])
        case .claudeCode, .codeBuddy, .codex:
            // 自动注册目标：复制串即完整 shell 命令（CLI 名 + 硬编码 argv）。
            guard let cliName, let args = addArgs(vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath) else {
                return ""
            }
            return ([cliName] + args).map(Self.shellQuoted).joined(separator: " ")
        }
    }

    /// 服务器条目的 JSON 字段（顺序固定，便于阅读与照抄）。
    private static func entryFields(command: String, vaultDir: String,
                                   leading: [(String, String)]) -> [(String, String)] {
        leading + [
            ("command", jsonQuoted(command)),
            ("args", jsonArray(["mcp", "--provider", McpRegisterSpec.serverName])),
            ("env", jsonObject([(vaultDirEnvironmentKey, jsonQuoted(vaultDir))])),
        ]
    }

    private static func jsonObject(_ pairs: [(String, String)]) -> String {
        "{" + pairs.map { jsonQuoted($0.0) + ":" + $0.1 }.joined(separator: ",") + "}"
    }

    private static func jsonArray(_ values: [String]) -> String {
        "[" + values.map(jsonQuoted).joined(separator: ",") + "]"
    }

    /// JSON 标量编码（交给 JSONEncoder，不手拼转义：引号 / 反斜杠 / 控制字符全覆盖）。
    private static func jsonQuoted(_ value: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        guard let data = try? encoder.encode(value), let text = String(data: data, encoding: .utf8) else {
            return "\"\""
        }
        return text
    }

    /// Shell 展示串转义：安全字符原样，其余整体单引号包裹，值内单引号按 '\'' 转义。
    private static func shellQuoted(_ token: String) -> String {
        guard !token.isEmpty else { return "''" }
        let safe = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./=:-@%+,")
        if token.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return token
        }
        return "'" + token.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
