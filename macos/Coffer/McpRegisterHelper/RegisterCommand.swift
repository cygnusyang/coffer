// McpRegisterHelper/RegisterCommand.swift —— MCP 注册命令 argv 构造（纯函数）。
//
// 安全契约（lead 裁定）：helper **不执行任意命令**——命令结构在此硬编码，
// 只允许固定的 `claude mcp add coffer --scope user ...` 形状；spawn 用 argv
// 数组直传（Process），**绝不 shell 字符串拼接**（config 中的 vaultDir /
// cofferBinaryPath 永远只是 argv 元素，无注入面）。
//
// 单源纪律：App 侧 Support/McpStatusConfig.swift 的 McpRegisterCommand.buildArgs
// 与此保持同构（一致性命中由 run_mcp_registrar_tests.sh 的一致性断言保证，
// 防两处漂移）。

import Foundation

enum RegisterCommandBuilder {
    /// 固定服务器名（claude config 顶层 mcpServers 的 key，恒为 coffer）。
    static let serverName = "coffer"

    /// 注册命令 argv 结构（claudePath 起，含 --scope user）。
    ///
    /// 规则（docs/20 §5.4 / lead 裁定）：
    ///   - `--scope user`：写 ~/.claude.json 顶层 mcpServers（非项目级 projects，
    ///     用户「打开就能用」语义，App/helper 语境下无 cwd 项目概念）；
    ///   - `-e COFFER_VAULT_DIR=<vaultDir>`：vault 目录 env（R2：不含密码）；
    ///   - `-- <cofferBinaryPath> mcp --provider coffer`：coffer CLI 执行面。
    ///
    /// - Parameters:
    ///   - claudePath: claude CLI 绝对路径（由 helper 主入口 resolve）。
    ///   - vaultDir: vault 目录绝对路径（config 传入）。
    ///   - cofferBinaryPath: 已校验位于 Contents/Helpers/ 的 coffer 二进制绝对路径。
    static func buildArgs(claudePath: String, vaultDir: String, cofferBinaryPath: String) -> [String] {
        [
            claudePath,
            "mcp", "add", serverName,
            "--scope", "user",
            "-e", "COFFER_VAULT_DIR=\(vaultDir)",
            "--",
            cofferBinaryPath,
            "mcp", "--provider", serverName,
        ]
    }
}
