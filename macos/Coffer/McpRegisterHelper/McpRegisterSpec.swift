// McpRegisterHelper/McpRegisterSpec.swift —— MCP 注册/移除命令 argv 构造**单源**
// （纯函数；lead 裁定修正：App 与 helper 两个 target 共享编译本文件，单源真义=
// 「同一 spec 构造 argv」；config 只传 vaultDir / cofferBinaryPath 两个**值**，
// argv **不**经 config 传递——无注入面）。
//
// 安全契约（lead 裁定）：helper **不执行任意命令**——命令形状在此硬编码，
// 只允许固定的 `claude mcp add coffer --scope user ...` / `claude mcp remove
// coffer --scope user`；spawn 用 argv 数组直传（Process），**绝不 shell 字符串
// 拼接**（vaultDir / cofferBinaryPath 永远只是 argv 元素）。
//
// 编译进两个 target（build 脚本：helper 3.7 全目录编译；App SOURCES 显式追加）：
//   - helper  main.swift 用 fullArgv / removeFullArgv 直接 spawn；
//   - App      McpRegisterCommand.buildArgs（coffer 分支）委托 commandArgs。
// 一致性由构造保证（同一 spec），不再依赖测试比对兜底。
//
// 规则（docs/20 §5.4 / lead 裁定）：
//   - `--scope user`：写 ~/.claude.json 顶层 mcpServers（非项目级 projects，
//     App/helper 语境下无 cwd 项目概念——用户「打开就能用」= 全局）；
//   - `-e COFFER_VAULT_DIR=<vaultDir>`：vault 目录 env（R2：不含密码）；
//   - `-- <cofferBinaryPath> mcp --provider coffer`：coffer CLI 执行面；
//   - remove：`mcp remove coffer --scope user`（开关 OFF 自动移除，lead 裁定）。

import Foundation

enum McpRegisterSpec {
    /// 固定服务器名（claude config 顶层 mcpServers 的 key，恒为 coffer）。
    static let serverName = "coffer"

    /// 注册命令 argv（**claude 之后**；App 展示/复制与 helper 校验共用，含
    /// --scope user）。仅含 vaultDir / cofferBinaryPath 两个值。
    static func commandArgs(vaultDir: String, cofferBinaryPath: String) -> [String] {
        [
            "mcp", "add", serverName,
            "--scope", "user",
            "-e", "COFFER_VAULT_DIR=\(vaultDir)",
            "--",
            cofferBinaryPath,
            "mcp", "--provider", serverName,
        ]
    }

    /// 完整注册 argv（含 claude 路径；helper resolve claude 后直接 spawn 用）。
    static func fullArgv(claudePath: String, vaultDir: String, cofferBinaryPath: String) -> [String] {
        [claudePath] + commandArgs(vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath)
    }

    /// 移除命令 argv（**claude 之后**；固定形状，无任何值注入）。
    static func removeCommandArgs() -> [String] {
        ["mcp", "remove", serverName, "--scope", "user"]
    }

    /// 完整移除 argv（含 claude 路径；helper spawn 用）。
    static func removeFullArgv(claudePath: String) -> [String] {
        [claudePath] + removeCommandArgs()
    }
}
