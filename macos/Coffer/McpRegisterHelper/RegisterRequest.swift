// McpRegisterHelper/RegisterRequest.swift —— helper 配置（Codable）+ 校验（纯函数）。
//
// 配置握手（BUG-30 三层取参收敛，lead 裁定）：
//   - App 侧 McpRegistrar 写固定名 config 到容器 tmp → helper 经 getpwuid 真实
//     主目录 + 硬编码 bundle id 定位（env 注入 → 固定路径 → argv 三级回退，
//     与 OTAInstaller 同款）；
//   - 只传**值**（mode / vaultDir / cofferBinaryPath / resultPath），命令结构
//     在 RegisterCommandBuilder 硬编码（安全契约：防其他进程投喂恶意 config
//     借 helper 注册任意命令）。
//   - R2：config 全程不含任何密码字段。

import Foundation

struct McpRegisterRequest: Codable, Equatable {
    enum Mode: String, Codable, Equatable {
        case register
        case check
    }

    /// 命令模式（register=执行注册；check=只读 ~/.claude.json 顶层 mcpServers）。
    let mode: Mode
    /// vault 目录绝对路径（仅 register 模式必填；R2：不含密码）。
    let vaultDir: String?
    /// coffer 二进制绝对路径（仅 register 模式必填；须位于 Contents/Helpers/ 下）。
    let cofferBinaryPath: String?
    /// 结果 JSON 落点（register 与 check 均必填，写回容器 tmp 固定名）。
    let resultPath: String

    /// 配置校验错误（结构化错误码，App 侧映射为用户可读文案）。
    enum ConfigError: String, Equatable {
        case missingVaultDir
        case missingBinary
        case binaryOutsideHelpers
        case missingResultPath
    }

    /// coffer 二进制必须位于预期 bundle 位置（`.app/Contents/Helpers/` 下）。
    ///
    /// 安全契约：阻止恶意 config 把任意可执行路径塞进 argv 尾端
    /// （claude mcp add 的 `--` 之后是 coffer 执行面）。要求路径含 `.app` 包的
    /// Helpers 段（拒绝 `/usr/bin/Contents/Helpers/…` 这类伪路径）；文件存在性
    /// （IO）由 main.swift 在 spawn 前再验一道。
    static func isExpectedHelperPath(_ path: String) -> Bool {
        path.contains(".app/Contents/Helpers/")
    }

    /// 返回 nil 表示合法；否则返回首个违规项（fail fast）。
    ///
    /// 模式分叉：check 只读 ~/.claude.json，仅需 resultPath；register 才要求
    /// vaultDir + coffer 二进制（并须位于 Contents/Helpers/ 下）。
    func validate() -> ConfigError? {
        guard !resultPath.isEmpty else { return .missingResultPath }
        guard mode == .register else { return nil }
        guard let vaultDir, !vaultDir.isEmpty else { return .missingVaultDir }
        guard let cofferBinaryPath else { return .missingBinary }
        guard Self.isExpectedHelperPath(cofferBinaryPath) else { return .binaryOutsideHelpers }
        return nil
    }
}
