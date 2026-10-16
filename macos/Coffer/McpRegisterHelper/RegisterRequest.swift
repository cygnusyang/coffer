// McpRegisterHelper/RegisterRequest.swift —— App↔helper 握手契约（Codable）+ 校验
// （纯函数）。本文件同时编译进 App 目标与 helper 目标（build 脚本 App 源收集显式
// 加这两个共享文件、排除 McpRegisterHelper/main.swift——其顶层代码只属 helper）。
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
        /// 注册（upsert：既有同名校则先 remove 再 add，防旧 COFFER_VAULT_DIR 残留）。
        case register
        /// 只读 ~/.claude.json 顶层 mcpServers 的 coffer 键（状态展示）。
        case check
        /// 移除注册项（开关 OFF 自动移除，lead 裁定；best-effort 不阻塞 OFF）。
        case remove
    }

    /// 命令模式（register=执行注册；check=只读；remove=移除注册项）。
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

// MARK: - 结果契约（helper 写 → App 读；同一 Codable 结构，防两侧漂移）

/// 结构化结果码（App 侧 McpRegistrar.errorMessage(for:) 映射为用户可读文案）。
enum ResultCode: String, Codable, Equatable {
    case ok
    /// config 字段缺失/越界（missingVaultDir / missingBinary /
    /// binaryOutsideHelpers / missingResultPath）
    case configInvalid
    /// coffer 二进制路径不存在（path 形状已过、IO 存在性不过）
    case cofferBinaryInvalid
    /// 未找到 claude CLI（candidates + login shell command -v 均无）
    case claudeNotFound
    /// claude mcp add 超时
    case claudeTimeout
    /// claude mcp add 退出码非 0
    case claudeAddFailed
    /// claude mcp remove 退出码非 0 / 读回确认 coffer 键仍在（upsert 清理旧条目
    /// 或开关 OFF 自动移除失败；App 侧错误码映射两套语境文案）
    case claudeRemoveFailed
    /// add 报告成功但读回 ~/.claude.json 无 coffer 键（read-back confirm 失败=
    /// 注册失败态，UI 显式，lead 裁定）
    case notRegistered
    /// ~/.claude.json 读取/解析异常（check 模式）
    case checkFailed
    /// result 文件写入失败（App 侧轮询超时兜底）
    case resultWriteFailed
}

/// 操作结果（App 侧读取；JSON：success/code/message/registered/vaultDir）。
struct McpRegisterResult: Codable, Equatable {
    let success: Bool
    let code: ResultCode
    let message: String
    /// 读回确认 / check 结论：顶层 mcpServers 是否含 coffer 键。
    let registered: Bool
    /// 已注册条目的 COFFER_VAULT_DIR（读回/check 时提取；未注册/无 env → nil）。
    let vaultDir: String?
}
