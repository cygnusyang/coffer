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
        /// 只读目标工具的配置文件，判定是否已注册 + 已注册目录（状态展示）。
        case check
        /// 移除注册项（开关 OFF 自动移除；best-effort 不阻塞 OFF）。
        case remove
        /// 探测本机可自动注册的目标（docs/23 §4.1「重新检测」；不写任何配置）。
        case probe
    }

    /// 命令模式（register=执行注册；check=只读；remove=移除注册项；
    /// probe=探测已安装的自动注册目标）。
    let mode: Mode
    /// vault 目录绝对路径（仅 register 模式必填；R2：不含密码）。
    let vaultDir: String?
    /// coffer 二进制绝对路径（仅 register 模式必填；须位于 Contents/Helpers/ 下）。
    let cofferBinaryPath: String?
    /// 结果 JSON 落点（全部模式必填，写回容器 tmp 固定名）。
    let resultPath: String
    /// 目标 AI 工具（v2.12.0 多工具注册；nil 按 .claudeCode 处理，兼容旧 config）。
    let target: McpAgentTarget?

    /// 显式 init：target 置末位并缺省 nil——旧调用点（不含 target）保持可编译，
    /// 旧 config JSON（无 target 键）解码后同样落到 .claudeCode。
    init(mode: Mode, vaultDir: String?, cofferBinaryPath: String?, resultPath: String,
         target: McpAgentTarget? = nil) {
        self.mode = mode
        self.vaultDir = vaultDir
        self.cofferBinaryPath = cofferBinaryPath
        self.resultPath = resultPath
        self.target = target
    }

    /// 解析目标（缺省 = Claude Code：v2.11.0 单工具时代唯一的注册目标）。
    var resolvedTarget: McpAgentTarget {
        target ?? .claudeCode
    }

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
    /// （目标 CLI 注册命令的 `--` 之后是 coffer 执行面）。要求路径含 `.app` 包的
    /// Helpers 段（拒绝 `/usr/bin/Contents/Helpers/…` 这类伪路径）；文件存在性
    /// （IO）由 main.swift 在 spawn 前再验一道。
    static func isExpectedHelperPath(_ path: String) -> Bool {
        // dev-review M4：先规范化（消解 "." / ".." / 重复分隔符）再判字面段——
        // 否则 "/tmp/x.app/Contents/Helpers/../../usr/bin/evil" 这类「字面含
        // Helpers、实际指向别处」的路径会通过校验。
        let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
        return normalized.contains(".app/Contents/Helpers/")
    }

    /// 返回 nil 表示合法；否则返回首个违规项（fail fast）。
    ///
    /// 模式分叉：check / remove / probe 只读或只执行固定形状命令，仅需
    /// resultPath；register 才要求 vaultDir + coffer 二进制（并须位于
    /// Contents/Helpers/ 下）。
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

/// 结构化结果码（App 侧 McpRegistrar.errorMessage(for:target:) 映射为用户可读文案）。
///
/// rawValue 是 App↔helper 的稳定契约，**不得更名**（v2.11.0 起冻结）。v2.12.0
/// 引入多 target 后，claude* 三个码的语义泛化为「目标工具 CLI 相关失败」：具体
/// 工具名由请求的 target 决定（文案侧经 McpAgentTarget.displayName 表达）。
enum ResultCode: String, Codable, Equatable {
    case ok
    /// config 字段缺失/越界（missingVaultDir / missingBinary /
    /// binaryOutsideHelpers / missingResultPath）
    case configInvalid
    /// coffer 二进制路径不存在（path 形状已过、IO 存在性不过）
    case cofferBinaryInvalid
    /// 未找到目标工具 CLI（固定候选 + login shell command -v 均无）
    case claudeNotFound
    /// 目标工具注册命令超时
    case claudeTimeout
    /// 目标工具注册命令退出码非 0
    case claudeAddFailed
    /// 目标工具移除命令退出码非 0 / 读回确认 coffer 条目仍在（upsert 清理旧条目
    /// 或开关 OFF 自动移除失败；App 侧按注册/移除两套语境映射文案）
    case claudeRemoveFailed
    /// add 报告成功但读回目标配置文件无 coffer 条目（read-back confirm 失败=
    /// 注册失败态，UI 显式）
    case notRegistered
    /// 目标配置文件读取/解析异常（check 模式）
    case checkFailed
    /// result 文件写入失败（App 侧轮询超时兜底）
    case resultWriteFailed
    /// 该目标不支持自动注册/自动移除（copy-only 工具：只能复制配置，docs/23 §4.1）
    case targetUnsupported
}

/// 操作结果（App 侧读取；JSON：success/code/message/registered/vaultDir/
/// installedTargets/target）。
struct McpRegisterResult: Codable, Equatable {
    let success: Bool
    let code: ResultCode
    let message: String
    /// 读回确认 / check 结论：目标配置文件是否含 coffer 条目。
    let registered: Bool
    /// 已注册条目的 COFFER_VAULT_DIR（读回/check 时提取；未注册/无 env → nil）。
    let vaultDir: String?
    /// probe 结论：本机探测到 CLI 的自动注册目标（rawValue，顺序同
    /// McpAgentTarget.autoRegisterTargets）；非 probe 模式为 nil。
    let installedTargets: [String]?
    /// 结果回显的目标（**新鲜度判据**，dev-review H1）：helper 写本次实际执行的
    /// target rawValue（probe 模式写 "probe"）。App 侧解码后与本次期望值不一致
    /// = 上一场残留的陈旧 result（取消后 helper 仍在跑），必须丢弃并继续轮询。
    /// 旧版本 result 无此键 → nil（不做判据，保持兼容）。
    let target: String?

    /// 显式 init：installedTargets / target 置末位并缺省 nil——既有调用点无需改动。
    init(success: Bool, code: ResultCode, message: String, registered: Bool, vaultDir: String?,
         installedTargets: [String]? = nil, target: String? = nil) {
        self.success = success
        self.code = code
        self.message = message
        self.registered = registered
        self.vaultDir = vaultDir
        self.installedTargets = installedTargets
        self.target = target
    }

    /// probe 模式的 result target 回显值（App 侧期望值 / helper 侧写入值同一字面量，
    /// 防两侧漂移）。
    static let probeEchoTarget = "probe"
}
