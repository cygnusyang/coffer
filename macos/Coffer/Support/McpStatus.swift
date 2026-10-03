// McpStatus.swift —— MCP 设置页就绪状态（docs/20 §6.1 状态行）。
//
// 状态来源纪律（docs/20 §6.2/§6.3）：主 App 不宿主 MCP 服务器，本状态是
// 「独立 coffer 进程可被消费」的前置就绪度——由配置（开关）+ 本地环境探测
// （op / coffer 二进制、会话 env 信号）组合判定，无 socket、不 spawn 常驻进程。
//
// 组合逻辑抽为纯函数（对齐 TouchIDStatus 先例）：判定只依赖四个布尔信号，
// 无 IO / 无 FFI / 无进程依赖，可独立单测（macos/Tests/McpStatusTests）。
//
// 信号语义（docs/20 §4.2/§4.3/§6.1）：
//   - enabled = 「启用 MCP 服务器」配置（UserDefaults 非敏感布尔）
//   - opBinary = 1Password CLI（op）可执行（COFFER_OP_BIN 或 PATH 查找）
//   - cofferBinary = coffer 命令可执行（MCP 服务器独立进程，随 App 分发并入 PATH）
//   - session = 1Password 会话 env 信号（COFFER_OP_SESSION_TOKEN / OP_SESSION）
//     诚实边界：env 级信号不代表 op 内部实际登录态，实际会话以 `op signin` 为准。

/// MCP 服务就绪四态（docs/20 §6.1 状态行）。
enum McpStatus: Equatable {
    /// 未启用（开关关闭）：状态行收敛为「已停用」，忽略其余信号。
    case disabled
    /// 配置 + 本地前置全部就绪：注册命令可直接复制。
    case ready
    /// 启用但缺某前置（op / coffer / 会话）。
    case notReady(McpStatusIssue)

    /// 未就绪的具体缺项（docs/20 §6.1 状态行引导文案按项区分）。
    enum McpStatusIssue: Equatable {
        /// 缺 1Password CLI（op）二进制
        case missingOpBinary
        /// 缺 coffer 命令（MCP 服务器独立进程）
        case missingCofferBinary
        /// 缺 1Password 会话 env 信号
        case missingSession
    }

    /// 就绪度判定纯函数（docs/20 §6.1 状态行）。
    ///
    /// 组合规则（缺项优先级 op → coffer → session，报首个缺项）：
    ///   - 未启用 → disabled（开关优先，与 TouchIDStatus.resolve 同序）
    ///   - 启用 ∧ 全就绪 → ready
    ///   - 启用 ∧ 缺 op → notReady(.missingOpBinary)
    ///   - 启用 ∧ 缺 coffer → notReady(.missingCofferBinary)
    ///   - 启用 ∧ 缺会话 → notReady(.missingSession)
    ///
    /// - Parameters:
    ///   - enabled: `McpSettings.loadEnabled()`——「启用 MCP 服务器」配置
    ///   - opBinaryAvailable: `McpStatusProbe.isOpBinaryAvailable()`
    ///   - cofferBinaryAvailable: `McpStatusProbe.isCofferBinaryAvailable()`
    ///   - sessionAvailable: `McpStatusProbe.isOpSessionAvailable()`
    static func resolve(
        enabled: Bool,
        opBinaryAvailable: Bool,
        cofferBinaryAvailable: Bool,
        sessionAvailable: Bool
    ) -> McpStatus {
        guard enabled else { return .disabled }
        guard opBinaryAvailable else { return .notReady(.missingOpBinary) }
        guard cofferBinaryAvailable else { return .notReady(.missingCofferBinary) }
        guard sessionAvailable else { return .notReady(.missingSession) }
        return .ready
    }

    /// 状态行短文案（docs/20 §6.1 状态行）。
    var label: String {
        switch self {
        case .disabled: return "已停用"
        case .ready: return "就绪"
        case .notReady(.missingOpBinary): return "未找到 1Password CLI（op）"
        case .notReady(.missingCofferBinary): return "未找到 coffer 命令"
        case .notReady(.missingSession): return "未检测到 1Password 会话"
        }
    }
}
