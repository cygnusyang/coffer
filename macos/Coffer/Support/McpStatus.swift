// McpStatus.swift —— MCP 设置页就绪状态（docs/20 §6.1 状态行；docs/29 §7.1 翻转）。
//
// 状态来源纪律（docs/20 §6.2/§6.3）：主 App 不宿主 MCP 服务器，本状态是
// 「独立 coffer 进程可被消费」的前置就绪度——由配置（开关）+ 本地环境探测
// （op / coffer 二进制、会话 env 信号、托管启用）组合判定，无 socket、不 spawn
// 常驻进程。
//
// 组合逻辑抽为纯函数（对齐 TouchIDStatus 先例）：判定只依赖布尔信号，无 IO /
// 无 FFI / 无进程依赖，可独立单测（macos/Tests/McpStatusTests）。
//
// 信号语义（docs/20 §4.2/§4.3/§6.1；docs/29 §7.1）：
//   - provider = 数据源选择（op / coffer），决定状态组合分支（docs/29 §7.1）
//   - enabled = 「启用 MCP 服务器」配置（UserDefaults 非敏感布尔）
//   - opBinary = 1Password CLI（op）可执行（COFFER_OP_BIN 或 PATH 查找；
//     仅 op 分支消费）
//   - cofferBinary = coffer 命令可执行（MCP 服务器独立进程，随 App 分发并入
//     PATH；两 provider 均需——MCP 服务器进程恒为 coffer）
//   - session = 1Password 会话 env 信号（COFFER_OP_SESSION_TOKEN / OP_SESSION；
//     仅 op 分支消费。诚实边界：env 级信号不代表 op 内部实际登录态）
//   - escrowEnabled = coffer 分支的托管启用信号（McpEscrowStatus.resolve 三态
//     == .enabled；header mcp_wrap + Keychain 条目 + 会话组合，docs/29 §5.2）

/// MCP 服务就绪四态（docs/20 §6.1 状态行）。
enum McpStatus: Equatable {
    /// 未启用（开关关闭）：状态行收敛为「已停用」，忽略其余信号。
    case disabled
    /// 配置 + 本地前置全部就绪：注册命令可直接复制。
    case ready
    /// 启用但缺某前置（op / coffer / 会话 / 托管）。
    case notReady(McpStatusIssue)

    /// 未就绪的具体缺项（docs/20 §6.1 状态行引导文案按项区分）。
    enum McpStatusIssue: Equatable {
        /// 缺 1Password CLI（op）二进制
        case missingOpBinary
        /// 缺 coffer 命令（MCP 服务器独立进程）
        case missingCofferBinary
        /// 缺 1Password 会话 env 信号
        case missingSession
        /// 缺 MCP 解锁托管（coffer 分支：header mcp_wrap + Keychain 条目未启用）
        case missingEscrow
    }

    /// 就绪度判定纯函数（docs/29 §7.1 provider 分流）。
    ///
    /// 组合规则（缺项按分支优先级报首个缺项）：
    ///   - 未启用 → disabled（开关优先，与 TouchIDStatus.resolve 同序）
    ///   - provider == .op：缺 op → missingOpBinary；缺 coffer →
    ///     missingCofferBinary；缺会话 → missingSession；全就绪 → ready
    ///   - provider == .coffer：缺 coffer → missingCofferBinary；缺托管 →
    ///     missingEscrow；全就绪 → ready（op 信号完全不参与组合）
    ///
    /// - Parameters:
    ///   - provider: `McpProvider`——数据源选择，决定状态组合分支
    ///   - enabled: `McpSettings.loadEnabled()`——「启用 MCP 服务器」配置
    ///   - opBinaryAvailable: `McpStatusProbe.isOpBinaryAvailable()`（仅 op 分支消费）
    ///   - cofferBinaryAvailable: `McpStatusProbe.isCofferBinaryAvailable()`
    ///   - sessionAvailable: `McpStatusProbe.isOpSessionAvailable()`（仅 op 分支消费）
    ///   - escrowEnabled: coffer 分支托管信号（`McpEscrowStatus.resolve(...) ==
    ///     .enabled`；docs/29 §7.1「新增 escrowEnabled 信号」）
    static func resolve(
        provider: McpProvider,
        enabled: Bool,
        opBinaryAvailable: Bool,
        cofferBinaryAvailable: Bool,
        sessionAvailable: Bool,
        escrowEnabled: Bool
    ) -> McpStatus {
        guard enabled else { return .disabled }
        switch provider {
        case .op:
            guard opBinaryAvailable else { return .notReady(.missingOpBinary) }
            guard cofferBinaryAvailable else { return .notReady(.missingCofferBinary) }
            guard sessionAvailable else { return .notReady(.missingSession) }
            return .ready
        case .coffer:
            guard cofferBinaryAvailable else { return .notReady(.missingCofferBinary) }
            guard escrowEnabled else { return .notReady(.missingEscrow) }
            return .ready
        }
    }

    /// 状态行短文案（docs/20 §6.1 状态行）。
    var label: String {
        switch self {
        case .disabled: return "已停用"
        case .ready: return "就绪"
        case .notReady(.missingOpBinary): return "未找到 1Password CLI（op）"
        case .notReady(.missingCofferBinary): return "未找到 coffer 命令"
        case .notReady(.missingSession): return "未检测到 1Password 会话"
        case .notReady(.missingEscrow): return "未启用 MCP 解锁托管"
        }
    }
}

/// MCP 解锁托管三态（docs/29 §5.2 三态判定 resolve）。
///
/// 三态组合逻辑抽为纯函数（镜像 `TouchIDStatus.resolve`，TouchIDStatus.swift:39-55）：
/// 判定只依赖三个布尔信号，无 IO / 无 FFI / 无 Keychain 依赖，可独立单测
/// （macos/Tests/McpStatusTests）。
///
/// 信号语义（docs/29 §5.2）：
///   - header.mcp_wrap.available = 「用户意图开启」（持久意愿，Rust header，
///     锁定态可查——hasMcpWrap）
///   - Keychain 项存在性 = 「实际可用」信号（Swift 侧；无 ACL 条目，元数据
///     探测不弹认证 UI——McpEscrowKeychain.itemExists）
///   - sessionOpen = 是否有打开的库会话（AppModel.session != nil）
enum McpEscrowStatus: Equatable {
    /// 功能未启用（header available=false，或无打开的库会话）
    case disabled
    /// header available=true 且 Keychain 项存在：可用
    case enabled
    /// header available=true 但 Keychain 项缺失（stale）：需主密码解锁后
    /// 「重新启用」（docs/29 §5.2——重派生同一 mcp_key，幂等覆盖，§5.3）
    case stale

    /// 三态判定纯函数（docs/29 §5.2，镜像 TouchIDStatus.resolve）。
    ///
    /// 组合规则：
    ///   - 无会话 / header 未启用 → disabled（Keychain 项残留不影响判定，
    ///     孤儿项危害 ≈ 0，docs/29 §5.3）
    ///   - header 启用 ∧ Keychain 项存在 → enabled
    ///   - header 启用 ∧ Keychain 项缺失 → stale
    ///
    /// - Parameters:
    ///   - headerMcpWrapAvailable: `session.hasMcpWrap()`——header
    ///     `mcp_wrap.available`
    ///   - keychainItemExists: `McpEscrowKeychain.itemExists(vaultUUID:)`
    ///   - sessionOpen: 是否有打开的库会话（AppModel.session != nil）
    static func resolve(
        headerMcpWrapAvailable: Bool,
        keychainItemExists: Bool,
        sessionOpen: Bool = true
    ) -> McpEscrowStatus {
        guard sessionOpen, headerMcpWrapAvailable else { return .disabled }
        return keychainItemExists ? .enabled : .stale
    }

    /// 状态行短文案（docs/29 §7.2）。
    var label: String {
        switch self {
        case .disabled: return "已停用"
        case .enabled: return "已启用"
        case .stale: return "凭据已失效（需重新启用）"
        }
    }
}
