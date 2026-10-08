// BrowserStatus.swift —— 浏览器集成设置页就绪状态（docs/31 §6.2 / §9.1 G-D）。
//
// 镜像 McpStatus（Support/McpStatus.swift）：状态来源纪律 = 配置（开关）+ 本地
// 环境探测（coffer 二进制、manifest 落盘）组合判定，无 socket、不 spawn 常驻
// 进程。broker 运行态是**独立进程**（App 仅管理其生命周期，docs/31 §2.1），由
// AppModel 单独持有并呈现（BrowserBrokerRuntime），不参与本处前置就绪度组合。
//
// 组合逻辑抽为纯函数（对齐 McpStatus.resolve / TouchIDStatus.resolve 先例）：
// 判定只依赖布尔信号，无 IO / 无 FFI / 无进程依赖，可独立单测
// （macos/Tests/BrowserStatusTests）。
//
// 信号语义（docs/31 §6.2 / §4.1）：
//   - enabled = 「启用浏览器集成」配置（UserDefaults 非敏感布尔）
//   - cofferBinary = coffer 命令可执行（broker/host 复用嵌套 bundle 二进制，
//     D-2，McpStatusProbe.cofferBinaryPath 定位）
//   - manifestsInstalled = 三浏览器 native messaging manifest 全部落盘
//     （Chrome/Edge/Firefox macOS，docs/31 §6.2）
// 注（G-A3）：broker 契约 = App 解锁 + stdin DEK 交付（docs/31 §4.1 r0.9「broker
// escrow 免密自解锁」作废），就绪度与 MCP escrow **零耦合**——不再把 escrow 当
// 前置（McpEscrowStatus 属 MCP 设置面，语义保留在 McpStatusTests 侧）。

import Foundation

/// 浏览器集成就绪四态（docs/31 §6.2 状态行，镜像 McpStatus）。
enum BrowserStatus: Equatable {
    /// 未启用（开关关闭）：状态行收敛为「已停用」，忽略其余信号。
    case disabled
    /// 配置 + 本地前置全部就绪：broker 可 spawn、扩展可配对。
    case ready
    /// 启用但缺某前置（coffer 二进制 / manifest；G-A3：escrow 已解耦）。
    case notReady(BrowserStatusIssue)

    /// 未就绪的具体缺项（docs/31 §6.2 状态行引导文案按项区分）。G-A3：就绪度
    /// 与 escrow 解耦（docs/31 §4.1 r0.9），缺项仅 coffer 二进制 / manifest 两型
    /// （case 数由 BrowserStatusTests 断言为 2，防回退）。
    enum BrowserStatusIssue: Equatable, CaseIterable {
        /// 缺 coffer 命令（broker/host 复用二进制，D-2）
        case missingCofferBinary
        /// 缺 native messaging manifest（未写入 / 被删 / 写入被拒）
        case missingManifest
    }

    /// 就绪度判定纯函数（docs/31 §6.2，镜像 McpStatus.resolve 同序）。
    ///
    /// 组合规则（缺项按优先级报首个缺项；G-A3：escrow 不再是前置）：
    ///   - 未启用 → disabled（开关优先，与 McpStatus/TouchIDStatus.resolve 同序）
    ///   - 缺 coffer → missingCofferBinary
    ///   - 缺 manifest → missingManifest
    ///   - 全就绪 → ready
    ///
    /// - Parameters:
    ///   - enabled: `BrowserIntegrationSettings.loadEnabled()`——「启用浏览器
    ///     集成」配置
    ///   - cofferBinaryAvailable: `BrowserStatusProbe.isCofferBinaryAvailable()`
    ///   - manifestsInstalled: `BrowserStatusProbe.allManifestsInstalled()`
    static func resolve(
        enabled: Bool,
        cofferBinaryAvailable: Bool,
        manifestsInstalled: Bool
    ) -> BrowserStatus {
        guard enabled else { return .disabled }
        guard cofferBinaryAvailable else { return .notReady(.missingCofferBinary) }
        guard manifestsInstalled else { return .notReady(.missingManifest) }
        return .ready
    }

    /// 状态行短文案（docs/31 §6.2 状态行）。
    var label: String {
        switch self {
        case .disabled: return "已停用"
        case .ready: return "就绪"
        case .notReady(.missingCofferBinary): return "未找到 coffer 命令"
        case .notReady(.missingManifest): return "未写入浏览器 native messaging manifest"
        }
    }
}

/// 浏览器种类（native messaging host manifest 目标，docs/31 §6.2）。
/// rawValue 仅供内部标识，展示名见 displayName。
enum BrowserKind: String, CaseIterable, Equatable {
    case chrome
    case edge
    case firefox

    /// 设置页展示名（1Password 对齐文案）。
    var displayName: String {
        switch self {
        case .chrome: return "Google Chrome"
        case .edge: return "Microsoft Edge"
        case .firefox: return "Firefox"
        }
    }

    /// manifest 目录相对「~/Library/Application Support」根目录的路径（纯路径
    /// 构造，无 IO；docs/31 §6.2：Chrome/Edge 与 Firefox 目录不同）。
    /// 文件名统一见 BrowserManifestPaths.manifestFileName。
    var nativeMessagingHostsRelativePath: String {
        switch self {
        case .chrome: return "Google/Chrome/NativeMessagingHosts"
        case .edge: return "Microsoft Edge/NativeMessagingHosts"
        case .firefox: return "Mozilla/NativeMessagingHosts"
        }
    }
}

/// broker（browser-broker 独立进程）运行态（docs/31 §2.1 状态机 running /
/// killed；App 解锁 spawn / 锁定 kill，锁态镜像）。AppModel 持有并呈现（设置页
/// 状态行 caption），不参与 BrowserStatus 前置就绪度组合（见文件头注释）。
enum BrowserBrokerRuntime: Equatable {
    /// 未 spawn（停用 / 锁定态）
    case stopped
    /// 运行中（持解锁会话，E2E 端点就绪，docs/31 §2.1 running）
    case running(pid: Int32)
    /// spawn 失败（携带可呈现文案，fail-closed）
    case failed(String)
}

/// 浏览器集成设置持久化（docs/31 §6.2 开关；镜像 McpSettings 纪律）。
/// 键值非敏感（布尔），存 UserDefaults——本域无密钥材料（PSK/公钥由 broker
/// 在配对批准后生成，不经 App 状态）。
enum BrowserIntegrationSettings {
    /// 「启用浏览器集成」开关（非敏感布尔，docs/31 §6.2）。
    static let enabledDefaultsKey = "browser_integration_enabled"

    /// 读开关（键不存在 → false，与 AppModel 其它 UserDefaults 读法同纪律）。
    nonisolated static func loadEnabled() -> Bool {
        UserDefaults.standard.bool(forKey: enabledDefaultsKey)
    }

    nonisolated static func saveEnabled(_ value: Bool) {
        UserDefaults.standard.set(value, forKey: enabledDefaultsKey)
    }
}
