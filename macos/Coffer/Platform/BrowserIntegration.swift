// BrowserIntegration.swift —— 浏览器集成的 App 侧平台层（docs/31 §6.2 / §9.1 G-D）。
//
// 职责三件：
//   ① native messaging manifest 写入/删除（各浏览器 NativeMessagingHosts 目录，
//      docs/31 §6.2；host_name = com.coffer.browser，path → bundle 内 shim）
//   ② broker 进程管理（spawn browser-broker / kill；D-2 复用嵌套 bundle coffer
//      二进制，App 解锁 spawn / 锁定 kill，锁态镜像 docs/31 §2.1/§4.1）
//   ③ 配对确认请求/响应模型与决策转发 seam（docs/31 §2.3/§4.2/§5.3：显式用户
//      批准才下发 PSK + broker 公钥）。**本文件不接触任何密钥材料**——PSK/公钥
//      由 broker（Rust 侧 G-A/G-B）在批准后生成下发，App 侧只做批准门 +
//      决策转发（BrowserPairingResponder seam）。
//
// 沙盒边界（诚实声明）：App 已启用 App Sandbox（Coffer.entitlements
// app-sandbox=true），写浏览器 NativeMessagingHosts 目录（容器外绝对路径）会被
// 沙盒拒绝，除非加装 sandbox temporary exception entitlement——该 entitlement
// 决策属 G-E/lead（tools/build_macos_app.sh 装配）。本文件把写入错误显式上抛
// （fail-closed），由 UI 呈现可操作文案。**合并期验收项**（本机 runtime 需
// entitlement 后才可端到端验证写入）。
//
// 冻结占位（D-4，发布前必须定稿，docs/31 §6.1 / 31a D-4）：扩展 ID / GUID 未
// 冻结，见 chromeExtensionID / edgeExtensionID / firefoxGUID 常量——与 G-C
// extension manifest 的 `key` / `browser_specific_settings.gecko.id` 对齐后于
// 发布前冻结（改 ID = 已装扩展断连 + 全量重配）。**合并期验收项**。

import Darwin
import Foundation

/// 浏览器集成操作错误（fail-closed：任何一步失败均显式上抛，不静默降级）。
enum BrowserIntegrationError: Error, Equatable {
    /// 未找到 coffer 二进制（broker/host 复用，D-2）
    case missingCofferBinary
    /// manifest 写入失败：无法创建目录 / 写文件（含沙盒拒绝）
    case manifestWriteFailed(BrowserKind, String)
    /// broker spawn 失败（Process 无法启动）
    case brokerSpawnFailed(String)
    /// 其他未预期错误
    case unexpected(String)

    /// 用户可操作文案（AppModel catch 分支经 lastErrorMessage 呈现）。
    var userText: String {
        switch self {
        case .missingCofferBinary:
            return "未找到 coffer 命令（App 包内或 PATH），无法启用浏览器集成。"
        case .manifestWriteFailed(let browser, let detail):
            return "无法写入 \(browser.displayName) 的浏览器集成配置文件（\(detail)）。"
        case .brokerSpawnFailed(let detail):
            return "浏览器集成后台进程启动失败（\(detail)）。"
        case .unexpected(let detail):
            return "浏览器集成操作失败（\(detail)）。"
        }
    }
}

/// native messaging host manifest（docs/31 §6.2；host_name = com.coffer.browser）。
/// JSON 构造为纯函数（可单测断言字段）；写入/删除为显式 I/O（错误上抛）。
enum BrowserManifest {
    /// native messaging host 名（docs/31 §6.2，manifest 文件名与之对应）。
    static let hostName = "com.coffer.browser"

    /// shim 文件名（嵌套 bundle 内与 coffer 二进制同级，G-E 装配）。
    ///
    /// 机制（docs/31 §6.2）：manifest `path` 不能传参 → 指向 bundle 内 shim
    /// （shell 脚本，`exec` 保父进程链 + PID 不变 → `browser-agent` 验父进程 =
    /// 浏览器仍成立）。shim 位于签名 bundle 内（受 seal 覆盖）、无受限
    /// entitlement（AMFI 门禁不适用）。**合并期验收项**：确切路径由 G-E
    /// build_macos_app.sh step 3.5 装配，此处为 G-D 侧约定（改动即本常量一处）。
    static let shimFilename = "browser-agent"

    // D-4 冻结占位（docs/31 §6.1 / 31a D-4，发布前必须定稿）：
    // 与 G-C extension manifest 对齐（G-C 2026-10-07 答复 verbatim：
    //   key: "PENDING_COFFER_CHROME_EXTENSION_KEY_BASE64"
    //   gecko.id: "PENDING_COFFER_GECKO_ID"）。
    // 占位串带 PENDING_ 标记，防止误当正式 ID 上架（改 ID = 全量重配）。
    // 注：Chrome/Edge 的 allowed_origins 理论上应是 key 派生出的扩展 ID（占位串
    // 非合法公钥、unpacked 按路径派发随机 ID），故本清单在 D-4 定稿前**不具
    // 运行可用性**——本地端到端调试须临时改成本机 chrome://extensions 实际 ID
    // （不进版本库），发布前统一替换回真实值。见合并期验收项 4。
    /// Chrome 扩展 ID 占位（allowed_origins 引用，对齐 G-C key 占位串）。
    static let chromeExtensionID = "PENDING_COFFER_CHROME_EXTENSION_KEY_BASE64"
    /// Edge 扩展 ID 占位（allowed_origins 引用，对齐 G-C key 占位串）。
    static let edgeExtensionID = "PENDING_COFFER_CHROME_EXTENSION_KEY_BASE64"
    /// Firefox 扩展 GUID 占位（allowed_extensions 引用，对齐 G-C gecko.id 占位串）。
    static let firefoxGUID = "PENDING_COFFER_GECKO_ID"

    /// shim 绝对路径：coffer 二进制所在目录下的 shimFilename（同目录，
    /// `Contents/Helpers/coffer.app/Contents/MacOS/`，docs/31 §6.2）。
    static func shimPath(cofferBinaryPath: String) -> String {
        URL(fileURLWithPath: cofferBinaryPath)
            .deletingLastPathComponent()
            .appendingPathComponent(shimFilename)
            .path
    }

    /// 生成 manifest 字典（纯函数，可单测断言字段）。
    ///
    /// 字段（docs/31 §6.2 / Chrome native messaging host manifest 规范）：
    ///   - name / description / type 三浏览器同构
    ///   - path → shim 绝对路径（bundle 内）
    ///   - Chrome/Edge：`allowed_origins`（chrome-extension://<ID>/，D-4 冻结）
    ///   - Firefox：`allowed_extensions`（GUID）
    static func json(browser: BrowserKind, shimPath: String) -> [String: Any] {
        var dict: [String: Any] = [
            "name": hostName,
            "description": "Coffer browser bridge (native messaging host)",
            "path": shimPath,
            "type": "stdio",
        ]
        switch browser {
        case .chrome, .edge:
            let id = (browser == .chrome ? chromeExtensionID : edgeExtensionID)
            dict["allowed_origins"] = ["chrome-extension://\(id)/"]
        case .firefox:
            dict["allowed_extensions"] = [firefoxGUID]
        }
        return dict
    }

    /// 写入 manifest（幂等覆盖，docs/31 §6.2「停用即删除」的反向）。创建
    /// NativeMessagingHosts 目录（含中间级）。homeDirectory 注入便于单测
    /// （临时根目录，不 touch 真实 ~）。
    /// - Returns: 写入的绝对路径（单测断言用）。
    @discardableResult
    static func write(browser: BrowserKind, shimPath: String, homeDirectory: String) throws -> String {
        let path = BrowserManifestPaths.manifestPath(browser: browser, homeDirectory: homeDirectory)
        let url = URL(fileURLWithPath: path)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try JSONSerialization.data(
                withJSONObject: json(browser: browser, shimPath: shimPath),
                options: [.prettyPrinted, .sortedKeys])
            try data.write(to: url, options: .atomic)
        } catch {
            throw BrowserIntegrationError.manifestWriteFailed(browser, error.localizedDescription)
        }
        return path
    }

    /// 删除 manifest（幂等：不存在视为成功，docs/31 §6.2「停用即删除」）。
    /// - Returns: 是否实际删除了文件（单测断言用）。
    @discardableResult
    static func delete(browser: BrowserKind, homeDirectory: String) throws -> Bool {
        let path = BrowserManifestPaths.manifestPath(browser: browser, homeDirectory: homeDirectory)
        guard FileManager.default.fileExists(atPath: path) else { return false }
        do {
            try FileManager.default.removeItem(atPath: path)
        } catch {
            throw BrowserIntegrationError.unexpected("删除 \(browser.displayName) manifest 失败：\(error.localizedDescription)")
        }
        return true
    }
}

/// broker（browser-broker）进程管理（D-2：复用嵌套 bundle coffer 二进制
/// browser-broker 子命令，长驻 daemon，App 解锁 spawn / 锁定 kill，锁态镜像
/// docs/31 §2.1/§4.1/§3.4——会话密钥随进程销毁）。
struct BrowserBroker {
    /// spawn 配置（集中点：G-B 落盘后按 frozen CLI 对齐，见合并期验收项）。
    enum SpawnConfig {
        /// browser-broker 子命令名（D-2）。
        static let subcommand = "browser-broker"
        /// UDS 参数（docs/31 §9.1 G-B：`coffer browser-broker --uds` 起服务）。
        static let udsFlag = "--uds"
        /// 库目录 env（escrow 免密解锁，docs/31 §4.1；与 `coffer mcp
        /// --provider coffer` 同款取密语义，docs/29 §4）。
        static let vaultDirEnv = "COFFER_VAULT_DIR"
        /// UDS socket 相对 App Library 的路径（私有父目录，docs/31 §3.1
        /// dir 0700/file 0600 纪律）。
        static let socketRelativePath = "Application Support/Coffer/browser/broker.sock"
    }

    /// UDS socket 绝对路径（App 沙盒容器内——broker 非沙盒可 bind）。
    static func brokerSocketPath(baseLibraryDirectory: String) -> String {
        (baseLibraryDirectory as NSString).appendingPathComponent(SpawnConfig.socketRelativePath)
    }

    /// 创建 UDS 私有父目录（docs/31 §3.1：dir 0700）。幂等；失败上抛。
    static func prepareSocketDirectory(baseLibraryDirectory: String) throws {
        let dir = (baseLibraryDirectory as NSString)
            .appendingPathComponent("Application Support/Coffer/browser")
        let fm = FileManager.default
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
    }

    /// spawn broker（App 解锁时调用，docs/31 §2.1 状态机 running）。
    ///
    /// - Parameters:
    ///   - executable: coffer 二进制绝对路径（McpStatusProbe.cofferBinaryPath）。
    ///   - arguments: 子命令 + 参数（如 browser-broker --uds <socketPath>）。
    ///   - environment: 追加到当前环境的键值（如 COFFER_VAULT_DIR=<vaultDir>）。
    /// - Returns: 已启动的 Process（调用方持有，lock/termination 时 kill）。
    /// - Throws: `.brokerSpawnFailed`（Process 无法启动，fail-closed）。
    static func spawn(
        executable: String,
        arguments: [String],
        environment: [String: String]
    ) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        var env = ProcessInfo.processInfo.environment
        for (key, value) in environment { env[key] = value }
        process.environment = env
        do {
            try process.run()
        } catch {
            throw BrowserIntegrationError.brokerSpawnFailed(error.localizedDescription)
        }
        return process
    }

    /// kill broker（App 锁定 / 退出 / 停用时调用，docs/31 §2.1 状态机 killed）。
    /// 幂等：未启动 / 已退出进程直接返回。SIGTERM 先发，超时未退出补 SIGKILL
    /// （锁态镜像保证：会话密钥随进程销毁，docs/31 §3.4）。
    static func kill(process: Process?, timeout: TimeInterval = 2.0) {
        guard let process, process.isRunning else { return }
        process.terminate()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            // Darwin.kill 显式限定：本类型有同名 static 方法 kill(process:timeout:)
            Darwin.kill(process.processIdentifier, SIGKILL)
        }
        process.waitUntilExit()
    }
}

// MARK: - 配对确认（docs/31 §2.3 / §4.2 / §5.3）

/// 配对确认请求（扩展首连 → broker 上报 App，弹配对确认）。
/// 纯数据：浏览器 + 扩展 ID + 权限说明 + 时间戳。**不含任何密钥材料**。
struct BrowserPairingRequest: Equatable {
    /// 发起配对的浏览器（broker 上报；G-B IPC 集成前为占位来源）。
    let browser: BrowserKind
    /// 扩展 ID / GUID（与 manifest allowed_origins/allowed_extensions 对应）。
    let extensionID: String
    /// 权限说明（固定文案，随请求下发，UI 呈现给用户复核）。
    let permissionDescription: String
    /// 请求到达时间（展示时序用）。
    let requestedAt: Date
}

/// 配对决策（批准/拒绝）。**批准才触发 broker 下发 PSK + 公钥**（docs/31 §5.3）
/// ——下发动作在 broker（Rust 侧 G-A/G-B），App 侧只做决策门 + 转发。本类型只
/// 携带决策元数据，**不含 PSK / 公钥**（密钥材料不进 App 状态、不进日志）。
struct BrowserPairingDecision: Equatable {
    let browser: BrowserKind
    let extensionID: String
    let approved: Bool
    let decidedAt: Date
}

/// 配对决策转发 seam（docs/31 §5.3：显式批准才下发 PSK + 公钥）。
///
/// G-B broker IPC 落盘前为**内存记录**实现（RecordingBrowserPairingResponder）；
/// broker 的配对确认通道（UDS / 私有文件）集成后替换为真实传输实现并经
/// AppModel 注入——**合并期验收项**（决策 → broker 下发 PSK 的端到端链路）。
protocol BrowserPairingResponder {
    func respond(_ decision: BrowserPairingDecision)
}

/// 内存记录 responder（当前默认 + 单测用）：只记录决策元数据，无密钥材料。
final class RecordingBrowserPairingResponder: BrowserPairingResponder {
    private(set) var decisions: [BrowserPairingDecision] = []

    func respond(_ decision: BrowserPairingDecision) {
        decisions.append(decision)
    }
}
