// BrowserIntegration.swift —— 浏览器集成的 App 侧平台层（docs/31 §6.2 / §9.1 G-D）。
//
// 职责三件：
//   ① native messaging manifest 写入/删除（各浏览器 NativeMessagingHosts 目录，
//      docs/31 §6.2；host_name = com.coffer.browser，path → bundle 内 shim）
//   ② broker 进程管理（spawn browser-broker / kill；D-2 复用嵌套 bundle coffer
//      二进制，App 解锁 spawn / 锁定 kill，锁态镜像 docs/31 §2.1/§4.1）
//   ③ 配对确认请求/响应模型与决策转发 seam（docs/31 §2.3/§4.2/§5.3：显式用户
//      批准才下发 PSK + broker 公钥）。**本文件不接触任何密钥材料**——决策①：
//      PSK 由 App 生成并存 keychain（BrowserPairingKeychain）、经 stdin 注入
//      broker、批准时随 pair_decision 一次性下发；broker 公钥由 broker 启动自报
//      （D-B：broker 身份确定性派生，App 侧无 P-256 复刻）。App 侧只做批准门 +
//      决策转发（BrowserPairingResponder seam，真实实现写 notify.sock）。
//
// 沙盒边界（Design Y 冻结，docs/31 r0.7 = d556e65）：生产 App 形态 = 去沙盒
// （Developer ID 非沙盒分发）——沙盒 `AF_UNIX bind` 被 `deny network*` 拦截 +
// 沙盒继承致「App 父进程」模型不成立（Wave-4 实证，/tmp/coffer-wave4/
// probe_*.log）。本文件据此以真实主目录为锚：manifest 写真实 ~/Library/
// NativeMessagingHosts、broker UDS 落 well-known `~/Library/Application Support/
// Coffer/browser/broker.sock`（0700/0600）。零网络由 check_no_network 代码门禁
// 承接（D-6 先例）。写入错误仍显式上抛（fail-closed），由 UI 呈现可操作文案。
// **合并期验收项**：build 侧去沙盒 + entitlement 变更归 G-E/lead 装配。
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
    /// docs/31 §6.2 L314：签名 Mach-O shim 装配 `Contents/Helpers/coffer-shim`
    /// （G-E step 3.5，tools/coffer-shim.c），manifest path → shim → exec
    /// coffer browser-agent。
    static let shimFilename = "coffer-shim"

    // D-4 正式冻结（2026-10-08 定稿，不可逆——改 ID 须全量重配）：
    // 与 G-C extension manifest 对齐（扩展仓 manifest.json key 派生，3f5a5fd）：
    //   key SPKI base64 见 coffer-browser-extension/manifest.json
    //   私钥：~/work/coffer-extension-keys/coffer-extension.pem（仓外，勿泄露）
    // Chrome/Edge allowed_origins = key 派生 ID；Firefox allowed_extensions = gecko.id。
    /// Chrome 扩展 ID（正式冻结）：imbfngccmiiocfalfmmijccmnkkhlibe
    static let chromeExtensionID = "imbfngccmiiocfalfmmijccmnkkhlibe"
    /// Edge 扩展 ID（正式冻结）：与 Chrome 同 key 派生同 ID。
    static let edgeExtensionID = "imbfngccmiiocfalfmmijccmnkkhlibe"
    /// Firefox 扩展 GUID（正式冻结）：coffer@cygnusyang.com（对齐 G-C gecko.id）。
    static let firefoxGUID = "coffer@cygnusyang.com"

    /// shim 绝对路径（docs/31 §6.2 L314：manifest path → shim → exec coffer
    /// browser-agent）。shim 装配于 bundle `Contents/Helpers/` 层
    /// （`Contents/Helpers/coffer-shim`，G-E step 3.5），而 coffer 二进制在
    /// 嵌套 bundle `Contents/Helpers/coffer.app/Contents/MacOS/coffer`——
    /// 故从 coffer 二进制上溯 4 级（MacOS/Contents/coffer.app → Helpers）
    /// 再拼 shimFilename，而非二进制同级（旧 `browser-agent` 语义作废）。
    static func shimPath(cofferBinaryPath: String) -> String {
        var url = URL(fileURLWithPath: cofferBinaryPath)
        // 上溯到 `Contents/Helpers` 层：coffer.app/Contents/MacOS/coffer
        // → Helpers（4 级：MacOS → Contents → coffer.app → Helpers）。
        for _ in 0..<4 {
            url = url.deletingLastPathComponent()
        }
        return url.appendingPathComponent(shimFilename).path
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
        /// 库目录 env（broker stdin DEK 直开：App 解锁后经 stdin 注入
        /// DEK 以 unlock_with_dek 直开，docs/31 §4.1——broker 与 escrow 零
        /// 耦合；同款取密语义见 `coffer mcp --provider coffer`，docs/29 §4）。
        static let vaultDirEnv = "COFFER_VAULT_DIR"
        /// well-known UDS 相对真实主目录的固定路径（HIGH-2 ②：host 无法经 env
        /// 拿到 `$COFFER_BROKER_UDS`——Chrome 不注入 env，须 well-known 固定路径；
        /// broker 与 host 共用同一落点，docs/31 §3.1 私有父目录 0700/0600）。
        /// 长度守卫：`~/Library/Application Support/Coffer/browser/broker.sock`
        /// 实测 68B << AF_UNIX sun_path 104B（Wave-4 实证，/tmp/coffer-wave4）。
        static let wellKnownUDSPathRelative = "Library/Application Support/Coffer/browser/broker.sock"

        /// well-known notify.sock 相对真实主目录的固定路径（契约 §2.3/§6.1：
        /// 与 broker.sock 同目录同公式——broker 监听、App 客户端持长连，68B ≪
        /// AF_UNIX sun_path 104B）。
        static let notifyUDSPathRelative = "Library/Application Support/Coffer/browser/notify.sock"

        /// well-known UDS 绝对路径（homeDirectory 注入便于单测临时根目录）。
        static func wellKnownUDSPath(homeDirectory: String) -> String {
            (homeDirectory as NSString).appendingPathComponent(wellKnownUDSPathRelative)
        }

        /// well-known notify.sock 绝对路径（homeDirectory 注入便于单测临时根目录）。
        static func notifyUDSPath(homeDirectory: String) -> String {
            (homeDirectory as NSString).appendingPathComponent(notifyUDSPathRelative)
        }
    }

    /// well-known UDS 绝对路径（HIGH-2 ② 冻结落点：真实主目录 + 固定相对路径，
    /// Design Y 去沙盒后 App/broker/host 共用，host 无需 env 发现）。
    static func brokerSocketPath(homeDirectory: String) -> String {
        SpawnConfig.wellKnownUDSPath(homeDirectory: homeDirectory)
    }

    /// well-known notify.sock 绝对路径（契约 §2.3：App 客户端连接的目标）。
    static func notifySocketPath(homeDirectory: String) -> String {
        SpawnConfig.notifyUDSPath(homeDirectory: homeDirectory)
    }

    /// 创建 UDS 私有父目录（docs/31 §3.1：dir 0700）。幂等——已存在不动其权限
    /// （与 G-B cli.rs ensure_broker_parent_dir 语义一致）；失败上抛。
    static func prepareSocketDirectory(homeDirectory: String) throws {
        let socketPath = SpawnConfig.wellKnownUDSPath(homeDirectory: homeDirectory)
        let dir = (socketPath as NSString).deletingLastPathComponent
        let fm = FileManager.default
        guard !fm.fileExists(atPath: dir) else { return }
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
    }

    /// spawn broker（App 解锁时调用，docs/31 §2.1 状态机 running）。
    ///
    /// - Parameters:
    ///   - executable: coffer 二进制绝对路径（McpStatusProbe.cofferBinaryPath）。
    ///   - arguments: 子命令 + 参数（如 browser-broker --uds <socketPath>）。
    ///   - environment: 追加到当前环境的键值（如 COFFER_VAULT_DIR=<vaultDir>）。
    ///   - stdinPayload: stdin 私有管道载荷（HIGH-3，docs/31 §3.1：DEK/UUID/PSK/
    ///     unlocked 四行，写完 close stdin 供 broker 读满零化；**不经 env/argv**，
    ///     `ps eww` 不可读）。传 nil 不接 stdin（沿用默认继承）。传入的 Data 为
    ///     值类型副本——本函数写后覆零该副本；调用方持有的原副本自行 zeroize。
    /// - Returns: 已启动的 Process（调用方持有，lock/termination 时 kill）。
    /// - Throws: `.brokerSpawnFailed`（Process 无法启动，fail-closed）。
    static func spawn(
        executable: String,
        arguments: [String],
        environment: [String: String],
        stdinPayload: Data? = nil
    ) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        var env = ProcessInfo.processInfo.environment
        for (key, value) in environment { env[key] = value }
        process.environment = env
        if stdinPayload != nil {
            process.standardInput = Pipe()
        }
        do {
            try process.run()
        } catch {
            throw BrowserIntegrationError.brokerSpawnFailed(error.localizedDescription)
        }
        if let stdinPipe = process.standardInput as? Pipe, let payload = stdinPayload {
            // M-6 核销（KNOWN-ISSUES.md:1100）：broker 早退写 stdin 不崩 App——
            //   ① 写端先置 SO_NOSIGPIPE（fcntl F_SETNOSIGPIPE）：子进程关读端后
            //      write 返回 EPIPE 而非投递 SIGPIPE（SIGPIPE 默认终止进程，会绕过
            //      catch 直接崩 App——CLI 测试实证 EXIT=141）。
            //   ② 改用 throwing write(contentsOf:)：EPIPE 抛 Swift 错误（而非
            //      NSFileHandleOperationException），归入 spawn 失败路径
            //      （fail-closed 呈现）。
            // 无论成败：close stdin 收尾（EOF，broker 读满 fail-closed；写失败时
            // close 仍让子进程走 5s 硬超时）+ 本副本覆零（M-7，不吞错不泄材料）。
            var local = payload
            defer { zeroize(&local) }
            do {
                setNoSIGPIPE(fileHandle: stdinPipe.fileHandleForWriting)
                try stdinPipe.fileHandleForWriting.write(contentsOf: payload)
                try? stdinPipe.fileHandleForWriting.close()
            } catch {
                try? stdinPipe.fileHandleForWriting.close()
                throw BrowserIntegrationError.brokerSpawnFailed(
                    "写入 broker stdin 失败（broker 可能已提前退出）：\(error.localizedDescription)")
            }
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

// MARK: - broker stdin 私有管道（HIGH-3：密钥不经 env/argv，docs/31 §3.1）

/// broker 解锁/配对材料（stdin 私有管道载荷，§3.1 冻结格式）。
///
/// 四行（LF 结尾）：`DEK_HEX` / `VAULT_UUID_HEX` / `PSK_HEX` / `UNLOCKED`，
/// 与 G-B cli.rs `resolve_broker_secrets` 的解析面一致（env 名即 key）。密钥材料
/// 仅存在于本结构体内存 + 序列化 Data 中，不进日志、不经 env/argv（H-3 核销）。
///
/// 零化纪律（裁定书 §1.4 / KNOWN-ISSUES M-7）：
///   - `dekBytes` 持 FFI exportDek() 的原始 32 字节（非 hex 串），组帧时
///     **hex 直编进 Data，不经中间 String**——Swift String 的 ARC/COW 存储无法
///     可靠覆零，是本链路的唯一薄弱点（§1.4 明令规避）。
///   - `vaultUUIDHex` / `pskHex` 为源串（CoW Swift String，G-D 裁定**不 zeroize**，
///     防止过度覆零破坏源串语义）。
///   - 调用方在 `payload` 写 stdin 后调用 `zeroizeDek()` 覆零 DEK 原始字节副本
///     （R1-2/M-7 用后即毁；Data 值语义仅覆零当前副本，COW 共享缓冲不触及——
///     已接受残余）。
struct BrokerStdinSecrets {
    /// vault 数据加密密钥（32 字节原始值，来自 FFI `VaultSession.exportDek()`）。
    /// `var` 仅服务于 `zeroizeDek()` 的覆零突变，不改语义。
    var dekBytes: Data
    /// vault UUID（16 字节 hex，32 字符）。
    let vaultUUIDHex: String
    /// 配对 PSK（32 字节 hex，64 字符）。
    let pskHex: String
    /// 解锁态标记（true = 已解锁，可服务扩展请求）。
    let unlocked: Bool

    /// 序列化为 §3.1 四行（LF 结尾）的 UTF-8 载荷。
    ///
    /// DEK 十六进制**直接逐字节进 Data**（`appendHex`，不经中间 String）——
    /// 满足 §1.4 零化纪律；vault_uuid/psk 为源串（CoW String）直接 UTF-8 拷贝。
    var payload: Data {
        var data = Data()
        data.append(Data("DEK_HEX=".utf8))
        appendHex(dekBytes, into: &data)
        data.append(Data("\nVAULT_UUID_HEX=".utf8))
        data.append(Data(vaultUUIDHex.utf8))
        data.append(Data("\nPSK_HEX=".utf8))
        data.append(Data(pskHex.utf8))
        data.append(Data("\nUNLOCKED=".utf8))
        data.append(Data((unlocked ? "1\n" : "0\n").utf8))
        return data
    }

    /// 用后即毁（R1-2/M-7 best-effort 纵深）：覆零 DEK 原始字节副本。调用方在
    /// `payload` 写 stdin 后调用（AppModel.startBrowserBrokerIfNeeded）。Data 值
    /// 语义下仅覆零当前副本（COW 共享缓冲的其它副本不触及，属 M-7 已接受残余）。
    mutating func zeroizeDek() {
        zeroize(&dekBytes)
    }
}

/// 把字节流的十六进制编码（小写，2 字符/字节）**直接追加进 Data**——DEK 十六进制
/// 必经此路径（不经中间 String，§1.4 零化纪律）。hex 表为编译期常量（非密钥材料），
/// 局部构造无泄漏面。
private func appendHex(_ bytes: Data, into out: inout Data) {
    let hexTable: [UInt8] = Array("0123456789abcdef".utf8)
    out.reserveCapacity(out.count + bytes.count * 2)
    for byte in bytes {
        out.append(hexTable[Int(byte >> 4)])
        out.append(hexTable[Int(byte & 0x0f)])
    }
}

/// 覆零字节缓冲（用后即毁：stdin 载荷写完即零化，密钥材料不进日志、不残留）。
/// Data 为值类型——调用方持有的原副本须自行传入本函数（spawn 内部只零化其副本）。
func zeroize(_ data: inout Data) {
    data.withUnsafeMutableBytes { buffer in
        guard let base = buffer.baseAddress else { return }
        memset(base, 0, buffer.count)
    }
}

/// 为 stdin 管道写端设置 SO_NOSIGPIPE（Darwin fcntl F_SETNOSIGPIPE）。
///
/// M-6 前置（KNOWN-ISSUES.md:1100）：broker 早退关读端后，未设 SO_NOSIGPIPE 的
/// write 会投递 SIGPIPE（默认终止进程）→ 绕过 throwing catch 直接崩 App（CLI
/// 实证 EXIT=141）；设置后 write 返回 EPIPE，由 M-6 的 throwing write 捕获并归入
/// spawn 失败路径。fcntl 返回 -1（fd 非法等）仅静默忽略——退化回 OS 默认
/// （SIGPIPE 语义），不额外吞写错误（写路径本身仍 throwing）。
private func setNoSIGPIPE(fileHandle: FileHandle) {
    let fd = fileHandle.fileDescriptor
    if fd >= 0 {
        _ = fcntl(fd, F_SETNOSIGPIPE, 1)
    }
}

// MARK: - 配对确认（docs/31 §2.3 / §4.2 / §5.3）

/// 配对确认请求（扩展首连 → broker 上报 App，弹配对确认）。
/// 纯数据：浏览器 + 扩展 ID + 权限说明 + request_id + 时间戳。**不含任何密钥
/// 材料**。
struct BrowserPairingRequest: Equatable {
    /// 发起配对的浏览器（broker 上报；G-B IPC 集成前为占位来源）。
    let browser: BrowserKind
    /// 扩展 ID / GUID（与 manifest allowed_origins/allowed_extensions 对应）。
    let extensionID: String
    /// 权限说明（固定文案，随请求下发，UI 呈现给用户复核）。
    let permissionDescription: String
    /// broker 分配的单调配对 request_id（决策帧回写匹配，契约 §2.3）。
    let requestId: Int
    /// 请求到达时间（展示时序用）。
    let requestedAt: Date

    /// App 侧常量权限文案（契约 §2.3：不由扩展/broker 供给，防扩展伪造文案
    /// 诱导；BrokerNotifyClient 组请求与 BrowserSettingsView 呈现共用）。
    static let defaultPermissionDescription =
        "访问本机密码库中的已绑定凭据（仅在你显式操作时填充）"
}

/// 配对决策（批准/拒绝）。**批准才触发 broker 下发 PSK + 公钥**（docs/31 §5.3）
/// ——下发动作在 broker（Rust 侧 G-A/G-B），App 侧只做决策门 + 转发。本类型只
/// 携带决策元数据，**不含 PSK / 公钥**（密钥材料不进 App 状态、不进日志）。
struct BrowserPairingDecision: Equatable {
    let browser: BrowserKind
    let extensionID: String
    /// 对应配对请求的 request_id（决策帧回写匹配，契约 §2.3）。
    let requestId: Int
    let approved: Bool
    let decidedAt: Date
}

/// 配对弹框结束态（视图呈现 拒绝/超时 文案，契约 §8-3「超时即拒」）。
enum BrowserPairingDismissal: Equatable {
    /// 用户显式批准。
    case approved
    /// 用户显式拒绝。
    case rejected
    /// 未获用户决策即关闭：pair_cancel（扩展断连/超时）或 App 侧 120s 超时兜底。
    case cancelled(reason: String)
}

/// 配对决策转发 seam（docs/31 §5.3：显式批准才下发 PSK + 公钥）。
///
/// G-B broker IPC 落盘前为**内存记录**实现（RecordingBrowserPairingResponder）；
/// broker 的配对确认通道（UDS / 私有文件）集成后替换为真实传输实现并经
/// AppModel 注入——**合并期验收项**（决策 → broker 下发 PSK 的端到端链路）。
protocol BrowserPairingResponder {
    func respond(_ decision: BrowserPairingDecision)
}

/// 内存记录 responder（默认 + 单测用）：只记录决策元数据，无密钥材料。
final class RecordingBrowserPairingResponder: BrowserPairingResponder {
    private(set) var decisions: [BrowserPairingDecision] = []

    func respond(_ decision: BrowserPairingDecision) {
        decisions.append(decision)
    }
}

/// 真实配对决策 responder（决策①③：决策 → notify.sock 写 pair_decision，契约
/// §2.3/§4）。批准时从 keychain 取回**同一** PSK（psKHexLoader——与 spawn 时
/// stdin PSK_HEX= 注入同源）随帧下发；拒绝 / PSK 缺失（keychain 项被删）→
/// approved:false（fail-closed，绝不伪造材料）。sendFrame 注入便于单测记录。
final class NotifyBrowserPairingResponder: BrowserPairingResponder {
    private let sendFrame: (NotifyFrame) -> Void
    private let pskHexLoader: () -> String?
    private let log: (String) -> Void

    init(sendFrame: @escaping (NotifyFrame) -> Void,
         pskHexLoader: @escaping () -> String?,
         log: @escaping (String) -> Void = { _ in }) {
        self.sendFrame = sendFrame
        self.pskHexLoader = pskHexLoader
        self.log = log
    }

    func respond(_ decision: BrowserPairingDecision) {
        var pskHex: String?
        if decision.approved {
            guard let loaded = pskHexLoader(), !loaded.isEmpty else {
                log("NotifyBrowserPairingResponder：批准配对但 PSK 缺失（keychain 项被删？），按拒绝处理")
                sendFrame(.pairDecision(requestId: decision.requestId, approved: false, pskHex: nil))
                return
            }
            pskHex = loaded
        }
        sendFrame(.pairDecision(requestId: decision.requestId, approved: decision.approved, pskHex: pskHex))
    }
}
