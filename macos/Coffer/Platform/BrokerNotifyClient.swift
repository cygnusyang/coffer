// BrokerNotifyClient.swift —— notify.sock 反向通道客户端（配对集成契约 v2.3.0 §2.3）。
//
// 拓扑（契约 §2.1/§2.2 选型 A 采纳）：broker 在 well-known 目录监听第二个 UDS
// notify.sock；**App 以客户端身份持长连**（不新增监听线程，维持「App 不宿主
// 服务器」判据 docs/20 §6.2）。broker 侧鉴权 = `peer_pid(stream)==getppid()`——
// 仅 App 能是 broker 父进程，故 App 侧无需额外认证（本机路径 + 自有 broker）。
//
// 职责：
//   ① spawn broker 成功后重试 connect（短退避，覆盖 broker bind 启动窗）；
//   ② 读决策线程：4B LE 长度前缀 + JSON 帧（复用 broker.sock 同款帧格式），
//      pair_request → 构造 BrowserPairingRequest 经 onPairRequest 回调（调用方
//      负责 hop 到 MainActor——AppModel 用 Task @MainActor 接 submitPendingPairing）；
//      pair_cancel → onPairCancel(request_id)（关弹框）；
//   ③ 断线（broker 被杀）→ EOF 清理连接态 + 短退避重连；
//   ④ send(frame:) 写 pair_decision 回 broker（批准时含 PSK，契约 §4）。
//
// 测试纪律：不直接依赖 AppModel（闭包注入），socket 路径可注入（单测用临时
// UDS 目录 + 仿 broker 监听器）。决策帧含 PSK 明文 → 序列化 Data 副本用后覆零
// （G-D 纪律：只 zeroize Data 副本，不 zeroize CoW Swift String 源串）。

import Darwin
import Foundation

/// notify.sock 帧（契约 §2.3，JSON snake_case，4B LE 长度前缀）。
enum NotifyFrame: Equatable {
    /// broker → App：扩展配对请求（requested_at 为毫秒时间戳）。
    case pairRequest(requestId: Int, browser: BrowserKind, extensionID: String, requestedAt: Int)
    /// broker → App：扩展断连/超时，关弹框。
    case pairCancel(requestId: Int, reason: String)
    /// App → broker：配对决策；批准时携带 PSK（hex，契约 §4）。
    case pairDecision(requestId: Int, approved: Bool, pskHex: String?)
}

/// notify.sock 帧编解码（4B LE 长度前缀 + JSON，契约 §2.3；与 broker.sock 同款
/// read_frame/write_frame）。纯函数，无 IO，可独立单测。
enum NotifyFrameCodec {
    /// 单帧最大 JSON 载荷（防御性上限：1MiB，防恶意/损坏帧撑爆内存）。
    static let maxPayloadBytes = 1 << 20

    /// 编码为 4B LE 长度前缀 + UTF-8 JSON。
    static func encode(_ frame: NotifyFrame) -> Data {
        let json: [String: Any]
        switch frame {
        case .pairRequest(let requestId, let browser, let extensionID, let requestedAt):
            json = ["type": "pair_request",
                    "request_id": requestId,
                    "browser": browser.rawValue,
                    "extension_id": extensionID,
                    "requested_at": requestedAt]
        case .pairCancel(let requestId, let reason):
            json = ["type": "pair_cancel", "request_id": requestId, "reason": reason]
        case .pairDecision(let requestId, let approved, let pskHex):
            var j: [String: Any] = ["type": "pair_decision", "request_id": requestId, "approved": approved]
            if let pskHex { j["psk"] = pskHex }   // 批准才下发明文 PSK（契约 §4）
            json = j
        }
        guard let payload = try? JSONSerialization.data(withJSONObject: json) else {
            // 编码失败只可能来自参数类型错误（Int/String/Bool 均可序列化）——
            // 防御性返回空帧（调用方 fail-closed）。
            return Data()
        }
        let length = UInt32(payload.count)
        var data = Data()
        data.reserveCapacity(4 + payload.count)
        data.append(UInt8(truncatingIfNeeded: length & 0xff))
        data.append(UInt8(truncatingIfNeeded: (length >> 8) & 0xff))
        data.append(UInt8(truncatingIfNeeded: (length >> 16) & 0xff))
        data.append(UInt8(truncatingIfNeeded: (length >> 24) & 0xff))
        data.append(payload)
        return data
    }

    /// 解码 JSON 载荷（不含长度前缀）→ 帧。非法 JSON / 未知 type / 缺字段 /
    /// 超长 → nil（fail-closed）。
    static func decode(_ payload: Data) -> NotifyFrame? {
        guard payload.count <= maxPayloadBytes,
              let obj = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let type = obj["type"] as? String else { return nil }
        switch type {
        case "pair_request":
            guard let requestId = obj["request_id"] as? Int,
                  let browserRaw = obj["browser"] as? String,
                  let browser = BrowserKind(rawValue: browserRaw),
                  let extensionID = obj["extension_id"] as? String,
                  let requestedAt = obj["requested_at"] as? Int else { return nil }
            return .pairRequest(requestId: requestId, browser: browser, extensionID: extensionID, requestedAt: requestedAt)
        case "pair_cancel":
            guard let requestId = obj["request_id"] as? Int,
                  let reason = obj["reason"] as? String else { return nil }
            return .pairCancel(requestId: requestId, reason: reason)
        case "pair_decision":
            guard let requestId = obj["request_id"] as? Int,
                  let approved = obj["approved"] as? Bool else { return nil }
            let pskHex = obj["psk"] as? String
            return .pairDecision(requestId: requestId, approved: approved, pskHex: pskHex)
        default:
            return nil
        }
    }
}

/// notify.sock 客户端（契约 §2.3：App 客户端持长连，读决策线程 + 重连）。
///
/// 线程模型：`start()` 在后台队列跑连接 + 读循环；帧回调从读线程触发，调用方
/// 负责 hop 到 MainActor（AppModel 用 `Task { @MainActor ... }`）。断线（EOF）→
/// onDisconnect + 短退避重连（200ms 起步，覆盖 broker bind 启动窗，契约 §2.3）。
/// `stop()` 置 running=false 并关 socket——安全退出依赖「先让对端 EOF、stop 落在
/// 退避睡眠窗口」的顺序（生产：AppModel 先 kill broker 再 stop 本客户端）。
final class BrokerNotifyClient {
    /// 连接失败 / 断线后的重连最小退避（秒）：覆盖 broker bind 启动窗，又给
    /// stop() 留出「读循环自然 EOF 后」安全退出的窗口（读线程不被跨线程关
    /// 阻塞 read）。
    private static let reconnectBackoff: TimeInterval = 0.2

    private let socketPath: String
    private let onPairRequest: (BrowserPairingRequest) -> Void
    private let onPairCancel: (Int) -> Void
    private let onDisconnect: () -> Void
    private let log: (String) -> Void

    /// 当前已连接 socket fd（读线程写、send/stop 读，经 stateLock 串行）。
    private var fd: Int32 = -1
    private var running = false
    private let stateLock = NSLock()
    private let queue = DispatchQueue(label: "cn.coffer.broker-notify-client")

    init(socketPath: String,
         onPairRequest: @escaping (BrowserPairingRequest) -> Void,
         onPairCancel: @escaping (Int) -> Void,
         onDisconnect: @escaping () -> Void,
         log: @escaping (String) -> Void = { _ in }) {
        self.socketPath = socketPath
        self.onPairRequest = onPairRequest
        self.onPairCancel = onPairCancel
        self.onDisconnect = onDisconnect
        self.log = log
    }

    deinit {
        stop()
    }

    var isRunning: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return running
    }

    /// 启动连接 + 读循环（后台线程）。幂等：重复 start 无副作用。
    func start() {
        stateLock.lock()
        guard !running else { stateLock.unlock(); return }
        running = true
        stateLock.unlock()
        queue.async { [weak self] in self?.run() }
    }

    /// 停止：置 running=false 并关 socket。幂等。
    func stop() {
        stateLock.lock()
        running = false
        stateLock.unlock()
        closeSocket()
    }

    /// 写 pair_decision 帧回 broker（批准时含 PSK 明文，契约 §4）。
    /// - Returns: 是否写入成功（无连接 / 写失败 → false，调用方记日志）。
    @discardableResult
    func send(frame: NotifyFrame) -> Bool {
        let data = NotifyFrameCodec.encode(frame)
        guard data.count > 4 else { return false }
        let current = currentFD
        guard current >= 0 else {
            log("BrokerNotifyClient.send：notify.sock 未连接（broker 未运行？），丢弃决策帧")
            return false
        }
        var local = data
        defer { zeroize(&local) }   // 决策帧含 PSK 明文 → 序列化 Data 副本用后覆零
        setNoSIGPIPE(fd: current)
        var offset = 0
        while offset < local.count {
            let n = local.withUnsafeBytes { buf -> Int in
                write(current, buf.baseAddress!.advanced(by: offset), local.count - offset)
            }
            if n <= 0 {
                log("BrokerNotifyClient.send：写入失败（errno=\(errno)）")
                return false
            }
            offset += n
        }
        return true
    }

    // MARK: - 内部

    private func run() {
        while isRunning {
            let connected = connectToServer()
            if connected >= 0 {
                currentFD = connected
                guard isRunning else {
                    // stop() 竞态：连接刚成功即被停 → 关掉新 fd 直接退出
                    Darwin.close(connected)
                    currentFD = -1
                    break
                }
                readLoop(on: connected)
                closeSocket()
                onDisconnect()
            }
            // 短退避：connect 失败（broker 未 bind）与断线重连共用；sleep 期间
            // stop() 置 running=false → 本循环安全退出（读线程不在阻塞 read 中）。
            Thread.sleep(forTimeInterval: Self.reconnectBackoff)
        }
    }

    /// 阻塞读循环：反复读 4B LE 长度 + JSON 载荷，解码分发。
    /// 返回 = EOF / 读错误（调用方清理连接态）。
    private func readLoop(on fd: Int32) {
        while isRunning {
            guard let header = readExact(fd, 4) else { break }
            let length = Int(UInt32(header[0]) | UInt32(header[1]) << 8
                             | UInt32(header[2]) << 16 | UInt32(header[3]) << 24)
            guard length > 0, length <= NotifyFrameCodec.maxPayloadBytes,
                  let payload = readExact(fd, length) else { break }
            guard let frame = NotifyFrameCodec.decode(payload) else {
                log("BrokerNotifyClient：收到不可解析帧（len=\(length)），忽略")
                continue
            }
            dispatch(frame)
        }
    }

    private func readExact(_ fd: Int32, _ count: Int) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count < count {
            let want = min(count - data.count, buffer.count)
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, want) }
            if n <= 0 { return nil }
            data.append(contentsOf: buffer[0..<n])
        }
        return data
    }

    private func dispatch(_ frame: NotifyFrame) {
        switch frame {
        case .pairRequest(let requestId, let browser, let extensionID, let requestedAt):
            onPairRequest(BrowserPairingRequest(
                browser: browser,
                extensionID: extensionID,
                permissionDescription: BrowserPairingRequest.defaultPermissionDescription,
                requestId: requestId,
                requestedAt: Date(timeIntervalSince1970: Double(requestedAt) / 1000.0)))
        case .pairCancel(let requestId, _):
            onPairCancel(requestId)
        case .pairDecision:
            // App 是决策发送方，不预期收到 broker 回发的 pair_decision——忽略。
            break
        }
    }

    private func connectToServer() -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return -1 }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let sunPathSize = MemoryLayout.size(ofValue: addr.sun_path)
        let pathBytes = Array(socketPath.utf8)
        guard pathBytes.count < sunPathSize else {
            Darwin.close(fd)
            return -1
        }
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { dst in
            pathBytes.withUnsafeBufferPointer { src in
                memcpy(dst, src.baseAddress!, pathBytes.count)
            }
        }
        // SUN_LEN（offsetof(sun_path) + strlen + 1）——与 broker.sock 连接同口径
        let sunPathOffset = MemoryLayout<sockaddr_un>.size - sunPathSize
        let addrLen = socklen_t(sunPathOffset + pathBytes.count + 1)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                connect(fd, sp, addrLen)
            }
        }
        if rc != 0 {
            Darwin.close(fd)
            return -1
        }
        return fd
    }

    private func closeSocket() {
        let fd = currentFD
        if fd >= 0 {
            Darwin.close(fd)
            currentFD = -1
        }
    }

    private var currentFD: Int32 {
        get { stateLock.lock(); defer { stateLock.unlock() }; return fd }
        set { stateLock.lock(); fd = newValue; stateLock.unlock() }
    }

    /// 为 socket fd 设置 SO_NOSIGPIPE（Darwin fcntl F_SETNOSIGPIPE）——写决策帧
    /// 时 broker 关读端 → write 返回 EPIPE 而非 SIGPIPE 崩溃（M-6 同款纪律）。
    private func setNoSIGPIPE(fd: Int32) {
        if fd >= 0 {
            _ = fcntl(fd, F_SETNOSIGPIPE, 1)
        }
    }
}
