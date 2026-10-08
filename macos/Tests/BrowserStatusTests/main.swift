// BrowserStatusTests/main.swift —— 浏览器集成 App 侧纯逻辑单元测试
// （docs/31 §6.2 / §9.1 G-D）。
//
// 编译运行：tools/run_browser_status_tests.sh
//
// 被测单元（零 AppKit / 零 CoreBindings 依赖，swiftc 可独立编译）：
//   - BrowserStatus.resolve / label —— 就绪四态判定（docs/31 §6.2；G-A3：
//     三参签名 enabled/coffer/manifest，escrow 已从就绪度解耦——缺项枚举仅两型）
//   - BrowserKind / BrowserManifestPaths —— 浏览器清单目标路径构造（纯函数）
//   - BrowserManifest.json / shimPath —— manifest 内容构造 + shim 路径派生
//   - BrowserManifest.write / delete —— manifest 写入/删除（显式 I/O，临时
//     根目录注入，不 touch 真实 ~；docs/31 §6.2「停用即删除」幂等断言）
//   - BrowserStatusProbe.manifestExists / allManifestsInstalled / brokerProcessRunning
//   - BrowserBroker.spawn / kill —— broker 生命周期（用 /bin/sleep 假进程，
//     不依赖 G-A/G-B 二进制；真 `coffer browser-broker` 集成 = 合并期验收项）
//   - §8 stdin 私有管道 + well-known UDS（HIGH-2 ②/3，docs/31 §3.1）：
//     SpawnConfig.wellKnownUDSPath / brokerSocketPath / prepareSocketDirectory
//     （0700 幂等）、BrokerStdinSecrets.payload（四行冻结格式）、zeroize、
//     spawn stdinPayload（写 4 行 + close stdin，/bin/sh 假读端验证）
//   - BrowserPairingRequest / BrowserPairingDecision / RecordingBrowserPairingResponder
//     —— 配对决策门 + 转发 seam（docs/31 §4.2/§5.3）
//
// 依项目测试纪律（同 TouchIDStatusTests/McpStatusTests）：只测纯逻辑与显式 I/O；
// UserDefaults 读写等 IO 薄封装不在此测（BrowserIntegrationSettings 同规）。

import Darwin
import Foundation

var passed = 0
var failed = 0

func check(_ condition: Bool, _ name: String) {
    if condition {
        passed += 1
        print("✓ \(name)")
    } else {
        failed += 1
        print("✗ \(name)")
    }
}

// 临时根目录（每次写入前重建，隔离测试）
func makeTempRoot() -> String {
    let dir = NSTemporaryDirectory() + "browser-status-tests-\(UUID().uuidString)"
    try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    return dir
}

// ---- 1. BrowserStatus.resolve：disabled 优先级最高（docs/31 §6.2 开关）----

check(
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: false, manifestsInstalled: false) == .disabled,
    "未启用 + 前置全缺失 → disabled"
)
check(
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: true, manifestsInstalled: true) == .disabled,
    "未启用 + 前置全就绪 → disabled（开关优先，镜像 McpStatus 同序）"
)
check(
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: true, manifestsInstalled: false) == .disabled,
    "未启用 + coffer 就绪缺 manifest → disabled（escrow 无关，G-A3 补全真值表）"
)
check(
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: false, manifestsInstalled: true) == .disabled,
    "未启用 + 仅 manifest 就绪 → disabled（escrow 无关，G-A3 补全真值表）"
)

// ---- 2. BrowserStatus.resolve：ready 与缺项（coffer → manifest 顺序）----

// G-A3 核心回归：enabled + coffer + manifest → .ready **无 escrow 参**——resolve
// 三参签名 = escrow 不再是就绪前置（docs/31 §4.1 r0.9「broker escrow 免密自解锁」
// 作废，broker 契约 = App 解锁 + stdin DEK 交付）；修复前 3 参调用不编译 → 恒红。
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: true, manifestsInstalled: true) == .ready,
    "启用 + coffer/manifest 就绪 → ready（就绪度与 escrow 解耦，G-A3）"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: false, manifestsInstalled: true) == .notReady(.missingCofferBinary),
    "缺 coffer 二进制 → missingCofferBinary"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: true, manifestsInstalled: false) == .notReady(.missingManifest),
    "缺 manifest → missingManifest"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: false, manifestsInstalled: false) == .notReady(.missingCofferBinary),
    "全缺 → 报第一个缺项（coffer 优先，sanity）"
)

// ---- 3. BrowserStatus：Equatable + label ----

check(BrowserStatus.ready != BrowserStatus.disabled, "ready ≠ disabled（sanity）")
check(
    BrowserStatus.notReady(.missingCofferBinary) != BrowserStatus.notReady(.missingManifest),
    "不同缺项互不相等（sanity）"
)
check(BrowserStatus.disabled.label == "已停用", "disabled 文案")
check(BrowserStatus.ready.label == "就绪", "ready 文案")
check(BrowserStatus.notReady(.missingCofferBinary).label == "未找到 coffer 命令", "missingCofferBinary 文案")
check(BrowserStatus.notReady(.missingManifest).label == "未写入浏览器 native messaging manifest", "missingManifest 文案")
// G-A3 回归：就绪度缺项枚举仅两型（missingEscrow case 已删；修复前 count=3 → 红）
check(BrowserStatus.BrowserStatusIssue.allCases.count == 2, "就绪度缺项枚举仅两型（missingEscrow 已删，G-A3）")

// ---- 4. BrowserKind / BrowserManifestPaths 路径构造（纯函数）----

check(BrowserKind.chrome.displayName == "Google Chrome", "Chrome 展示名")
check(BrowserKind.edge.displayName == "Microsoft Edge", "Edge 展示名")
check(BrowserKind.firefox.displayName == "Firefox", "Firefox 展示名")
check(BrowserKind.allCases.count == 3, "三浏览器目标（Chrome/Edge/Firefox，docs/31 §6.2）")

let home = "/Users/tester"
check(
    BrowserManifestPaths.manifestPath(browser: .chrome, homeDirectory: home)
        == "/Users/tester/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.coffer.browser.json",
    "Chrome manifest 路径（docs/31 §6.2 目录）"
)
check(
    BrowserManifestPaths.manifestPath(browser: .edge, homeDirectory: home)
        == "/Users/tester/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.coffer.browser.json",
    "Edge manifest 路径"
)
check(
    BrowserManifestPaths.manifestPath(browser: .firefox, homeDirectory: home)
        == "/Users/tester/Library/Application Support/Mozilla/NativeMessagingHosts/com.coffer.browser.json",
    "Firefox manifest 路径（Mozilla/NativeMessagingHosts）"
)

// ---- 5. BrowserManifest.json 内容构造（纯函数）----

let shim = "/Applications/Coffer.app/Contents/Helpers/coffer-shim"

func jsonString(_ dict: [String: Any], _ key: String) -> String? { dict[key] as? String }
func jsonArray(_ dict: [String: Any], _ key: String) -> [String]? { dict[key] as? [String] }

for browser in BrowserKind.allCases {
    let j = BrowserManifest.json(browser: browser, shimPath: shim)
    check(jsonString(j, "name") == "com.coffer.browser", "\(browser.rawValue)：name = com.coffer.browser（host_name）")
    check(jsonString(j, "type") == "stdio", "\(browser.rawValue)：type = stdio")
    check(jsonString(j, "path") == shim, "\(browser.rawValue)：path = shim 绝对路径")
}

check(
    jsonArray(BrowserManifest.json(browser: .chrome, shimPath: shim), "allowed_origins")
        == ["chrome-extension://\(BrowserManifest.chromeExtensionID)/"],
    "Chrome：allowed_origins = 冻结扩展 ID（D-4 占位）"
)
check(
    jsonArray(BrowserManifest.json(browser: .edge, shimPath: shim), "allowed_origins")
        == ["chrome-extension://\(BrowserManifest.edgeExtensionID)/"],
    "Edge：allowed_origins = 冻结扩展 ID（D-4 占位）"
)
check(
    jsonArray(BrowserManifest.json(browser: .firefox, shimPath: shim), "allowed_extensions")
        == [BrowserManifest.firefoxGUID],
    "Firefox：allowed_extensions = 冻结 GUID（D-4 占位）"
)
check(
    BrowserManifest.json(browser: .chrome, shimPath: shim)["allowed_extensions"] == nil,
    "Chrome 无 allowed_extensions 键（Chrome/Edge 用 allowed_origins）"
)
check(
    BrowserManifest.json(browser: .firefox, shimPath: shim)["allowed_origins"] == nil,
    "Firefox 无 allowed_origins 键（Firefox 用 allowed_extensions）"
)

// ---- 6. BrowserManifest.shimPath 派生（docs/31 §6.2 L314：shim 装配
//      `Contents/Helpers/coffer-shim`，manifest path → shim → exec coffer
//      browser-agent，故从 coffer 二进制上溯到 bundle `Contents/Helpers`
//      层拼 shim 文件名，而非二进制同级）----

let cofferBin = "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
check(
    BrowserManifest.shimPath(cofferBinaryPath: cofferBin)
        == "/Applications/Coffer.app/Contents/Helpers/coffer-shim",
    "shim 路径 = Contents/Helpers/coffer-shim（bundle 装配层，非二进制同级）"
)
check(
    BrowserManifest.shimPath(cofferBinaryPath: "/tmp/x/Helpers/coffer.app/Contents/MacOS/coffer")
        == "/tmp/x/Helpers/coffer-shim",
    "任意前缀下 shim 上溯至 Contents/Helpers 层"
)

// ---- 7. BrowserManifest.write / delete（显式 I/O，临时根目录）----

do {
    let root = makeTempRoot()
    defer { try? FileManager.default.removeItem(atPath: root) }

    // 写入三浏览器 → 全部落盘且内容正确
    for browser in BrowserKind.allCases {
        let written = try BrowserManifest.write(
            browser: browser, shimPath: shim, homeDirectory: root)
        check(
            FileManager.default.fileExists(atPath: written),
            "\(browser.rawValue)：写入后文件存在（\(written)）"
        )
        let data = try Data(contentsOf: URL(fileURLWithPath: written))
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        check(parsed != nil, "\(browser.rawValue)：落盘 JSON 可解析")
        if parsed != nil {
            // 序列化比对（[String: Any] 不可 Equatable，用 sortedKeys 确定性序列化）
            let expected = try JSONSerialization.data(
                withJSONObject: BrowserManifest.json(browser: browser, shimPath: shim),
                options: [.prettyPrinted, .sortedKeys])
            check(data == expected, "\(browser.rawValue)：落盘 JSON 与构造内容一致")
        }
    }
    check(
        BrowserStatusProbe.allManifestsInstalled(homeDirectory: root),
        "写入后 allManifestsInstalled = true（resolve 的 manifestsInstalled 信号）"
    )

    // 幂等覆盖：重写同路径不报错
    _ = try BrowserManifest.write(browser: .chrome, shimPath: shim, homeDirectory: root)
    check(true, "Chrome：重复写入幂等不抛错")

    // 删除 → 文件消失；再删幂等返回 false
    let deleted = try BrowserManifest.delete(browser: .chrome, homeDirectory: root)
    check(deleted, "Chrome：删除返回 true（实际删除）")
    check(
        !FileManager.default.fileExists(
            atPath: BrowserManifestPaths.manifestPath(browser: .chrome, homeDirectory: root)),
        "Chrome：删除后文件不存在"
    )
    let deletedAgain = try BrowserManifest.delete(browser: .chrome, homeDirectory: root)
    check(!deletedAgain, "Chrome：重复删除幂等返回 false（docs/31 §6.2 停用即删除）")

    // 删除后 allManifestsInstalled = false
    try BrowserManifest.delete(browser: .edge, homeDirectory: root)
    try BrowserManifest.delete(browser: .firefox, homeDirectory: root)
    check(
        !BrowserStatusProbe.allManifestsInstalled(homeDirectory: root),
        "全部删除后 allManifestsInstalled = false"
    )
} catch {
    check(false, "manifest write/delete 流程未预期抛错：\(error)")
}

// ---- 8. BrowserStatusProbe.manifestExists / brokerProcessRunning ----

do {
    let root = makeTempRoot()
    defer { try? FileManager.default.removeItem(atPath: root) }
    check(
        !BrowserStatusProbe.manifestExists(browser: .firefox, homeDirectory: root),
        "未写入时 manifestExists = false"
    )
    _ = try BrowserManifest.write(browser: .firefox, shimPath: shim, homeDirectory: root)
    check(
        BrowserStatusProbe.manifestExists(browser: .firefox, homeDirectory: root),
        "写入后 manifestExists = true"
    )
} catch {
    check(false, "manifestExists 流程未预期抛错：\(error)")
}

// broker 存活探测：用假进程（/bin/sleep），不依赖 G-A/G-B 二进制
do {
    let process = try BrowserBroker.spawn(
        executable: "/bin/sleep", arguments: ["300"], environment: [:])
    Thread.sleep(forTimeInterval: 0.2)
    check(process.isRunning, "假 broker 进程已启动")
    check(
        BrowserStatusProbe.brokerProcessRunning(pid: process.processIdentifier),
        "brokerProcessRunning(pid) = true（kill(0) 存活探测）"
    )
    BrowserBroker.kill(process: process)
    Thread.sleep(forTimeInterval: 0.1)
    check(!process.isRunning, "kill 后假 broker 进程已退出")
    check(
        !BrowserStatusProbe.brokerProcessRunning(pid: process.processIdentifier),
        "kill 后 brokerProcessRunning(pid) = false"
    )
    check(
        !BrowserStatusProbe.brokerProcessRunning(pid: -1),
        "非法 pid → false（fail-closed）"
    )
} catch {
    check(false, "broker spawn/kill 流程未预期抛错：\(error)")
}

// ---- 9. 配对决策门 + 转发 seam（docs/31 §4.2/§5.3）----

let responder = RecordingBrowserPairingResponder()
let request = BrowserPairingRequest(
    browser: .chrome, extensionID: BrowserManifest.chromeExtensionID,
    permissionDescription: "访问本机密码库中的已绑定凭据（仅在你显式操作时填充）",
    requestId: 1, requestedAt: Date())
check(request.extensionID == BrowserManifest.chromeExtensionID, "配对请求携带扩展 ID")
check(request.requestId == 1, "配对请求携带 request_id（notify 协议回写所需，契约 §2.3）")
check(responder.decisions.isEmpty, "初始无决策记录")

responder.respond(
    BrowserPairingDecision(browser: request.browser, extensionID: request.extensionID,
                           requestId: request.requestId, approved: true, decidedAt: Date()))
check(responder.decisions.count == 1, "批准后决策记录 +1")
check(responder.decisions.first?.approved == true, "批准决策 approved = true")
check(responder.decisions.first?.browser == .chrome, "批准决策携带浏览器种类")

responder.respond(
    BrowserPairingDecision(browser: .firefox, extensionID: BrowserManifest.firefoxGUID,
                           requestId: 2, approved: false, decidedAt: Date()))
check(responder.decisions.count == 2, "拒绝后决策记录 +1")
check(responder.decisions.last?.approved == false, "拒绝决策 approved = false")

// 决策记录不含密钥材料（PSK/公钥字段不存在于模型——编译期保证 + 此处 sanity）
let mirror = Mirror(reflecting: BrowserPairingDecision(
    browser: .chrome, extensionID: "id", requestId: 3, approved: true, decidedAt: Date()))
check(
    !mirror.children.contains { "\($0.label ?? "")".lowercased().contains("psk") },
    "配对决策模型无 PSK 字段（密钥材料不进 App 状态，docs/31 §5.3）"
)

// ---- 9.2 FR-16.1：BrowserPairingRequest Identifiable（前置 sheet 绑定 id=requestId）----

check(request.id == 1, "BrowserPairingRequest Identifiable: id == request_id（sheet(item:) 绑定）")

// ---- 10. 用户主目录解析（沙盒外 = NSHomeDirectory；沙盒内 getpwuid 真实 home）----

check(!BrowserStatusProbe.userHomeDirectory().isEmpty, "userHomeDirectory 非空")

// ---- 11. §8 stdin 私有管道 + well-known UDS（HIGH-2 ② / HIGH-3，docs/31 §3.1）----

// 11.1 well-known UDS 路径构造（真实主目录 + 固定相对路径，host 无需 env 发现）
let wellKnownRel = "Library/Application Support/Coffer/browser/broker.sock"
let probeHome = "/Users/averylongusername123"
let probeSocket = BrowserBroker.SpawnConfig.wellKnownUDSPath(homeDirectory: probeHome)
check(
    probeSocket == probeHome + "/" + wellKnownRel,
    "wellKnownUDSPath = home + 固定相对路径"
)
check(
    probeSocket.utf8.count < 104,
    "well-known UDS ≤ AF_UNIX sun_path 104B（实测 \(probeSocket.utf8.count)B）"
)
check(
    BrowserBroker.brokerSocketPath(homeDirectory: probeHome) == probeSocket,
    "brokerSocketPath 与 wellKnownUDSPath 同落点"
)

// 11.1b broker spawn --log 接线（B-2 诊断盲区闭环：App spawn 曾不传 --log → broker
// 日志进 /dev/null，真机配对断点全靠猜；固定日志路径与 socket 同目录——父目录已由
// prepareSocketDirectory 保证，Logger 不建目录）
check(BrowserBroker.SpawnConfig.logFlag == "--log",
      "broker 日志参数 = --log（对齐 G-B parse_broker_args，cli.rs）")
let probeLog = BrowserBroker.SpawnConfig.brokerLogPath(homeDirectory: probeHome)
check(
    probeLog == probeHome + "/Library/Application Support/Coffer/browser/broker.log",
    "brokerLogPath = home + 固定相对路径（与 broker.sock 同目录）"
)
check(
    probeLog.utf8.count < 104,
    "broker 日志路径长度合理（实测 \(probeLog.utf8.count)B）"
)
let spawnArgs = BrowserBroker.SpawnConfig.brokerArguments(
    udsPath: probeSocket, logPath: probeLog)
check(
    spawnArgs == [BrowserBroker.SpawnConfig.subcommand, "--uds", probeSocket,
                  "--log", probeLog],
    "broker spawn 参数 = [subcommand, --uds socket, --log log]（App 接线顺序冻结）"
)

// 11.2 prepareSocketDirectory：创建 0700 私有父目录 + 幂等（已存在不动权限，
// 对齐 G-B cli.rs ensure_broker_parent_dir）
do {
    let tempHome = makeTempRoot()
    try BrowserBroker.prepareSocketDirectory(homeDirectory: tempHome)
    let dir = (BrowserBroker.brokerSocketPath(homeDirectory: tempHome) as NSString)
        .deletingLastPathComponent
    var isDir: ObjCBool = false
    check(
        FileManager.default.fileExists(atPath: dir, isDirectory: &isDir) && isDir.boolValue,
        "prepareSocketDirectory 创建私有父目录"
    )
    let mode = try FileManager.default.attributesOfItem(atPath: dir)[.posixPermissions] as? NSNumber
    check(mode?.intValue == 0o700, "私有父目录权限 = 0700")
    try BrowserBroker.prepareSocketDirectory(homeDirectory: tempHome)
    let mode2 = try FileManager.default.attributesOfItem(atPath: dir)[.posixPermissions] as? NSNumber
    check(mode2?.intValue == 0o700, "prepareSocketDirectory 幂等：重复调用保持 0700")
    try? FileManager.default.removeItem(atPath: tempHome)
} catch {
    check(false, "prepareSocketDirectory 未预期抛错：\(error)")
}

// 11.3 BrokerStdinSecrets.payload：§3.1 四行冻结格式
// DEK 以原始字节传入（FFI exportDek 语义），payload 组帧时 hex 直编进 Data
// （不经中间 String，裁定书 §1.4）；期望 hex 仅在测试侧用 String(format:) 构造
//（测试代码允许中间 String，生产路径已规避）。
let dekBytes = Data((0..<32).map { UInt8($0) })         // 00 01 ... 1f（32B 原始）
let expectedDekHex = (0..<32).map { String(format: "%02x", $0) }.joined()
let vaultUUIDHex = String(repeating: "cd", count: 16) // 32 字符 = 16 字节 hex
let pskHex = String(repeating: "ef", count: 32)       // 64 字符 = 32 字节 hex
let secrets = BrokerStdinSecrets(
    dekBytes: dekBytes, vaultUUIDHex: vaultUUIDHex, pskHex: pskHex, unlocked: true)
let expectedText = "DEK_HEX=\(expectedDekHex)\n"
    + "VAULT_UUID_HEX=\(vaultUUIDHex)\n"
    + "PSK_HEX=\(pskHex)\n"
    + "UNLOCKED=1\n"
check(
    String(data: secrets.payload, encoding: .utf8) == expectedText,
    "payload = §3.1 四行（LF 结尾，DEK hex 由原始字节直编，unlocked→1）"
)
check(
    secrets.payload.count == expectedText.utf8.count,
    "payload 字节数 = 期望四行 UTF-8 定长（\(expectedText.utf8.count) B，与内容断言互证）"
)
check(
    String(data: BrokerStdinSecrets(
        dekBytes: Data([0xde, 0xad]), vaultUUIDHex: "u", pskHex: "p", unlocked: false).payload,
           encoding: .utf8)?.hasSuffix("UNLOCKED=0\n") == true,
    "unlocked=false → UNLOCKED=0"
)

// 11.4 zeroize：覆零字节缓冲（用后即毁，密钥材料不进日志/不残留）
var secretData = Data("top-secret-bytes".utf8)
zeroize(&secretData)
check(
    secretData.allSatisfy { $0 == 0 } && secretData.count == "top-secret-bytes".utf8.count,
    "zeroize 覆零且长度不变"
)

// 11.5 R1-2/M-7：BrokerStdinSecrets.zeroizeDek 覆零 DEK 原始字节（用后即毁）
do {
    var s = BrokerStdinSecrets(
        dekBytes: Data([0xde, 0xad, 0xbe, 0xef]), vaultUUIDHex: "u", pskHex: "p", unlocked: true)
    check(s.dekBytes == Data([0xde, 0xad, 0xbe, 0xef]), "zeroizeDek 前 DEK 字节原样")
    s.zeroizeDek()
    check(
        s.dekBytes.allSatisfy { $0 == 0 } && s.dekBytes.count == 4,
        "zeroizeDek 覆零 DEK 原始字节（长度不变）"
    )
}

// 11.6 spawn stdin 私有管道机制：写 §3.1 四行 + close stdin → 子进程读到精确
// 内容并退出 0（不经 env/argv；关闭在 spawn 内同步完成，无挂起风险）
do {
    let process = try BrowserBroker.spawn(
        executable: "/bin/sh",
        arguments: ["-c",
                    "IFS= read -r a && IFS= read -r b && IFS= read -r c && IFS= read -r d "
                        + "&& [ \"$a\" = \"DEK_HEX=\(expectedDekHex)\" ] "
                        + "&& [ \"$b\" = \"VAULT_UUID_HEX=\(vaultUUIDHex)\" ] "
                        + "&& [ \"$c\" = \"PSK_HEX=\(pskHex)\" ] "
                        + "&& [ \"$d\" = \"UNLOCKED=1\" ]"],
        environment: [:],
        stdinPayload: secrets.payload)
    process.waitUntilExit()
    check(process.terminationStatus == 0, "spawn stdin 载荷被子进程精确读取（4 行 + close）")
} catch {
    check(false, "spawn stdin 流程未预期抛错：\(error)")
}

// 11.7 M-6 核销（KNOWN-ISSUES.md:1100）：broker 早退写 stdin（EPIPE）不崩 App——
// throwing write(contentsOf:) 把 EPIPE 归入 spawn 失败路径（browserSpawnFailed）
// 而非 NSFileHandleOperationException。用「不读 stdin 立即退出」的子进程 + 大载荷
//（> pipe buffer）强制 EPIPE 或写成功——两路皆断言「不崩 App」（M-6 本质）。
do {
    let big = Data(repeating: 0x61, count: 256 * 1024)
    let p = try BrowserBroker.spawn(
        executable: "/bin/sh",
        arguments: ["-c", "exec 0<&-; exit 0"],   // 关 stdin 立即退出，不读
        environment: [:],
        stdinPayload: big)
    p.waitUntilExit()
    check(true, "M-6：早退 broker 写 stdin 成功（未触发 EPIPE），不崩 App")
} catch let error as BrowserIntegrationError {
    let isSpawnFailed: Bool = {
        if case .brokerSpawnFailed = error { return true }
        return false
    }()
    check(
        isSpawnFailed,
        "M-6：早退 broker 写 stdin 抛 browserSpawnFailed（EPIPE 被 throwing 捕获）而非崩溃：\(error.userText)"
    )
} catch {
    check(false, "M-6：早退 broker 写 stdin 抛非预期错误：\(error)")
}

// ---- 12. 配对集成 V：PSK keychain + notify 协议 + 决策转发（v2.3.0，契约 §4/§2.3）----

func jsonData(_ s: String) -> Data { Data(s.utf8) }

// 12.1 BrowserPairingKeychain：PSK keychain 往返（注入临时 service/account +
// useDataProtection=false 文件钥匙串——无签名测试二进制可写，McpEscrowKeychain
// 同款缝隙；service 注入隔离真实 cn.coffer.browser-psk 项）
do {
    let kc = BrowserPairingKeychain()
    let service = "cn.coffer.browser-psk.test.\(UUID().uuidString)"
    let account = "test-vault-\(UUID().uuidString)"
    let psk = Data((0..<32).map { UInt8($0) })
    check(!kc.itemExists(vaultUUID: account, service: service, useDataProtection: false),
          "keychain：初始 itemExists = false（注入临时 service/account）")
    try kc.save(key: psk, vaultUUID: account, service: service, useDataProtection: false)
    check(kc.itemExists(vaultUUID: account, service: service, useDataProtection: false),
          "keychain：save 后 itemExists = true")
    check(kc.load(vaultUUID: account, service: service, useDataProtection: false) == psk,
          "keychain：load 往返 = 原 32B 值")
    // 幂等覆盖（DuplicateItem → 删旧重写，契约 §4.3 重启用同钥覆盖语义）
    try kc.save(key: psk, vaultUUID: account, service: service, useDataProtection: false)
    check(true, "keychain：重复 save 幂等覆盖不抛错")
    // 非法长度拒绝（写入路径防御，contract §4.2 keyLength=32）
    do {
        try kc.save(key: Data([0x01, 0x02, 0x03]), vaultUUID: account, service: service, useDataProtection: false)
        check(false, "keychain：非法长度保存应抛 invalidKeyLength")
    } catch let e as BrowserPairingKeychainError {
        if case .invalidKeyLength = e {
            check(true, "keychain：非法长度保存抛 invalidKeyLength")
        } else {
            check(false, "keychain：非法长度抛错类型不符 \(e)")
        }
    } catch {
        check(false, "keychain：非法长度抛非预期错误 \(error)")
    }
    // 删除 + 幂等（停用即删，契约 §4.3）
    let deleted = try kc.delete(vaultUUID: account, service: service, useDataProtection: false)
    check(deleted, "keychain：delete 返回 true（实际删除）")
    check(!kc.itemExists(vaultUUID: account, service: service, useDataProtection: false),
          "keychain：删除后 itemExists = false")
    check(kc.load(vaultUUID: account, service: service, useDataProtection: false) == nil,
          "keychain：删除后 load = nil（fail-closed 不 spawn）")
    let deletedAgain = try kc.delete(vaultUUID: account, service: service, useDataProtection: false)
    check(!deletedAgain, "keychain：重复 delete 幂等返回 false")
} catch {
    check(false, "keychain 流程未预期抛错：\(error)")
}

// 12.2 BrowserPairingKeychain：hexString + randomPSK（CSPRNG 32B，决策①）
check(
    BrowserPairingKeychain.hexString(from: Data([0xde, 0xad, 0xbe, 0xef])) == "deadbeef",
    "keychain：hexString 小写 hex（2 字符/字节，与 broker stdin PSK_HEX 同格式）"
)
let r1 = BrowserPairingKeychain.randomPSK()
let r2 = BrowserPairingKeychain.randomPSK()
check(
    r1?.count == BrowserPairingKeychain.keyLength && r2?.count == BrowserPairingKeychain.keyLength,
    "keychain：randomPSK 均为 32B（CSPRNG SecRandomCopyBytes）"
)
check(r1 != nil && r1 != r2, "keychain：randomPSK 两次不同")

// 12.3 SpawnConfig.notifyUDSPathRelative：well-known notify.sock 同目录同公式
// （契约 §2.3/§6.1：Library/Application Support/Coffer/browser/notify.sock）
let notifyRel = "Library/Application Support/Coffer/browser/notify.sock"
let notifyPath = BrowserBroker.SpawnConfig.notifyUDSPath(homeDirectory: probeHome)
check(
    notifyPath == probeHome + "/" + notifyRel,
    "notify：notifyUDSPath = home + 固定相对路径"
)
check(
    notifyPath.utf8.count < 104,
    "notify：notify.sock ≤ AF_UNIX sun_path 104B（实测 \(notifyPath.utf8.count)B）"
)
check(
    (notifyPath as NSString).deletingLastPathComponent == (probeSocket as NSString).deletingLastPathComponent,
    "notify：与 broker.sock 同目录（Library/Application Support/Coffer/browser）"
)

// 12.4 NotifyFrameCodec：notify.sock 帧编解码（4B LE 长度前缀 + JSON，契约 §2.3）
check(
    NotifyFrameCodec.decode(jsonData(#"{"type":"pair_request","request_id":7,"browser":"firefox","extension_id":"ext-abc","requested_at":1700000000123}"#))
        == .pairRequest(requestId: 7, browser: .firefox, extensionID: "ext-abc", requestedAt: 1700000000123),
    "codec：decode pair_request（request_id/browser/extension_id/requested_at）"
)
check(
    NotifyFrameCodec.decode(jsonData(#"{"type":"pair_cancel","request_id":9,"reason":"timeout"}"#))
        == .pairCancel(requestId: 9, reason: "timeout"),
    "codec：decode pair_cancel（reason=timeout）"
)
// 批准决策 encode → 4B LE 长度前缀 + JSON roundtrip（含 psk 明文，契约 §4）
let decisionData = NotifyFrameCodec.encode(.pairDecision(requestId: 7, approved: true, pskHex: pskHex))
let frameLen = Int(UInt32(decisionData[0]) | UInt32(decisionData[1]) << 8 | UInt32(decisionData[2]) << 16 | UInt32(decisionData[3]) << 24)
let decisionPayload = decisionData.dropFirst(4)
check(frameLen == decisionPayload.count, "codec：4B LE 长度前缀 = JSON 字节数")
check(
    NotifyFrameCodec.decode(Data(decisionPayload)) == .pairDecision(requestId: 7, approved: true, pskHex: pskHex),
    "codec：pair_decision roundtrip（approved + psk 原样 64 hex）"
)
// 拒绝决策：approved=false + 无 psk 字段（明文材料不随拒绝下发）
let rejectData = NotifyFrameCodec.encode(.pairDecision(requestId: 8, approved: false, pskHex: nil))
let rejectPayload = rejectData.dropFirst(4)
check(
    NotifyFrameCodec.decode(Data(rejectPayload)) == .pairDecision(requestId: 8, approved: false, pskHex: nil),
    "codec：拒绝决策 roundtrip（approved=false，无 psk）"
)
check(
    String(data: rejectPayload, encoding: .utf8)?.contains("\"psk\"") != true,
    "codec：拒绝帧 JSON 不含 psk 字段"
)
// 非法输入 → nil（fail-closed）
check(NotifyFrameCodec.decode(jsonData("not-json")) == nil, "codec：非法 JSON → nil")
check(NotifyFrameCodec.decode(jsonData(#"{"type":"bogus"}"#)) == nil, "codec：未知 type → nil")
check(NotifyFrameCodec.decode(jsonData(#"{"type":"pair_request"}"#)) == nil, "codec：pair_request 缺字段 → nil")
check(NotifyFrameCodec.decode(Data(repeating: 0x7b, count: 3_000_000)) == nil,
      "codec：超大 payload → nil（fail-closed，防内存膨胀）")

// 12.5 NotifyBrowserPairingResponder：决策 → pair_decision 帧转发（真实 responder）
var sentFrames: [NotifyFrame] = []
let realResponder = NotifyBrowserPairingResponder(
    sendFrame: { sentFrames.append($0) },
    pskHexLoader: { pskHex },
    log: { _ in })

// 批准 → approved:true + psk（同一 PSK，stdin 注入与 pair_decision 同源，契约 §4）
realResponder.respond(BrowserPairingDecision(
    browser: .chrome, extensionID: "ext-1", requestId: 7, approved: true, decidedAt: Date()))
check(sentFrames.count == 1, "responder：批准转发 1 帧")
if case .pairDecision(let rid, let approved, let psk) = sentFrames.last ?? .pairCancel(requestId: -1, reason: "sentinel") {
    check(rid == 7 && approved == true && psk == pskHex,
          "responder：批准帧 request_id=7 + approved=true + psk 同源")
} else {
    check(false, "responder：批准帧类型应为 pairDecision")
}
// 拒绝 → approved:false + 无 psk
sentFrames.removeAll()
realResponder.respond(BrowserPairingDecision(
    browser: .chrome, extensionID: "ext-1", requestId: 8, approved: false, decidedAt: Date()))
check(sentFrames.count == 1, "responder：拒绝转发 1 帧")
if case .pairDecision(let rid, let approved, let psk) = sentFrames.last ?? .pairCancel(requestId: -1, reason: "sentinel") {
    check(rid == 8 && approved == false && psk == nil,
          "responder：拒绝帧 request_id=8 + approved=false + 无 psk")
} else {
    check(false, "responder：拒绝帧类型应为 pairDecision")
}
// 批准但 PSK 缺失 → fail-closed 按拒绝处理（不伪造材料）+ 记日志不吞错
sentFrames.removeAll()
var noPskLog = ""
let noPskResponder = NotifyBrowserPairingResponder(
    sendFrame: { sentFrames.append($0) },
    pskHexLoader: { nil },
    log: { noPskLog = $0 })
noPskResponder.respond(BrowserPairingDecision(
    browser: .chrome, extensionID: "ext-1", requestId: 9, approved: true, decidedAt: Date()))
if case .pairDecision(let rid, let approved, let psk) = sentFrames.last ?? .pairCancel(requestId: -1, reason: "sentinel") {
    check(rid == 9 && approved == false && psk == nil,
          "responder：批准但 PSK 缺失 → fail-closed 按拒绝处理")
} else {
    check(false, "responder：PSK 缺失帧类型错误")
}
check(!noPskLog.isEmpty, "responder：PSK 缺失已记日志（不吞错误）")

// ---- 13. BrokerNotifyClient：连接 + 读帧 + 发送（注入路径，真 UDS loopback）----

// 轮询等待辅助（socket 测试时序：读线程异步回调，需带超时等待）
func waitUntil(_ seconds: TimeInterval, _ cond: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if cond() { return true }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return cond()
}

// 测试用 UDS 监听器（仿 broker 侧）：bind/listen
func makeUnixListener(at path: String) -> Int32 {
    precondition(path.utf8.count < 104, "测试 socket 路径超限（AF_UNIX sun_path 104B）")
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    precondition(fd >= 0, "socket() 失败")
    unlink(path)
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    _ = withUnsafeMutablePointer(to: &addr.sun_path) { dst in
        pathBytes.withUnsafeBufferPointer { src in
            memcpy(dst, src.baseAddress!, pathBytes.count)
        }
    }
    let sunPathOffset = MemoryLayout<sockaddr_un>.size - MemoryLayout.size(ofValue: addr.sun_path)
    let addrLen = socklen_t(sunPathOffset + pathBytes.count + 1)
    let rc = withUnsafePointer(to: &addr) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
            bind(fd, sp, addrLen)
        }
    }
    precondition(rc == 0, "bind() 失败 errno=\(errno)")
    listen(fd, 8)
    return fd
}

// 从 fd 精确读 n 字节（测试侧读 broker 收到的决策帧）
func readExactBytes(_ fd: Int32, _ n: Int) -> Data? {
    var data = Data()
    var buf = [UInt8](repeating: 0, count: 4096)
    while data.count < n {
        let want = min(n - data.count, buf.count)
        let got = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, want) }
        if got <= 0 { return nil }
        data.append(contentsOf: buf[0..<got])
    }
    return data
}

// 测试侧组帧（4B LE 长度前缀 + JSON）
func makeFrame(_ json: String) -> Data {
    let payload = Data(json.utf8)
    let len = UInt32(payload.count)
    var frame = Data()
    frame.append(UInt8(truncatingIfNeeded: len & 0xff))
    frame.append(UInt8(truncatingIfNeeded: (len >> 8) & 0xff))
    frame.append(UInt8(truncatingIfNeeded: (len >> 16) & 0xff))
    frame.append(UInt8(truncatingIfNeeded: (len >> 24) & 0xff))
    frame.append(payload)
    return frame
}

do {
    // UDS sun_path 限 104B（macOS）：测试临时根目录含长 UUID 超限（实测 123B），
    // 须用短路径（NSTemporaryDirectory 根 + 短随机名，实测 ~72B < 104）。
    let sockPath = NSTemporaryDirectory() + "coffer-notify-\(UUID().uuidString.prefix(8)).sock"
    check(sockPath.utf8.count < 104, "notify 测试：socket 路径 < 104B（实测 \(sockPath.utf8.count)B）")
    defer { unlink(sockPath) }

    var received: [BrowserPairingRequest] = []
    var cancelled: [Int] = []
    var disconnectCount = 0
    let client = BrokerNotifyClient(
        socketPath: sockPath,
        onPairRequest: { received.append($0) },
        onPairCancel: { cancelled.append($0) },
        onDisconnect: { disconnectCount += 1 })
    client.start()

    let listener = makeUnixListener(at: sockPath)
    let peer = accept(listener, nil, nil)
    check(peer >= 0, "notify client：App 连接被 broker accept")

    // broker 下发 pair_request 帧 → 读线程解码 → onPairRequest
    let reqJSON = #"{"type":"pair_request","request_id":42,"browser":"chrome","extension_id":"ext-c","requested_at":1700000000000}"#
    let reqFrame = makeFrame(reqJSON)
    reqFrame.withUnsafeBytes { _ = write(peer, $0.baseAddress, reqFrame.count) }
    let gotRequest = waitUntil(3.0) { received.count == 1 }
    check(gotRequest, "notify client：收到 pair_request 并经 onPairRequest 回调")
    check(
        received.first?.browser == .chrome && received.first?.extensionID == "ext-c"
            && received.first?.requestId == 42,
        "notify client：pair_request 字段（browser/extension_id/request_id）"
    )
    check(
        received.first?.permissionDescription == BrowserPairingRequest.defaultPermissionDescription,
        "notify client：权限说明 = App 侧常量（不随帧供给，防伪造诱导，契约 §2.3）"
    )

    // App 写回 pair_decision（含 PSK）→ broker 读回 4B 长度 + payload
    let sendOK = client.send(frame: .pairDecision(requestId: 42, approved: true, pskHex: pskHex))
    check(sendOK, "notify client：send pair_decision 写回成功")
    if let hdr = readExactBytes(peer, 4),
       let payload = readExactBytes(peer, Int(UInt32(hdr[0]) | UInt32(hdr[1]) << 8 | UInt32(hdr[2]) << 16 | UInt32(hdr[3]) << 24)) {
        check(
            NotifyFrameCodec.decode(payload) == .pairDecision(requestId: 42, approved: true, pskHex: pskHex),
            "notify client：broker 读回 pair_decision（request_id/approved/psk）"
        )
    } else {
        check(false, "notify client：broker 读取 pair_decision 帧失败")
    }

    // broker 关闭连接（扩展断连场景）→ 客户端 EOF → onDisconnect（清理连接态）
    close(peer)
    let gotDisconnect = waitUntil(3.0) { disconnectCount >= 1 }
    check(gotDisconnect, "notify client：broker 断连 → onDisconnect（EOF 清理连接态）")

    // 客户端重连（200ms 退避）→ broker 再次 accept → 下发 pair_cancel → onPairCancel
    let peer2 = accept(listener, nil, nil)
    check(peer2 >= 0, "notify client：断线后重连被 broker accept")
    let cancelJSON = #"{"type":"pair_cancel","request_id":42,"reason":"disconnect"}"#
    let cancelFrame = makeFrame(cancelJSON)
    cancelFrame.withUnsafeBytes { _ = write(peer2, $0.baseAddress, cancelFrame.count) }
    let gotCancel = waitUntil(3.0) { cancelled.contains(42) }
    check(gotCancel, "notify client：pair_cancel → onPairCancel(request_id)（关弹框）")

    // 清理：先关 peer 使客户端读循环自然 EOF（不跨线程关阻塞 read），
    // 再 stop() 落在 200ms 重连退避窗口内 → running=false 安全退出
    close(peer2)
    close(listener)
    client.stop()
    unlink(sockPath)
} catch {
    check(false, "notify client socket 流程未预期抛错：\(error)")
}

print("")
print(failed == 0
      ? "BROWSER STATUS TESTS OK —— \(passed) 项断言全部通过"
      : "BROWSER STATUS TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
