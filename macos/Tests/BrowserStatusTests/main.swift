// BrowserStatusTests/main.swift —— 浏览器集成 App 侧纯逻辑单元测试
// （docs/31 §6.2 / §9.1 G-D）。
//
// 编译运行：tools/run_browser_status_tests.sh
//
// 被测单元（零 AppKit / 零 CoreBindings 依赖，swiftc 可独立编译）：
//   - BrowserStatus.resolve / label —— 就绪四态判定（docs/31 §6.2）
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
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: false, manifestsInstalled: false, escrowEnabled: false) == .disabled,
    "未启用 + 前置全缺失 → disabled"
)
check(
    BrowserStatus.resolve(enabled: false, cofferBinaryAvailable: true, manifestsInstalled: true, escrowEnabled: true) == .disabled,
    "未启用 + 前置全就绪 → disabled（开关优先，镜像 McpStatus 同序）"
)

// ---- 2. BrowserStatus.resolve：ready 与缺项（coffer → manifest → escrow 顺序）----

check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: true, manifestsInstalled: true, escrowEnabled: true) == .ready,
    "启用 + coffer/manifest/escrow 全就绪 → ready"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: false, manifestsInstalled: true, escrowEnabled: true) == .notReady(.missingCofferBinary),
    "缺 coffer 二进制 → missingCofferBinary"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: true, manifestsInstalled: false, escrowEnabled: true) == .notReady(.missingManifest),
    "缺 manifest → missingManifest"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: true, manifestsInstalled: true, escrowEnabled: false) == .notReady(.missingEscrow),
    "缺 escrow 托管 → missingEscrow（broker 免密解锁依赖，docs/31 §4.1）"
)
check(
    BrowserStatus.resolve(enabled: true, cofferBinaryAvailable: false, manifestsInstalled: false, escrowEnabled: false) == .notReady(.missingCofferBinary),
    "全缺 → 报第一个缺项（coffer 优先，sanity）"
)

// ---- 3. BrowserStatus：Equatable + label ----

check(BrowserStatus.ready != BrowserStatus.disabled, "ready ≠ disabled（sanity）")
check(
    BrowserStatus.notReady(.missingManifest) != BrowserStatus.notReady(.missingEscrow),
    "不同缺项互不相等（sanity）"
)
check(BrowserStatus.disabled.label == "已停用", "disabled 文案")
check(BrowserStatus.ready.label == "就绪", "ready 文案")
check(BrowserStatus.notReady(.missingCofferBinary).label == "未找到 coffer 命令", "missingCofferBinary 文案")
check(BrowserStatus.notReady(.missingManifest).label == "未写入浏览器 native messaging manifest", "missingManifest 文案")
check(BrowserStatus.notReady(.missingEscrow).label == "未启用 MCP 解锁托管", "missingEscrow 文案")

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

let shim = "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/browser-agent"

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

// ---- 6. BrowserManifest.shimPath 派生（docs/31 §6.2 shim 与二进制同级）----

let cofferBin = "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
check(
    BrowserManifest.shimPath(cofferBinaryPath: cofferBin)
        == "/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/browser-agent",
    "shim 路径 = coffer 二进制同级 browser-agent"
)
check(
    BrowserManifest.shimPath(cofferBinaryPath: "/tmp/x/y/coffer")
        == "/tmp/x/y/browser-agent",
    "任意前缀下 shim 与二进制同级"
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
    requestedAt: Date())
check(request.extensionID == BrowserManifest.chromeExtensionID, "配对请求携带扩展 ID")
check(responder.decisions.isEmpty, "初始无决策记录")

responder.respond(
    BrowserPairingDecision(browser: request.browser, extensionID: request.extensionID,
                           approved: true, decidedAt: Date()))
check(responder.decisions.count == 1, "批准后决策记录 +1")
check(responder.decisions.first?.approved == true, "批准决策 approved = true")
check(responder.decisions.first?.browser == .chrome, "批准决策携带浏览器种类")

responder.respond(
    BrowserPairingDecision(browser: .firefox, extensionID: BrowserManifest.firefoxGUID,
                           approved: false, decidedAt: Date()))
check(responder.decisions.count == 2, "拒绝后决策记录 +1")
check(responder.decisions.last?.approved == false, "拒绝决策 approved = false")

// 决策记录不含密钥材料（PSK/公钥字段不存在于模型——编译期保证 + 此处 sanity）
let mirror = Mirror(reflecting: BrowserPairingDecision(
    browser: .chrome, extensionID: "id", approved: true, decidedAt: Date()))
check(
    !mirror.children.contains { "\($0.label ?? "")".lowercased().contains("psk") },
    "配对决策模型无 PSK 字段（密钥材料不进 App 状态，docs/31 §5.3）"
)

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
let dekHex = String(repeating: "ab", count: 32)   // 64 字符 = 32 字节 hex
let vaultUUIDHex = String(repeating: "cd", count: 16) // 32 字符 = 16 字节 hex
let pskHex = String(repeating: "ef", count: 32)   // 64 字符 = 32 字节 hex
let secrets = BrokerStdinSecrets(
    dekHex: dekHex, vaultUUIDHex: vaultUUIDHex, pskHex: pskHex, unlocked: true)
let expectedText = "DEK_HEX=\(dekHex)\n"
    + "VAULT_UUID_HEX=\(vaultUUIDHex)\n"
    + "PSK_HEX=\(pskHex)\n"
    + "UNLOCKED=1\n"
check(
    String(data: secrets.payload, encoding: .utf8) == expectedText,
    "payload = §3.1 四行（LF 结尾，unlocked→1）"
)
check(
    String(data: BrokerStdinSecrets(
        dekHex: "d", vaultUUIDHex: "u", pskHex: "p", unlocked: false).payload,
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

// 11.5 spawn stdin 私有管道机制：写 §3.1 四行 + close stdin → 子进程读到精确
// 内容并退出 0（不经 env/argv；关闭在 spawn 内同步完成，无挂起风险）
do {
    let process = try BrowserBroker.spawn(
        executable: "/bin/sh",
        arguments: ["-c",
                    "IFS= read -r a && IFS= read -r b && IFS= read -r c && IFS= read -r d "
                        + "&& [ \"$a\" = \"DEK_HEX=\(dekHex)\" ] "
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

print("")
print(failed == 0
      ? "BROWSER STATUS TESTS OK —— \(passed) 项断言全部通过"
      : "BROWSER STATUS TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
