// UpdateTests/main.swift —— v2.7.0 OTA 组 A（Updater 核心）的 Swift 侧自动化验收。
//
// 覆盖（docs/35 §6 契约冻结：6.1 清单 schema v1 / 6.2 白名单 / 6.3 Updater
// 公开接口 + §2.3 三级验签 + §2.2 应用层白名单）：
//   - 清单解析：合法 / schemaVersion≠1 / appId 不匹配 / 缺字段 / 非 JSON；
//   - canonical JSON 字节确定性（sortedKeys + withoutEscapingSlashes 双侧一致）；
//   - Ed25519 验签：自生成密钥对 sign→verify 通过；篡改消息/签名 → 拒绝；
//   - 版本比较：2.7.0>2.6.0、2.10>2.9（数字点分）、equal、minimumVersion 高于当前 → 拒装；
//   - 白名单 host 纯函数：4 host 放行、http 拒绝、任意其它 host 拒绝；
//   - SecCodeVerifier：macos/build/Coffer.app 已签名产物断言 DR/TeamID/identifier
//     + kSecCodeInfoUnique 比对清单 cdHash（产物缺失时显式 SKIP 不算 fail）；
//   - UpdaterManager 状态机：stub 网络层驱动 check/install 成功与失败路径
//     （全程不真联网，网络层用协议注入）；
//   - OTAInstaller perform（§6.4 r0.4）：install 配置 JSON 5 字段构造 + result/backup
//     路径写 UserDefaults + 注入 launcher 断言 `--config <路径>`（真 LaunchServices
//     启动标「真机核销」，不在 CI 实跑）；
//   - 首启消费安装结果（consumePendingInstallResult）：成功删备份/清 key/静默、
//     失败 → failed、损坏 → fail-closed、无 pending → 幂等 no-op；
//   - H-3：嵌套 Contents/Helpers/*.app 验签——真实产物正面 + 合成伪造（无嵌套/
//     未签名/异 identifier）负面，任一不过即拒装（§2.3 第 3 级纵深）；
//   - M-3：launcher 抛错 → pending keys + 已写配置回滚，下次 consume no-op；
//   - C-1：consume 删备份前校验 backupDir 前缀（防 prefs 被改指向任意文件误删）；
//   - LOW：host 白名单大小写不敏感（对齐 UpdateCopy 口径）；
//   - 便捷构造 UpdaterManager() 生产接线（编译级验证）。
//
// 注：HoldingFetcher/Downloader 的计数放在 continuation body 内——`await
// withCheckedThrowingContinuation` 本身是异步调用，await 前自增会让自旋方在
// continuation 未入队时退出等待，resumeAll 读到空数组而挂死（全量门禁实证）。
//
// 驱动：tools/run_update_tests.sh（swiftc 直编 Updater/*.swift + 本文件，
// 不链接 libcf_ffi.a —— 本组纯 Swift 无 Rust 依赖；链 Security/CryptoKit/Combine）。
// 密钥纪律：只自生成测试临时密钥对，绝不 print 私钥；公钥仅用于验签注入。

import Foundation
import CryptoKit

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0
var skipped = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

func skip(_ tc: String, _ name: String, _ reason: String) {
    skipped += 1
    print("SKIP  \(tc)  \(name)  \(reason)")
}

// MARK: - 测试夹具（自生成临时密钥，不联网）

enum TestFixture {
    /// 测试专用 Ed25519 密钥对（每次运行临时生成；私钥仅用于签名，不落盘/不 print）。
    static let privateKey = Curve25519.Signing.PrivateKey()
    static let publicKeyBase64 = privateKey.publicKey.rawRepresentation.base64EncodedString()

    static let validDownloadUrl =
        "https://github.com/cygnusyang/coffer/releases/download/v2.7.0/Coffer-v2.7.0.zip"
    static let sampleCdHash = "1e5f59c34a30849287d969095a91feb33b940606"

    /// 清单 9 个被签名字段的 dict（契约 6.1；signature 由签名时再补）。
    static func manifestFields(
        schemaVersion: Int = UpdateManifest.currentSchemaVersion,
        appId: String = UpdateManifest.expectedAppId,
        version: String = "2.7.0",
        minimumVersion: String = "2.6.0",
        buildTime: String = "2026-10-10T00:00:00Z",
        downloadUrl: String = validDownloadUrl,
        cdHash: String = sampleCdHash,
        securityCritical: Bool = false,
        notes: String? = "发布说明"
    ) -> [String: Any] {
        var fields: [String: Any] = [
            "schemaVersion": schemaVersion,
            "appId": appId,
            "version": version,
            "minimumVersion": minimumVersion,
            "buildTime": buildTime,
            "downloadUrl": downloadUrl,
            "cdHash": cdHash,
            "securityCritical": securityCritical,
        ]
        if let notes {
            fields["notes"] = notes
        }
        return fields
    }

    /// canonical(9 字段) → Ed25519 签名 → 组装完整清单 JSON 字节。
    static func signedManifestData(
        fields: [String: Any],
        key: Curve25519.Signing.PrivateKey = privateKey
    ) throws -> Data {
        let canonical = try ManifestVerifier.canonicalJSONData(fields)
        let signature = try key.signature(for: canonical)
        var full = fields
        full["signature"] = signature.base64EncodedString()
        return try JSONSerialization.data(withJSONObject: full)
    }

    /// 组装完整清单 JSON（不签名——篡改 / 验签失败场景用）。
    static func manifestData(fields: [String: Any], signature: String) throws -> Data {
        var full = fields
        full["signature"] = signature
        return try JSONSerialization.data(withJSONObject: full)
    }

    static func parseRFC3339(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }
}

// MARK: - 测试用 stub（协议注入，代替网络层 / 安装层）

final class StubFetcher: ManifestFetching {
    var result: Result<Data, Error>
    init(_ result: Result<Data, Error>) { self.result = result }
    func fetchManifest(from url: URL) async throws -> Data {
        switch result {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }
}

final class StubDownloader: DataDownloading {
    var result: Result<URL, Error>
    var progressValues: [Double] = []
    init(_ result: Result<URL, Error>) { self.result = result }
    func download(from url: URL, progress: @escaping (Double) -> Void) async throws -> URL {
        switch result {
        case .success(let url):
            progress(1.0)
            progressValues.append(1.0)
            return url
        case .failure(let error):
            throw error
        }
    }
}

final class StubInstaller: Installing {
    var result: Result<Void, Error>
    var receivedInfo: UpdateInfo?
    var receivedAppURL: URL?
    init(_ result: Result<Void, Error>) { self.result = result }
    func prepare(downloadedArchive: URL) async throws -> URL {
        downloadedArchive
    }
    func perform(info: UpdateInfo, downloadedAppURL: URL, currentAppURL: URL) async throws {
        receivedInfo = info
        receivedAppURL = downloadedAppURL
        switch result {
        case .success: return
        case .failure(let error): throw error
        }
    }
}

final class StubVerifier: ProductVerifying {
    var result: Result<Void, Error>
    init(_ result: Result<Void, Error>) { self.result = result }
    func verifyApp(at url: URL, expectedCdHash: String) throws {
        switch result {
        case .success: return
        case .failure(let error): throw error
        }
    }
}

struct TestError: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// 捕获子进程 stdout（测试辅助：读 codesign/security 输出；非 0 退出/无法启动/
/// 超过硬超时 → nil）。硬超时防 keychain 解锁弹窗等外部因素把测试挂死（测试纪律：
/// 环境缺失应显式 SKIP，而不是卡住整个门禁）。
func runCapture(_ executable: String, args: [String], timeout: TimeInterval = 20) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = args
    let out = Pipe()
    process.standardOutput = out
    process.standardError = Pipe()
    let queue = DispatchQueue(label: "runCapture")
    let sem = DispatchSemaphore(value: 0)
    var launched = false
    queue.async {
        do {
            try process.run()
            launched = true
        } catch {
            sem.signal()
            return
        }
        process.waitUntilExit()
        sem.signal()
    }
    _ = sem.wait(timeout: .now() + timeout)
    if process.isRunning {
        process.terminate()
        queue.sync {}
    }
    guard launched, process.terminationStatus == 0 else { return nil }
    return String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
}

/// 第一个可用的 codesign 身份（`security find-identity -p codesigning` 引号内身份名；
/// 无 → nil，供 TC-SEC-08 在环境缺失时显式 SKIP 而非误判 fail）。
func firstCodeSigningIdentity() -> String? {
    guard let out = runCapture("/usr/bin/security",
                               args: ["find-identity", "-p", "codesigning"]),
          let line = out.split(separator: "\n").first(where: {
              $0.contains("Apple Development") || $0.contains("Developer ID Application")
          }),
          let open = line.firstIndex(of: "\"") else { return nil }
    let afterOpen = line.index(after: open)
    guard let close = line[afterOpen...].firstIndex(of: "\"") else { return nil }
    return String(line[afterOpen..<close])
}

/// 计数型 fetcher：记录 fetch 次数（用于断言「不应被调用 / 仅调用一次」）。
final class CountingFetcher: ManifestFetching {
    private(set) var fetchCount = 0
    func fetchManifest(from url: URL) async throws -> Data {
        fetchCount += 1
        throw TestError(message: "不应被调用")
    }
}

/// 持有型 fetcher：进入 fetch 后挂起，供测试在 .checking 进行态做防重入断言。
/// 注意：`fetchCount += 1` 放在 continuation body 内（而非 await 前）——`await
/// withCheckedThrowingContinuation` 本身是异步调用，await 前自增会让自旋方在
/// continuation 尚未入队时就退出等待，resumeAll 读到空数组而挂死（实证：全量
/// 门禁在 TC-UPD-22/23 复现）。计数=1 即表示「continuation 已入队且已挂起」。
final class HoldingFetcher: ManifestFetching {
    private(set) var fetchCount = 0
    private var continuations: [CheckedContinuation<Data, Error>] = []
    func fetchManifest(from url: URL) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            fetchCount += 1
            continuations.append(continuation)
        }
    }
    func resumeAll(returning data: Data = Data()) {
        continuations.forEach { $0.resume(returning: data) }
        continuations.removeAll()
    }
}

/// 持有型 downloader：进入下载后挂起，供测试在 .downloading 进行态做防重入断言。
final class HoldingDownloader: DataDownloading {
    private(set) var downloadCount = 0
    private var continuations: [CheckedContinuation<URL, Error>] = []
    func download(from url: URL, progress: @escaping (Double) -> Void) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            downloadCount += 1
            continuations.append(continuation)
        }
    }
    func resumeAll(returning url: URL = URL(fileURLWithPath: "/tmp/fake.zip")) {
        continuations.forEach { $0.resume(returning: url) }
        continuations.removeAll()
    }
}

/// 便捷：构造一个 stub 驱动、待测的 UpdaterManager。
@MainActor
func makeManager(
    currentVersion: String = "2.6.0",
    fetcher: ManifestFetching,
    downloader: DataDownloading = StubDownloader(.failure(TestError(message: "unused"))),
    installer: Installing = StubInstaller(.failure(TestError(message: "unused"))),
    verifier: ProductVerifying = StubVerifier(.success(())),
    publicKeyBase64: String = TestFixture.publicKeyBase64,
    userDefaults: UserDefaults = .standard
) -> UpdaterManager {
    UpdaterManager(
        currentVersion: currentVersion,
        currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"),
        publicKeyBase64: publicKeyBase64,
        fetcher: fetcher,
        downloader: downloader,
        installer: installer,
        verifier: verifier,
        userDefaults: userDefaults
    )
}

// MARK: - TC-MAN 清单解析

do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let m = try UpdateManifest.parse(data)
    check("TC-MAN-01", "合法清单解析 → 各字段正确",
          m.schemaVersion == 1 && m.appId == "app.coffer.Coffer"
          && m.version == "2.7.0" && m.minimumVersion == "2.6.0"
          && m.buildTime == "2026-10-10T00:00:00Z"
          && m.downloadUrl == TestFixture.validDownloadUrl
          && m.cdHash == TestFixture.sampleCdHash
          && m.securityCritical == false && m.notes == "发布说明"
          && !m.signature.isEmpty)

    do {
        _ = try UpdateManifest.parse(Data("not json".utf8))
        check("TC-MAN-02", "非 JSON 字节 → 显式报错（fail-closed）", false, "竟然没报错")
    } catch {
        check("TC-MAN-02", "非 JSON 字节 → 显式报错（fail-closed）", true)
    }

    let badSchema = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(schemaVersion: 2))
    do {
        _ = try UpdateManifest.parse(badSchema)
        check("TC-MAN-03", "schemaVersion≠1 → 拒装", false, "竟然没报错")
    } catch UpdateManifest.ParseError.unsupportedSchemaVersion(let v) {
        check("TC-MAN-03", "schemaVersion≠1 → 拒装", v == 2)
    } catch {
        check("TC-MAN-03", "schemaVersion≠1 → 拒装", false, "错误类型 \(error)")
    }

    let wrongApp = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(appId: "com.other.app"))
    do {
        _ = try UpdateManifest.parse(wrongApp)
        check("TC-MAN-04", "appId 不匹配 → 拒装", false, "竟然没报错")
    } catch UpdateManifest.ParseError.wrongAppId(let id) {
        check("TC-MAN-04", "appId 不匹配 → 拒装", id == "com.other.app")
    } catch {
        check("TC-MAN-04", "appId 不匹配 → 拒装", false, "错误类型 \(error)")
    }

    // 缺必需字段（cdHash）→ Codable 解码报缺字段
    var missingFields = TestFixture.manifestFields()
    missingFields.removeValue(forKey: "cdHash")
    let missingData = try TestFixture.signedManifestData(fields: missingFields)
    do {
        _ = try UpdateManifest.parse(missingData)
        check("TC-MAN-05", "缺必需字段 → 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.missingField(let key) {
        check("TC-MAN-05", "缺必需字段 → 显式报错", key == "cdHash", "缺的字段 \(key)")
    } catch {
        check("TC-MAN-05", "缺必需字段 → 显式报错", false, "错误类型 \(error)")
    }

    // 缺 signature → 解析即拒（signature 为必需字段）
    var noSigFields = TestFixture.manifestFields()
    noSigFields.removeValue(forKey: "signature")
    let noSigData = try JSONSerialization.data(withJSONObject: noSigFields)
    do {
        _ = try UpdateManifest.parse(noSigData)
        check("TC-MAN-06", "缺 signature → 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.missingField(let key) {
        check("TC-MAN-06", "缺 signature → 显式报错", key == "signature")
    } catch {
        check("TC-MAN-06", "缺 signature → 显式报错", false, "错误类型 \(error)")
    }

    // schemaVersion / appId 缺失 → 同样 fail-closed
    var noSchema = TestFixture.manifestFields()
    noSchema.removeValue(forKey: "schemaVersion")
    let noSchemaData = try JSONSerialization.data(withJSONObject: noSchema)
    do {
        _ = try UpdateManifest.parse(noSchemaData)
        check("TC-MAN-07", "缺 schemaVersion → 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.missingField {
        check("TC-MAN-07", "缺 schemaVersion → 显式报错", true)
    } catch {
        check("TC-MAN-07", "缺 schemaVersion → 显式报错", false, "错误类型 \(error)")
    }

    // 字段类型错（schemaVersion 为字符串）→ typeMismatch → invalidJSON
    var badSchemaType = TestFixture.manifestFields()
    badSchemaType["schemaVersion"] = "1"
    let badSchemaTypeData = try TestFixture.signedManifestData(fields: badSchemaType)
    do {
        _ = try UpdateManifest.parse(badSchemaTypeData)
        check("TC-MAN-08", "schemaVersion 类型错（字符串）→ 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.invalidJSON {
        check("TC-MAN-08", "schemaVersion 类型错（字符串）→ 显式报错", true)
    } catch {
        check("TC-MAN-08", "schemaVersion 类型错（字符串）→ 显式报错", false, "错误类型 \(error)")
    }

    // 字段存在但为 null（version=null）→ valueNotFound → missingField
    var nullVersion = TestFixture.manifestFields()
    nullVersion["version"] = NSNull()
    let nullVersionData = try TestFixture.signedManifestData(fields: nullVersion)
    do {
        _ = try UpdateManifest.parse(nullVersionData)
        check("TC-MAN-09", "version 为 null → 显式报错（fail-closed）", false, "竟然没报错")
    } catch UpdateManifest.ParseError.missingField {
        check("TC-MAN-09", "version 为 null → 显式报错（fail-closed）", true)
    } catch {
        check("TC-MAN-09", "version 为 null → 显式报错（fail-closed）", false, "错误类型 \(error)")
    }

    // 缺 securityCritical（必需 Bool）→ missingField
    var noCritical = TestFixture.manifestFields()
    noCritical.removeValue(forKey: "securityCritical")
    let noCriticalData = try TestFixture.signedManifestData(fields: noCritical)
    do {
        _ = try UpdateManifest.parse(noCriticalData)
        check("TC-MAN-10", "缺 securityCritical → 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.missingField(let key) {
        check("TC-MAN-10", "缺 securityCritical → 显式报错", key == "securityCritical", "缺的字段 \(key)")
    } catch {
        check("TC-MAN-10", "缺 securityCritical → 显式报错", false, "错误类型 \(error)")
    }

    // notes 为 null / 缺失 → 解析成功且 notes == nil（可选字段语义）
    var nullNotes = TestFixture.manifestFields()
    nullNotes["notes"] = NSNull()
    let nullNotesData = try TestFixture.signedManifestData(fields: nullNotes)
    let m1 = try UpdateManifest.parse(nullNotesData)
    check("TC-MAN-11", "notes 为 null → 解析成功 notes == nil", m1.notes == nil)
    var noNotes = TestFixture.manifestFields()
    noNotes.removeValue(forKey: "notes")
    let noNotesData = try TestFixture.signedManifestData(fields: noNotes)
    let m2 = try UpdateManifest.parse(noNotesData)
    check("TC-MAN-11", "notes 缺失 → 解析成功 notes == nil", m2.notes == nil)

    // extra 未知字段 → 解析成功（Codable 忽略未知键；验签侧另行拒绝未签名注入）
    var extra = TestFixture.manifestFields()
    extra["unknownExtra"] = "surprise"
    let extraData = try TestFixture.signedManifestData(fields: extra)
    let m3 = try UpdateManifest.parse(extraData)
    check("TC-MAN-12", "extra 未知字段 → 解析成功（Codable 忽略未知键）", m3.version == "2.7.0")

    // securityCritical 为字符串 "false" → 类型错 → invalidJSON
    var badCritical = TestFixture.manifestFields()
    badCritical["securityCritical"] = "false"
    let badCriticalData = try TestFixture.signedManifestData(fields: badCritical)
    do {
        _ = try UpdateManifest.parse(badCriticalData)
        check("TC-MAN-13", "securityCritical 类型错（字符串）→ 显式报错", false, "竟然没报错")
    } catch UpdateManifest.ParseError.invalidJSON {
        check("TC-MAN-13", "securityCritical 类型错（字符串）→ 显式报错", true)
    } catch {
        check("TC-MAN-13", "securityCritical 类型错（字符串）→ 显式报错", false, "错误类型 \(error)")
    }
} catch {
    check("TC-MAN", "夹具异常", false, "\(error)")
}

// MARK: - TC-CANON canonical JSON 字节确定性

do {
    let fields = TestFixture.manifestFields()
    let a = try ManifestVerifier.canonicalJSONData(fields)
    let b = try ManifestVerifier.canonicalJSONData(fields)
    check("TC-CANON-01", "同输入两次序列化字节一致（确定性）", a == b)

    let text = String(data: a, encoding: .utf8) ?? ""
    check("TC-CANON-02", "不包含 signature 字段", !text.contains("signature"))
    check("TC-CANON-03", "withoutEscapingSlashes：URL 斜杠未转义", text.contains("https://github.com/"))
    check("TC-CANON-04", "无缩进（单行、无换行）", !text.contains("\n"))

    // 键按字典序（sortedKeys）：appId < buildTime < cdHash ...
    let appIdx = text.range(of: "\"appId\"")!.lowerBound
    let buildIdx = text.range(of: "\"buildTime\"")!.lowerBound
    let cdIdx = text.range(of: "\"cdHash\"")!.lowerBound
    check("TC-CANON-05", "sortedKeys：appId 在 buildTime 前", appIdx < buildIdx)
    check("TC-CANON-05", "sortedKeys：buildTime 在 cdHash 前", buildIdx < cdIdx)

    // 双侧一致：从完整清单 JSON 解析出的 dict 复算 canonical，与字段级复算字节一致
    let fullData = try TestFixture.signedManifestData(fields: fields)
    let rawDict = try JSONSerialization.jsonObject(with: fullData) as! [String: Any]
    var payloadDict = rawDict
    payloadDict.removeValue(forKey: "signature")
    let c2 = try ManifestVerifier.canonicalJSONData(payloadDict)
    check("TC-CANON-06", "清单 JSON 复算 canonical 与字段级复算字节一致（双侧同实现）", c2 == a,
          "diff 见 a=\(String(data: a, encoding: .utf8)!)")
} catch {
    check("TC-CANON", "夹具异常", false, "\(error)")
}

// MARK: - TC-SIG Ed25519 验签

do {
    let message = try ManifestVerifier.canonicalJSONData(TestFixture.manifestFields())
    let signature = try TestFixture.privateKey.signature(for: message)
    let pubKey = try Curve25519.Signing.PublicKey(
        rawRepresentation: Data(base64Encoded: TestFixture.publicKeyBase64)!)

    check("TC-SIG-01", "自生成密钥对 sign → verify 通过",
          pubKey.isValidSignature(signature, for: message))
    check("TC-SIG-02", "篡改消息 → verify 拒绝",
          !pubKey.isValidSignature(signature, for: message + Data([0x00])))
    let tamperedSig = signature.dropFirst().base64EncodedString()
    check("TC-SIG-03", "篡改签名 → verify 拒绝",
          !pubKey.isValidSignature(Data(base64Encoded: tamperedSig)!, for: message))

    // 完整路径：合法签名清单 → verify 通过
    let goodData = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    check("TC-SIG-04", "完整清单 verify 通过（注入测试公钥）",
          try ManifestVerifier.verify(manifestJSONData: goodData, publicKeyBase64: TestFixture.publicKeyBase64))

    // 篡改字段（改 version，未重新签名）→ 验签拒绝（verify 抛 signatureMismatch）
    do {
        var tampered = TestFixture.manifestFields()
        tampered["version"] = "9.9.9"
        let originalSig = (try JSONSerialization.jsonObject(with: goodData) as! [String: Any])["signature"] as! String
        let tamperedManifest = try TestFixture.manifestData(fields: tampered, signature: originalSig)
        _ = try ManifestVerifier.verify(manifestJSONData: tamperedManifest,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-05", "篡改清单字段（signature 未随改）→ 验签拒绝", false, "竟然通过")
    } catch {
        check("TC-SIG-05", "篡改清单字段（signature 未随改）→ 验签拒绝", true)
    }

    // 非本公钥签名 → 拒绝
    do {
        let otherKey = Curve25519.Signing.PrivateKey()
        let foreignData = try TestFixture.signedManifestData(
            fields: TestFixture.manifestFields(), key: otherKey)
        _ = try ManifestVerifier.verify(manifestJSONData: foreignData,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-06", "用其它公钥签名 → 本公钥验签拒绝", false, "竟然通过")
    } catch {
        check("TC-SIG-06", "用其它公钥签名 → 本公钥验签拒绝", true)
    }

    // 缺 signature 的清单数据 → 显式报错
    var noSigFields = TestFixture.manifestFields()
    noSigFields.removeValue(forKey: "signature")
    let noSigData = try JSONSerialization.data(withJSONObject: noSigFields)
    do {
        _ = try ManifestVerifier.verify(manifestJSONData: noSigData, publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-07", "缺 signature → 显式报错", false, "竟然没报错")
    } catch {
        check("TC-SIG-07", "缺 signature → 显式报错", true)
    }

    // 坏公钥 base64 → 显式报错
    do {
        _ = try ManifestVerifier.verify(manifestJSONData: goodData, publicKeyBase64: "!!!not-base64!!!")
        check("TC-SIG-08", "非法公钥 → 显式报错", false, "竟然没报错")
    } catch {
        check("TC-SIG-08", "非法公钥 → 显式报错", true)
    }

    // ---- 类型断言补全（原 TC-SIG-07/08 只判 any-error，这里把每个可失败点钉死）----

    // 非 JSON → invalidJSON（类型断言）
    do {
        _ = try ManifestVerifier.verify(manifestJSONData: Data("not json".utf8),
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-09", "verify 非 JSON → invalidJSON（类型断言）", false, "竟然没报错")
    } catch ManifestVerifier.VerificationError.invalidJSON {
        check("TC-SIG-09", "verify 非 JSON → invalidJSON（类型断言）", true)
    } catch {
        check("TC-SIG-09", "verify 非 JSON → invalidJSON（类型断言）", false, "错误类型 \(error)")
    }

    // 缺 signature → missingSignature（类型断言）
    do {
        var noSigFields2 = TestFixture.manifestFields()
        noSigFields2.removeValue(forKey: "signature")
        let noSigData2 = try JSONSerialization.data(withJSONObject: noSigFields2)
        _ = try ManifestVerifier.verify(manifestJSONData: noSigData2,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-10", "缺 signature → missingSignature（类型断言）", false, "竟然没报错")
    } catch ManifestVerifier.VerificationError.missingSignature {
        check("TC-SIG-10", "缺 signature → missingSignature（类型断言）", true)
    } catch {
        check("TC-SIG-10", "缺 signature → missingSignature（类型断言）", false, "错误类型 \(error)")
    }

    // signature 非法 base64 → invalidSignatureData
    do {
        let badSigData = try TestFixture.manifestData(
            fields: TestFixture.manifestFields(), signature: "!!!not-base64!!!")
        _ = try ManifestVerifier.verify(manifestJSONData: badSigData,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-11", "signature 非法 base64 → invalidSignatureData", false, "竟然没报错")
    } catch ManifestVerifier.VerificationError.invalidSignatureData {
        check("TC-SIG-11", "signature 非法 base64 → invalidSignatureData", true)
    } catch {
        check("TC-SIG-11", "signature 非法 base64 → invalidSignatureData", false, "错误类型 \(error)")
    }

    // signature 合法 base64 但非 64 字节 Ed25519（3B）→ signatureMismatch（不是 invalidSignatureData）
    do {
        let shortSig = Data([0x01, 0x02, 0x03]).base64EncodedString()
        let shortSigData = try TestFixture.manifestData(fields: TestFixture.manifestFields(), signature: shortSig)
        _ = try ManifestVerifier.verify(manifestJSONData: shortSigData,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-12", "signature 长度不符（3B）→ signatureMismatch", false, "竟然通过")
    } catch ManifestVerifier.VerificationError.signatureMismatch {
        check("TC-SIG-12", "signature 长度不符（3B）→ signatureMismatch", true)
    } catch {
        check("TC-SIG-12", "signature 长度不符（3B）→ signatureMismatch", false, "错误类型 \(error)")
    }

    // 公钥非法 base64 → invalidPublicKey（类型断言）
    do {
        _ = try ManifestVerifier.verify(manifestJSONData: goodData, publicKeyBase64: "!!!not-base64!!!")
        check("TC-SIG-13", "公钥非法 base64 → invalidPublicKey（类型断言）", false, "竟然没报错")
    } catch ManifestVerifier.VerificationError.invalidPublicKey {
        check("TC-SIG-13", "公钥非法 base64 → invalidPublicKey（类型断言）", true)
    } catch {
        check("TC-SIG-13", "公钥非法 base64 → invalidPublicKey（类型断言）", false, "错误类型 \(error)")
    }

    // 公钥合法 base64 但非 32 字节 → invalidPublicKey
    do {
        _ = try ManifestVerifier.verify(manifestJSONData: goodData,
                                        publicKeyBase64: Data([0x01, 0x02]).base64EncodedString())
        check("TC-SIG-14", "公钥合法 base64 但非 32 字节 → invalidPublicKey", false, "竟然没报错")
    } catch ManifestVerifier.VerificationError.invalidPublicKey {
        check("TC-SIG-14", "公钥合法 base64 但非 32 字节 → invalidPublicKey", true)
    } catch {
        check("TC-SIG-14", "公钥合法 base64 但非 32 字节 → invalidPublicKey", false, "错误类型 \(error)")
    }

    // canonical 键序无关：同一字段集，sorted 键序与任意键序清单验签结果一致（都通过）。
    // 签名对象 = canonical(去 signature)，JSON 输入键序不影响 canonical 字节。
    let orderFields = TestFixture.manifestFields()
    let orderCanonical = try ManifestVerifier.canonicalJSONData(orderFields)
    let orderSig = try TestFixture.privateKey.signature(for: orderCanonical)
    var orderFull = orderFields
    orderFull["signature"] = orderSig.base64EncodedString()
    let sortedFull = try JSONSerialization.data(withJSONObject: orderFull, options: [.sortedKeys])
    let arbitraryFull = try JSONSerialization.data(withJSONObject: orderFull)  // 无 sortedKeys → 键序任意
    do {
        let a = try ManifestVerifier.verify(manifestJSONData: sortedFull,
                                            publicKeyBase64: TestFixture.publicKeyBase64)
        let b = try ManifestVerifier.verify(manifestJSONData: arbitraryFull,
                                            publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-15", "字段顺序变化 → 仍验签通过（canonical 键序无关）", a == true && b == true)
    } catch {
        check("TC-SIG-15", "字段顺序变化 → 仍验签通过（canonical 键序无关）", false, "\(error)")
    }

    // extra 字段注入（未随签名重签的未知键）→ 验签失败（signatureMismatch）
    do {
        var injected = TestFixture.manifestFields()
        injected["evil"] = "injected"
        let injectedSig = (try JSONSerialization.jsonObject(with: goodData) as! [String: Any])["signature"] as! String
        let injectedData = try TestFixture.manifestData(fields: injected, signature: injectedSig)
        _ = try ManifestVerifier.verify(manifestJSONData: injectedData,
                                        publicKeyBase64: TestFixture.publicKeyBase64)
        check("TC-SIG-16", "extra 字段注入 → 验签失败（signatureMismatch）", false, "竟然通过")
    } catch ManifestVerifier.VerificationError.signatureMismatch {
        check("TC-SIG-16", "extra 字段注入 → 验签失败（signatureMismatch）", true)
    } catch {
        check("TC-SIG-16", "extra 字段注入 → 验签失败（signatureMismatch）", false, "错误类型 \(error)")
    }
} catch {
    check("TC-SIG", "夹具异常", false, "\(error)")
}

// MARK: - TC-VER 版本比较

check("TC-VER-01", "2.7.0 比 2.6.0 新",
      VersionCompare.isNewer("2.7.0", than: "2.6.0"))
check("TC-VER-02", "2.10 比 2.9 新（数字点分，非字典序）",
      VersionCompare.isNewer("2.10", than: "2.9"))
check("TC-VER-03", "2.7.0 与 2.7.0 相等（equal）",
      VersionCompare.compare("2.7.0", "2.7.0") == .equal)
check("TC-VER-04", "缺组件按 0 补齐：2.7 与 2.7.0 相等",
      VersionCompare.compare("2.7", "2.7.0") == .equal)
check("TC-VER-05", "当前 2.6.0 低于最低 2.7.0（minimum 高于当前 → 拒装判据）",
      VersionCompare.isBelow("2.6.0", minimum: "2.7.0"))
check("TC-VER-06", "当前等于最低 2.6.0 → 不拒装",
      !VersionCompare.isBelow("2.6.0", minimum: "2.6.0"))
check("TC-VER-07", "当前 2.8.0 高于最低 2.6.0 → 不拒装",
      !VersionCompare.isBelow("2.8.0", minimum: "2.6.0"))
check("TC-VER-08", "非数字组件 → 无法比较（nil）",
      VersionCompare.compare("2.x", "2.6.0") == nil)
check("TC-VER-09", "旧版不比新（descending 判据）",
      VersionCompare.compare("2.6.0", "2.7.0") == .ascending)
check("TC-VER-10", "前导零：2.07.0 == 2.7.0（Int 归一）",
      VersionCompare.compare("2.07.0", "2.7.0") == .equal)
check("TC-VER-11", "空串：点分为空 → 按 0 补齐，与 0.0.0 相等",
      VersionCompare.compare("", "0.0.0") == .equal)
check("TC-VER-12", "更长点分：2.7.0.1 比 2.7.0 新",
      VersionCompare.isNewer("2.7.0.1", than: "2.7.0"))
check("TC-VER-13", "负组件可比较：-1.0 < 0.0",
      VersionCompare.compare("-1.0", "0.0") == .ascending)

// MARK: - TC-HOST 白名单 host 判定（纯函数）

let allowed = OTAEndpointPolicy.allowedHosts
check("TC-HOST-01", "白名单恰为契约 4 host", allowed == [
    "api.github.com", "github.com", "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
])

check("TC-HOST-02", "api.github.com 放行", OTAEndpointPolicy.isAllowedHost("api.github.com"))
check("TC-HOST-02", "github.com 放行", OTAEndpointPolicy.isAllowedHost("github.com"))
check("TC-HOST-02", "objects.githubusercontent.com 放行", OTAEndpointPolicy.isAllowedHost("objects.githubusercontent.com"))
check("TC-HOST-02", "release-assets.githubusercontent.com 放行", OTAEndpointPolicy.isAllowedHost("release-assets.githubusercontent.com"))

check("TC-HOST-03", "https + 白名单 host URL 放行",
      OTAEndpointPolicy.isAllowedURL(URL(string: TestFixture.validDownloadUrl)!))
check("TC-HOST-04", "http 拒绝（强制 https）",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "http://github.com/foo.zip")!))
check("TC-HOST-05", "任意其它 host 拒绝",
      !OTAEndpointPolicy.isAllowedHost("evil.example.com"))
check("TC-HOST-06", "https 但非白名单 host 拒绝",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "https://evil.example.com/foo")!))

do {
    try OTAEndpointPolicy.validate(URL(string: "http://github.com/foo")!)
    check("TC-HOST-07", "validate 对 http → 抛错", false, "竟然没报错")
} catch {
    check("TC-HOST-07", "validate 对 http → 抛错", true)
}
do {
    try OTAEndpointPolicy.validate(URL(string: "https://evil.example.com/foo")!)
    check("TC-HOST-08", "validate 对非白名单 host → 抛错", false, "竟然没报错")
} catch {
    check("TC-HOST-08", "validate 对非白名单 host → 抛错", true)
}

// ---- 边界：大小写 / 端口 / 无 host / 非 https / 子域与后缀混淆 / 路径查询 ----
check("TC-HOST-09", "大写 host（GITHUB.com）→ 放行（host 小写统一比较，对齐 UpdateCopy，LOW）",
      OTAEndpointPolicy.isAllowedURL(URL(string: "https://GITHUB.com/foo")!))
check("TC-HOST-10", "端口不影响 host 判定（:443 放行）",
      OTAEndpointPolicy.isAllowedURL(URL(string: "https://github.com:443/foo")!))
check("TC-HOST-10", "端口不影响 host 判定（:8443 仍放行——host-only 策略）",
      OTAEndpointPolicy.isAllowedURL(URL(string: "https://github.com:8443/foo")!))
check("TC-HOST-11", "无 host（https:///foo）→ 拒绝",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "https:///foo")!))
check("TC-HOST-12", "非 https scheme（ftp://github.com）→ 拒绝",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "ftp://github.com/foo")!))
check("TC-HOST-12", "大写 scheme（HTTP://github.com）→ 拒绝（scheme 小写化后仍非 https）",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "HTTP://github.com/foo")!))
check("TC-HOST-13", "子域名（evil.github.com）→ 拒绝（精确匹配，非后缀/前缀通配）",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "https://evil.github.com/foo")!))
check("TC-HOST-14", "后缀混淆（github.com.evil.com）→ 拒绝",
      !OTAEndpointPolicy.isAllowedURL(URL(string: "https://github.com.evil.com/foo")!))
check("TC-HOST-15", "path/query/fragment 不影响 host 判定（放行）",
      OTAEndpointPolicy.isAllowedURL(URL(string: "https://github.com/path?q=1#frag")!))
do {
    try OTAEndpointPolicy.validate(URL(string: "https:///foo")!)
    check("TC-HOST-16", "validate 对无 host URL → 抛错（hostNotAllowed(nil)）", false, "竟然没报错")
} catch {
    check("TC-HOST-16", "validate 对无 host URL → 抛错（hostNotAllowed(nil)）", true)
}
check("TC-HOST-17", "isAllowedHost 大写 → 放行（统一小写比较，LOW 口径一致）",
      OTAEndpointPolicy.isAllowedHost("GITHUB.COM"))

// MARK: - TC-SEC SecCodeVerifier（真实已签名产物；产物缺失显式 SKIP）

do {
    // 产物路径由运行器经 env 注入（无产物时以下测试显式 SKIP，不算 fail）。
    let artifact = URL(fileURLWithPath:
        ProcessInfo.processInfo.environment["COFFER_UPDATE_ARTIFACT_PATH"]
        ?? "/Users/cygnus/work/github/coffer/macos/build/Coffer.app")
    if FileManager.default.fileExists(atPath: artifact.path) {
        // 读出产物真实 cdHash（与 codesign -dv 输出一致），再断言 DR / 比对
        let realCdHash = try SecCodeVerifier.cdHashHex(of: artifact)
        check("TC-SEC-01", "读产物 kSecCodeInfoUnique 为 40 位 hex",
              realCdHash.count == 40 && realCdHash.allSatisfy { $0.isHexDigit },
              "实际 \(realCdHash)")

        // 用真实 cdHash → 三级验签全过
        do {
            try SecCodeVerifier.verifyApp(at: artifact, expectedCdHash: realCdHash)
            check("TC-SEC-02", "DR(TeamID+identifier)+CDHash 比对通过（真实产物）", true)
        } catch {
            check("TC-SEC-02", "DR(TeamID+identifier)+CDHash 比对通过（真实产物）", false, "\(error)")
        }

        // H-3 正面：对真实产物的嵌套 Contents/Helpers/*.app 逐一验签通过
        do {
            try SecCodeVerifier.verifyNestedHelpers(in: artifact)
            check("TC-SEC-05", "嵌套 Contents/Helpers 逐一验签通过（真实产物，H-3 正面）", true)
        } catch {
            check("TC-SEC-05", "嵌套 Contents/Helpers 逐一验签通过（真实产物，H-3 正面）", false, "\(error)")
        }

        // 篡改 cdHash → 拒绝（次锚生效）
        let wrongCdHash = realCdHash == String(repeating: "0", count: 40)
            ? "1" + realCdHash.dropFirst()
            : String(repeating: "0", count: 40)
        do {
            try SecCodeVerifier.verifyApp(at: artifact, expectedCdHash: wrongCdHash)
            check("TC-SEC-03", "cdHash 不匹配 → 拒绝（次锚）", false, "竟然通过")
        } catch SecCodeVerifier.VerificationError.cdHashMismatch {
            check("TC-SEC-03", "cdHash 不匹配 → 拒绝（次锚）", true)
        } catch {
            check("TC-SEC-03", "cdHash 不匹配 → 拒绝（次锚）", false, "错误类型 \(error)")
        }

        // 非 .app 路径 → 显式报错
        let nonApp = URL(fileURLWithPath: "/etc/hosts")
        do {
            try SecCodeVerifier.verifyApp(at: nonApp, expectedCdHash: realCdHash)
            check("TC-SEC-04", "非 .app 路径 → 显式报错", false, "竟然通过")
        } catch {
            check("TC-SEC-04", "非 .app 路径 → 显式报错", true)
        }

        // 完整链路（无网络）：真实产物 → zip → prepare 解压 → 三级验签通过。
        // 证明 ditto 打/解 zip 保留签名（下载→解压→验签的离线闭环）。
        do {
            let zipDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("coffer-ota-sec-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
            try FileManager.default.createDirectory(at: zipDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: zipDir) }
            let zipURL = zipDir.appendingPathComponent("Coffer.zip")
            try OTAInstaller.archiveApp(artifact, to: zipURL)
            let installer = OTAInstaller(helperURL: URL(fileURLWithPath: "/tmp/unused-helper"))
            let extracted = try await installer.prepare(downloadedArchive: zipURL)
            do {
                try SecCodeVerifier.verifyApp(at: extracted, expectedCdHash: realCdHash)
                check("TC-INST-03", "真实产物 zip→解压→三级验签通过（ditto 保留签名）", true)
            } catch {
                check("TC-INST-03", "真实产物 zip→解压→三级验签通过（ditto 保留签名）", false, "\(error)")
            }
        } catch {
            check("TC-INST-03", "真实产物 zip→解压→三级验签通过（ditto 保留签名）", false, "\(error)")
        }

        // H-3 负面（identifier）：复制真实嵌套 helper → 改 CFBundleIdentifier →
        // 真实签名重签 → 嵌套 identifier 不在期望集合 → 拒装。异 TeamID 无法用单一
        // 身份伪造（探针+单证书约束），此「同 TeamID 异 identifier」为代理；真异
        // TeamID 归真机/CI 双身份核销。环境缺签名身份/codesign 失败 → 显式 SKIP。
        do {
            let helpersDir = artifact.appendingPathComponent("Contents/Helpers")
            let nestedSources = (try? FileManager.default.contentsOfDirectory(
                at: helpersDir, includingPropertiesForKeys: nil)) ?? []
            if let helperSource = nestedSources.first(where: { $0.pathExtension == "app" }),
               let identity = firstCodeSigningIdentity() {
                let secDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent("coffer-ota-sec8-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: secDir, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: secDir) }
                let modified = secDir
                    .appendingPathComponent("Contents/Helpers/Modified.app")
                try FileManager.default.createDirectory(
                    at: modified.deletingLastPathComponent(), withIntermediateDirectories: true)
                try FileManager.default.copyItem(at: helperSource, to: modified)
                // 改 identifier → 真实重签（与 Helper 同 TeamID；DR anchor+OU 仍过，
                // identifier 集合复核应拒）
                let infoPlist = modified.appendingPathComponent("Contents/Info.plist")
                _ = runCapture("/usr/libexec/PlistBuddy",
                               args: ["-c", "Set :CFBundleIdentifier com.attacker.app", infoPlist.path])
                if runCapture("/usr/bin/codesign",
                              args: ["--force", "--sign", identity, modified.path]) != nil {
                    do {
                        try SecCodeVerifier.verifyNestedHelpers(in: secDir)
                        check("TC-SEC-08", "嵌套 identifier 不在期望集合 → 拒装（真实重签副本，H-3）",
                              false, "竟然通过")
                    } catch SecCodeVerifier.VerificationError.identifierMismatch {
                        check("TC-SEC-08", "嵌套 identifier 不在期望集合 → 拒装（真实重签副本，H-3）",
                              true)
                    } catch {
                        check("TC-SEC-08", "嵌套 identifier 不在期望集合 → 拒装（真实重签副本，H-3）",
                              false, "错误类型 \(error)")
                    }
                } else {
                    skip("TC-SEC-08", "真实重签失败（codesign 不可用）→ SKIP",
                         "无法构造异 identifier 副本")
                }
            } else {
                skip("TC-SEC-08", "产物无嵌套 helper 或无可签名身份 → SKIP",
                     "Contents/Helpers 无 .app 或 find-identity 空")
            }
        } catch {
            check("TC-SEC-08", "夹具异常", false, "\(error)")
        }
    } else {
        skip("TC-SEC-01", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-SEC-02", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-SEC-03", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-SEC-04", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-SEC-05", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-SEC-08", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
        skip("TC-INST-03", "产物缺失 SKIP", "macos/build/Coffer.app 不存在")
    }
} catch {
    check("TC-SEC", "夹具异常", false, "\(error)")
}

// H-3 负面（合成目录直调 verifyNestedHelpers，不依赖真实产物）：
// 伪造无嵌套 → nestedHelperMissing；伪造未签名嵌套 → nestedHelperInvalid。
do {
    // 无 Contents/Helpers 目录（或空）→ 「伪造无嵌套」→ 拒装
    let noNestedDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("coffer-ota-sec6-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: noNestedDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: noNestedDir) }
    do {
        try SecCodeVerifier.verifyNestedHelpers(in: noNestedDir)
        check("TC-SEC-06", "伪造无嵌套（无 Contents/Helpers）→ 拒装（nestedHelperMissing，H-3）",
              false, "竟然通过")
    } catch SecCodeVerifier.VerificationError.nestedHelperMissing {
        check("TC-SEC-06", "伪造无嵌套（无 Contents/Helpers）→ 拒装（nestedHelperMissing，H-3）",
              true)
    } catch {
        check("TC-SEC-06", "伪造无嵌套（无 Contents/Helpers）→ 拒装（nestedHelperMissing，H-3）",
              false, "错误类型 \(error)")
    }
} catch {
    check("TC-SEC-06", "夹具异常", false, "\(error)")
}

do {
    // 合法 bundle 结构 + 未签名可执行 → 嵌套验签失败（DR 不过）→ 拒装
    let unsignedDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("coffer-ota-sec7-\(UUID().uuidString)", isDirectory: true)
    let exeDir = unsignedDir
        .appendingPathComponent("Contents/Helpers/FakeHelper.app/Contents/MacOS")
    try FileManager.default.createDirectory(at: exeDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: unsignedDir) }
    let infoPlist = unsignedDir
        .appendingPathComponent("Contents/Helpers/FakeHelper.app/Contents/Info.plist")
    try Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>FakeHelper</string>
    <key>CFBundleIdentifier</key><string>app.coffer.Coffer.updater</string>
    <key>CFBundleName</key><string>FakeHelper</string>
    </dict></plist>
    """.utf8).write(to: infoPlist)
    try Data("#!/bin/sh\nexit 0\n".utf8).write(
        to: exeDir.appendingPathComponent("FakeHelper"))
    do {
        try SecCodeVerifier.verifyNestedHelpers(in: unsignedDir)
        check("TC-SEC-07", "伪造未签名嵌套 helper → 拒装（nestedHelperInvalid，H-3）",
              false, "竟然通过")
    } catch SecCodeVerifier.VerificationError.nestedHelperInvalid {
        check("TC-SEC-07", "伪造未签名嵌套 helper → 拒装（nestedHelperInvalid，H-3）",
              true)
    } catch {
        check("TC-SEC-07", "伪造未签名嵌套 helper → 拒装（nestedHelperInvalid，H-3）",
              false, "错误类型 \(error)")
    }
} catch {
    check("TC-SEC-07", "夹具异常", false, "\(error)")
}

// MARK: - TC-UPD UpdaterManager 状态机（stub 网络层，不联网）

// 检查成功路径 → updateAvailable 且 UpdateInfo 正确
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let fetcher = StubFetcher(.success(data))
    let manager = makeManager(currentVersion: "2.6.0", fetcher: fetcher)
    await manager.check()
    switch manager.state {
    case .updateAvailable(let info):
        check("TC-UPD-01", "check 成功 → updateAvailable", true)
        check("TC-UPD-02", "UpdateInfo.version 正确", info.version == "2.7.0")
        check("TC-UPD-02", "UpdateInfo.minimumVersion 正确", info.minimumVersion == "2.6.0")
        check("TC-UPD-02", "UpdateInfo.downloadUrl 正确",
              info.downloadUrl.absoluteString == TestFixture.validDownloadUrl)
        check("TC-UPD-02", "UpdateInfo.cdHash 正确", info.cdHash == TestFixture.sampleCdHash)
        check("TC-UPD-02", "UpdateInfo.securityCritical 正确", info.securityCritical == false)
        check("TC-UPD-02", "UpdateInfo.notes 正确", info.notes == "发布说明")
        check("TC-UPD-02", "UpdateInfo.buildTime 解析为 Date",
              info.buildTime == TestFixture.parseRFC3339("2026-10-10T00:00:00Z"))
    default:
        check("TC-UPD-01", "check 成功 → updateAvailable", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-01", "夹具异常", false, "\(error)")
}

// 已是最新：清单 version == current → upToDate
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(version: "2.6.0"))
    let manager = makeManager(currentVersion: "2.6.0", fetcher: StubFetcher(.success(data)))
    await manager.check()
    check("TC-UPD-03", "清单 version == 当前 → upToDate", manager.state == .upToDate,
          "state=\(manager.state)")
} catch {
    check("TC-UPD-03", "夹具异常", false, "\(error)")
}

// 清单 version 低于当前 → upToDate
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(version: "2.5.0"))
    let manager = makeManager(currentVersion: "2.6.0", fetcher: StubFetcher(.success(data)))
    await manager.check()
    check("TC-UPD-04", "清单 version 低于当前 → upToDate", manager.state == .upToDate,
          "state=\(manager.state)")
} catch {
    check("TC-UPD-04", "夹具异常", false, "\(error)")
}

// 网络失败 → failed（fail-closed）
do {
    let manager = makeManager(
        fetcher: StubFetcher(.failure(TestError(message: "network down"))))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-05", "网络失败 → failed（用户可见文案）", !msg.isEmpty)
    } else {
        check("TC-UPD-05", "网络失败 → failed（用户可见文案）", false, "state=\(manager.state)")
    }
}

// 验签失败（signature 未随字段改）→ failed
do {
    var tampered = TestFixture.manifestFields()
    tampered["version"] = "9.9.9"
    let goodData = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let originalSig = (try JSONSerialization.jsonObject(with: goodData) as! [String: Any])["signature"] as! String
    let tamperedData = try TestFixture.manifestData(fields: tampered, signature: originalSig)
    let manager = makeManager(fetcher: StubFetcher(.success(tamperedData)))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-06", "验签失败 → failed（fail-closed）", !msg.isEmpty)
    } else {
        check("TC-UPD-06", "验签失败 → failed（fail-closed）", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-06", "夹具异常", false, "\(error)")
}

// 非 JSON → failed
do {
    let manager = makeManager(fetcher: StubFetcher(.success(Data("garbage".utf8))))
    await manager.check()
    if case .failed = manager.state {
        check("TC-UPD-07", "清单非 JSON → failed", true)
    } else {
        check("TC-UPD-07", "清单非 JSON → failed", false, "state=\(manager.state)")
    }
}

// schemaVersion≠1 → failed
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(schemaVersion: 2))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed = manager.state {
        check("TC-UPD-08", "schemaVersion≠1 → failed", true)
    } else {
        check("TC-UPD-08", "schemaVersion≠1 → failed", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-08", "夹具异常", false, "\(error)")
}

// current < minimumVersion → 拒装（failed 带用户可见文案）
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(version: "2.7.0", minimumVersion: "2.8.0"))
    let manager = makeManager(currentVersion: "2.6.0", fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-09", "当前低于 minimumVersion → 拒装（fail-closed）", !msg.isEmpty)
    } else {
        check("TC-UPD-09", "当前低于 minimumVersion → 拒装（fail-closed）", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-09", "夹具异常", false, "\(error)")
}

// 清单 downloadUrl host 非白名单 → failed（纵深防御）
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields(
        downloadUrl: "https://evil.example.com/Coffer.zip"))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-10", "downloadUrl 非白名单 host → failed（纵深）", !msg.isEmpty)
    } else {
        check("TC-UPD-10", "downloadUrl 非白名单 host → failed（纵深）", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-10", "夹具异常", false, "\(error)")
}

// install 成功路径：downloading → downloaded → installing
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let downloader = StubDownloader(.success(URL(fileURLWithPath: "/tmp/fake.zip")))
    let installer = StubInstaller(.success(()))
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)), downloader: downloader, installer: installer)
    await manager.check()
    await manager.install()
    check("TC-UPD-11", "install 成功 → 终态 installing", manager.state == .installing,
          "state=\(manager.state)")
    check("TC-UPD-12", "downloader 收到下载（进度回调触发）",
          downloader.progressValues == [1.0])
    check("TC-UPD-13", "installer 收到正确 info", installer.receivedInfo?.version == "2.7.0")
    check("TC-UPD-13", "installer 收到解压产物路径", installer.receivedAppURL?.path == "/tmp/fake.zip")
} catch {
    check("TC-UPD-11", "夹具异常", false, "\(error)")
}

// install 失败（installer 抛错）→ failed
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let installer = StubInstaller(.failure(TestError(message: "helper exit 2")))
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)),
        downloader: StubDownloader(.success(URL(fileURLWithPath: "/tmp/fake.zip"))),
        installer: installer)
    await manager.check()
    await manager.install()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-14", "install 失败（installer 抛错）→ failed", !msg.isEmpty)
    } else {
        check("TC-UPD-14", "install 失败（installer 抛错）→ failed", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-14", "夹具异常", false, "\(error)")
}

// install 失败（下载失败）→ failed
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)),
        downloader: StubDownloader(.failure(TestError(message: "download failed"))))
    await manager.check()
    await manager.install()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-15", "install 失败（下载失败）→ failed", !msg.isEmpty)
    } else {
        check("TC-UPD-15", "install 失败（下载失败）→ failed", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-15", "夹具异常", false, "\(error)")
}

// dismiss → idle
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    manager.dismiss()
    check("TC-UPD-16", "dismiss → idle", manager.state == .idle, "state=\(manager.state)")
} catch {
    check("TC-UPD-16", "夹具异常", false, "\(error)")
}

// 进行中（downloaded/installing）时忽略重复 check —— 用 install 进行态验证不被打断
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)),
        downloader: StubDownloader(.success(URL(fileURLWithPath: "/tmp/fake.zip"))),
        installer: StubInstaller(.success(())))
    await manager.check()
    await manager.install()
    let during = manager.state
    await manager.check()
    check("TC-UPD-17", "installing 中重复 check 不改状态", manager.state == during,
          "during=\(during) after=\(manager.state)")
} catch {
    check("TC-UPD-17", "夹具异常", false, "\(error)")
}

// 清单 buildTime 非法 → failed（fail-closed，不静默）
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(buildTime: "not-a-date"))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-18", "buildTime 非法 → failed", !msg.isEmpty)
    } else {
        check("TC-UPD-18", "buildTime 非法 → failed", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-18", "夹具异常", false, "\(error)")
}

// install 验签失败（verifier 抛错）→ failed
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)),
        downloader: StubDownloader(.success(URL(fileURLWithPath: "/tmp/fake.zip"))),
        installer: StubInstaller(.success(())),
        verifier: StubVerifier(.failure(TestError(message: "cdHash mismatch"))))
    await manager.check()
    await manager.install()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-19", "install 验签失败（verifier 抛错）→ failed", !msg.isEmpty)
    } else {
        check("TC-UPD-19", "install 验签失败（verifier 抛错）→ failed", false, "state=\(manager.state)")
    }
} catch {
    check("TC-UPD-19", "夹具异常", false, "\(error)")
}

// MARK: - TC-UPD2 状态机补全（manifestURL 白名单 / 非数字版本 / downloadUrl 纵深 / 防重入）

// manifestURL 非白名单 → failed（发起请求前拦截），fetcher 不应被调用
do {
    let counting = CountingFetcher()
    let manager = UpdaterManager(
        manifestURL: URL(string: "https://evil.example.com/update-manifest.json")!,
        currentVersion: "2.6.0",
        currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"),
        publicKeyBase64: TestFixture.publicKeyBase64,
        fetcher: counting,
        downloader: StubDownloader(.failure(TestError(message: "unused"))),
        installer: StubInstaller(.failure(TestError(message: "unused"))),
        verifier: StubVerifier(.success(())),
        userDefaults: .standard)
    await manager.check()
    if case .failed = manager.state {
        check("TC-UPD-20", "manifestURL 非白名单 → failed（请求前拦截）", true)
    } else {
        check("TC-UPD-20", "manifestURL 非白名单 → failed（请求前拦截）", false, "state=\(manager.state)")
    }
    check("TC-UPD-20", "manifestURL 拦截时 fetcher 未被调用",
          counting.fetchCount == 0, "fetchCount=\(counting.fetchCount)")
}

// manifest.version 非数字 → failed（版本无法解析文案）
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields(version: "abc"))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed(let msg) = manager.state {
        check("TC-UPD-21", "manifest.version 非数字 → failed（fail-closed）", !msg.isEmpty)
    } else {
        check("TC-UPD-21", "manifest.version 非数字 → failed（fail-closed）", false, "state=\(manager.state)")
    }
}

// checking 进行中二次 check 被忽略（防重入，fetch 仅一次）
do {
    let fetcher = HoldingFetcher()
    let manager = makeManager(fetcher: fetcher)
    let t1 = Task { await manager.check() }
    // 等 check 挂起在 fetch：continuation body 可能被延迟成独立 job，
    // 须用 sleep 真正让出主执行器（yield 的抢占式重排队会饿死 body job → 门禁偶发挂死）。
    // 上限 5s：异常时降级为断言失败而非无限挂起。
    var waits = 0
    while fetcher.fetchCount == 0 && waits < 5_000 {
        try? await Task.sleep(nanoseconds: 1_000_000)
        waits += 1
    }
    await manager.check()   // .checking 中 → guard 拦截
    let countDuring = fetcher.fetchCount
    fetcher.resumeAll()
    await t1.value
    check("TC-UPD-22", "checking 中二次 check 被忽略（fetch 仅一次）",
          countDuring == 1 && fetcher.fetchCount == 1, "fetchCount=\(fetcher.fetchCount)")
}

// downloading 进行中：check() 被忽略 + install() no-op（downloader 仅一次，perform 未触发）
do {
    let data = try TestFixture.signedManifestData(fields: TestFixture.manifestFields())
    let downloader = HoldingDownloader()
    let installer = StubInstaller(.success(()))
    let manager = makeManager(
        fetcher: StubFetcher(.success(data)),
        downloader: downloader,
        installer: installer)
    await manager.check()   // → updateAvailable
    let t = Task { await manager.install() }   // → downloading(0) 后挂起在 download
    // 同上：sleep 让出主执行器等 continuation body 运行（yield 抢占可饿死 body job → 偶发挂死）
    var waits = 0
    while downloader.downloadCount == 0 && waits < 5_000 {
        try? await Task.sleep(nanoseconds: 1_000_000)
        waits += 1
    }
    await manager.check()     // downloading 中 → 忽略
    await manager.install()   // downloading 中 → install() guard .updateAvailable no-op
    let countDuring = downloader.downloadCount
    let installerDuring = installer.receivedInfo   // 应为 nil（二次 install 未进 perform）
    downloader.resumeAll()
    await t.value
    check("TC-UPD-23", "downloading 中 check() 被忽略（download 仅一次）",
          countDuring == 1 && downloader.downloadCount == 1, "count=\(downloader.downloadCount)")
    check("TC-UPD-24", "downloading 中 install() no-op（未触发 perform）",
          installerDuring == nil, "installer.receivedInfo=\(String(describing: installerDuring))")
}

// downloadUrl http → failed（纵深：validate insecureScheme）
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(downloadUrl: "http://github.com/Coffer.zip"))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed = manager.state {
        check("TC-UPD-25", "downloadUrl http → failed（纵深拦截）", true)
    } else {
        check("TC-UPD-25", "downloadUrl http → failed（纵深拦截）", false, "state=\(manager.state)")
    }
}

// downloadUrl 非 URL 字符串 → failed（UpdateInfo.invalidDownloadURL）
// 注意：URL(string:) 对 "not a url" 宽容（百分号编码成相对 URL，scheme=nil）——
// 它会在 validate 处因缺 scheme 失败；这里用 URL(string:) 真拒的串（未闭合 IPv6）
// 才能命中 invalidDownloadURL 分支。
do {
    let data = try TestFixture.signedManifestData(
        fields: TestFixture.manifestFields(downloadUrl: "http://[::1"))
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .failed = manager.state {
        check("TC-UPD-26", "downloadUrl 非 URL → failed（fail-closed）", true)
    } else {
        check("TC-UPD-26", "downloadUrl 非 URL → failed（fail-closed）", false, "state=\(manager.state)")
    }
}

// UpdateInfo(manifest:) 直接单测（精确错误类型 + RFC3339 边界）
do {
    let badURLManifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields(downloadUrl: "http://[::1")))
    do {
        _ = try UpdateInfo(manifest: badURLManifest)
        check("TC-UPD-27", "UpdateInfo invalidDownloadURL（类型断言）", false, "竟然没报错")
    } catch UpdateInfoError.invalidDownloadURL {
        check("TC-UPD-27", "UpdateInfo invalidDownloadURL（类型断言）", true)
    } catch {
        check("TC-UPD-27", "UpdateInfo invalidDownloadURL（类型断言）", false, "错误类型 \(error)")
    }

    let badTimeManifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields(buildTime: "not-a-date")))
    do {
        _ = try UpdateInfo(manifest: badTimeManifest)
        check("TC-UPD-27", "UpdateInfo invalidBuildTime（类型断言）", false, "竟然没报错")
    } catch UpdateInfoError.invalidBuildTime {
        check("TC-UPD-27", "UpdateInfo invalidBuildTime（类型断言）", true)
    } catch {
        check("TC-UPD-27", "UpdateInfo invalidBuildTime（类型断言）", false, "错误类型 \(error)")
    }
    // RFC3339 边界：默认 ISO8601 .withInternetDateTime 不含小数秒 → 小数秒解析失败。
    // 提醒 CI 签名工具：MF_BUILD_TIME 必须用整秒（如 2026-10-10T00:00:00Z），勿带 .123。
    check("TC-UPD-27", "RFC3339 带小数秒 → 解析失败（CI 须用整秒）",
          TestFixture.parseRFC3339("2026-10-10T00:00:00.123Z") == nil)
}

// userMessage 映射（LocalizedError 优先 / 非 LocalizedError 前缀）
check("TC-UPD-28", "userMessage 对 LocalizedError 取 errorDescription",
      UpdaterManager.userMessage(from: UpdateManifest.ParseError.invalidJSON("bad"))
        == "更新清单格式无效：bad")
check("TC-UPD-28", "userMessage 对非 LocalizedError 加「更新失败：」前缀",
      UpdaterManager.userMessage(from: NSError(domain: "x", code: 1, userInfo: nil)).hasPrefix("更新失败："))

// 含 extra 字段且重新签名 → 正常 updateAvailable（parse 忽略未知键 + 验签通过 = 向后兼容）
do {
    var extra = TestFixture.manifestFields()
    extra["futureField"] = "future"
    let data = try TestFixture.signedManifestData(fields: extra)
    let manager = makeManager(fetcher: StubFetcher(.success(data)))
    await manager.check()
    if case .updateAvailable = manager.state {
        check("TC-UPD-29", "含 extra 字段且重新签名 → updateAvailable（向后兼容）", true)
    } else {
        check("TC-UPD-29", "含 extra 字段且重新签名 → updateAvailable（向后兼容）", false, "state=\(manager.state)")
    }
}

// MARK: - TC-INST OTAInstaller.prepare（解压 zip 提取 .app；无网络）

do {
    let fm = FileManager.default
    let tempRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-inst-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
    try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempRoot) }

    // 造一个假的 .app 目录结构
    let fakeApp = tempRoot.appendingPathComponent("Fake.app", isDirectory: true)
    let macosDir = fakeApp.appendingPathComponent("Contents/MacOS", isDirectory: true)
    try fm.createDirectory(at: macosDir, withIntermediateDirectories: true)
    let binURL = macosDir.appendingPathComponent("Fake")
    try Data("#!/bin/sh\necho fake\n".utf8).write(to: binURL)
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binURL.path)
    try "fakeroot".write(
        to: tempRoot.appendingPathComponent("sentinel.txt"), atomically: true, encoding: .utf8)

    // 用 ditto 打 zip
    let zipURL = tempRoot.appendingPathComponent("fake.zip")
    try OTAInstaller.archiveApp(fakeApp, to: zipURL)

    let installer = OTAInstaller(helperURL: URL(fileURLWithPath: "/tmp/unused-helper"))
    let extracted = try await installer.prepare(downloadedArchive: zipURL)
    check("TC-INST-01", "prepare 从 zip 提取出 .app", extracted.lastPathComponent == "Fake.app",
          "提取 \(extracted.lastPathComponent)")
    check("TC-INST-01", "提取的 .app 结构完整（Contents/MacOS）",
          fm.fileExists(atPath: extracted.appendingPathComponent("Contents/MacOS/Fake").path))

    // 非 zip → 抛错
    let junk = tempRoot.appendingPathComponent("junk.zip")
    try Data("this is not a zip".utf8).write(to: junk)
    do {
        _ = try await installer.prepare(downloadedArchive: junk)
        check("TC-INST-02", "非 zip → prepare 显式报错", false, "竟然没报错")
    } catch {
        check("TC-INST-02", "非 zip → prepare 显式报错", true)
    }
} catch {
    check("TC-INST", "夹具异常", false, "\(error)")
}

// MARK: - TC-INST2 prepare 边界（无 .app / 混有其它文件）+ perform 失败路径

do {
    let fm = FileManager.default
    let tempRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-inst2-\(Int(Date().timeIntervalSince1970))", isDirectory: true)
    try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempRoot) }

    let installer = OTAInstaller(helperURL: URL(fileURLWithPath: "/tmp/unused-helper"))

    // 合法 zip 但内无 .app → appNotFound（fail-closed）
    let payload = tempRoot.appendingPathComponent("payload", isDirectory: true)
    try fm.createDirectory(at: payload, withIntermediateDirectories: true)
    try Data("readme".utf8).write(to: payload.appendingPathComponent("README.txt"))
    let noAppZip = tempRoot.appendingPathComponent("noapp.zip")
    try OTAInstaller.archiveApp(payload, to: noAppZip)
    do {
        _ = try await installer.prepare(downloadedArchive: noAppZip)
        check("TC-INST-04", "zip 内无 .app → appNotFound（fail-closed）", false, "竟然没报错")
    } catch OTAInstaller.InstallError.appNotFound {
        check("TC-INST-04", "zip 内无 .app → appNotFound（fail-closed）", true)
    } catch {
        check("TC-INST-04", "zip 内无 .app → appNotFound（fail-closed）", false, "错误类型 \(error)")
    }

    // zip 混有其它文件时仍提取出 .app（first(where:) 命中）。
    // 注意：prepare 只看 zip 顶层条目；用 ditto -c -k（无 --keepParent）把
    // Fake.app 与 README.txt 都放在 zip 根，模拟「官方发布 zip：Coffer.app 在根」。
    let payload2 = tempRoot.appendingPathComponent("payload2", isDirectory: true)
    let fakeApp = payload2.appendingPathComponent("Fake.app/Contents/MacOS", isDirectory: true)
    try fm.createDirectory(at: fakeApp, withIntermediateDirectories: true)
    try Data("#!/bin/sh\necho fake\n".utf8).write(to: fakeApp.appendingPathComponent("Fake"))
    try fm.setAttributes([.posixPermissions: 0o755],
                         ofItemAtPath: fakeApp.appendingPathComponent("Fake").path)
    try Data("readme".utf8).write(to: payload2.appendingPathComponent("README.txt"))
    let mixedZip = tempRoot.appendingPathComponent("mixed.zip")
    try OTAInstaller.runProcess("/usr/bin/ditto",
                                args: ["-c", "-k", payload2.path, mixedZip.path])
    let extracted = try await installer.prepare(downloadedArchive: mixedZip)
    check("TC-INST-05", "zip 混有其它文件时仍提取 .app",
          extracted.lastPathComponent == "Fake.app", "提取 \(extracted.lastPathComponent)")
} catch {
    check("TC-INST2", "夹具异常", false, "\(error)")
}

// helper 未装配（路径不存在）→ 同步可判失败 helperLaunchFailed（真函数 launchViaLaunchServices）
do {
    do {
        try OTAInstaller.launchViaLaunchServices(
            helper: URL(fileURLWithPath: "/nonexistent/CofferUpdater.app"),
            args: ["--config", "/tmp/x.json"])
        check("TC-INST-06", "helper 未装配（路径不存在）→ helperLaunchFailed（同步可判失败）", false, "竟然没报错")
    } catch OTAInstaller.InstallError.helperLaunchFailed {
        check("TC-INST-06", "helper 未装配（路径不存在）→ helperLaunchFailed（同步可判失败）", true)
    } catch {
        check("TC-INST-06", "helper 未装配（路径不存在）→ helperLaunchFailed（同步可判失败）", false, "错误类型 \(error)")
    }
}

// 配置写盘失败（backupDirectory 父目录不存在）→ configWriteFailed（fail-closed）
do {
    let fm = FileManager.default
    let missingDir = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-no-such-\(UUID().uuidString)/sub", isDirectory: true)
    let suiteName = "coffer-ota-test-\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suiteName)!
    defaults.removePersistentDomain(forName: suiteName)
    defer { defaults.removePersistentDomain(forName: suiteName) }
    let installer = OTAInstaller(
        helperURL: URL(fileURLWithPath: "/unused/helper"),
        backupDirectory: missingDir,
        pidProvider: { 4242 },
        userDefaults: defaults) { _, _ in }
    let manifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
    let info = try UpdateInfo(manifest: manifest)
    do {
        try await installer.perform(
            info: info,
            downloadedAppURL: URL(fileURLWithPath: "/tmp/new.app"),
            currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"))
        check("TC-INST-07", "配置写盘失败 → configWriteFailed（fail-closed）", false, "竟然没报错")
    } catch OTAInstaller.InstallError.configWriteFailed {
        check("TC-INST-07", "配置写盘失败 → configWriteFailed（fail-closed）", true)
    } catch {
        check("TC-INST-07", "配置写盘失败 → configWriteFailed（fail-closed）", false, "错误类型 \(error)")
    }
}

// launcher 抛 InstallError → 透传原错误（不二次包装成 helperLaunchFailed）
do {
    let manifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
    let info = try UpdateInfo(manifest: manifest)
    let installer = OTAInstaller(
        helperURL: URL(fileURLWithPath: "/unused/helper"),
        userDefaults: UserDefaults(suiteName: "coffer-ota-inst8-\(UUID().uuidString)")!) { _, _ in
            throw OTAInstaller.InstallError.helperLaunchFailed("装配缺失")
        }
    do {
        try await installer.perform(
            info: info,
            downloadedAppURL: URL(fileURLWithPath: "/tmp/new.app"),
            currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"))
        check("TC-INST-08", "launcher 抛 InstallError → 透传原错误（不二次包装）", false, "竟然没报错")
    } catch OTAInstaller.InstallError.helperLaunchFailed {
        check("TC-INST-08", "launcher 抛 InstallError → 透传原错误（不二次包装）", true)
    } catch {
        check("TC-INST-08", "launcher 抛 InstallError → 透传原错误（不二次包装）", false, "错误类型 \(error)")
    }
}

// launcher 抛非 InstallError → 包装为 helperLaunchFailed
do {
    let manifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
    let info = try UpdateInfo(manifest: manifest)
    let installer = OTAInstaller(
        helperURL: URL(fileURLWithPath: "/unused/helper"),
        userDefaults: UserDefaults(suiteName: "coffer-ota-inst9-\(UUID().uuidString)")!) { _, _ in
            throw TestError(message: "boom")
        }
    do {
        try await installer.perform(
            info: info,
            downloadedAppURL: URL(fileURLWithPath: "/tmp/new.app"),
            currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"))
        check("TC-INST-09", "launcher 抛非 InstallError → helperLaunchFailed", false, "竟然没报错")
    } catch OTAInstaller.InstallError.helperLaunchFailed {
        check("TC-INST-09", "launcher 抛非 InstallError → helperLaunchFailed", true)
    } catch {
        check("TC-INST-09", "launcher 抛非 InstallError → helperLaunchFailed", false, "错误类型 \(error)")
    }
}

// M-3：launcher 抛错 → pending keys（含第三个 backupDir key）全清 + 已写配置残留清理，
// 保证下次启动 consume 为 no-op（不误弹「无法读取上次更新的结果」）。
do {
    let fm = FileManager.default
    let tempRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-inst10-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempRoot) }
    let suiteName = "coffer-ota-inst10-\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suiteName)!
    defaults.removePersistentDomain(forName: suiteName)
    defer { defaults.removePersistentDomain(forName: suiteName) }
    var launched: [String] = []
    let installer = OTAInstaller(
        helperURL: URL(fileURLWithPath: "/unused/helper"),
        backupDirectory: tempRoot,
        pidProvider: { 4242 },
        userDefaults: defaults) { helper, args in
            launched = [helper.path] + args
            throw OTAInstaller.InstallError.helperLaunchFailed("装配缺失")
        }
    let manifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
    let info = try UpdateInfo(manifest: manifest)
    do {
        try await installer.perform(
            info: info,
            downloadedAppURL: URL(fileURLWithPath: "/tmp/new.app"),
            currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"))
        check("TC-INST-10", "launcher 抛错 → 显式失败（M-3 前置）", false, "竟然没报错")
    } catch OTAInstaller.InstallError.helperLaunchFailed {
        check("TC-INST-10", "launcher 抛错 → 三个 pending key 全清（M-3 回滚）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
        let configPath = launched.count >= 3 ? launched[2] : ""
        check("TC-INST-10", "launcher 抛错 → 已写配置残留被清理（M-3）",
              configPath.isEmpty || !fm.fileExists(atPath: configPath))
    } catch {
        check("TC-INST-10", "launcher 抛错 → pending 回滚（M-3）", false, "错误类型 \(error)")
    }
}

// MARK: - TC-CFG OTAInstaller.perform（§6.4 r0.4：配置 JSON + UserDefaults 持久化 + 注入 launcher）

do {
    let fm = FileManager.default

    // 配置 JSON 5 字段构造（纯函数）
    let config = OTAInstaller.InstallConfig(
        newAppPath: "/tmp/new/Coffer.app",
        currentAppPath: "/Applications/Coffer.app",
        backupPath: "/tmp/backup/Coffer-123.app",
        resultFilePath: "/tmp/result/coffer-ota-result-abc.json",
        pid: 4242)
    let configData = try OTAInstaller.encodeConfig(config)
    let dict = try JSONSerialization.jsonObject(with: configData) as! [String: Any]
    check("TC-CFG-01", "配置 JSON 恰为 5 字段且值正确",
          dict.count == 5
          && dict["newAppPath"] as? String == "/tmp/new/Coffer.app"
          && dict["currentAppPath"] as? String == "/Applications/Coffer.app"
          && dict["backupPath"] as? String == "/tmp/backup/Coffer-123.app"
          && dict["resultFilePath"] as? String == "/tmp/result/coffer-ota-result-abc.json"
          && (dict["pid"] as? NSNumber)?.int32Value == 4242)
    check("TC-CFG-02", "配置 JSON 确定性（两次序列化字节一致）",
          configData == (try OTAInstaller.encodeConfig(config)))

    // perform：写配置 → UserDefaults 持久化 → 注入 launcher 断言参数
    let tempRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-cfg-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempRoot) }

    let suiteName = "coffer-ota-test-\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suiteName)!
    defaults.removePersistentDomain(forName: suiteName)
    defer { defaults.removePersistentDomain(forName: suiteName) }

    var launched: [String] = []
    let installer = OTAInstaller(
        helperURL: URL(fileURLWithPath: "/Applications/Coffer.app/Contents/Helpers/CofferUpdater.app"),
        backupDirectory: tempRoot,
        pidProvider: { 4242 },
        userDefaults: defaults) { helper, args in
            launched = [helper.path] + args
        }

    let manifest = try UpdateManifest.parse(
        try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
    let info = try UpdateInfo(manifest: manifest)
    let downloadedAppURL = URL(fileURLWithPath: "/tmp/new/Coffer.app")
    let currentAppURL = URL(fileURLWithPath: "/Applications/Coffer.app")
    try await installer.perform(
        info: info, downloadedAppURL: downloadedAppURL, currentAppURL: currentAppURL)

    // launcher 收到 `--config <配置文件路径>`（helperURL 保持不变）
    check("TC-CFG-03", "perform 以 `--config <配置路径>` 启动 helper（注入 seam 断言）",
          launched.count == 3
          && launched[0].hasSuffix("/Contents/Helpers/CofferUpdater.app")
          && launched[1] == "--config" && !launched[2].isEmpty,
          "launched=\(launched)")

    // 配置文件真实写盘且 5 字段与 perform 实参一致
    let configURL = URL(fileURLWithPath: launched[2])
    let writtenDict = try JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as! [String: Any]
    check("TC-CFG-04", "配置文件已写盘且 newAppPath/currentAppPath/pid 正确",
          fm.fileExists(atPath: configURL.path)
          && writtenDict["newAppPath"] as? String == "/tmp/new/Coffer.app"
          && writtenDict["currentAppPath"] as? String == "/Applications/Coffer.app"
          && (writtenDict["pid"] as? NSNumber)?.int32Value == 4242)

    // result/backup 路径写 UserDefaults（被 relaunch 的 .app 首启找回）
    let pendingResult = defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey)
    let pendingBackup = defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey)
    check("TC-CFG-05", "resultFilePath 写入 UserDefaults 且与配置一致",
          pendingResult == writtenDict["resultFilePath"] as? String
          && pendingResult?.hasSuffix(".json") == true)
    check("TC-CFG-06", "backupPath 写入 UserDefaults 且与配置一致（成功消费删备份用）",
          pendingBackup == writtenDict["backupPath"] as? String
          && pendingBackup?.hasPrefix(tempRoot.path + "/Coffer-") == true
          && pendingBackup?.hasSuffix(".app") == true)
    check("TC-CFG-06", "backupDir 路径写入 UserDefaults（C-1 守卫）",
          defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == tempRoot.path)

    // 真 LaunchServices 启动 = 真机核销（CI 只验证注入 seam 与参数形状）。
    skip("TC-CFG-07", "真 LaunchServices 启动 helper（嵌套 bundle 装配后）", "真机核销")
} catch {
    check("TC-CFG", "夹具异常", false, "\(error)")
}

// MARK: - TC-CONSUME 首启消费安装结果（consumePendingInstallResult，幂等）

do {
    let fm = FileManager.default
    let tempRoot = fm.temporaryDirectory
        .appendingPathComponent("coffer-ota-consume-\(UUID().uuidString)", isDirectory: true)
    try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    defer { try? fm.removeItem(at: tempRoot) }

    func freshDefaults() -> UserDefaults {
        let name = "coffer-ota-test-\(UUID().uuidString)"
        let d = UserDefaults(suiteName: name)!
        d.removePersistentDomain(forName: name)
        return d
    }

    // 成功：删备份 + 清 key + 删 result + 静默 upToDate
    do {
        let defaults = freshDefaults()
        let backupURL = tempRoot.appendingPathComponent("Coffer-old.app", isDirectory: true)
        try fm.createDirectory(at: backupURL, withIntermediateDirectories: true)
        // result 用真实形状 coffer-ota-result-*.json（M-C 守卫下才能合法删除）
        let resultURL = tempRoot.appendingPathComponent("coffer-ota-result-success.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(backupURL.path, forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        defaults.set(tempRoot.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)

        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-01", "成功：删备份", !fm.fileExists(atPath: backupURL.path))
        check("TC-CONSUME-02", "成功：清 pending key（幂等起点）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
        check("TC-CONSUME-03", "成功：删 result 文件", !fm.fileExists(atPath: resultURL.path))
        check("TC-CONSUME-04", "成功：静默呈 upToDate（UI 呈现新版本）",
              manager.state == .upToDate, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-01", "夹具异常", false, "\(error)")
    }

    // 失败：result success=false → failed（含退出码 + 文案），key/文件同样清干净
    do {
        let defaults = freshDefaults()
        // 失败路径 result 同样为 coffer-ota-result-*.json 且父目录=backupDir
        // （M-C 守卫下才合法删除；perform 三者同写，backupDir key 必在）
        let resultURL = tempRoot.appendingPathComponent("coffer-ota-result-fail.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: false, code: 2, message: "替换失败")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(tempRoot.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)

        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        if case .failed(let msg) = manager.state {
            check("TC-CONSUME-05", "失败：→ failed（含退出码与文案）",
                  msg.contains("2") && msg.contains("替换失败"), "msg=\(msg)")
        } else {
            check("TC-CONSUME-05", "失败：→ failed（含退出码与文案）", false, "state=\(manager.state)")
        }
        check("TC-CONSUME-06", "失败：清 pending key",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil)
        check("TC-CONSUME-07", "失败：删 result 文件", !fm.fileExists(atPath: resultURL.path))
    } catch {
        check("TC-CONSUME-05", "夹具异常", false, "\(error)")
    }

    // 无 pending → no-op（state 不变），重复调用幂等
    let defaults = freshDefaults()
    let noopManager = makeManager(
        fetcher: StubFetcher(.failure(TestError(message: "unused"))),
        userDefaults: defaults)
    noopManager.consumePendingInstallResult()
    check("TC-CONSUME-08", "无 pending → no-op（state 不变）", noopManager.state == .idle)
    noopManager.consumePendingInstallResult()
    check("TC-CONSUME-09", "幂等：重复调用仍 no-op", noopManager.state == .idle)

    // 损坏 result 文件 → fail-closed（failed），pending 同样清理
    do {
        let defaults = freshDefaults()
        // 损坏 result 同样真实形状 + backupDir（M-C 守卫下才合法删除）
        let resultURL = tempRoot.appendingPathComponent("coffer-ota-result-corrupt.json")
        try Data("not json".utf8).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(tempRoot.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)

        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        if case .failed = manager.state {
            check("TC-CONSUME-10", "损坏 result → failed（fail-closed）", true)
        } else {
            check("TC-CONSUME-10", "损坏 result → failed（fail-closed）", false, "state=\(manager.state)")
        }
        check("TC-CONSUME-11", "损坏 result 也删 result 文件", !fm.fileExists(atPath: resultURL.path))
    } catch {
        check("TC-CONSUME-10", "夹具异常", false, "\(error)")
    }

    // result 文件缺失但 key 存在 → fail-closed（failed），pending 清理，不阻塞启动
    // （本段全为非抛调用，无 do-catch 包装，避免不可达 catch 编译警告）
    let defaults12 = freshDefaults()
    defaults12.set("/nonexistent/coffer-ota-result-missing.json",
                   forKey: OTAInstaller.pendingResultPathDefaultsKey)
    let manager12 = makeManager(
        fetcher: StubFetcher(.failure(TestError(message: "unused"))),
        userDefaults: defaults12)
    manager12.consumePendingInstallResult()
    if case .failed(let msg) = manager12.state {
        check("TC-CONSUME-12", "result 文件缺失 → failed（fail-closed）", !msg.isEmpty)
    } else {
        check("TC-CONSUME-12", "result 文件缺失 → failed（fail-closed）", false, "state=\(manager12.state)")
    }
    check("TC-CONSUME-12", "result 缺失也清 pending key（幂等起点）",
          defaults12.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil)

    // 失败且 message 为空 → 文案退化为「上次更新失败（退出码 N）。」
    do {
        let defaults = freshDefaults()
        let resultURL = tempRoot.appendingPathComponent("fail-empty.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: false, code: 3, message: "")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        if case .failed(let msg) = manager.state {
            check("TC-CONSUME-13", "失败且 message 为空 → 文案含退出码（「上次更新失败（退出码 3）。」）",
                  msg.contains("3") && msg.contains("上次更新失败"), "msg=\(msg)")
        } else {
            check("TC-CONSUME-13", "失败且 message 为空 → 文案含退出码", false, "state=\(manager.state)")
        }
    } catch {
        check("TC-CONSUME-13", "夹具异常", false, "\(error)")
    }

    // 成功但删备份失败（try? 吞掉）→ 仍 upToDate（静默；备份残留待下次清理）。
    // 记录现状：备份清理是 best-effort，不因清理失败把成功更新误报为失败。
    do {
        let defaults = freshDefaults()
        let resultURL = tempRoot.appendingPathComponent("success-nodel.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set("/nonexistent-parent-\(UUID().uuidString)/backup.app",
                     forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-14", "成功但删备份失败（try? 吞掉）→ 仍 upToDate（静默）",
              manager.state == .upToDate, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-14", "夹具异常", false, "\(error)")
    }

    // result JSON 结构不对（缺 code/message 字段）→ decode 失败 → failed（fail-closed）
    do {
        let defaults = freshDefaults()
        let resultURL = tempRoot.appendingPathComponent("shape.json")
        try Data(#"{"success": true}"#.utf8).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        if case .failed = manager.state {
            check("TC-CONSUME-15", "result JSON 结构不对（缺 code/message）→ failed（fail-closed）", true)
        } else {
            check("TC-CONSUME-15", "result JSON 结构不对（缺 code/message）→ failed（fail-closed）",
                  false, "state=\(manager.state)")
        }
    } catch {
        check("TC-CONSUME-15", "夹具异常", false, "\(error)")
    }

    // 成功且 message 非空 → 仍静默 upToDate（成功不呈现失败文案）
    do {
        let defaults = freshDefaults()
        let resultURL = tempRoot.appendingPathComponent("success-msg.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "更新完成。")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-16", "成功（message 非空）→ 仍静默 upToDate",
              manager.state == .upToDate, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-16", "夹具异常", false, "\(error)")
    }

    // M-3：launcher 抛错 → pending 已回滚 → 下次启动 consume 为 no-op（不误弹失败）
    do {
        let defaults = freshDefaults()
        let installer = OTAInstaller(
            helperURL: URL(fileURLWithPath: "/unused/helper"),
            backupDirectory: tempRoot,
            pidProvider: { 4242 },
            userDefaults: defaults) { _, _ in
                throw OTAInstaller.InstallError.helperLaunchFailed("装配缺失")
            }
        let manifest = try UpdateManifest.parse(
            try TestFixture.signedManifestData(fields: TestFixture.manifestFields()))
        let info = try UpdateInfo(manifest: manifest)
        do {
            try await installer.perform(
                info: info,
                downloadedAppURL: URL(fileURLWithPath: "/tmp/new.app"),
                currentAppURL: URL(fileURLWithPath: "/Applications/Coffer.app"))
            check("TC-CONSUME-17", "launcher 抛错 → perform 显式失败（M-3 前置）", false, "竟然没报错")
        } catch {
            check("TC-CONSUME-17", "launcher 抛错 → perform 显式失败（M-3 前置）", true)
        }
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-17", "launcher 抛错 → 下次 consume no-op（state 保持 idle，M-3）",
              manager.state == .idle, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-17", "夹具异常", false, "\(error)")
    }

    // C-1：backupPath 不在持久化 backupDir 前缀内 → 不删目标（防同用户进程改 prefs
    // 指向任意文件误删）；成功更新仍静默 upToDate（不误报失败）。
    do {
        let defaults = freshDefaults()
        let backupDir = tempRoot.appendingPathComponent("real-backup", isDirectory: true)
        try fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        let resultURL = tempRoot.appendingPathComponent("c18.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        let victim = tempRoot.appendingPathComponent("victim.txt")
        try Data("keep me".utf8).write(to: victim)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(victim.path, forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        defaults.set(backupDir.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-18", "C-1：backupPath 在 backupDir 前缀外 → 不删目标文件（防误删）",
              fm.fileExists(atPath: victim.path), "victim 被误删")
        check("TC-CONSUME-18", "C-1：前缀不符 → 仍静默 upToDate（不误报失败）",
              manager.state == .upToDate, "state=\(manager.state)")
        check("TC-CONSUME-18", "C-1：pending key 仍全部清理（幂等起点）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
    } catch {
        check("TC-CONSUME-18", "夹具异常", false, "\(error)")
    }

    // C-1：backupDir key 缺失（老版本残留/异常态）→ 保守不删备份（fail-closed），仍 upToDate
    do {
        let defaults = freshDefaults()
        let resultURL = tempRoot.appendingPathComponent("c19.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        let backupURL = tempRoot.appendingPathComponent("Coffer-old-c19.app", isDirectory: true)
        try fm.createDirectory(at: backupURL, withIntermediateDirectories: true)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(backupURL.path, forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        // 故意不写 pendingBackupDirDefaultsKey
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-19", "C-1：backupDir key 缺失 → 不删备份（fail-closed）",
              fm.fileExists(atPath: backupURL.path), "备份被误删")
        check("TC-CONSUME-19", "C-1：backupDir key 缺失 → 仍 upToDate",
              manager.state == .upToDate, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-19", "夹具异常", false, "\(error)")
    }

    // MEDIUM 收紧：basename 非 `Coffer-*.app` 形状（即便前缀符合）→ 不删目标
    // （同用户进程改 prefs 也只能让 App 删「backupDir 下 Coffer-*.app」，无法指向
    // 任意受害者文件）；成功更新仍静默 upToDate，3 key 照常清理。
    do {
        let defaults = freshDefaults()
        let backupDir = tempRoot.appendingPathComponent("med20-backup", isDirectory: true)
        try fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        let resultURL = tempRoot.appendingPathComponent("c20.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        let victim = backupDir.appendingPathComponent("notes.txt")
        try Data("keep me".utf8).write(to: victim)   // 前缀符合、形状不符
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(victim.path, forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        defaults.set(backupDir.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-20", "MEDIUM：basename 非 Coffer-*.app 形状 → 不删目标（防误删）",
              fm.fileExists(atPath: victim.path), "目标被误删")
        check("TC-CONSUME-20", "MEDIUM：形状不符 → 仍静默 upToDate（不误报失败）",
              manager.state == .upToDate, "state=\(manager.state)")
        check("TC-CONSUME-20", "MEDIUM：pending key 仍全部清理（幂等起点）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
    } catch {
        check("TC-CONSUME-20", "夹具异常", false, "\(error)")
    }

    // MEDIUM：basename 正确形状（Coffer-<stamp>.app）+ 前缀符合 → 正常删备份
    // （与既有 TC-CONSUME-01 成功用例并存，覆盖形状守卫的放行路径）。
    do {
        let defaults = freshDefaults()
        let backupDir = tempRoot.appendingPathComponent("med21-backup", isDirectory: true)
        try fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        let resultURL = tempRoot.appendingPathComponent("c21.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        let backupURL = backupDir.appendingPathComponent("Coffer-1770000000.app", isDirectory: true)
        try fm.createDirectory(at: backupURL, withIntermediateDirectories: true)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(backupURL.path, forKey: OTAInstaller.pendingBackupPathDefaultsKey)
        defaults.set(backupDir.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-21", "MEDIUM：Coffer-*.app 形状 + 前缀符合 → 正常删备份",
              !fm.fileExists(atPath: backupURL.path), "备份未被删除")
        check("TC-CONSUME-21", "MEDIUM：放行路径仍 upToDate",
              manager.state == .upToDate, "state=\(manager.state)")
    } catch {
        check("TC-CONSUME-21", "夹具异常", false, "\(error)")
    }

    // M-C：result 路径 basename 形状不符（非 coffer-ota-result-*.json，前缀符合）
    // → result 文件不被删 + 仍静默 upToDate + pending key 仍清理（幂等起点）。
    do {
        let defaults = freshDefaults()
        let backupDir = tempRoot.appendingPathComponent("med22-backup", isDirectory: true)
        try fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        let resultURL = backupDir.appendingPathComponent("config.json")   // 形状不符
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(backupDir.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-22", "M-C：result 形状不符 → 不删 result 文件（防误删）",
              fm.fileExists(atPath: resultURL.path), "result 被误删")
        check("TC-CONSUME-22", "M-C：result 形状不符 → 仍静默 upToDate（不误报失败）",
              manager.state == .upToDate, "state=\(manager.state)")
        check("TC-CONSUME-22", "M-C：pending key 仍全部清理（幂等起点）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
    } catch {
        check("TC-CONSUME-22", "夹具异常", false, "\(error)")
    }

    // M-C：result 路径在 backupDir 前缀外（形状符合）→ 同样不删 result（父目录判据，
    // 与 TC-CONSUME-18 备份前缀守卫对称），仍 upToDate + key 清理。
    do {
        let defaults = freshDefaults()
        let backupDir = tempRoot.appendingPathComponent("med23-backup", isDirectory: true)
        try fm.createDirectory(at: backupDir, withIntermediateDirectories: true)
        // 形状符合但父目录在 backupDir 外（tempRoot 下）
        let resultURL = tempRoot.appendingPathComponent("coffer-ota-result-outside.json")
        try OTAInstaller.encodeResult(
            OTAInstaller.InstallResult(success: true, code: 0, message: "")
        ).write(to: resultURL)
        defaults.set(resultURL.path, forKey: OTAInstaller.pendingResultPathDefaultsKey)
        defaults.set(backupDir.path, forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        let manager = makeManager(
            fetcher: StubFetcher(.failure(TestError(message: "unused"))),
            userDefaults: defaults)
        manager.consumePendingInstallResult()
        check("TC-CONSUME-23", "M-C：result 在 backupDir 前缀外 → 不删 result（防误删）",
              fm.fileExists(atPath: resultURL.path), "result 被误删")
        check("TC-CONSUME-23", "M-C：前缀不符 → 仍静默 upToDate（不误报失败）",
              manager.state == .upToDate, "state=\(manager.state)")
        check("TC-CONSUME-23", "M-C：pending key 仍全部清理（幂等起点）",
              defaults.string(forKey: OTAInstaller.pendingResultPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupPathDefaultsKey) == nil
              && defaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey) == nil)
    } catch {
        check("TC-CONSUME-23", "夹具异常", false, "\(error)")
    }
} catch {
    check("TC-CONSUME", "夹具异常", false, "\(error)")
}

// MARK: - TC-WIRE UpdaterManager 便捷构造（生产接线编译级验证）

// 顶层为 MainActor 隔离：直接构造。Bundle.main 为测试可执行（非 App bundle），
// 版本读为空串、helper 路径按测试可执行位置拼装——只验证接线可构造、不联网。
let manager = UpdaterManager()
check("TC-WIRE-01", "UpdaterManager() 便捷构造可用（生产接线编译级验证）",
      manager.state == .idle, "state=\(manager.state)")

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed / \(skipped) skipped")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
