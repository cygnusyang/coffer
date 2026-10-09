// UpdaterManager.swift —— Updater 公开接口（docs/35 §6.3，契约冻结；组 D 唯一依赖）。
//
// UpdaterManager：@MainActor ObservableObject 状态机。check/install/dismiss +
// 首启消费安装结果（consumePendingInstallResult，契约 6.4 r0.4 步骤 6）的
// 网络层与安装层经协议（ManifestFetching/DataDownloading/Installing）注入，
// 测试用 stub 驱动全部状态迁移，不真联网。

import Foundation
import Combine

/// 校验通过的更新信息（契约 6.3，组 D 展示用）。
struct UpdateInfo: Equatable {
    let version: String
    let minimumVersion: String
    let downloadUrl: URL
    let cdHash: String
    let buildTime: Date
    let securityCritical: Bool
    let notes: String?

    /// 从已通过解析/验签的清单构造；downloadUrl / buildTime 非法则显式报错
    /// （fail-closed，不静默降级）。
    init(manifest: UpdateManifest) throws {
        guard let url = URL(string: manifest.downloadUrl) else {
            throw UpdateInfoError.invalidDownloadURL(manifest.downloadUrl)
        }
        guard let date = Self.parseRFC3339(manifest.buildTime) else {
            throw UpdateInfoError.invalidBuildTime(manifest.buildTime)
        }
        self.version = manifest.version
        self.minimumVersion = manifest.minimumVersion
        self.downloadUrl = url
        self.cdHash = manifest.cdHash
        self.buildTime = date
        self.securityCritical = manifest.securityCritical
        self.notes = manifest.notes
    }

    /// RFC3339 解析（与清单 `buildTime` 语义一致，契约 6.1）。
    static func parseRFC3339(_ string: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: string)
    }
}

/// UpdateInfo 构造的显式错误。
enum UpdateInfoError: Error, LocalizedError {
    case invalidDownloadURL(String)
    case invalidBuildTime(String)

    var errorDescription: String? {
        switch self {
        case .invalidDownloadURL(let url):
            return "更新清单下载地址无效：\(url)。"
        case .invalidBuildTime(let time):
            return "更新清单构建时间无效：\(time)。"
        }
    }
}

/// Updater 状态机（契约 6.3，组 D 渲染 + 按钮可用性）。
enum UpdaterState: Equatable {
    /// 未检查
    case idle
    /// 检查中
    case checking
    /// 发现可更新
    case updateAvailable(UpdateInfo)
    /// 已是最新
    case upToDate
    /// 下载中（0...1 进度）
    case downloading(Double)
    /// 下载 + 验签完成，等待安装
    case downloaded
    /// 安装中（退出 + 替换 + relaunch）
    case installing
    /// 失败（用户可见文案）
    case failed(String)
}

/// Updater 状态机（契约 6.3）。
@MainActor
final class UpdaterManager: ObservableObject {
    @Published private(set) var state: UpdaterState = .idle

    /// 固定清单 URL（契约 6.1，恒一 URL，不依赖版本枚举）。
    /// `nonisolated`：类为 @MainActor，纯常量供非隔离上下文（init 默认参）引用。
    nonisolated static let defaultManifestURL = URL(
        string: "https://github.com/cygnusyang/coffer/releases/latest/download/update-manifest.json")!

    private let manifestURL: URL
    private let currentVersion: String
    private let currentAppURL: URL
    private let publicKeyBase64: String
    private let fetcher: ManifestFetching
    private let downloader: DataDownloading
    private let installer: Installing
    private let verifier: ProductVerifying
    private let userDefaults: UserDefaults

    /// - Parameters:
    ///   - manifestURL: 清单 URL（默认契约固定 URL）。
    ///   - currentVersion: 当前版本号（`CFBundleShortVersionString`；测试注入固定值）。
    ///   - currentAppURL: 当前 App 路径（替换安装目标，契约 6.4 `/Applications/Coffer.app`）。
    ///   - publicKeyBase64: 更新验签公钥（默认硬编码常量；测试注入自生成公钥）。
    ///   - fetcher/downloader/installer/verifier: 网络/安装/验签注入点。
    ///   - userDefaults: 首启消费安装结果的持久化域（测试注入独立 suite）。
    init(
        manifestURL: URL = UpdaterManager.defaultManifestURL,
        currentVersion: String,
        currentAppURL: URL,
        publicKeyBase64: String = ManifestVerifier.cofferUpdatePublicKeyBase64,
        fetcher: ManifestFetching,
        downloader: DataDownloading,
        installer: Installing,
        verifier: ProductVerifying = SecCodeVerifierAdapter(),
        userDefaults: UserDefaults = .standard
    ) {
        self.manifestURL = manifestURL
        self.currentVersion = currentVersion
        self.currentAppURL = currentAppURL
        self.publicKeyBase64 = publicKeyBase64
        self.fetcher = fetcher
        self.downloader = downloader
        self.installer = installer
        self.verifier = verifier
        self.userDefaults = userDefaults
    }

    /// 生产便捷构造（组 D / AppModel 用，无参）：从 Bundle.main 读当前版本、
    /// 以 `/Applications/Coffer.app` 为替换目标、注入真实网络/安装/验签实现。
    /// `Installing`/`ManifestFetching`/`DataDownloading` 与网络层为纯生产路径，
    /// 自动化测试走完整 init（协议注入），此处仅编译级接线验证。
    convenience init() {
        let bundle = Bundle.main
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let appURL = URL(fileURLWithPath: "/Applications/Coffer.app")
        let helperURL = bundle.bundleURL
            .appendingPathComponent("Contents/Helpers/CofferUpdater.app")
        self.init(
            currentVersion: version,
            currentAppURL: appURL,
            fetcher: OTANetworkSession(),
            downloader: OTANetworkSession(),
            installer: OTAInstaller(helperURL: helperURL),
            verifier: SecCodeVerifierAdapter())
    }

    /// 检查更新：拉清单 → HTTPS+白名单 → canonical 验签 → 版本比较 → 状态迁移。
    /// 网络失败 / 验签失败 / 不匹配 → `.failed`（fail-closed，不静默）。
    func check() async {
        guard !isInFlight else { return }
        state = .checking
        do {
            try OTAEndpointPolicy.validate(manifestURL)
            let data = try await fetcher.fetchManifest(from: manifestURL)
            let manifest = try UpdateManifest.parse(data)
            _ = try ManifestVerifier.verify(manifestJSONData: data, publicKeyBase64: publicKeyBase64)
            let info = try UpdateInfo(manifest: manifest)
            // 纵深：下载地址也必须 https + 白名单（验签通过仍不例外，§2.2）。
            try OTAEndpointPolicy.validate(info.downloadUrl)
            resolveCheckOutcome(manifest: manifest, info: info)
        } catch {
            state = .failed(Self.userMessage(from: error))
        }
    }

    /// 安装更新：下载（进度）→ 解压 → 三级验签 → downloaded → 写配置 +
    /// LaunchServices 启动 helper → installing。App 侧随即退出（helper 负责
    /// 备份/替换/relaunch，结果经 result 文件在下次启动消费，契约 6.4 r0.4）。
    func install() async {
        guard case .updateAvailable(let info) = state else { return }
        do {
            state = .downloading(0)
            let archive = try await downloader.download(from: info.downloadUrl) { progress in
                self.state = .downloading(progress)
            }
            let extractedApp = try await installer.prepare(downloadedArchive: archive)
            try verifier.verifyApp(at: extractedApp, expectedCdHash: info.cdHash)
            state = .downloaded
            state = .installing
            try await installer.perform(
                info: info, downloadedAppURL: extractedApp, currentAppURL: currentAppURL)
            // 成功路径：helper 完成替换并 relaunch，本进程即将退出；保持 .installing。
        } catch {
            state = .failed(Self.userMessage(from: error))
        }
    }

    /// 备份文件名的形状校验（MEDIUM 收紧）：`perform` 写备份固定为
    /// `Coffer-<stamp>.app`（OTAInstaller.perform）。仅「目录前缀 + 在 backupDir
    /// 内」约束下，同用户进程改 prefs 仍可把 backupPath 指向 backupDir 下任意
    /// 文件；叠加 basename 形状后，攻击者只能让 App 删「backupDir 下
    /// Coffer-*.app」——Coffer 自己的备份或自建文件，无法指向任意受害者文件。
    private static func isBackupShape(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        return name.hasPrefix("Coffer-") && name.hasSuffix(".app")
    }

    /// result 文件名的形状校验（M-C 加固）：`perform` 写 result 文件固定为
    /// `coffer-ota-result-<uuid>.json`（OTAInstaller.perform），父目录 = 持久化的
    /// backupDir（result 与备份同目录）。删除前校验 basename 形状，与备份删除的
    /// 双守卫对称——防同用户进程改 prefs 污染 `ota_pending_result_path` 指向容器内
    /// 其它文件被误删（fail-closed：不符则不删 result，仍清 key + 状态照旧）。
    private static func isResultShape(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        return name.hasPrefix("coffer-ota-result-") && name.hasSuffix(".json")
    }

    /// 首启消费上次安装结果（组 D 在启动早期调用；幂等）。路径经 UserDefaults
    /// 找回 → 成功：删备份 + 静默（UI 呈现新版本，.upToDate）；失败：呈现 failed
    /// （含退出码文案）。UserDefaults key 一次性消费后清除；result 文件仅在
    /// 形状/父目录守卫通过时删除（M-C，fail-closed 不误删）；无 pending 则
    /// no-op（不打扰正常启动）。
    func consumePendingInstallResult() {
        guard let resultPath = userDefaults.string(
            forKey: OTAInstaller.pendingResultPathDefaultsKey) else { return }
        let resultURL = URL(fileURLWithPath: resultPath)
        // M-C：删除 result 前取持久化 backupDir（result 与备份同目录）作前缀判据。
        let backupDir = userDefaults.string(forKey: OTAInstaller.pendingBackupDirDefaultsKey)
        defer {
            userDefaults.removeObject(forKey: OTAInstaller.pendingResultPathDefaultsKey)
            userDefaults.removeObject(forKey: OTAInstaller.pendingBackupPathDefaultsKey)
            userDefaults.removeObject(forKey: OTAInstaller.pendingBackupDirDefaultsKey)
            // M-C 守卫：basename `coffer-ota-result-*.json` + 父目录在 backupDir 内
            //（与备份删除双守卫对称；不符 → 不删 result，仍清 key，fail-closed）。
            if let dir = backupDir,
               resultPath.hasPrefix(dir + "/"),
               Self.isResultShape(resultPath) {
                try? FileManager.default.removeItem(at: resultURL)
            }
        }
        guard let data = try? Data(contentsOf: resultURL),
              let result = try? JSONDecoder().decode(OTAInstaller.InstallResult.self, from: data) else {
            // result 文件缺失/损坏 → fail-closed（清理 pending，下次启动不再重复）
            state = .failed("无法读取上次更新的结果，请确认当前应用是否已是最新版本。")
            return
        }
        guard result.success else {
            state = .failed(result.message.isEmpty
                ? "上次更新失败（退出码 \(result.code)）。"
                : "上次更新失败（退出码 \(result.code)）：\(result.message)")
            return
        }
        // 成功：删除 helper 留下的备份（当前运行中的已是新版本），静默不打扰。
        // C-1+MEDIUM 守卫：backup 路径必须位于持久化的 backupDirectory 前缀内
        // **且** basename 为 `Coffer-*.app` 形状才删——同用户进程可改 prefs plist，
        // 仅前缀校验会指向 backupDir 下任意文件；形状绑定后只能删 Coffer 自己的
        // 备份（fail-closed：不符则跳过删除，但不误报失败，仍呈现 .upToDate）。
        if let backupPath = userDefaults.string(
            forKey: OTAInstaller.pendingBackupPathDefaultsKey),
            let backupDir = userDefaults.string(
                forKey: OTAInstaller.pendingBackupDirDefaultsKey),
            backupPath.hasPrefix(backupDir + "/"),
            Self.isBackupShape(backupPath) {
            try? FileManager.default.removeItem(at: URL(fileURLWithPath: backupPath))
        }
        state = .upToDate
    }

    /// 关面板 / 清理失败态。
    func dismiss() {
        state = .idle
    }

    /// 进行中状态（不可重复 check / install）。
    private var isInFlight: Bool {
        switch state {
        case .checking, .downloading, .downloaded, .installing:
            return true
        case .idle, .upToDate, .updateAvailable, .failed:
            return false
        }
    }

    /// 版本比较 → 状态迁移（纯逻辑，便于理解/测试）。
    private func resolveCheckOutcome(manifest: UpdateManifest, info: UpdateInfo) {
        guard let order = VersionCompare.compare(currentVersion, manifest.version) else {
            state = .failed("无法解析版本号「\(manifest.version)」或当前版本「\(currentVersion)」。")
            return
        }
        switch order {
        case .ascending:
            if VersionCompare.isBelow(currentVersion, minimum: manifest.minimumVersion) {
                state = .failed("当前版本（\(currentVersion)）低于该更新的最低版本（\(manifest.minimumVersion)），无法自动安装。请手动下载最新版本。")
            } else {
                state = .updateAvailable(info)
            }
        case .equal, .descending:
            state = .upToDate
        }
    }

    /// 错误 → 用户可见文案（LocalizedError 优先）。
    static func userMessage(from error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? "更新失败：\(error)"
    }
}
