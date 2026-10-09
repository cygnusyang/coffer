// OTAInstaller.swift —— 安装机制真实实现（docs/35 §6.4 替换协议，r0.4）。
//
// 本组（A）只负责：解压 zip 提取 .app（prepare）+ 写 install 配置文件 + 经
// LaunchServices 启动嵌入式 helper（perform）。备份 / 替换 / relaunch / 回滚
// 全归 helper——App 是沙盒单渠道，直接 spawn 的子进程继承沙盒，写 /Applications
// 必失败（r0.4 实证，退出码 7）；`open` 无法 waitpid（退出码改经 result 文件
// 握手）且打不开裸 Mach-O（helper 必须装配成嵌套 .app bundle）。helper 由组 B
// 装配为 Contents/Helpers/CofferUpdater.app。

import Foundation
import AppKit

/// 安装机制协议（注入点：测试用 stub；生产用 `OTAInstaller`）。
protocol Installing {
    /// 解压下载的 zip 到临时目录，返回解压出的 .app URL。
    func prepare(downloadedArchive: URL) async throws -> URL
    /// 执行替换安装：写 install 配置 + 经 LaunchServices 启动 helper，随即返回
    /// （不阻塞等待——`open` 无法 waitpid；替换/回滚/relaunch 由 helper 负责）。
    func perform(info: UpdateInfo, downloadedAppURL: URL, currentAppURL: URL) async throws
}

/// helper 启动器（注入点：测试记录并断言启动参数；生产 = LaunchServices）。
typealias HelperLauncher = (URL, [String]) throws -> Void

/// 真实安装机制（解压 / 写配置 / LaunchServices 启动 helper）。
struct OTAInstaller: Installing {
    /// 嵌入式安装 helper 路径（Contents/Helpers/CofferUpdater.app，组 B 装配；契约 6.4 r0.4）。
    let helperURL: URL
    /// 临时区（写配置文件 / 指定 helper 的备份与 result 落点；契约 6.4 r0.4）。
    let backupDirectory: URL
    /// 当前进程 pid 提供者（helper 等待其退出后替换）。
    let pidProvider: () -> Int32
    /// UserDefaults 域（持久化 result 文件路径供被 relaunch 的 .app 首启找回；测试注入独立 suite）。
    let userDefaults: UserDefaults
    /// helper 启动器（默认 LaunchServices；测试注入记录器断言参数）。
    let launchHelper: HelperLauncher

    /// 首启找回 result 文件的 UserDefaults key（被 relaunch 的 .app 消费，契约 6.4 r0.4 步骤 6）。
    static let pendingResultPathDefaultsKey = "ota_pending_result_path"
    /// 成功消费时删除备份所需备份路径的 UserDefaults key（App 侧扩展字段，非 helper 契约）。
    static let pendingBackupPathDefaultsKey = "ota_pending_backup_path"
    /// 备份目录（backupDirectory.path）的 UserDefaults key（C-1 守卫：消费删备份前
    /// 校验 backup 路径在该目录前缀内，防同用户进程改 prefs 指向任意文件造成误删）。
    static let pendingBackupDirDefaultsKey = "ota_pending_backup_dir"

    /// 安装显式错误（fail-closed：任何一步失败即呈现 failed）。
    enum InstallError: Error, LocalizedError {
        case unzipFailed(String)
        case appNotFound
        case configWriteFailed(String)
        case helperLaunchFailed(String)

        var errorDescription: String? {
            switch self {
            case .unzipFailed(let detail):
                return "更新包解压失败：\(detail)"
            case .appNotFound:
                return "更新包内未找到 .app，已拒绝安装。"
            case .configWriteFailed(let detail):
                return "安装配置写入失败：\(detail)"
            case .helperLaunchFailed(let detail):
                return "启动安装辅助进程失败：\(detail)"
            }
        }
    }

    /// install 配置文件（契约 6.4 r0.4 步骤 3 的 5 字段；helper 读它执行替换）。
    struct InstallConfig: Codable, Equatable {
        let newAppPath: String
        let currentAppPath: String
        let backupPath: String
        let resultFilePath: String
        let pid: Int32
    }

    /// helper 写回的结果文件（契约 6.4 r0.4 步骤 5：成功/失败 + 退出码 + 文案；App 首启消费）。
    struct InstallResult: Codable, Equatable {
        let success: Bool
        let code: Int
        let message: String
    }

    init(
        helperURL: URL,
        backupDirectory: URL = FileManager.default.temporaryDirectory,
        pidProvider: @escaping () -> Int32 = { ProcessInfo.processInfo.processIdentifier },
        userDefaults: UserDefaults = .standard,
        launchHelper: @escaping HelperLauncher = OTAInstaller.launchViaLaunchServices
    ) {
        self.helperURL = helperURL
        self.backupDirectory = backupDirectory
        self.pidProvider = pidProvider
        self.userDefaults = userDefaults
        self.launchHelper = launchHelper
    }

    /// 解压下载的 zip 到临时目录，返回首个 `.app` URL。解压失败 / 无 .app
    /// 显式报错（fail-closed）。
    func prepare(downloadedArchive: URL) async throws -> URL {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
            .appendingPathComponent("coffer-ota-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        do {
            try Self.runProcess("/usr/bin/ditto", args: ["-x", "-k", downloadedArchive.path, tempDir.path])
        } catch {
            throw InstallError.unzipFailed("\(error)")
        }
        let contents = try fm.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil)
        guard let app = contents.first(where: { $0.pathExtension == "app" }) else {
            throw InstallError.appNotFound
        }
        return app
    }

    /// 写 install 配置（5 字段 JSON）→ 持久化 result/backup/backupDir 到
    /// UserDefaults → 经 LaunchServices 启动 helper 并返回（不等待；备份/替换/
    /// 回滚全归 helper）。launcher 抛错（helper 未装配等）→ 回滚 pending keys +
    /// best-effort 清已写配置残留（M-3），避免下次启动误弹「无法读取上次更新的结果」。
    func perform(info: UpdateInfo, downloadedAppURL: URL, currentAppURL: URL) async throws {
        let stamp = Int(Date().timeIntervalSince1970)
        let uuid = UUID().uuidString
        let backupPath = backupDirectory.appendingPathComponent("Coffer-\(stamp).app").path
        let resultFilePath = backupDirectory
            .appendingPathComponent("coffer-ota-result-\(uuid).json").path
        let configURL = backupDirectory
            .appendingPathComponent("coffer-ota-config-\(uuid).json")
        let config = InstallConfig(
            newAppPath: downloadedAppURL.path,
            currentAppPath: currentAppURL.path,
            backupPath: backupPath,
            resultFilePath: resultFilePath,
            pid: pidProvider())
        do {
            try Self.encodeConfig(config).write(to: configURL, options: .atomic)
        } catch {
            throw InstallError.configWriteFailed("\(error)")
        }
        // result/backup/backupDir 路径持久化：被 relaunch 的 .app 首启据此找回并
        // 消费（契约 r0.4 步骤 6）；backupDir 供 C-1 守卫（删备份前校验前缀）。
        userDefaults.set(resultFilePath, forKey: Self.pendingResultPathDefaultsKey)
        userDefaults.set(backupPath, forKey: Self.pendingBackupPathDefaultsKey)
        userDefaults.set(backupDirectory.path, forKey: Self.pendingBackupDirDefaultsKey)
        do {
            try launchHelper(helperURL, ["--config", configURL.path])
        } catch let error as InstallError {
            Self.clearPendingState(userDefaults: userDefaults, configURL: configURL,
                                   resultFilePath: resultFilePath)
            throw error
        } catch {
            Self.clearPendingState(userDefaults: userDefaults, configURL: configURL,
                                   resultFilePath: resultFilePath)
            throw InstallError.helperLaunchFailed("\(error)")
        }
    }

    /// launch 失败后的 pending 状态回滚（M-3）：清除三个 pending keys + best-effort
    /// 删已写配置/result 残留，保证下次启动 consume 为 no-op（不误报）。
    static func clearPendingState(userDefaults: UserDefaults, configURL: URL, resultFilePath: String) {
        userDefaults.removeObject(forKey: Self.pendingResultPathDefaultsKey)
        userDefaults.removeObject(forKey: Self.pendingBackupPathDefaultsKey)
        userDefaults.removeObject(forKey: Self.pendingBackupDirDefaultsKey)
        try? FileManager.default.removeItem(at: configURL)
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: resultFilePath))
    }

    /// 配置 JSON（sortedKeys 确定性序列化，字段与契约 6.4 一一对应）。
    static func encodeConfig(_ config: InstallConfig) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(config)
    }

    /// result JSON（与 helper 写入、App 首启读取同构；测试夹具复用）。
    static func encodeResult(_ result: InstallResult) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(result)
    }

    /// 生产启动器：NSWorkspace.openApplication（LaunchServices，launchd 按 helper
    /// 自身 entitlements 加载，不继承 App 沙盒，契约 r0.4）。回调式 API：提交即
    /// 返回（不阻塞——open 无法 waitpid）。同步可判失败只有 helper bundle 缺失
    /// （组 B 未装配）→ 立即 fail-closed；提交失败在回调里兜底 `/usr/bin/open -n
    /// <helper> --args ...`（装配/真机验证基线），彻底失败由下次启动消费 result
    /// 文件缺失呈现（契约 r0.4 步骤 6，fail-closed）。真机核销项。
    static func launchViaLaunchServices(helper: URL, args: [String]) throws {
        guard FileManager.default.fileExists(atPath: helper.path) else {
            throw InstallError.helperLaunchFailed("未找到安装辅助程序 \(helper.lastPathComponent)")
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = args
        configuration.activates = false
        NSWorkspace.shared.openApplication(at: helper, configuration: configuration) { _, error in
            guard error != nil else { return }
            // 兜底：open -n（App 可能即将退出，回调未必来得及执行；失败终态交给
            // result 文件消费兜底，见函数注释）。
            try? runProcess("/usr/bin/open", args: ["-n", helper.path, "--args"] + args)
        }
    }

    /// 同步跑子进程（解压 / 打 zip / open 兜底），非 0 退出抛错（子进程 stderr 并入
    /// 错误，不吞错误也不让原始 stderr 污染调用方输出）。
    static func runProcess(_ executable: String, args: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = args
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let suffix = detail.isEmpty ? "" : "：\(detail)"
            throw NSError(
                domain: "OTAInstaller", code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "\(executable) 退出码 \(process.terminationStatus)\(suffix)"])
        }
    }

    /// 打 zip（测试夹具 / 后续复验用）：ditto -c -k --keepParent。
    static func archiveApp(_ appURL: URL, to zipURL: URL) throws {
        try runProcess("/usr/bin/ditto", args: ["-c", "-k", "--keepParent", appURL.path, zipURL.path])
    }
}
