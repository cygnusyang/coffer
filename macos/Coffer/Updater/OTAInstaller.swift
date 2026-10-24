// OTAInstaller.swift —— 安装机制真实实现（docs/35 §6.4 替换协议，r0.4）。
//
// 本组（A）只负责：解压 zip 提取 .app（prepare）+ 写 install 配置文件 + 经
// LaunchServices 启动嵌入式 helper（perform）。备份 / 替换 / relaunch / 回滚
// 全归 helper——App 是沙盒单渠道，直接 spawn 的子进程继承沙盒，写 /Applications
// 必失败（r0.4 实证，退出码 7）；`open` 无法 waitpid（退出码改经 result 文件
// 握手）且打不开裸 Mach-O（helper 必须装配成嵌套 .app bundle）。helper 由组 B
// 装配为 Contents/Helpers/CofferUpdater.app。

import Foundation

/// 安装机制协议（注入点：测试用 stub；生产用 `OTAInstaller`）。
protocol Installing {
    /// 解压下载的 zip 到临时目录，返回解压出的 .app URL。
    func prepare(downloadedArchive: URL) async throws -> URL
    /// 执行替换安装：写 install 配置 + 经 LaunchServices 启动 helper，随即返回
    /// （不阻塞等待——`open` 无法 waitpid；替换/回滚/relaunch 由 helper 负责）。
    func perform(info: UpdateInfo, downloadedAppURL: URL, currentAppURL: URL) async throws
}

/// helper 启动器（注入点：测试记录并断言启动参数；生产 = open(1) launchViaOpen）。
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
    /// helper 启动器（默认 open(1)；测试注入记录器断言参数）。
    let launchHelper: HelperLauncher
    /// 当前运行 App 路径提供者（BUG-29 后续 B 启动路径守卫）：生产默认 =
    /// Bundle.main.bundleURL（正在运行的 App）；测试注入假值断言守卫行为。
    let runningAppURLProvider: () -> URL

    /// 首启找回 result 文件的 UserDefaults key（被 relaunch 的 .app 消费，契约 6.4 r0.4 步骤 6）。
    static let pendingResultPathDefaultsKey = "ota_pending_result_path"
    /// 成功消费时删除备份所需备份路径的 UserDefaults key（App 侧扩展字段，非 helper 契约）。
    static let pendingBackupPathDefaultsKey = "ota_pending_backup_path"
    /// 备份目录（backupDirectory.path）的 UserDefaults key（C-1 守卫：消费删备份前
    /// 校验 backup 路径在该目录前缀内，防同用户进程改 prefs 指向任意文件造成误删）。
    static let pendingBackupDirDefaultsKey = "ota_pending_backup_dir"
    /// BUG-30 固定名 pending config 文件名（三层冗余取参的固定路径兜底核心）：
    /// App 写容器 tmp 固定名；helper 无沙盒经 getpwuid 推导同一路径读取（零传播
    /// 假设——不依赖 open 的 --args/env 传递，见 perform 与 Installer/main.swift）。
    static let pendingConfigFixedName = "coffer-ota-pending-config.json"
    /// 固定名 pending config URL（沙盒 App 的 FileManager.temporaryDirectory =
    /// 容器 tmp，与 helper 端 getpwuid 推导路径一致）。
    static var pendingConfigFixedURL: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(pendingConfigFixedName)
    }

    /// 安装显式错误（fail-closed：任何一步失败即呈现 failed）。
    enum InstallError: Error, LocalizedError {
        case unzipFailed(String)
        case appNotFound
        case configWriteFailed(String)
        case helperLaunchFailed(String)
        /// BUG-29 后续 B：启动路径错位（运行中 App ≠ 安装目标 /Applications）。
        case launchPathMismatch

        var errorDescription: String? {
            switch self {
            case .unzipFailed(let detail):
                return String(localized: "更新包解压失败：\(detail)")
            case .appNotFound:
                return String(localized: "更新包内未找到 .app，已拒绝安装。")
            case .configWriteFailed(let detail):
                return String(localized: "安装配置写入失败：\(detail)")
            case .helperLaunchFailed(let detail):
                return String(localized: "启动安装辅助进程失败：\(detail)")
            case .launchPathMismatch:
                return String(localized: "当前运行的应用不是已安装版本（/Applications），请从「应用程序」文件夹中的 Coffer 执行更新。")
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
        // runningAppURLProvider 必须在 launchHelper 之前：launchHelper 是最后一个
        // 参数，既有调用点全部用尾随闭包绑定它（HelperLauncher），不得被打乱。
        runningAppURLProvider: @escaping () -> URL = { Bundle.main.bundleURL },
        launchHelper: @escaping HelperLauncher = OTAInstaller.launchViaOpen
    ) {
        self.helperURL = helperURL
        self.backupDirectory = backupDirectory
        self.pidProvider = pidProvider
        self.userDefaults = userDefaults
        self.launchHelper = launchHelper
        self.runningAppURLProvider = runningAppURLProvider
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
        // BUG-29 后续 B：启动路径守卫（fail-fast 错位拦截）。config 的
        // currentAppPath 硬编码 /Applications/Coffer.app（生产），而用户从 build
        // 副本点升级时运行中 App（Bundle.main）在 build 路径——「替了 A 跑着 B」
        // 错位，且正是用户 22:39 现场的双变量叠加（helperURL=build 路径 +
        // /Applications 未替换）。入口拦死：运行中 App ≠ 安装目标 → 不写配置、
        // 不启 helper，直接显式失败（可操作文案）。测试注入 provider 断言两分支。
        guard runningAppURLProvider().path == currentAppURL.path else {
            DiagLog.append("BUG-29B：启动路径错位拦截（running=\(runningAppURLProvider().path) target=\(currentAppURL.path)）")
            // BUG-30 顺手修（Spotlight）：错位拦截同样留下未消费的解压产物，一并
            // best-effort 清理（coffer-ota-* 前缀守卫内，见 cleanupFailedProduct
            // ExtractionDir——测试任意夹具路径不被触碰）。
            Self.cleanupFailedProductExtractionDir(of: downloadedAppURL)
            throw InstallError.launchPathMismatch
        }
        DiagLog.append("BUG-26 插桩：perform 进入（newApp=\(downloadedAppURL.lastPathComponent)）")
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
        DiagLog.append("BUG-26 插桩：perform 写配置 \(configURL.lastPathComponent)")
        do {
            try Self.encodeConfig(config).write(to: configURL, options: .atomic)
        } catch {
            DiagLog.append("BUG-26 插桩：写配置失败 → configWriteFailed（\(error)）")
            throw InstallError.configWriteFailed("\(error)")
        }
        // BUG-30：三层冗余取参的固定路径兜底——除 uuid config 外，再写一份固定名
        // coffer-ota-pending-config.json 到容器 tmp。helper 无沙盒，可经 getpwuid
        // 推导同一路径读取，零传播假设（沙盒 App 的 open(1) 会把 --args 剥掉、
        // env 传播未证，argv/env 都不可靠时必须有一条确定性路径）。写前先删旧
        // （防串场：上一场残留若未被消费/清理，会先于本场被 helper 读到）。固定
        // config 的 resultFilePath 仍指 uuid result——App 消费契约（首启经
        // UserDefaults 找回 result）完全不变，helper 只把固定 config 当入口。
        // 写失败不阻塞主流程（argv/env 仍可送达），仅 DiagLog 留痕。
        try? FileManager.default.removeItem(at: Self.pendingConfigFixedURL)
        do {
            try Self.encodeConfig(config).write(to: Self.pendingConfigFixedURL, options: .atomic)
            DiagLog.append("BUG-30：固定 config 已写 \(Self.pendingConfigFixedURL.lastPathComponent)")
        } catch {
            DiagLog.append("BUG-30：固定 config 写失败（\(error)），回退 argv/env 取参")
        }
        // result/backup/backupDir 路径持久化：被 relaunch 的 .app 首启据此找回并
        // 消费（契约 r0.4 步骤 6）；backupDir 供 C-1 守卫（删备份前校验前缀）。
        userDefaults.set(resultFilePath, forKey: Self.pendingResultPathDefaultsKey)
        userDefaults.set(backupPath, forKey: Self.pendingBackupPathDefaultsKey)
        userDefaults.set(backupDirectory.path, forKey: Self.pendingBackupDirDefaultsKey)
        DiagLog.append("BUG-26 插桩：三个 pending key 已写（result 形状 \((resultFilePath as NSString).lastPathComponent)）")
        do {
            DiagLog.append("BUG-26 插桩：调 launchHelper（\(helperURL.lastPathComponent)）")
            try launchHelper(helperURL, ["--config", configURL.path])
            DiagLog.append("BUG-26 插桩：launchHelper 同步返回（未抛错，pending 保留）")
        } catch let error as InstallError {
            Self.clearPendingState(userDefaults: userDefaults, configURL: configURL,
                                   resultFilePath: resultFilePath)
            Self.cleanupFailedProductExtractionDir(of: downloadedAppURL)
            DiagLog.append("BUG-26 插桩：launchHelper 抛 InstallError → 回滚 pending，\(error)")
            throw error
        } catch {
            Self.clearPendingState(userDefaults: userDefaults, configURL: configURL,
                                   resultFilePath: resultFilePath)
            Self.cleanupFailedProductExtractionDir(of: downloadedAppURL)
            DiagLog.append("BUG-26 插桩：launchHelper 抛未知错误 → 回滚 pending，\(error)")
            throw InstallError.helperLaunchFailed("\(error)")
        }
    }

    /// BUG-30 顺手修（Spotlight）：install 失败路径 best-effort 清理解压目录。
    /// 失败时 helper 未运行 / 未替换，解压产物（coffer-ota-<uuid>/Coffer.app）是无
    /// 用残留——容器 tmp 里完整 .app 会被 Spotlight 索引成独立 Coffer.app（用户
    /// 困扰）。安全边界：父目录名必须匹配 App 自建的 `coffer-ota-*` 前缀才删（
    /// prepare 产出；测试夹具的任意路径一律不动，绝不误删非本场目录）；失败静默。
    static func cleanupFailedProductExtractionDir(of downloadedAppURL: URL) {
        let dir = downloadedAppURL.deletingLastPathComponent()
        guard dir.lastPathComponent.hasPrefix("coffer-ota-") else { return }
        try? FileManager.default.removeItem(at: dir)
    }

    /// launch 失败后的 pending 状态回滚（M-3）：清除三个 pending keys + best-effort
    /// 删已写配置/result/固定 config 残留，保证下次启动 consume 为 no-op（不误报）。
    static func clearPendingState(userDefaults: UserDefaults, configURL: URL, resultFilePath: String) {
        userDefaults.removeObject(forKey: Self.pendingResultPathDefaultsKey)
        userDefaults.removeObject(forKey: Self.pendingBackupPathDefaultsKey)
        userDefaults.removeObject(forKey: Self.pendingBackupDirDefaultsKey)
        try? FileManager.default.removeItem(at: configURL)
        try? FileManager.default.removeItem(at: URL(fileURLWithPath: resultFilePath))
        // BUG-30 顺手修：一并清固定名 pending config（防串场 + 容器 tmp 不积陈）。
        try? FileManager.default.removeItem(at: Self.pendingConfigFixedURL)
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

    /// open(1) 启动参数构造（BUG-29）：`-n <helper> --args <args>`。`-n` 开新
    /// 实例（防复用已有同名实例的旧命令行）；`--args` 之后全部透传给 helper 的
    /// argv（helper 入口解析 `--config`，见 Installer/main.swift）。纯函数供测试
    /// 断言参数构造。
    static func openLaunchArgs(helper: URL, args: [String]) -> [String] {
        ["-n", helper.path, "--args"] + args
    }

    /// BUG-30：从 launcher args 提取 config 路径注入环境（三层冗余取参第一源）。
    /// open(1) 传播自身 env 给被拉起的 helper——非沙盒 spike 已证；沙盒下未证，
    /// 与固定路径兜底并列，argv 被 LS 剥掉后仍有一条传递通道。返回
    /// `[COFFER_UPDATER_CONFIG: <configPath>]`；args 无 `--config` → nil。纯函数
    /// 供测试断言（TC-BUG30）。
    static func configEnvironment(from args: [String]) -> [String: String]? {
        guard let index = args.firstIndex(of: "--config"),
              args.indices.contains(index + 1) else { return nil }
        return ["COFFER_UPDATER_CONFIG": args[index + 1]]
    }

    /// 生产启动器（BUG-29 修复，2026-10-14）：主路径 = `/usr/bin/open -n <helper>
    /// --args <args>`（同步跑，open(1) 提交即返回不 waitpid）。退出码非 0 或
    /// stderr 有内容 → helperLaunchFailed 显式抛错（fail-closed，可诊断）。
    ///
    /// 原 NSWorkspace.openApplication 路径在 macOS 26 沙盒 App 内被实证为**静默
    /// no-op**：回调 error=nil 假成功、helper 从未被拉起（lead 真机 21:19 全链路：
    /// App 正常退出但 /Applications 未替换、无 result 文件、全系统统一日志 90 分钟
    /// 零 coffer-update 痕迹；对照 17:59 手动 `/usr/bin/open -n <helper> --args`
    /// 驱动同 helper 成功并写 result）。故**删除** openApplication 路径并禁止回归
    /// 捡回——本注释即防回归记录。
    ///
    /// 风险如实：open(1) 是沙盒 App 的子进程，继承沙盒——其 LaunchServices XPC
    /// 是否被沙盒拦只能真机全链路复测定谳（lead 2026-10-14：被拦则 next =
    /// launchd 用户 agent / XPC service，留给真机结果再裁定）。
    ///
    /// 诊断边界：open(1) 只承接**自身的**启动错误（沙盒拦 / 路径无效等，走其
    /// stderr）；helper 进程的 stdout/stderr 经 LaunchServices 分离启动后归统一
    /// 日志（**不**回到 open 的 stderr），helper 运行期诊断靠 result 文件 /
    /// `log show`。
    static func launchViaOpen(helper: URL, args: [String]) throws {
        DiagLog.append("BUG-29：launchViaOpen 进入（helper=\(helper.lastPathComponent)）")
        guard FileManager.default.fileExists(atPath: helper.path) else {
            DiagLog.append("BUG-29：helper bundle 缺失 → helperLaunchFailed")
            throw InstallError.helperLaunchFailed(String(localized: "未找到安装辅助程序 \(helper.lastPathComponent)"))
        }
        let openArgs = openLaunchArgs(helper: helper, args: args)
        DiagLog.append("BUG-29：执行 open \(openArgs.joined(separator: " "))")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = openArgs
        // BUG-30：三层冗余取参第一源——把 config 路径经 env 注入 open 进程，由其
        // 传播给被拉起的 helper（open 传播自身 env；沙盒下是否生效待真机复测，
        // 与固定路径兜底双保险）。仅当 args 含 --config 时注入（构造失败静默降级
        // 到其余两源，不影响主流程）。
        if let configEnv = configEnvironment(from: args) {
            var env = ProcessInfo.processInfo.environment
            for (key, value) in configEnv { env[key] = value }
            process.environment = env
            DiagLog.append("BUG-30：env 注入 COFFER_UPDATER_CONFIG（open 子进程传播）")
        }
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        let detail = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let status = process.terminationStatus
        guard status == 0 && detail.isEmpty else {
            let suffix = detail.isEmpty ? "（无 stderr 输出）" : "：\(detail)"
            DiagLog.append("BUG-29：open 启动失败（exit \(status)）\(suffix)")
            // 用户面只给退出码：open 的 stderr 是外部进程原文（不属可译文案），拼进
            // 本地化句子会让英文界面混入未翻译片段（设计 24 §5.5 文案/数据分界）。
            throw InstallError.helperLaunchFailed(String(localized: "退出码 \(String(status))"))
        }
        DiagLog.append("BUG-29：open(1) 提交成功（exit 0 无 stderr；helper 已交 LaunchServices，进程归属 launchd）")
    }

    /// 同步跑子进程（解压 / 打 zip），非 0 退出抛错（子进程 stderr 并入错误，不吞
    /// 错误也不让原始 stderr 污染调用方输出）。launchViaOpen 不复用本函数——open
    /// 成功契约 = exit 0 **且** stderr 空，需同时读两者，runProcess 不满足。
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
            // 该 description 会作为 detail 进入上游的本地化模板（如「更新包解压失败：%@」），
            // 属用户可见串；退出码按 String 插值避免「1,005」式分组。
            let exitText = String(process.terminationStatus)
            let message = detail.isEmpty
                ? String(localized: "\(executable) 退出码 \(exitText)")
                : String(localized: "\(executable) 退出码 \(exitText)：\(detail)")
            throw NSError(
                domain: "OTAInstaller", code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    /// 打 zip（测试夹具 / 后续复验用）：ditto -c -k --keepParent。
    static func archiveApp(_ appURL: URL, to zipURL: URL) throws {
        try runProcess("/usr/bin/ditto", args: ["-c", "-k", "--keepParent", appURL.path, zipURL.path])
    }
}
