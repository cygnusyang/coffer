// main.swift —— OTA install helper（v2.7.0，契约 docs/35 §6.4 替换协议，r0.4）。
//
// 形态：嵌入式非沙盒 install helper，装配为嵌套 .app bundle
// Contents/Helpers/CofferUpdater.app（r0.4 定稿：open/LaunchServices 只认 bundle，
// 不认裸 Mach-O）。Spike-0 裁定：无受限 entitlement、无 embedded.provisionprofile，
// Apple Development 签名即 AMFI 放行。职责单一：等待 App 退出 → 备份当前 App →
// 替换为新包 → relaunch → 写 result 文件。不做网络、不碰 Keychain、不读秘密材料。
//
// 调用协议（契约 docs/35 §6.4，r0.4，冻结）：
//   CofferUpdater.app --config <JSON 配置文件路径>
//   配置文件字段（组 A 写）：newAppPath / currentAppPath / backupPath /
//   resultFilePath / pid。App 经 LaunchServices 启动本 helper（open -n
//   <CofferUpdater.app> --args --config <path>），不 spawn 不 waitpid——
//   成败经 result 文件握手（open 无法 waitpid，实证）。
//
// 退出码（helper 内部 + 进 result，语义与 r0.3 一致）：
//   0 成功；1 备份失败；2 替换失败；3 relaunch 失败；4 用法错误
//   （等待 App 退出超时归入 3，此时未做任何修改）
//
// result 文件 JSON（App 侧首启读取，一次性消费后删除）：
//   {success: Bool, code: Int32, message: String}
//
// 回滚纪律：替换前完整备份当前 .app 到 backupPath；备份失败(1)/替换失败(2)/
// relaunch 失败(3) → helper 自身尽力恢复备份 + relaunch 旧 .app（relaunch 失败时
// 目标里已是新包，须用旧包覆盖回去），再写 result 记失败。备份不删（由被 relaunch
// 的 .app 首启校验通过后删除）。
//
// 安全（C-1/H-1 安全审查硬锚定 + 载荷验签，2026-10-10）：
//   - currentAppPath 硬锚定：生产编译（-D COFFER_UPDATER_PRODUCTION）锚为编译期常量
//     /Applications/Coffer.app；测试构建（无该 define）锚读 env COFFER_UPDATER_TEST_ANCHOR。
//     配置 currentAppPath != 锚 → exit 4（未做任何修改）。生产路径严禁读环境变量。
//   - newAppPath 载荷验签：basename 必须为 Coffer.app；用 Security framework 静态验签，
//     DR = anchor apple generic and certificate leaf[subject.OU]="A6DS985SJJ" and
//     identifier "top.cygnusyang.coffer"；embedded.provisionprofile 必须存在且未过期。
//     任一失败 → exit 2（未做任何修改）。
//   - backupPath/resultFilePath 软锚：绝对路径 + 形状约束（.app / .json）。
//   - C-2 收敛不变式（2026-10-10 复审）：任何被 relaunch 的包必须「刚刚通过 DR」——
//     单点 gate 在 relaunchApp 内（主流程 step6 与所有回滚路径都经它），先验签后启动，
//     未过 DR → 不启动、exit 2。backupPath/newAppPath/resultFilePath 含符号链接分量，
//     或 backupPath==currentAppPath / ==newAppPath / newAppPath==currentAppPath（相等
//     判定用规范化路径 URL.standardizedFileURL 且两侧小写化，APFS 卷大小写不敏感）
//     → 配置非法 exit 4（零修改）。
//   - 参数全部按值处理，不拼接 shell（子进程参数以数组传递，路径含空格/引号安全）。

import Darwin
import Foundation
import Security

// MARK: - 常量

/// 等待 App 进程退出的最大秒数（契约未定死，超时 → exit 3）。
private let waitTimeout: TimeInterval = 30

/// 轮询间隔（秒）。
private let pollInterval: TimeInterval = 0.5

// MARK: - BUG-30 固定路径取参兜底（App 侧容器 tmp 固定名 config）

/// 沙盒 App 的容器 bundle id（固定路径取参推导用；与 App 侧
/// FileManager.default.temporaryDirectory 解析到的容器 tmp 同一目录）。
private let containerBundleID = "top.cygnusyang.coffer"

/// 固定名 pending config 文件名（App 写容器 tmp 固定名；helper 推导同一路径读取）。
private let fixedConfigFileName = "coffer-ota-pending-config.json"

/// 真实用户家目录（getpwuid 用户数据库，**不**读 HOME 环境变量——open 传播调用方
/// env，沙盒 App 的 HOME 指向容器 Data，读它会把固定路径算到错误的双层容器目录）。
/// 失败回退 NSHomeDirectory()（best-effort）。
func realUserHomeDirectory() -> String {
    if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
        return String(cString: dir)
    }
    return NSHomeDirectory()
}

/// 固定路径兜底 config 的确定性路径：$HOME/Library/Containers/<bundle>/Data/tmp/
/// coffer-ota-pending-config.json。零传播假设——helper 无沙盒，仅凭用户数据库推导，
/// 不依赖任何参数/env 传递（BUG-30 三层冗余取参的第二源）。
func fixedConfigPath() -> String {
    realUserHomeDirectory()
        + "/Library/Containers/\(containerBundleID)/Data/tmp/\(fixedConfigFileName)"
}

// MARK: - 安全锚定（C-1：硬锚 currentAppPath + 载荷 DR）

#if COFFER_UPDATER_PRODUCTION
/// 生产锚：配置 currentAppPath 必须精确等于该固定路径。编译期硬编码常量——
/// 生产路径严禁读取环境变量（条件编译保证生产二进制不含 env 分支）。
private let expectedCurrentAppPath = "/Applications/Coffer.app"
#else
/// 测试锚（run_install_helper_tests.sh 注入 COFFER_UPDATER_TEST_ANCHOR）。
/// 未注入时回退生产锚——fail-closed，绝不因缺少环境变量而放行任意路径。
private let expectedCurrentAppPath: String = {
    let env = ProcessInfo.processInfo.environment["COFFER_UPDATER_TEST_ANCHOR"] ?? ""
    return env.isEmpty ? "/Applications/Coffer.app" : env
}()
#endif

/// 新包静态验签的 DR（Designated Requirement）：锚定 Apple 证书链 + TeamID(OU) +
/// 应用 identifier。本机任意进程即使伪造配置也无法让非 Apple 签名载荷通过：
/// 证书由 Apple 签发、OU 必须是 A6DS985SJJ、identifier 必须是 top.cygnusyang.coffer。
private let updatePackageRequirement =
    "anchor apple generic and certificate leaf[subject.OU] = \"A6DS985SJJ\" and identifier \"top.cygnusyang.coffer\""

// MARK: - 退出码（契约 docs/35 §6.4，冻结）

enum ExitCode {
    static let success: Int32 = 0
    static let backupFailed: Int32 = 1
    static let replaceFailed: Int32 = 2
    static let relaunchFailed: Int32 = 3
    static let usageError: Int32 = 4
}

// MARK: - 日志（BUG-29 后续：双写 stderr + /tmp/coffer-update.log，现场第一诊断入口）

/// 文件日志路径。helper 是无沙盒短命进程，/tmp 可写；固定路径便于现场取证——
/// 统一日志曾整体失效（连 last 5m 都 0 行），OTA 诊断只能靠文件落盘（BUG-29 后续）。
private let fileLogPath = "/tmp/coffer-update.log"

/// 文件日志轮转上限（字节）：超过则在下一次追加前截断重写，防长期膨胀。
private let fileLogMaxBytes: off_t = 1_000_000

/// 日志统一写 stderr + append 到 /tmp/coffer-update.log（O_APPEND 原子行写——
/// 多实例并发追加单行不交错，供并行/重试场景取证）。helper 无密码/密钥材料，
/// 但纪律照旧：只打印操作过程与路径。文件写入失败静默——文件日志是诊断增强，
/// 绝不能因 /tmp 异常影响安装主流程。
func log(_ message: String) {
    let line = message + "\n"
    if let data = line.data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
    appendToFileLog(line)
}

/// append 一行到文件日志（open O_APPEND + 单次 write = 原子行写）。超过轮转
/// 上限先截断到 0 再写当前行（当前行不丢）。失败静默（见 log 注释）。
private func appendToFileLog(_ line: String) {
    guard let data = line.data(using: .utf8) else { return }
    let fd = open(fileLogPath, O_WRONLY | O_APPEND | O_CREAT, 0o644)
    guard fd >= 0 else { return }
    defer { close(fd) }
    var st = stat()
    if fstat(fd, &st) == 0, st.st_size > fileLogMaxBytes {
        ftruncate(fd, 0)
    }
    data.withUnsafeBytes { buf in
        guard let base = buf.baseAddress else { return }
        _ = write(fd, base, buf.count)
    }
}

// MARK: - 配置（JSON，组 A 写）

/// 安装配置（App 写入的 JSON，字段与退出码语义对应，契约 §6.4）。
struct InstallConfig: Codable {
    let newAppPath: String
    let currentAppPath: String
    let backupPath: String
    let resultFilePath: String
    let pid: pid_t
}

/// 用法文本（exit 4 时写 stderr）。
let usageText = """
用法:
  CofferUpdater.app --config <JSON 配置文件路径>

取参（BUG-30 三层冗余，优先级由高到低）:
  env COFFER_UPDATER_CONFIG=<路径>   App 侧 Process 注入（open 传播 env）
  固定路径 <容器tmp>/coffer-ota-pending-config.json
  argv --config <路径>                非沙盒调试/终端手动路径

配置文件字段（JSON）:
  newAppPath      新下载的 .app 包路径（须为 Coffer.app、验签 + profile 未过期）
  currentAppPath  当前 App 目标位置（固定锚，生产 = /Applications/Coffer.app）
  backupPath      替换前备份路径（以 .app 结尾，本 helper 不删除备份）
  resultFilePath  操作结果 JSON 路径（以 .json 结尾，App 首启读取）
  pid             当前 App 进程 pid（等待其退出后再替换）

退出码（契约 docs/35 §6.4）:
  0 成功
  1 备份失败
  2 替换失败（helper 已尽力恢复备份 + relaunch 旧 App）
  3 relaunch 失败
  4 用法错误（含配置读取/校验失败）
"""

/// 判断路径是否为绝对路径（相对路径在未知 CWD 下不可靠，一律拒绝）。
func isAbsolutePath(_ path: String) -> Bool {
    return path.hasPrefix("/")
}

/// C-2 加固：路径含「攻击者可控」符号链接分量 → true。逐分量 lstat（不跟随）：
/// 仅放行 macOS 根级系统重定向 /var、/tmp、/etc（root 所有、固定指向 private/…，
/// 普通用户不可翻转；App 临时区 /var/folders 与 /tmp 都要经过它们，误拒会让合法
/// 配置 exit 4）；其余任一分量是符号链接（含备份/新包/result 的末级本身）→ 配置非法
/// exit 4（零修改）——防 symlink 翻转把备份/新包/result 定向到攻击者目录（备份写入、
/// 恢复读出、result 落点全被劫持）。启动时逐分量检查关闭常见攻击；等待窗内翻转的
/// 残余竞速由 relaunchApp 的 C-2 gate 兜底。
private let benignRootSymlinkNames: Set<String> = ["var", "tmp", "etc"]

func containsSymlinkComponent(_ path: String) -> Bool {
    var current = "/"
    var depth = 0
    for part in (path as NSString).pathComponents {
        guard part != "/" else { continue }
        depth += 1
        current = (current as NSString).appendingPathComponent(part)
        var st: stat = stat()
        guard lstat(current, &st) == 0 else { continue }
        if (Int32(st.st_mode) & Int32(S_IFMT)) != Int32(S_IFLNK) { continue }
        // 根级系统重定向（/var /tmp /etc → private/…）：root 所有、不可被普通用户翻转，
        // 放行；其余任何符号链接（含深度 ≥2 的攻击者链接）→ 拒绝。
        if depth == 1, benignRootSymlinkNames.contains(part),
           let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: current),
           dest.hasPrefix("private/") || dest.hasPrefix("/private/") {
            continue
        }
        return true
    }
    return false
}

/// 规范化路径（URL.standardizedFileURL.path：词法归并 ".." 与重复斜杠；不解析符号
/// 链接——与 containsSymlinkComponent 检查正交，避免相互打架）。仅用于相等性判定。
func standardizedPath(_ path: String) -> String {
    return URL(fileURLWithPath: path).standardizedFileURL.path
}

/// 校验配置字段；返回 nil = 合法，否则为错误描述。
func validateConfig(_ config: InstallConfig) -> String? {
    if !isAbsolutePath(config.newAppPath) {
        return "newAppPath 必须为绝对路径"
    }
    if !isAbsolutePath(config.currentAppPath) {
        return "currentAppPath 必须为绝对路径"
    }
    if !isAbsolutePath(config.backupPath) {
        return "backupPath 必须为绝对路径"
    }
    if !isAbsolutePath(config.resultFilePath) {
        return "resultFilePath 必须为绝对路径"
    }
    if config.pid <= 0 {
        return "pid 必须为正整数"
    }
    // C-1 硬锚：currentAppPath 必须精确等于固定锚（生产编译期常量 / 测试 env 注入）。
    // 不满足 → exit 4（配置非法，未做任何修改）——杜绝把任意目标路径当 App 覆盖。
    if config.currentAppPath != expectedCurrentAppPath {
        return "currentAppPath 必须为 \(expectedCurrentAppPath)（固定锚）"
    }
    // 软锚（形状约束，对齐 App 侧命名；硬安全边界由上面的锚定 + 载荷验签承担）
    if !config.backupPath.hasSuffix(".app") {
        return "backupPath 必须以 .app 结尾"
    }
    if !config.resultFilePath.hasSuffix(".json") {
        return "resultFilePath 必须以 .json 结尾"
    }
    // C-2 加固：backupPath/newAppPath/resultFilePath 含符号链接分量 → 配置非法（零修改）。
    // 备份/新包/result 一旦可被链接定向到攻击者目录，替换/恢复/握手全被劫持。
    if containsSymlinkComponent(config.backupPath) {
        return "backupPath 不得包含符号链接分量"
    }
    if containsSymlinkComponent(config.newAppPath) {
        return "newAppPath 不得包含符号链接分量"
    }
    if containsSymlinkComponent(config.resultFilePath) {
        return "resultFilePath 不得包含符号链接分量"
    }
    // C-2 加固：backupPath/newAppPath 不得与彼此或与 currentAppPath 同路径——
    // backupCurrentApp 会先 removeItem 备份目标：backup==current 会先删掉
    // /Applications/Coffer.app 本体再失败回滚（DoS）；backup==new 会删掉新包源；
    // new==current 无合法场景且回滚混乱（replace 先删 current 再 move 源已删）。
    // 相等判定用规范化路径（URL.standardizedFileURL：词法归并 ".." 与重复斜杠，不解析
    // 符号链接，避免与 symlink 分量检查打架）再两侧小写化——APFS 默认卷大小写不敏感，
    // 目录 case 变体（…/TARGET/ 与 …/target/）解析为同一目录，判等必须 case-insensitive。
    // 小写化仅用于相等判定，不参与路径解析/锚匹配：currentAppPath 硬锚（L187）与
    // newAppPath basename 精确 "Coffer.app" 检查仍精确匹配，case 变体自然 exit 4。
    if standardizedPath(config.backupPath).lowercased() == standardizedPath(config.currentAppPath).lowercased() {
        return "backupPath 不得等于 currentAppPath"
    }
    if standardizedPath(config.backupPath).lowercased() == standardizedPath(config.newAppPath).lowercased() {
        return "backupPath 不得等于 newAppPath"
    }
    if standardizedPath(config.newAppPath).lowercased() == standardizedPath(config.currentAppPath).lowercased() {
        return "newAppPath 不得等于 currentAppPath"
    }
    return nil
}

/// 配置读取/校验错误（Fail-closed：任何一步失败即 exit 4）。
enum ConfigError: Error {
    case message(String)
}

/// 读取并校验配置文件；成功返回配置，失败返回 ConfigError（调用方 exit 4）。
func loadConfig(from path: String) -> Result<InstallConfig, ConfigError> {
    let fm = FileManager.default
    guard fm.fileExists(atPath: path) else {
        return .failure(.message("配置文件不存在: \(path)"))
    }
    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let config = try JSONDecoder().decode(InstallConfig.self, from: data)
        if let message = validateConfig(config) {
            return .failure(.message(message))
        }
        return .success(config)
    } catch {
        return .failure(.message("配置解析失败: \(error)"))
    }
}

// MARK: - 参数解析

/// 解析命令行参数：只接受 `--config <路径>`；缺参/未知参 → nil（exit 4）。
func parseArguments(_ arguments: [String]) -> String? {
    var configPath: String?
    var iterator = arguments.makeIterator()
    while let flag = iterator.next() {
        switch flag {
        case "--config":
            guard let value = iterator.next(), !value.isEmpty else {
                return nil
            }
            configPath = value
        default:
            return nil
        }
    }
    return configPath
}

// MARK: - 取参（BUG-30 三层冗余：env → 固定路径 → argv）

/// 三层冗余取参，返回命中的 config 路径；三源皆无 → nil（调用方 exit 4）。
/// 背景（BUG-30 定谳，真机现场实证）：沙盒 App 经 `open(1)` 发起 helper 时，`--args`
/// 参数在 LaunchServices 交接处被剥掉（/tmp/coffer-update.log 首行 `argv=` 为空 +
/// exit 4 用法路径；对照：非沙盒终端手动 open 送达正常）。修复 = 三源冗余，优先级：
///   1. env  COFFER_UPDATER_CONFIG=<path>（App 侧 Process 设 environment 注入；
///            open(1) 传播自身 env 给被拉起进程——非沙盒 spike 已证；沙盒下未证，
///            列为第一优先）
///   2. 固定路径 <容器tmp>/coffer-ota-pending-config.json（App 写容器 tmp 固定名，
///            helper 无沙盒可经 getpwuid 推导同一路径——零传播假设，兜底核心）
///   3. argv --config（保留，非沙盒调试/终端手动 open 路径仍工作）
/// log() 记录命中哪一来源，现场据此分诊（env 是否传播 / 固定路径是否写成功）。
func resolveConfigPath(arguments: [String]) -> String? {
    // 1. env
    let fromEnv = ProcessInfo.processInfo.environment["COFFER_UPDATER_CONFIG"] ?? ""
    if !fromEnv.isEmpty {
        log("取参来源：env COFFER_UPDATER_CONFIG=\(fromEnv)")
        return fromEnv
    }
    // 2. 固定路径（容器 tmp）
    let fixed = fixedConfigPath()
    if FileManager.default.fileExists(atPath: fixed) {
        log("取参来源：固定路径 \(fixed)")
        return fixed
    }
    // 3. argv --config
    if let fromArgs = parseArguments(arguments) {
        log("取参来源：argv --config \(fromArgs)")
        return fromArgs
    }
    log("取参失败：env / 固定路径 / argv 三源皆无（BUG-30 场景：沙盒 open 剥 argv 且 env 未传播 / 固定 config 未落盘）")
    return nil
}

// MARK: - 进程等待

/// 判断 pid 对应进程是否存活（kill(pid, 0) 探测；EPERM 也视为存活）。
func isProcessAlive(_ pid: pid_t) -> Bool {
    guard pid > 0 else { return false }
    if kill(pid, 0) == 0 { return true }
    return errno != ESRCH
}

/// 等待 App 进程退出，最长 waitTimeout 秒。返回 true = 已退出。
func waitForProcessExit(pid: pid_t) -> Bool {
    let deadline = Date().addingTimeInterval(waitTimeout)
    while isProcessAlive(pid) {
        if Date() >= deadline { return false }
        Thread.sleep(forTimeInterval: pollInterval)
    }
    return true
}

// MARK: - 备份与替换

/// 备份当前 App：把 source 完整复制到 backup；已存在的备份先清掉再复制。
/// 返回 nil = 成功，否则为错误描述。
func backupCurrentApp(from source: String, to backup: String) -> String? {
    let fm = FileManager.default
    do {
        // 备份父目录可能尚不存在（App 侧临时区由本 helper 兜底创建）
        let backupParent = URL(fileURLWithPath: backup).deletingLastPathComponent()
        try fm.createDirectory(at: backupParent, withIntermediateDirectories: true)
        if fm.fileExists(atPath: backup) {
            try fm.removeItem(atPath: backup)
        }
        try fm.copyItem(atPath: source, toPath: backup)
        return nil
    } catch {
        return "备份失败（source=\(source) backup=\(backup)）: \(error)"
    }
}

/// 替换：把新包移到目标位置；目标已存在则先移除。跨卷 move 失败回退 copy + 清理源。
/// 返回 nil = 成功，否则为错误描述。
func replaceCurrentApp(newPackage: String, target: String) -> String? {
    let fm = FileManager.default
    do {
        if fm.fileExists(atPath: target) {
            try fm.removeItem(atPath: target)
        }
        do {
            try fm.moveItem(atPath: newPackage, toPath: target)
        } catch {
            try fm.copyItem(atPath: newPackage, toPath: target)
            try? fm.removeItem(atPath: newPackage)
        }
        return nil
    } catch {
        return "替换失败（new=\(newPackage) target=\(target)）: \(error)"
    }
}

// MARK: - relaunch（C-2 单点 gate：任何被 relaunch 的包必须刚通过 DR）

/// relaunch 失败类别（C-2 收敛）：未过 DR（安全边界，绝不启动，exit 2）与
/// open 启动失败（真实启动失败，exit 3）须区分——前者是安全拦截，后者是启动故障。
enum RelaunchFailure {
    case signature(String)
    case launch(String)
}

/// 底层启动：用 /usr/bin/open -n 启动 App（与 App→helper 同一 LaunchServices 路径；
/// 目标在固定位置 /Applications，无 App translocation 风险）。返回 nil = 启动成功。
func launchViaOpen(at path: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    process.arguments = ["-n", path]
    do {
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus == 0 {
            return nil
        }
        return "open -n 启动失败（target=\(path)），退出码 \(process.terminationStatus)"
    } catch {
        return "open 无法启动（target=\(path)）: \(error)"
    }
}

#if COFFER_UPDATER_PRODUCTION
/// 生产启动：真实 /usr/bin/open -n。生产二进制不含测试 seam（env 读被编译掉）。
private func performLaunch(at path: String) -> String? {
    return launchViaOpen(at: path)
}
#else
/// 测试 seam（仅测试构建）：设 COFFER_UPDATER_TEST_FAKE_RELAUNCH=<记录文件> 时，
/// 把「已通过 gate 的 relaunch」追加记录到文件并假装成功（不真 open -n）——供断言
/// 「gate 拦截后未发生任何 relaunch」。生产（-D）编译掉该分支，绝不读该 env。
private func performLaunch(at path: String) -> String? {
    if let recordPath = ProcessInfo.processInfo.environment["COFFER_UPDATER_TEST_FAKE_RELAUNCH"],
       !recordPath.isEmpty {
        let line = (path + "\n").data(using: .utf8) ?? Data()
        let url = URL(fileURLWithPath: recordPath)
        if let fh = FileHandle(forWritingAtPath: recordPath) {
            fh.seekToEndOfFile()
            fh.write(line)
            try? fh.close()
        } else {
            try? line.write(to: url)
        }
        return nil
    }
    return launchViaOpen(at: path)
}
#endif

/// 单点 relaunch 门（C-2 收敛终点，最终不变式）：任何被 relaunch 的包必须「刚刚
/// 通过 DR」。先对 path 静态验签，通过才启动；未过 DR → 不启动（返回 .signature，
/// 调用方 exit 2，不 relaunch）。主流程 step6 与所有回滚路径的 relaunch 都经此单缝，
/// 不补特例分支——被启动的无条件 = 过 DR 的官方包。
func relaunchApp(at path: String) -> RelaunchFailure? {
    if let error = verifyNewPackageSignature(at: path) {
        return .signature(error)
    }
    if let error = performLaunch(at: path) {
        return .launch(error)
    }
    return nil
}

// MARK: - 回滚与旧 App relaunch

/// 尽力恢复旧 App 并 relaunch（备份失败/替换失败/relaunch 失败兜底；best-effort，
/// 不改变退出码）。备份存在且（目标缺失 或 forceRestore）→ 从备份复制回目标（备份保留）；
/// forceRestore 用于 relaunch 失败时——此时目标里已是替换上去的新包，须用旧包覆盖回去。
/// 再 relaunch 目标（或备份）。
func rollbackAndRelaunchOldApp(config: InstallConfig, forceRestore: Bool = false) {
    let fm = FileManager.default
    let currentExists = fm.fileExists(atPath: config.currentAppPath)
    if fm.fileExists(atPath: config.backupPath), (forceRestore || !currentExists) {
        do {
            if currentExists {
                try fm.removeItem(atPath: config.currentAppPath)
            }
            try fm.copyItem(atPath: config.backupPath, toPath: config.currentAppPath)
            log("已从备份恢复旧 App 到目标位置（备份保留）。")
        } catch {
            log("从备份恢复旧 App 失败（best-effort）: \(error)")
        }
    }
    let launchPath: String?
    if fm.fileExists(atPath: config.currentAppPath) {
        launchPath = config.currentAppPath
    } else if fm.fileExists(atPath: config.backupPath) {
        launchPath = config.backupPath
    } else {
        launchPath = nil
    }
    guard let path = launchPath else {
        log("无旧 App 可 relaunch（目标与备份均不存在）。")
        return
    }
    switch relaunchApp(at: path) {
    case nil:
        log("已 relaunch 旧 App: \(path)")
    case .some(.launch(let error)):
        log("relaunch 旧 App 失败（best-effort）: \(error)")
    case .some(.signature(let error)):
        log("拒绝 relaunch 未验内容（best-effort，C-2 gate 拦截）: \(error)")
    }
}

// MARK: - result 文件

/// 操作结果（App 首启读取；JSON：success/code/message）。
struct InstallResult: Encodable {
    let success: Bool
    let code: Int32
    let message: String
}

/// 写 result 文件（best-effort：失败只记 stderr，不改变退出码）。父目录兜底创建。
func writeResultFile(at path: String, success: Bool, code: Int32, message: String) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard let data = try? encoder.encode(InstallResult(success: success, code: code, message: message)) else {
        log("result 文件编码失败: \(path)")
        return
    }
    let url = URL(fileURLWithPath: path)
    do {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    } catch {
        log("result 文件写入失败（\(path)）: \(error)")
    }
}

/// 写 result 并返回对应退出码（所有已读配置成功的路径统一经此退出）。
func finish(_ config: InstallConfig, success: Bool, code: Int32, message: String) -> Int32 {
    writeResultFile(at: config.resultFilePath, success: success, code: code, message: message)
    return code
}

// MARK: - 载荷校验（C-1 静态验签 + H-1 profile 过期，fail-closed）

/// 从 provisioning profile 读取 ExpirationDate（/usr/bin/security cms -D 解码 CMS 内容）。
/// 返回 nil = 文件缺失 / 解码失败 / 无法解析（全部视为不可用，fail-closed）。
/// profile 为 CMS 签名 plist（DER），不能直接 plutil 解析，须先经 security cms 解码。
func profileExpirationDate(from profilePath: String) -> Date? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    process.arguments = ["cms", "-D", "-i", profilePath]
    let pipe = Pipe()
    process.standardOutput = pipe
    do {
        try process.run()
    } catch {
        return nil
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            as? [String: Any],
          let date = plist["ExpirationDate"] as? Date else {
        return nil
    }
    return date
}

/// 对磁盘上的新包做静态验签（SecStaticCodeCreateWithPath + SecStaticCodeCheckValidity），
/// 验签要求见 updatePackageRequirement。返回 nil = 通过，否则为错误描述。
func verifyNewPackageSignature(at appPath: String) -> String? {
    let url = URL(fileURLWithPath: appPath)
    var staticCode: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(rawValue: 0), &staticCode)
    guard createStatus == errSecSuccess, let code = staticCode else {
        return "载荷验签失败：无法创建静态代码引用（OSStatus=\(createStatus)）"
    }
    var requirement: SecRequirement?
    let reqStatus = SecRequirementCreateWithString(updatePackageRequirement as CFString,
                                                   SecCSFlags(rawValue: 0), &requirement)
    guard reqStatus == errSecSuccess, let req = requirement else {
        return "载荷验签失败：DR 构造失败（OSStatus=\(reqStatus)）"
    }
    let checkStatus = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: 0), req)
    guard checkStatus == errSecSuccess else {
        return "载荷验签失败：签名不满足 DR（OSStatus=\(checkStatus)）"
    }
    return nil
}

/// 载荷校验（fail-closed，未做任何修改）：文件名必须为 Coffer.app；静态验签须通过 DR；
/// embedded.provisionprofile 必须存在且未过期。失败 → exit 2（与「新包缺失」同族）。
func verifyPayload(config: InstallConfig) -> Int32? {
    let newName = (config.newAppPath as NSString).lastPathComponent
    guard newName == "Coffer.app" else {
        log("新包文件名必须为 Coffer.app，实际: \(newName)")
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包不可用（文件名不符），未做任何修改。")
    }
    if let error = verifyNewPackageSignature(at: config.newAppPath) {
        log(error)
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包签名校验未通过，未做任何修改。")
    }
    let profilePath = "\(config.newAppPath)/Contents/embedded.provisionprofile"
    guard let expiry = profileExpirationDate(from: profilePath) else {
        log("新包 provisioning profile 缺失或无法读取: \(profilePath)")
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包 profile 缺失或无效，未做任何修改。")
    }
    guard expiry > Date() else {
        log("新包 provisioning profile 已过期（expiry=\(expiry)）: \(profilePath)")
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包 profile 已过期，未做任何修改。")
    }
    return nil
}

/// TOCTOU 闭环（C-1 复审）：替换成功后、relaunch 前，对**已安装目标**再跑一次静态验签
/// （同一 DR 函数，可对任意路径调用）。攻击者可在等待窗内把 newAppPath 换成恶意 bundle，
/// 但替换完成后被 relaunch 的只能是过 DR 的官方包。失败 → exit 2 + 恢复备份（forceRestore，
/// 目标里已是换过的包，须用旧包覆盖回去）。恢复后的 relaunch 经 relaunchApp 的 C-2 gate
/// 再兜底——恢复源即使被攻击者翻转（symlink 残余竞速），被启动的仍只能是刚过 DR 的包。
func verifyInstalledResult(config: InstallConfig) -> Int32? {
    if let error = verifyNewPackageSignature(at: config.currentAppPath) {
        log(error)
        rollbackAndRelaunchOldApp(config: config, forceRestore: true)
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包校验未通过，已恢复原版本。")
    }
    return nil
}

// MARK: - 主流程

/// 前置校验路径存在；失败返回退出码（1/2，result 已写、已尽力恢复旧 App）。
/// 失败快——此时尚未做任何修改。
func precheckPaths(config: InstallConfig) -> Int32? {
    guard FileManager.default.fileExists(atPath: config.currentAppPath) else {
        log("当前 App 路径不存在: \(config.currentAppPath)")
        rollbackAndRelaunchOldApp(config: config)
        return finish(config, success: false, code: ExitCode.backupFailed, message: "更新安装失败：未找到当前应用。")
    }
    guard FileManager.default.fileExists(atPath: config.newAppPath) else {
        log("新包路径不存在: \(config.newAppPath)")
        rollbackAndRelaunchOldApp(config: config)
        return finish(config, success: false, code: ExitCode.replaceFailed, message: "更新安装失败：更新包不可用，已尝试恢复原版本。")
    }
    return nil
}

/// 备份 + 替换。成功返回 nil；失败返回退出码（1/2，result 已写、已尽力恢复旧 App）。
func backupAndReplace(config: InstallConfig) -> Int32? {
    if let error = backupCurrentApp(from: config.currentAppPath, to: config.backupPath) {
        log(error)
        rollbackAndRelaunchOldApp(config: config)
        return finish(config, success: false, code: ExitCode.backupFailed, message: "更新安装失败：备份失败。")
    }
    log("备份完成: \(config.backupPath)")
    if let error = replaceCurrentApp(newPackage: config.newAppPath, target: config.currentAppPath) {
        log(error)
        rollbackAndRelaunchOldApp(config: config)
        return finish(config, success: false, code: ExitCode.replaceFailed, message: "更新安装失败：替换失败，已尝试恢复原版本。")
    }
    log("替换完成: \(config.currentAppPath)")
    // BUG-30 顺手修（Spotlight）：替换成功后解压目录已空（新包被 move 走），
    // best-effort 移除——容器 tmp 残留的 coffer-ota-* 含 .app 目录会被 Spotlight
    // 索引成独立 Coffer.app（用户困扰）。只在目录为空时移除，绝不递归删有内容的目录。
    cleanupExtractionDir(of: config.newAppPath)
    return nil
}

/// BUG-30 顺手修：替换成功后 best-effort 移除已清空的解压目录（newAppPath 父目录）。
/// 安全边界：仅当目录存在且内容为空才删——新包 move 走后必空；目录还有内容（替换失败
/// 回滚残留 / 测试夹具其它文件）一律不动，绝不误删。删除失败静默（best-effort 纪律）。
func cleanupExtractionDir(of newPackagePath: String) {
    let parent = URL(fileURLWithPath: newPackagePath).deletingLastPathComponent().path
    let fm = FileManager.default
    guard fm.fileExists(atPath: parent),
          (try? fm.contentsOfDirectory(atPath: parent))?.isEmpty == true else { return }
    try? fm.removeItem(atPath: parent)
}

/// 主流程，返回契约退出码（docs/35 §6.4）。
func run(arguments: [String]) -> Int32 {
    // 0. 入口第一行：argv 原文落盘（在 arg parse 之前！）。现场「helper 没被
    //    拉起」vs「被拉起但 args 丢失 exit 4」据此一锤定音（BUG-29 后续——此前
    //    现有证据无法区分）。此后各阶段 log 一行一条，/tmp/coffer-update.log 是
    //    OTA 现场第一诊断入口。
    log("coffer-update 启动 pid=\(getpid()) argv=\(arguments.map { "\"\($0)\"" }.joined(separator: " "))")

    // 1. 三层冗余取参（BUG-30：env → 固定路径 → argv；resolveConfigPath 内 log
    //    记录命中来源；三源皆无 → exit 4）
    guard let configPath = resolveConfigPath(arguments: arguments) else {
        log(usageText)
        return ExitCode.usageError
    }

    // 2. 读配置（校验失败 → exit 4；此时 resultFilePath 未知，无法写 result）
    let config: InstallConfig
    switch loadConfig(from: configPath) {
    case .success(let loaded):
        config = loaded
        // BUG-30 顺手修：固定名 pending config 是 App 一次性临时产物，helper 一旦
        // 消费即无留存价值——best-effort 删掉（防下下场误读/容器 tmp 积陈；App 侧
        // 下次写前也会先删旧，双保险）。删除失败静默，不影响安装主流程。
        if configPath == fixedConfigPath() {
            try? FileManager.default.removeItem(atPath: configPath)
        }
    case .failure(let error):
        if case .message(let message) = error {
            log("配置加载失败（\(configPath)）: \(message)")
        }
        return ExitCode.usageError
    }
    log("coffer-update: 开始安装 new=\(config.newAppPath) current=\(config.currentAppPath) backup=\(config.backupPath) pid=\(config.pid)")

    // 3. 前置校验路径存在（失败快）
    if let code = precheckPaths(config: config) {
        return code
    }

    // 3.5 载荷校验：文件名 + 静态验签 + profile 过期（C-1/H-1，未做任何修改；
    //     放在等待之前，载荷不可用立即拒装，不空等 30s）
    if let code = verifyPayload(config: config) {
        return code
    }

    // 4. 等待 App 进程退出（超时 → exit 3，未做任何修改）
    guard waitForProcessExit(pid: config.pid) else {
        log("等待 App 进程（pid=\(config.pid)）退出超时（\(Int(waitTimeout))s），未做任何修改，放弃安装。")
        return finish(config, success: false, code: ExitCode.relaunchFailed, message: "等待应用退出超时，更新未执行。")
    }
    log("App 进程（pid=\(config.pid)）已退出。")

    // 5. 备份 → 替换
    if let code = backupAndReplace(config: config) {
        return code
    }

    // 5.5 TOCTOU 闭环（C-1 复审）：替换成功后、relaunch 前，对已安装目标再验签。
    //     等待窗内 newAppPath 可能被换包（pid 攻击者可控），此步兜底——只有过 DR 的
    //     官方包会被 relaunch；失败 → exit 2 + 恢复备份。
    if let code = verifyInstalledResult(config: config) {
        return code
    }

    // 6. relaunch 新 App（C-2 单点 gate 内含：先验签后启动）。open 失败 → exit 3，
    //    尽力恢复备份 + relaunch 旧 App（M-1）；已安装目标未过 DR → 不 relaunch、
    //    不恢复（恢复源 backup 同不可信，恢复后仍会被 gate 拦），直接 exit 2。
    switch relaunchApp(at: config.currentAppPath) {
    case nil:
        log("relaunch 完成。")
    case .some(.launch(let error)):
        log(error)
        rollbackAndRelaunchOldApp(config: config, forceRestore: true)
        return finish(config, success: false, code: ExitCode.relaunchFailed,
                      message: "更新安装失败：启动新版本失败，已尝试恢复原版本。")
    case .some(.signature(let error)):
        log(error)
        return finish(config, success: false, code: ExitCode.replaceFailed,
                      message: "更新安装失败：更新包校验未通过，未启动。")
    }

    // 7. 写 result → exit 0
    return finish(config, success: true, code: ExitCode.success, message: "更新完成。")
}

// 入口（main.swift 顶层代码，swiftc 直编，无需 -parse-as-library）
let exitCode = run(arguments: Array(CommandLine.arguments.dropFirst()))
log("coffer-update 退出 exit=\(exitCode)")
exit(exitCode)
