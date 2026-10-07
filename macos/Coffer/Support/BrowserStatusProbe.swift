// BrowserStatusProbe.swift —— 浏览器集成前置环境探测（docs/31 §6.2 / §9.1 G-D）。
//
// 镜像 McpStatusProbe：全部探测为本地快路径（路径存在性 / kill(0) 存活探测），
// 无网络、无 FFI、不 spawn 常驻进程。broker 运行态 = App 持有的 Process 的
// 存活探测（kill(pid, 0)，零信号副作用），与「主 App 不宿主服务器」判据不冲突
// ——broker 是独立进程（docs/31 §2.1），App 仅管理其生命周期。
//
// 诚实边界（docs/31 §6.2）：manifest 存在 ≠ 浏览器可消费（签名 / 冻结 ID 对齐
// 以扩展实际连接行为为准）；此处仅做就绪度展示信号，最终以扩展首连行为为准。

import Darwin
import Foundation

/// native messaging manifest 落盘路径构造（纯函数，无 IO，可独立单测）。
/// 根目录（~ 展开后）+ BrowserKind.nativeMessagingHostsRelativePath +
/// 固定文件名（host_name，docs/31 §6.2）。
enum BrowserManifestPaths {
    /// manifest 文件名（= host_name，docs/31 §6.2）。
    static let manifestFileName = "com.coffer.browser.json"

    /// `~/Library/Application Support` 根目录（纯字符串拼接，不 touch 文件系统；
    /// homeDirectory 注入便于单测临时根目录）。
    static func nativeMessagingHostsRoot(homeDirectory: String) -> String {
        (homeDirectory as NSString).appendingPathComponent("Library/Application Support")
    }

    /// 指定浏览器的 manifest 绝对路径（纯函数）。
    static func manifestPath(browser: BrowserKind, homeDirectory: String) -> String {
        var path = nativeMessagingHostsRoot(homeDirectory: homeDirectory) as NSString
        path = path.appendingPathComponent(browser.nativeMessagingHostsRelativePath) as NSString
        return path.appendingPathComponent(manifestFileName)
    }
}

/// 浏览器集成前置探测（状态行输入源，供 BrowserStatus.resolve 使用）。
enum BrowserStatusProbe {
    /// coffer 二进制路径：复用 McpStatusProbe（App 包内嵌套 bundle 优先、PATH
    /// 兜底——broker/host 复用同一二进制，D-2，docs/31 §6.2）。
    static func cofferBinaryPath() -> String? { McpStatusProbe.cofferBinaryPath() }

    /// coffer 命令可用。
    static func isCofferBinaryAvailable() -> Bool { cofferBinaryPath() != nil }

    /// 用户主目录（manifest 写入目标根「~」的真实解析）。
    ///
    /// 沙盒边界（诚实声明）：App Sandbox（Coffer.entitlements app-sandbox=true）
    /// 下 `NSHomeDirectory()` 返回容器路径（写容器内对浏览器无效）；`getpwuid`
    /// 经系统口令库解析**真实用户主目录**（沙盒内可读）。但写入浏览器
    /// NativeMessagingHosts 目录（容器外绝对路径）仍需 sandbox exception
    /// entitlement——该 entitlement 决策属 G-E/lead（tools/build_macos_app.sh
    /// 装配），本探测只负责「指向正确位置」，写入是否被许可由写路径显式上抛。
    static func userHomeDirectory() -> String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return String(cString: dir)
        }
        return NSHomeDirectory()
    }

    /// manifest 是否已落盘（存在性探测，无内容读取）。
    static func manifestExists(browser: BrowserKind, homeDirectory: String) -> Bool {
        FileManager.default.fileExists(
            atPath: BrowserManifestPaths.manifestPath(browser: browser, homeDirectory: homeDirectory))
    }

    /// 全部目标浏览器 manifest 是否已落盘（resolve 的 manifestsInstalled 信号）。
    static func allManifestsInstalled(homeDirectory: String) -> Bool {
        BrowserKind.allCases.allSatisfy {
            manifestExists(browser: $0, homeDirectory: homeDirectory)
        }
    }

    /// broker 进程存活探测（kill(pid, 0)：0 成功 = 进程存在；ESRCH = 不存在）。
    /// 纯探测：不产生新进程、不发送实际信号。
    static func brokerProcessRunning(pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0
    }
}
