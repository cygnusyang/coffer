// DropzoneDirectoryWatcher.swift —— 放置区目录监视（docs/21a-v2.11.0-放置区导入-实现方案.md
// §2.2 裁定 A：DispatchSource.vnode + 补扫；接口见 §3.3）。
//
// 机制：一目录一 O_EVTONLY fd + DispatchSourceFileSystemObject（.write/.delete/.rename）。
// vnode 事件可能合并/丢失 → 由「补扫」（rescan）确定性兜底；补扫时机（调用方触发）=
// ①监视启动 ②App 回前台（applicationDidBecomeActive）③解锁恢复。不做后台常驻监视
// （裁定⑤，短生命周期单目录）。
//
// 生命周期与 fail-closed 结构绑定：向导 sheet 挂 MainView（仅 .unlocked 渲染）→
// 锁定相变即拆树、sheet 随拆、监视自动停（结构性 fail-closed，W-2）；向导内
// onDisappear / onChange(phase) 防御性调 stop()。fd 严谨关闭：stop() 经 cancel
// 处理器 close，deinit 兜底 stop（防泄漏）。
//
// 沙盒作用域：本类在 start 时自行持有授权目录的安全作用域（startAccessing），
// stop()/deinit 配对释放（refcount 配对，嵌套 withAccess 亦平衡）；startAccessing
// 失败即授权失效，抛错交由调用方转 .stale（D-18.3 失效不静默）。

import Foundation

/// 监视错误（面向调用方可操作）。
enum DropzoneWatchError: Error, LocalizedError {
    /// 无法进入授权目录的安全作用域（授权失效）。
    case scopeDenied(URL)
    /// 无法打开目录（O_EVTONLY open 失败）。
    case cannotOpen(URL, errno: Int32)

    var errorDescription: String? {
        switch self {
        case let .scopeDenied(url):
            return "无法访问放置区目录（\(url.lastPathComponent)），授权可能已失效。"
        case let .cannotOpen(url, err):
            return "无法监视放置区目录（\(url.lastPathComponent)，errno \(err)）。"
        }
    }
}

/// 放置区目录监视器：vnode 事件 + 补扫（docs/21a §2.2 / §3.3）。
final class DropzoneDirectoryWatcher {
    /// 事件串行队列：回调在此队列触发；start/stop/rescan 期望主队列调用。
    private let eventQueue = DispatchQueue(label: "com.coffer.dropzone.watcher")

    private var source: DispatchSourceFileSystemObject?
    private var watchedDirectory: URL?
    /// start 时取得的作用域持有标记（stop/deinit 配对释放）。
    private var scopeActive = false

    deinit {
        stop()
    }

    /// 开始监视 url（幂等：先释放上一轮资源再启动）。onEvent 在内部串行队列触发，
    /// 调用方收到后应执行 rescan() + 指纹过滤 → W-3 判多/判已导入过。
    func start(watching url: URL, onEvent: @escaping () -> Void) throws {
        stop()

        // 沙盒内访问授权目录须持有安全作用域；startAccessing 失败 = 授权失效。
        let scoped = url.startAccessingSecurityScopedResource()
        guard scoped else {
            throw DropzoneWatchError.scopeDenied(url)
        }

        let fd = open(url.path, O_EVTONLY)
        guard fd >= 0 else {
            url.stopAccessingSecurityScopedResource()
            throw DropzoneWatchError.cannotOpen(url, errno: errno)
        }

        let eventSource = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename],
            queue: eventQueue
        )
        eventSource.setEventHandler {
            onEvent()
        }
        eventSource.setCancelHandler {
            close(fd)
        }

        watchedDirectory = url
        scopeActive = true
        source = eventSource
        eventSource.resume()
    }

    /// 停止监视（幂等）。cancel 处理器负责 close(fd)；作用域配对释放；deinit 兜底。
    func stop() {
        guard let active = source else { return }
        source = nil
        active.setEventHandler {}
        active.cancel()
        if scopeActive, let url = watchedDirectory {
            url.stopAccessingSecurityScopedResource()
        }
        scopeActive = false
        watchedDirectory = nil
    }

    /// 补扫：列出被监视目录内的 CSV 候选（docs/21a §3.3）。目录枚举失败
    /// （权限/失效）返回空数组；失效的权威判定由调用方经
    /// DropzoneBookmarkStore.validate 统一转 .stale（D-18.3 不静默）。
    func rescan() -> [URL] {
        guard let directory = watchedDirectory else { return [] }
        let contents: [URL]
        do {
            contents = try FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
        } catch {
            return []
        }
        return contents.filter { url in
            guard url.pathExtension.caseInsensitiveCompare("csv") == .orderedSame else { return false }
            // 排除同后缀目录（如 foo.csv/ 目录）；resourceValues 失败时放行，交由
            // 下游 CSV 解析 fail-closed 兜底。
            let isRegular = (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile
            return isRegular ?? true
        }
    }
}
