// DirectoryWatching.swift —— 目录监视窄协议（docs/19 §3.2 契约 stub 先例）。
//
// L1 可测化依赖隔离：DropzoneImportModel 只依赖本协议（start/stop/rescan），
// 不直接依赖 DropzoneDirectoryWatcher 具体类——测试注入 FakeWatcher（记录
// start/stop 次数 + 受控 rescan 返回），生产由 DropzoneDirectoryWatcher 在
// 下方 extension conform（该类零改动）。
//
// 通用模式（docs/19 §3.4 ③）：服务类一律注入式（init 注入），协议供测试替身
// 替换；`shared` 仅生产装配点。

import Foundation

/// 目录监视窄面（DropzoneDirectoryWatcher conforms；测试注入 FakeWatcher
/// 记录 start/stop + 受控 rescan）。
protocol DirectoryWatching: AnyObject {
    /// 开始监视 url；onEvent 在后台队列触发（调用方须自行跳主队列处理）。
    func start(watching url: URL, onEvent: @escaping () -> Void) throws
    /// 停止监视（幂等）。
    func stop()
    /// 补扫被监视目录内的候选 URL 列表（目录枚举失败返回空数组）。
    func rescan() -> [URL]
}

// MARK: - 生产 conform（DropzoneDirectoryWatcher.swift 零改动）

extension DropzoneDirectoryWatcher: DirectoryWatching {}
