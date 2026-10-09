// OTANetworkLayer.swift —— OTA 网络层（docs/35 §6.2 应用层白名单落地）。
//
// 协议抽象 = 注入点（UpdateTests 用 stub 数据无真网测试）；生产实现 =
// OTANetworkSession（URLSession + 请求前 URL 校验 + challenge/重定向兜底，
// 全程只在白名单 host 上强制 HTTPS）。网络代码全部在 Swift 侧（check_no_network.sh
// 的 cargo 黑名单不受影响）。

import Foundation

// MARK: - 注入点协议

/// 清单拉取（协议，便于测试注入 stub）。
protocol ManifestFetching {
    func fetchManifest(from url: URL) async throws -> Data
}

/// 产物下载（协议，便于测试注入 stub）。
protocol DataDownloading {
    /// 下载到本地文件，`progress` 回调 0...1 进度（主队列调用）。
    func download(from url: URL, progress: @escaping (Double) -> Void) async throws -> URL
}

// MARK: - 显式错误

/// HTTP 非 2xx 响应。
struct OTAHTTPError: Error, LocalizedError {
    let statusCode: Int
    var errorDescription: String? { "更新服务器返回 HTTP \(statusCode)。" }
}

/// 下载产物落盘失败（临时文件移动失败）。
struct OTADownloadMoveError: Error, LocalizedError {
    let detail: String
    var errorDescription: String? { "下载产物保存失败：\(detail)" }
}

// MARK: - 生产网络层

/// URLSession 实现：请求前 `OTAEndpointPolicy.validate`（https + host 白名单），
/// 每个操作独立 session（OTA 低频手动触发，隔离状态最简）。
final class OTANetworkSession: ManifestFetching, DataDownloading {
    private let configuration: URLSessionConfiguration

    init(configuration: URLSessionConfiguration = .default) {
        // URLSessionConfiguration 是引用类型：拷贝一份再设超时，避免原地改
        // 调用方/默认共享实例；拷贝失败（理论不可能）则退回原配置。
        if let config = configuration.copy() as? URLSessionConfiguration {
            config.timeoutIntervalForRequest = 30
            self.configuration = config
        } else {
            self.configuration = configuration
        }
    }

    func fetchManifest(from url: URL) async throws -> Data {
        try OTAEndpointPolicy.validate(url)
        let delegate = ManifestFetchTaskDelegate()
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: .main)
        defer { session.invalidateAndCancel() }
        let task = session.dataTask(with: url)
        return try await withCheckedThrowingContinuation { continuation in
            delegate.start(task: task, continuation: continuation)
        }
    }

    func download(from url: URL, progress: @escaping (Double) -> Void) async throws -> URL {
        try OTAEndpointPolicy.validate(url)
        let delegate = DownloadTaskDelegate(progress: progress)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: .main)
        defer { session.invalidateAndCancel() }
        let task = session.downloadTask(with: url)
        return try await withCheckedThrowingContinuation { continuation in
            delegate.start(task: task, continuation: continuation)
        }
    }
}

// MARK: - 白名单兜底（challenge + 重定向，URLSessionDelegate/TaskDelegate 共用）

/// 清单拉取的 session delegate：host 白名单 challenge 兜底 + 拒绝向非白名单
/// host 重定向 + 数据收集 + 一次性 continuation 恢复。
private final class ManifestFetchTaskDelegate: NSObject,
    URLSessionDelegate, URLSessionTaskDelegate, URLSessionDataDelegate
{
    private var continuation: CheckedContinuation<Data, Error>?
    private var collected = Data()

    func start(task: URLSessionDataTask, continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
        task.resume()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard OTAEndpointPolicy.isAllowedHost(challenge.protectionSpace.host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard let redirect = newRequest.url, OTAEndpointPolicy.isAllowedURL(redirect) else {
            completionHandler(nil) // 拒绝向非白名单 host 重定向
            return
        }
        completionHandler(newRequest)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        collected.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { continuation = nil }
        if let error {
            continuation?.resume(throwing: error)
        } else if let response = task.response as? HTTPURLResponse, !(200..<300).contains(response.statusCode) {
            continuation?.resume(throwing: OTAHTTPError(statusCode: response.statusCode))
        } else {
            continuation?.resume(returning: collected)
        }
    }
}

/// 产物下载的 session delegate：白名单兜底 + 进度 + 落盘 + 一次性 continuation 恢复。
private final class DownloadTaskDelegate: NSObject,
    URLSessionDelegate, URLSessionTaskDelegate, URLSessionDownloadDelegate
{
    private var continuation: CheckedContinuation<URL, Error>?
    private let progress: (Double) -> Void
    private var savedURL: URL?

    init(progress: @escaping (Double) -> Void) {
        self.progress = progress
        super.init()
    }

    func start(task: URLSessionDownloadTask, continuation: CheckedContinuation<URL, Error>) {
        self.continuation = continuation
        task.resume()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard OTAEndpointPolicy.isAllowedHost(challenge.protectionSpace.host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard let redirect = newRequest.url, OTAEndpointPolicy.isAllowedURL(redirect) else {
            completionHandler(nil)
            return
        }
        completionHandler(newRequest)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        guard totalBytesExpectedToWrite > 0 else { return }
        let p = min(1, max(0, Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)))
        progress(p)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        // 回调返回后 location 可能被系统删除 → 立即移到稳定临时位置。
        do {
            let fm = FileManager.default
            let dest = fm.temporaryDirectory
                .appendingPathComponent("coffer-download-\(UUID().uuidString).zip")
            try fm.moveItem(at: location, to: dest)
            savedURL = dest
        } catch {
            savedURL = nil
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { continuation = nil }
        if let error {
            continuation?.resume(throwing: error)
        } else if let url = savedURL {
            continuation?.resume(returning: url)
        } else {
            continuation?.resume(throwing: OTADownloadMoveError(detail: "临时文件移动失败"))
        }
    }
}
