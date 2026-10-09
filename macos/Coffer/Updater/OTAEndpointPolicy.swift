// OTAEndpointPolicy.swift —— 更新期零网络豁免的应用层白名单（docs/35 §6.2，契约冻结）。
//
// 三道锁的应用层：URLSession 只能连白名单 host 且强制 HTTPS。纯函数，供
// OTANetworkSession（请求前校验 + challenge 兜底）与 UpdaterManager.check
// （downloadUrl 纵深校验）共用；`check_ota_whitelist.sh`（组 C）以本文件为
// host 唯一事实源防漂移。

import Foundation

/// 更新端点白名单策略（应用层，4 host 硬编码，契约 6.2）。
enum OTAEndpointPolicy {
    /// 白名单端点（docs/35 §6.2：发布查询 / 下载重定向源 / Release asset CDN）。
    static let allowedHosts: Set<String> = [
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ]

    /// 显式错误（fail-closed：非白名单一律拒绝，不静默降级）。
    enum PolicyError: Error, LocalizedError {
        /// 非 https（强制 HTTPS，契约 6.2）。
        case insecureScheme(String)
        /// host 不在白名单（nil = 无 host 的 URL）。
        case hostNotAllowed(String?)

        var errorDescription: String? {
            switch self {
            case .insecureScheme(let scheme):
                return "更新请求必须使用 HTTPS（当前 scheme 为 \(scheme)）。"
            case .hostNotAllowed(let host):
                return "更新端点 \(host ?? "（无 host）") 不在白名单内，已拒绝连接。"
            }
        }
    }

    /// host 是否在白名单（纯函数）。host 大小写不敏感（DNS/URL 语义），
    /// 统一小写比较——对齐 UpdateCopy 侧的 `host?.lowercased()`（dev-reviewer
    /// LOW：两侧口径一致，消除「UI 显示可信 / check 报 host not allowed」困惑；
    /// 两侧均 fail-closed，无安全绕过）。
    static func isAllowedHost(_ host: String) -> Bool {
        allowedHosts.contains(host.lowercased())
    }

    /// URL 是否放行：强制 https + host ∈ 白名单（纯函数）。
    static func isAllowedURL(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https", let host = url.host else {
            return false
        }
        return isAllowedHost(host)
    }

    /// 校验并抛错（fail-closed）；不通过即拒绝发起连接。
    static func validate(_ url: URL) throws {
        guard url.scheme?.lowercased() == "https" else {
            throw PolicyError.insecureScheme(url.scheme ?? "（无 scheme）")
        }
        guard let host = url.host, isAllowedHost(host) else {
            throw PolicyError.hostNotAllowed(url.host)
        }
    }
}
