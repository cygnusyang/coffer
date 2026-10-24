// UpdateChecksum.swift —— 更新产物 SHA256 完整性校验（docs/35 §6.1 sha256 字段落地，
// v2.10.3 T1，docs/01 下载完整性加固）。
//
// 在 UpdaterManager.download() 的下载落盘之后、ditto 解压之前调用：对 zip 文件
// 字节流式算 SHA256（CryptoKit，分块读取，不整包载入内存），与清单声明的 sha256
// 比对——不匹配即拒装（fail-closed）。缺省/空串的跳过逻辑在调用方（UpdaterManager），
// 本模块只负责「文件 → hex」与「不匹配」错误。

import Foundation
import CryptoKit

/// 下载包 SHA256 校验的显式错误（走既有更新错误通道，用户可见文案 fail-closed）。
enum UpdateChecksumError: Error, LocalizedError {
    /// 计算失败（下载文件不可读 / 读取中断）。
    case readFailed(String)
    /// 与清单声明不一致（fail-closed 拒装，文案冻结见 UpdaterManager 契约）。
    case mismatch

    var errorDescription: String? {
        switch self {
        case .readFailed(let detail):
            return String(localized: "下载包完整性校验失败：无法读取下载文件（\(detail)）。")
        case .mismatch:
            return String(localized: "下载包完整性校验失败（SHA256 不匹配），已拒绝安装。")
        }
    }
}

/// 更新产物 SHA256 工具。
enum UpdateChecksum {
    /// 流式计算文件 SHA256 hex（64KB 块读取，内存占用恒定；FileHandle 字节级遍历）。
    static func sha256Hex(of url: URL) throws -> String {
        var hasher = SHA256()
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw UpdateChecksumError.readFailed("\(error)")
        }
        defer { try? handle.close() }
        while true {
            let chunk: Data?
            do {
                chunk = try handle.read(upToCount: 64 * 1024)
            } catch {
                throw UpdateChecksumError.readFailed("\(error)")
            }
            guard let chunk, !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
