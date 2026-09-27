// DiagLog.swift —— 共享诊断日志（Touch ID 排障专用，2026-09-27）。
//
// 写入位置：沙盒 App 内为容器路径
//   ~/Library/Containers/app.coffer.Coffer/Data/Library/Logs/Coffer-diag.log
// （App 内 FileManager 的 ~/Library 自动重定向；CLI 测试二进制无沙盒时
//   落在真实 ~/Library/Logs —— 两处都查）
//
// 纪律：只写错误原文与状态码（Rust 层已脱敏、无字段值），绝无密钥材料。

import Foundation

enum DiagLog {
    /// 追加一行（自动带时间戳）。任何失败都静默降级——诊断日志绝不引起新错误。
    static func append(_ text: String) {
        let line = "\(Date()) \(text)\n"
        let dir = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Logs")
        let url = dir.appendingPathComponent("Coffer-diag.log")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let handle = FileHandle(forWritingAtPath: url.path) {
            handle.seekToEndOfFile()
            handle.write(line.data(using: .utf8)!)
            try? handle.close()
        } else {
            try? line.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
