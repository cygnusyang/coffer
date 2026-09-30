// McpStatusProbe.swift —— MCP 前置环境探测（docs/20 §6.1 状态行数据源）。
//
// 全部探测为本地快路径（PATH 扫描 + 环境变量读取），无进程 spawn、无网络、
// 无 socket——与「主 App 不宿主 MCP 服务器、App 运行时 0 socket」判据一致
// （docs/20 §6.2）。op 的慢调用（`op vault list` 等真进程交互）不在本文件，
// 属 op 集成组（docs/20 §9 G-C）后续经 cf-ffi 只读接口或进程调用接入。
//
// 诚实边界（docs/20 §3.6/§4.3）：env 级会话信号不代表 op 内部实际登录态，
// 实际会话以 `op signin` 为准；二进制存在 ≠ 可正确执行，此处仅做就绪度
// 展示信号，最终以独立 coffer 进程实际行为为准。

import Foundation

/// MCP 前置环境探测（状态行输入源，供 McpStatus.resolve 使用）。
enum McpStatusProbe {
    /// op 二进制路径：`COFFER_OP_BIN` 优先，否则 PATH 查找（docs/20 §4.2）。
    static func opBinaryPath() -> String? {
        if let custom = ProcessInfo.processInfo.environment["COFFER_OP_BIN"],
           !custom.isEmpty, FileManager.default.isExecutableFile(atPath: custom) {
            return custom
        }
        return findInPath("op")
    }

    /// coffer 命令路径：PATH 查找（docs/20 §6.2 分发方式：随 App 分发并入 PATH）。
    static func cofferBinaryPath() -> String? {
        findInPath("coffer")
    }

    /// op 二进制可用。
    static func isOpBinaryAvailable() -> Bool { opBinaryPath() != nil }

    /// coffer 命令可用。
    static func isCofferBinaryAvailable() -> Bool { cofferBinaryPath() != nil }

    /// 1Password 会话 env 信号（docs/20 §4.2/§4.3）：
    /// `COFFER_OP_SESSION_TOKEN`（Coffer 侧定义，透传 `OP_SESSION`）或
    /// `OP_SESSION`（op 自身集成会话变量）任一存在即视为有会话信号。
    ///
    /// 诚实边界：仅 App 环境变量级信号；1Password 集成会话由用户在终端
    /// `op signin` 建立，App 内此信号通常为空——状态行据此引导，不误报就绪。
    static func isOpSessionAvailable() -> Bool {
        let env = ProcessInfo.processInfo.environment
        let cofferToken = env["COFFER_OP_SESSION_TOKEN"] ?? ""
        let opSession = env["OP_SESSION"] ?? ""
        return !cofferToken.isEmpty || !opSession.isEmpty
    }

    /// 在 PATH 中查找可执行文件（纯本地，无 spawn）。
    private static func findInPath(_ name: String) -> String? {
        guard let path = ProcessInfo.processInfo.environment["PATH"] else { return nil }
        for dir in path.split(separator: ":") {
            let candidate = URL(fileURLWithPath: String(dir)).appendingPathComponent(name).path
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }
}
