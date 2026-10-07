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

    /// coffer 命令路径。**App 包内嵌套 bundle 路径优先**（docs/20 §5.4 / docs/29 §8
    /// D-6：`Contents/Helpers/coffer.app/Contents/MacOS/coffer`——CLI 随 App 分发、
    /// **不入 PATH**；拷出 App 路径运行会因 AMFI 找不到 provisioning profile 被
    /// SIGKILL(137)，G5 真机实证）。PATH 仅作**开发环境兜底**（dev/CI 未装配 App
    /// bundle 时的 fallback，如非 App 进程的测试/脚本）。
    ///
    /// 诚实边界（docs/20 §3.6/§4.3）：二进制存在 ≠ 可正确执行——签名 / profile
    /// 覆盖以实际进程行为为准，此处仅做就绪度展示信号。
    static func cofferBinaryPath() -> String? {
        // ① App 包内嵌套 bundle（生产分发路径，D-6）
        let bundled = bundledCofferBinaryPath()
        if FileManager.default.isExecutableFile(atPath: bundled) {
            return bundled
        }
        // ② PATH 兜底（开发环境 fallback）
        return findInPath("coffer")
    }

    /// App 包内嵌套 bundle 的 coffer 二进制路径（`Bundle.main.bundleURL` 非可选，
    /// 恒有值——App 内即 Coffer.app 根路径）：
    /// `Contents/Helpers/coffer.app/Contents/MacOS/coffer`（docs/20 §5.4 /
    /// docs/29 §8 D-6；装配见 tools/build_macos_app.sh step 3.5，G5）。
    static func bundledCofferBinaryPath() -> String {
        Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/coffer.app/Contents/MacOS/coffer")
            .path
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
