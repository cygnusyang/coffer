// McpRegisterHelper/SpawnEnvironment.swift —— 目标 CLI 子进程环境构造**纯函数**
// （#1：脚本型 CLI 的 shebang 解释器不在 helper 的 PATH 里 → spawn 127）。
//
// 背景（#1 实证，2026-10-24）：helper 由沙盒 App 经 /usr/bin/open 拉起，继承的是
// **精简 PATH**（不含 node / python 等运行时目录）。原生 Mach-O CLI（如 claude）
// 用绝对路径 exec 即可，但 npm / pip 装的 CLI 首行是 `#!/usr/bin/env node`——内核
// 交给 /usr/bin/env，它在 PATH 里找不到 node 就 127：
// `env: node: No such file or directory`。CodeBuddy 正是此形态，导致 register /
// remove 全失败（check 只读 JSON、不 spawn CLI，故不受影响）。
//
// 分工：读 shebang 与解释器解析（resolveCLIPath）是 IO，留在 main.swift；
// 本文件只做「首行 → 解释器名」与「PATH 组装」两件纯计算，standalone 单测覆盖。

import Foundation

enum SpawnEnvironment {
    /// 系统默认 PATH 兜底（解释器解析落空时用；与 macOS 默认 PATH 同构，另加
    /// Homebrew 两个前缀——node / python 最常见落点）。
    static let systemDefaultDirectories = [
        "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]

    /// 读 CLI 首行 shebang，返回**需要经 PATH 查找**的解释器名。
    ///
    /// 只认 `#!/usr/bin/env <name>`（含 `env -S <name>` 变体）：
    ///   - `#!/opt/homebrew/bin/node` 这类绝对路径解释器由内核直接 exec，与 PATH
    ///     无关 → nil（不注入）；
    ///   - 无 shebang（Mach-O 原生）→ nil。
    static func envInterpreterName(fromShebangLine line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: CharacterSet(charactersIn: "\r\n"))
        guard trimmed.hasPrefix("#!") else { return nil }
        let tokens = trimmed.dropFirst(2)
            .split(whereSeparator: { $0 == " " || $0 == "\t" })
            .map(String.init)
        guard let executable = tokens.first,
              (executable as NSString).lastPathComponent == "env" else { return nil }
        // env 的选项（-S / -i / -u …）跳过，取第一个非选项 token 作解释器名。
        guard let name = tokens.dropFirst().first(where: { !$0.hasPrefix("-") }),
              !name.contains("/") else { return nil }
        return name
    }

    /// PATH 组装：前置目录 → 现有 PATH → 系统默认兜底；去空、去重、保序。
    ///
    /// 前置优先于现有（解释器目录必须压过任何同名旧条目），现有项保留以免丢掉
    /// 调用方原本可用的查找面。
    static func commandPATH(current: String?, prepending directories: [String]) -> String {
        var seen = Set<String>()
        var result: [String] = []
        let currentDirectories = (current ?? "").split(separator: ":").map(String.init)
        for directory in directories + currentDirectories + systemDefaultDirectories
        where !directory.isEmpty && seen.insert(directory).inserted {
            result.append(directory)
        }
        return result.joined(separator: ":")
    }
}
