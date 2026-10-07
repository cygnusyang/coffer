// McpStatusConfig.swift —— MCP 设置页配置常量 / 持久化 / 注册命令构造
// （docs/20 §5.2/§5.4/§6.1；docs/29 §7.1 翻转）。
//
// 与 TouchIDStatus（Support/TouchIDStatus.swift）分离的原因：MCP 域把
// 「状态判定」「配置持久化」「命令构造」三类纯逻辑集中在此，供
// McpSettingsView 与单元测试共用（无 AppKit/SwiftUI 依赖，纯 Foundation）。

import Foundation

/// MCP provider 常量（docs/20 §6.1 Provider 下拉；docs/29 §7.1 翻转后
/// coffer 取消灰态、默认 coffer）。
enum McpProvider: String, CaseIterable, Equatable {
    /// 1Password CLI（docs/20 §4.2 OpProvider；v2.2.0 转可选）
    case op
    /// Coffer 自家库（docs/20 §4.5 CofferStoreProvider；v2.2.0 转正默认）
    case coffer

    /// 默认 provider（docs/29 §7.1：coffer 转正）。
    /// rawValue 即 `coffer mcp --provider <rawValue>` 用的值；展示名见 displayName。
    static let defaultProvider = McpProvider.coffer

    /// 设置页展示名（1Password 对齐文案）。
    var displayName: String {
        switch self {
        case .op: return "1Password CLI"
        case .coffer: return "Coffer 自家库"
        }
    }

    /// 本版是否可用（docs/29 §7.1：coffer 取消灰态，两个 provider 均可用）。
    var isAvailableInMvp: Bool { self == .op || self == .coffer }
}

/// MCP 设置持久化（docs/20 §6.1 开关 / Vault 配置项）。
/// 键值均非敏感（布尔 / vault 名），存 UserDefaults——与 Touch ID 密钥材料
/// 走 Keychain 不同，这里没有密钥（op token 走 env/Keychain 另行处理，
/// 不落本设置域，见 docs/20 §6.3）。
enum McpSettings {
    /// 「启用 MCP 服务器」开关（非敏感布尔，docs/20 §6.1）。
    static let enabledDefaultsKey = "mcp_enabled"
    /// 默认 vault 名（`coffer mcp --vault <name>`，docs/20 §5.2）。
    static let vaultDefaultsKey = "mcp_op_vault"

    // MARK: 启用开关

    /// 读开关（键不存在 → false，与 AppModel 其它 UserDefaults 读法同纪律）。
    nonisolated static func loadEnabled() -> Bool {
        UserDefaults.standard.bool(forKey: enabledDefaultsKey)
    }

    nonisolated static func saveEnabled(_ value: Bool) {
        UserDefaults.standard.set(value, forKey: enabledDefaultsKey)
    }

    // MARK: Vault 配置项

    /// 读 vault 名（未配置 → 空串）。
    nonisolated static func loadVaultName() -> String {
        UserDefaults.standard.string(forKey: vaultDefaultsKey) ?? ""
    }

    /// 存 vault 名：归一化（首尾空白剔除）后落盘；空/全空白视为未配置并删除键
    /// （不留脏值，与 ClipboardManager 档位校验纪律同向）。
    nonisolated static func saveVaultName(_ value: String) {
        let trimmed = normalizedVaultName(value)
        if trimmed.isEmpty {
            UserDefaults.standard.removeObject(forKey: vaultDefaultsKey)
        } else {
            UserDefaults.standard.set(trimmed, forKey: vaultDefaultsKey)
        }
    }

    /// vault 名归一化（纯函数）：首尾空白剔除；空/全空白 → 空串（未配置）。
    nonisolated static func normalizedVaultName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 是否已配置 vault（纯函数；视图层据此提示「省略 --vault」）。
    nonisolated static func hasConfiguredVault(_ name: String) -> Bool {
        !normalizedVaultName(name).isEmpty
    }
}

/// 注册命令构造（docs/20 §5.4：设置页「复制」输出，对齐 1Password
/// 「Connect to Claude」一键复制；docs/29 §7.1：coffer 版随 provider 分支）。
///
/// 输出形如：
///   claude mcp add coffer -- coffer mcp --provider op --vault <vault>
///   claude mcp add coffer -e COFFER_VAULT_DIR=<vaultDirPath> -- coffer mcp --provider coffer
/// 用户前置：op 路径需 `op signin`（1Password 集成会话）+ `coffer` 在 PATH
/// （随 App 分发，docs/20 §6.2）；coffer 路径只需 `coffer` 在 PATH（解锁走
/// MCP 托管，**不含密码 env**——docs/29 §7.1 本版收口核心）。
enum McpRegisterCommand {
    /// 无需引号的「安全字符集」：字母数字 + 常见路径/域内标点。
    /// 仅当 vault 名 / 目录路径含此集合以外的字符（空格、单引号等）才加引号
    /// ——简单名保持 §5.4 示例的自然形态（`--vault Personal`），特殊字符才包裹。
    private static let safeUnquotedCharacters = "._-@/%+=:,"

    /// 生成注册命令。op 路径：vault 为空/全空白则省略 `--vault`，非空则按需
    /// shell 单引号包裹（含内嵌单引号转义）；coffer 路径：出
    /// `-e COFFER_VAULT_DIR=<vaultDirPath>` 版（目录路径同样按需引号包裹）。
    /// 命令粘贴到终端即原样执行，vault 名 / 路径含空格或引号也能正确解析。
    ///
    /// - Parameters:
    ///   - provider: `McpProvider` 的 rawValue（如 `"op"` / `"coffer"`，
    ///     docs/29 §7.1 注册命令随 provider 分支）。
    ///   - vault: 默认 vault 名（仅 op 分支消费；nil / 空 / 全空白 → 省略
    ///     `--vault`）。
    ///   - vaultDirPath: 自家库目录路径（docs/29 §7.1，仅 coffer 分支消费；
    ///     空/全空白 → 仍输出 `-e COFFER_VAULT_DIR=` 空值——UI 侧无会话时应
    ///     禁用复制入口）。
    /// - Returns: 可直接粘贴执行的 `claude mcp add …` 命令。
    static func build(provider: String, vault: String?, vaultDirPath: String? = nil) -> String {
        switch provider {
        case "coffer":
            let dir = (vaultDirPath ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            return "claude mcp add coffer -e COFFER_VAULT_DIR=\(shellQuoteIfNeeded(dir)) -- coffer mcp --provider coffer"
        default:
            let trimmed = vault.map(McpSettings.normalizedVaultName) ?? ""
            var parts = ["claude mcp add coffer -- coffer mcp --provider \(provider)"]
            if !trimmed.isEmpty {
                parts.append("--vault \(shellQuoteIfNeeded(trimmed))")
            }
            return parts.joined(separator: " ")
        }
    }

    /// 按需加引号：vault 名仅含安全字符则原样输出（对齐 §5.4 自然形态）；
    /// 否则走 shellQuote 单引号包裹（含转义）。
    private static func shellQuoteIfNeeded(_ value: String) -> String {
        let isSafe = value.allSatisfy {
            $0.isLetter || $0.isNumber || safeUnquotedCharacters.contains($0)
        }
        return isSafe ? value : shellQuote(value)
    }

    /// shell 单引号转义（纯函数）：`'` → `'\''`，外层包单引号；空串 → `''`。
    /// 只包单引号即可（POSIX sh 内单引号内仅 `'` 需转义）。
    static func shellQuote(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }
}
