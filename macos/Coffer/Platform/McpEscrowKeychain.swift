// McpEscrowKeychain.swift —— mcp_key（MCP 解锁托管 wrap-key）的 Keychain 存取封装。
//
// 设计依据（docs/29 §5.1 / D-2，参数已冻结勿改）：
//   - generic password 项，service = "cn.coffer.mcp-escrow" + account = <vault_uuid>
//     定位，多库并发天然隔离（§5.1，与 BiometricKeychain 的
//     "cn.coffer.biometric" 平行命名空间，互不干扰）
//   - kSecAttrAccessible = WhenUnlockedThisDeviceOnly（绝不随 iCloud 钥匙串同步）
//     + **无 ACL**（关键差异，docs/29 §2 表）：CLI 为后台 spawn 进程无法交互
//     认证，任何 ACL（biometry 等）都会弹窗或失败（memory
//     `coffer-real-machine-keychain-acl-consent` 实证坑）。kSecAttrAccessControl
//     与 kSecAttrAccessible 互斥（BUG-2 实证）——本条目不设 ACL，直接设
//     accessible，无此冲突。
//   - access group = "A6DS985SJJ.app.coffer.Coffer"（与 App entitlement 同组，
//     Coffer.entitlements:27；组内二进制读取静默放行，无跨组同意弹窗——
//     D-6 spike 实证 Security 层对 entitlement 列表内 group 完全静默）
//   - 本封装只搬运 mcp_key 字节，不做任何加解密——派生与封装统一在 Rust
//     （docs/29 §3/§5.2）；mcp_key 是「受系统钥匙串门禁保护的派生字节」里的
//     内容物（确定性派生，重启用幂等覆盖，docs/29 §5.3）
//   - 写/删由 App Swift 侧承担，v2.2.0 CLI 只读（docs/29 §4.2，
//     cf-escrow-keychain 只实现 read_generic_password）
//
// mcp_key 纪律（docs/29 §5.3）：取回即用，不落 @Published / 不进全局状态。
// 本封装只写 / 删 / 探测存在性，不实现读取——App 侧无读取 mcp_key 的需求
// （CLI 才读，经 cf-escrow-keychain）。

import Foundation
import Security

/// Keychain 操作错误（docs/29 §5.1）。无 ACL 条目无 authFailed / userCanceled
/// 语义，故错误集比 BiometricKeychainError 更小。
enum McpEscrowKeychainError: Error, Equatable {
    /// 项不存在（未启用 / 已删 / stale 清理路径）。
    case itemNotFound
    /// mcp_key 长度非法（应为 32B，docs/29 §3.3）——程序员错误，写入路径防御。
    case invalidKeyLength(Int)
    /// 其他未预期 OSStatus（含 -34018 缺 entitlement 等签名/配置错误）。
    case unexpected(OSStatus)

    /// 用户可操作文案（AppModel catch 分支经 lastErrorMessage 呈现）。
    var userText: String {
        switch self {
        case .itemNotFound:
            return "未找到 MCP 解锁托管凭据（Keychain 项不存在）。"
        case .invalidKeyLength:
            return "内部错误：MCP 解锁托管密钥长度非法。"
        case .unexpected(let status):
            return "MCP 解锁托管 Keychain 操作失败（OSStatus \(status)）。"
        }
    }
}

/// mcp_key 的 Keychain 封装器（docs/29 §5.1 条目定义）。
///
/// 无状态值类型：所有定位信息经参数传入，持有与否不影响 Keychain 项。
struct McpEscrowKeychain {

    /// Keychain 项 service 标识（与 BiometricKeychain 的 "cn.coffer.biometric"
    /// 平行命名空间，互不干扰）；account = vault_uuid 文本（多库天然隔离）。
    static let service = "cn.coffer.mcp-escrow"

    /// mcp_key 标准长度（HKDF-SHA256 输出 32 字节，docs/29 §3.1）。
    static let keyLength = 32

    /// Keychain access group（与 App entitlement 同组，Coffer.entitlements:27；
    /// 组内二进制读取静默放行——CLI 同 bundle 同身份同组签名读取的承载，
    /// docs/29 §5.1 / D-6）。
    static let accessGroup = "A6DS985SJJ.app.coffer.Coffer"

    // MARK: - 项查询 / 存取

    /// 项是否存在。只查属性不取数据（kSecReturnData=false）。无 ACL 条目查询
    /// 不弹认证 UI（与 BiometricKeychain 的 interactionNotAllowed 探测不同——
    /// 本条目不设 kSecAttrAccessControl，元数据查询本身不触发认证）。
    /// 返回语义：
    ///   - 查询成功 → true（项存在）
    ///   - errSecItemNotFound → false（项不存在 / 已删）
    ///   其他未预期状态码 → 记日志并返回 false（保守：不把未知错误当「存在」）。
    func itemExists(vaultUUID: String, useDataProtection: Bool = true) -> Bool {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(
            Self.queryForExists(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary,
            &item)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            return false
        default:
            DiagLog.append("McpEscrowKeychain.itemExists 失败 status=\(status)（\(vaultUUID.prefix(8))…）")
            return false
        }
    }

    /// 写入 mcp_key。SecItemAdd → DuplicateItem 则删旧重写（幂等覆盖，
    /// 重启用同钥覆盖语义，docs/29 §5.3）。
    ///
    /// - Parameters:
    ///   - key: mcp_key，必须恰好 32 字节（docs/29 §3.3）。
    ///   - vaultUUID: 库 UUID 文本（Keychain 项 account）。
    func save(key: Data, vaultUUID: String, useDataProtection: Bool = true) throws {
        guard key.count == Self.keyLength else {
            throw McpEscrowKeychainError.invalidKeyLength(key.count)
        }

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        if useDataProtection {
            attributes[kSecUseDataProtectionKeychain as String] = true
        }

        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // 覆盖语义（docs/29 §5.3 幂等）：删旧再写新。
            SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            DiagLog.append("McpEscrowKeychain.save 失败 status=\(status) useDP=\(useDataProtection)")
            throw Self.mapStatus(status)
        }
    }

    /// 删除 mcp_key 项。幂等：项不存在视为成功（docs/29 §5.2）。
    /// - Returns: 是否实际删除了项（单测断言用）。
    @discardableResult
    func delete(vaultUUID: String, useDataProtection: Bool = true) throws -> Bool {
        let status = SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            // 幂等：已不存在视为成功
            return false
        default:
            DiagLog.append("McpEscrowKeychain.delete 失败 status=\(status)（\(vaultUUID.prefix(8))…）")
            throw Self.mapStatus(status)
        }
    }

    // MARK: - 内部

    /// 存在性探测查询构造（内部可见的最小可测 seam）：定位 + access group，
    /// 不含返回数据开关。
    static func queryForExists(vaultUUID: String, useDataProtection: Bool) -> [String: Any] {
        var query = baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection)
        query[kSecReturnData as String] = false
        return query
    }

    /// 定位查询（service + account + access group，不含返回数据开关）。
    /// access group 与 cf-escrow-keychain 读取查询同口径（docs/29 §4.2
    /// read_generic_password 带 access_group 参数）。
    private static func baseQuery(vaultUUID: String, useDataProtection: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        // 数据保护钥匙串（iOS 语义，macOS 10.15+）：与 BiometricKeychain 同款
        // 语义；useDataProtection=false 为单测缝隙（无签名 CLI 可跑文件钥匙串）。
        if useDataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }

    /// OSStatus → 语义错误：
    ///   - errSecItemNotFound → .itemNotFound（未启用 / 已删 / stale 清理路径）
    ///   - 其余 → .unexpected(status)
    private static func mapStatus(_ status: OSStatus) -> McpEscrowKeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        default:
            return .unexpected(status)
        }
    }
}
