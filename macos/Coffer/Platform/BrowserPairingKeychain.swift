// BrowserPairingKeychain.swift —— 浏览器扩展配对 PSK（pre-shared key）的 Keychain
// 存取封装。
//
// 设计依据（配对集成契约 v2.3.0 §4，参数已冻结勿改）：
//   - generic password 项，service = "cn.coffer.browser-psk" + account =
//     vault_uuid（16B hex 去横线，与 broker stdin VAULT_UUID_HEX 同值 → 多库
//     天然隔离），镜像 McpEscrowKeychain 的 service/account 定位模式
//   - kSecAttrAccessible = WhenUnlockedThisDeviceOnly（绝不随 iCloud 钥匙串同步）
//     + **无 ACL**（关键差异，同 McpEscrowKeychain：无 ACL 项读取不弹认证 UI，
//     broker 为后台 spawn 进程无法交互认证——memory
//     `coffer-real-machine-keychain-acl-consent` 实证坑；kSecAttrAccessControl
//     与 kSecAttrAccessible 互斥，BUG-2 实证）
//   - access group = "A6DS985SJJ.app.coffer.Coffer"（与 App entitlement 同组，
//     D-6 spike 实证 Security 层对 entitlement 列表内 group 完全静默）
//   - 决策①（PSK 生成方 = App）：启用集成时 CSPRNG 32B 生成 + 本封装 store；
//     spawn 时 App 读回 hex 经 stdin PSK_HEX= 注入 broker；配对批准时同一 PSK 经
//     pair_decision 下发（契约 §4）。**PSK 属传输层材料，仅经 stdin 管道与
//     pair_decision 帧传递**，不落 argv / 日志 / 全局状态。
//   - 写/删/读全由 App Swift 侧承担（broker 只经 stdin 收 PSK_HEX，不经 keychain）
//
// 单测缝隙（镜像 McpEscrowKeychain / BiometricKeychain）：useDataProtection=false
// 走文件钥匙串（无签名测试二进制可写）；service 可注入（隔离真实项）。

import Foundation
import Security

/// 浏览器扩展配对 PSK Keychain 操作错误。
enum BrowserPairingKeychainError: Error, Equatable {
    /// 项不存在（未启用 / 已删 / stale 清理路径）。
    case itemNotFound
    /// PSK 长度非法（应为 32B，契约 §4.2）——程序员错误，写入路径防御。
    case invalidKeyLength(Int)
    /// 其他未预期 OSStatus（含 -34018 缺 entitlement 等签名/配置错误）。
    case unexpected(OSStatus)

    /// 用户可操作文案（AppModel catch 分支经 lastErrorMessage 呈现）。
    var userText: String {
        switch self {
        case .itemNotFound:
            return "未找到浏览器配对密钥（Keychain 项不存在）。"
        case .invalidKeyLength:
            return "内部错误：浏览器配对密钥长度非法。"
        case .unexpected(let status):
            return "浏览器配对 Keychain 操作失败（OSStatus \(status)）。"
        }
    }
}

/// 浏览器扩展配对 PSK 的 Keychain 封装器（契约 §4.2 条目定义）。
///
/// 无状态值类型：所有定位信息经参数传入，持有与否不影响 Keychain 项。
struct BrowserPairingKeychain {

    /// Keychain 项 service 标识（契约 §4.2 冻结：cn.coffer.browser-psk）；
    /// account = vault_uuid（多库天然隔离）。service 可注入供单测隔离。
    static let service = "cn.coffer.browser-psk"

    /// PSK 标准长度（CSPRNG 32 字节，契约 §4.1）。
    static let keyLength = 32

    /// Keychain access group（与 App entitlement 同组，Coffer.entitlements:27；
    /// 镜像 McpEscrowKeychain，D-6 spike 实证）。
    static let accessGroup = "A6DS985SJJ.app.coffer.Coffer"

    // MARK: - 项查询 / 存取

    /// 项是否存在。只查属性不取数据（kSecReturnData=false）。无 ACL 条目查询
    /// 不弹认证 UI。返回语义（镜像 McpEscrowKeychain）：
    ///   - 查询成功 / errSecInteractionNotAllowed → true（WhenUnlockedThisDeviceOnly
    ///     条目锁屏期「存在 ≠ 可读」，避免锁屏期被误判为 stale）
    ///   - errSecItemNotFound → false
    ///   其他未预期状态码 → false（保守：不把未知错误当「存在」）。
    func itemExists(vaultUUID: String, service: String = Self.service, useDataProtection: Bool = true) -> Bool {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(
            Self.queryForExists(vaultUUID: vaultUUID, service: service, useDataProtection: useDataProtection) as CFDictionary,
            &item)
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            return false
        }
    }

    /// 读回 PSK 原始字节（决策①：spawn 时读回 hex 经 stdin 注入；批准时同一 PSK
    /// 经 pair_decision 下发）。返回 nil = 项不存在（未启用 / 已删）或读失败
    /// ——调用方 fail-closed 不 spawn / 按拒绝处理。
    ///
    /// - Returns: 32B PSK 原始值；不存在/失败 → nil。
    func load(vaultUUID: String, service: String = Self.service, useDataProtection: Bool = true) -> Data? {
        var query = Self.baseQuery(vaultUUID: vaultUUID, service: service, useDataProtection: useDataProtection)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound, errSecInteractionNotAllowed:
            return nil
        default:
            return nil
        }
    }

    /// 写入 PSK。SecItemAdd → DuplicateItem 则删旧重写（幂等覆盖，重启用同钥
    /// 覆盖语义，契约 §4.3）。
    ///
    /// - Parameters:
    ///   - key: PSK，必须恰好 32 字节（契约 §4.2）。
    ///   - vaultUUID: 库 UUID 文本（Keychain 项 account）。
    func save(key: Data, vaultUUID: String, service: String = Self.service, useDataProtection: Bool = true) throws {
        guard key.count == Self.keyLength else {
            throw BrowserPairingKeychainError.invalidKeyLength(key.count)
        }

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
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
            // 覆盖语义（契约 §4.3 幂等）：删旧再写新。
            SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, service: service, useDataProtection: useDataProtection) as CFDictionary)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw Self.mapStatus(status)
        }
    }

    /// 删除 PSK 项（停用即删，契约 §4.3：重启用 = 新 PSK，旧扩展失配须重配对）。
    /// 幂等：项不存在视为成功。
    /// - Returns: 是否实际删除了项（单测断言用）。
    @discardableResult
    func delete(vaultUUID: String, service: String = Self.service, useDataProtection: Bool = true) throws -> Bool {
        let status = SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, service: service, useDataProtection: useDataProtection) as CFDictionary)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            // 幂等：已不存在视为成功
            return false
        default:
            throw Self.mapStatus(status)
        }
    }

    // MARK: - 生成 / 编码

    /// CSPRNG 生成 32B PSK（决策①：PSK 生成方 = App，SecRandomCopyBytes）。
    /// - Returns: 32B 随机值；系统随机源失败 → nil（fail-closed，绝不硬编码占位）。
    static func randomPSK() -> Data? {
        var bytes = [UInt8](repeating: 0, count: keyLength)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { return nil }
        return Data(bytes)
    }

    /// 字节流 → 小写 hex 字符串（2 字符/字节，与 broker stdin PSK_HEX= 同格式）。
    /// 用于 App 读回 PSK 后经 stdin / pair_decision 传递。
    static func hexString(from data: Data) -> String {
        let hexTable: [UInt8] = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(hexTable[Int(byte >> 4)])
            out.append(hexTable[Int(byte & 0x0f)])
        }
        return String(bytes: out, encoding: .utf8) ?? ""
    }

    // MARK: - 内部

    /// 存在性探测查询构造（内部可见的最小可测 seam）：定位 + access group。
    static func queryForExists(vaultUUID: String, service: String, useDataProtection: Bool) -> [String: Any] {
        var query = baseQuery(vaultUUID: vaultUUID, service: service, useDataProtection: useDataProtection)
        query[kSecReturnData as String] = false
        return query
    }

    /// 定位查询（service + account + access group，不含返回数据开关）。
    private static func baseQuery(vaultUUID: String, service: String, useDataProtection: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultUUID,
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        // 数据保护钥匙串（iOS 语义，macOS 10.15+）：与 BiometricKeychain 同款语义；
        // useDataProtection=false 为单测缝隙（无签名 CLI 可跑文件钥匙串）。
        if useDataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }

    /// OSStatus → 语义错误：
    ///   - errSecItemNotFound → .itemNotFound（未启用 / 已删 / stale 清理路径）
    ///   - 其余 → .unexpected(status)
    private static func mapStatus(_ status: OSStatus) -> BrowserPairingKeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        default:
            return .unexpected(status)
        }
    }
}
