// BiometricKeychain.swift —— K_bio（bio unwrap-key）的 Keychain 存取封装。
//
// 设计依据（docs/08 §3.2 / §7.3）：
//   - generic password 项，service = "cn.coffer.biometric" + account = <vault_uuid>
//     定位，多库并发天然隔离（§3.3）
//   - kSecAttrAccessible = WhenUnlockedThisDeviceOnly（绝不随 iCloud 钥匙串同步）
//     + SecAccessControl .biometryCurrentSet（D-4：指纹集变更 → 项立即失效 →
//     强制主密码降级）
//   - 本封装只搬运随机字节（K_bio），不做任何加解密——加解密统一在 Rust
//     （docs/08 D-7）；K_bio 是「受门禁保护的随机字节保险柜」里的内容物
//
// K_bio 纪律（docs/08 §7.4）：取回即用，不落 @Published / 不进全局状态。

import Foundation
import LocalAuthentication
import Security

/// Keychain 操作错误（docs/08 §7.3 错误语义表）。
/// 解锁流程中的呈现语义见 ErrorPresenter：itemNotFound / authFailed → 4002。
enum BiometricKeychainError: Error, Equatable {
    /// 项不存在（未启用 / 已删 / biometryCurrentSet 失效的清理路径）→ 4002
    case itemNotFound
    /// 认证拒绝（用户取消 / 指纹集变更后 ACL 拒绝 / 锁定态读取）→ 4002
    case authFailed
    /// K_bio 长度非法（应为 32B，docs/08 D-3）——程序员错误，写入路径防御
    case invalidKeyLength(Int)
    /// 其他未预期 OSStatus
    case unexpected(OSStatus)
}

/// K_bio 的 Keychain 封装器（docs/08 §7.3 职责边界）。
///
/// 无状态值类型：所有定位信息经参数传入，持有与否不影响 Keychain 项。
struct BiometricKeychain {

    /// Keychain 项 service 标识；account = vault_uuid 文本（多库天然隔离）。
    static let service = "cn.coffer.biometric"

    /// K_bio 标准长度（Rust CSPRNG 生成 32 字节，docs/08 D-3）。
    static let keyLength = 32

    // MARK: - 生物识别可用性（只检测，不弹窗）

    /// 当前设备是否支持生物识别解锁（Touch ID 硬件 + 已录入指纹）。
    /// false 时 UI 应整体隐藏 Touch ID 入口（docs/08 §8 降级矩阵第一行）；
    /// 只检测不弹窗（canEvaluatePolicy 无 UI 副作用）。
    static func isBiometricsAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    // MARK: - 项查询 / 存取

    /// 项是否存在。只查属性不取数据（kSecReturnData=false），
    /// 预期不触发认证弹窗（docs/08 Q-2，T05 真机复核）。
    /// 注意：biometryCurrentSet 失效后项通常仍存在（读取时才报 AuthFailed），
    /// 「存在」≠「可读」，stale 终判以 read 失败为准（docs/08 §4.1）。
    func itemExists(vaultUUID: String) -> Bool {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(Self.baseQuery(vaultUUID: vaultUUID) as CFDictionary, &item)
        return status == errSecSuccess
    }

    /// 写入 K_bio。SecItemAdd → DuplicateItem 则删旧重写（幂等覆盖，docs/08 §4.1）。
    ///
    /// - Parameters:
    ///   - key: K_bio，必须恰好 32 字节（docs/08 D-3）。
    ///   - vaultUUID: 库 UUID 文本（Keychain 项 account）。
    ///   - requireBiometry: 项是否挂 `.biometryCurrentSet` ACL。生产路径恒为
    ///     true；单测在无 Touch ID 环境用 false 走可自动化路径（docs/08 §9
    ///     T03 验收①「无 accessControl 的测试路径」）。两档都强制
    ///     ThisDeviceOnly——密钥材料绝不离开本机（docs/03 §10.4）。
    func save(key: Data, vaultUUID: String, requireBiometry: Bool = true) throws {
        guard key.count == Self.keyLength else {
            throw BiometricKeychainError.invalidKeyLength(key.count)
        }

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
            kSecValueData as String: key,
        ]

        if requireBiometry {
            // D-4 裁定：WhenUnlockedThisDeviceOnly + biometryCurrentSet 组合。
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                &accessError
            ) else {
                // ACL 创建失败属系统层异常，按参数错误归类（带日志语义的注释）
                throw BiometricKeychainError.unexpected(errSecParam)
            }
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            attributes[kSecAttrAccessControl as String] = access
        } else {
            // 测试路径：无 ACL，但仍强制 ThisDeviceOnly
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }

        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // 覆盖语义（docs/08 §4.1）：删旧再写新。
            // 与 §4.1 草案「SecItemUpdate」的偏差说明：SecItemUpdate 不能替换
            // kSecAttrAccessControl——指纹集变更后旧项 ACL 已失效，仅更新
            // kSecValueData 会留下「新密文 + 永不可读旧 ACL」。删旧重写才是
            // biometryCurrentSet 语义下正确的幂等覆盖。
            SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID) as CFDictionary)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw Self.mapStatus(status)
        }
    }

    /// 读取 K_bio。认证与读取绑定同一 LAContext：调用方在 `evaluatePolicy`
    /// 成功后传入同一 context，读取时复用认证结果、不再二次弹窗（docs/08 §3.2）。
    func read(vaultUUID: String, context: LAContext) throws -> Data {
        var query = Self.baseQuery(vaultUUID: vaultUUID)
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw Self.mapStatus(status)
        }
        guard let data = item as? Data else {
            // 理论不可达：kSecReturnData=true 成功时必然返回 CFData
            throw BiometricKeychainError.unexpected(errSecParam)
        }
        return data
    }

    /// 删除 K_bio 项。幂等：项不存在视为成功（docs/08 §7.3）。
    /// - Returns: 是否实际删除了项（单测断言用）。
    @discardableResult
    func delete(vaultUUID: String) throws -> Bool {
        let status = SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID) as CFDictionary)
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

    // MARK: - 内部

    /// 定位查询（service + account，不含返回数据开关与认证上下文）。
    private static func baseQuery(vaultUUID: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
        ]
    }

    /// OSStatus → 语义错误（docs/08 §4.1：NotFound / AuthFailed 均为降级信号）。
    private static func mapStatus(_ status: OSStatus) -> BiometricKeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed:
            return .authFailed
        default:
            return .unexpected(status)
        }
    }
}
