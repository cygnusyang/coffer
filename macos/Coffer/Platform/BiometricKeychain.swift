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
//   - 解锁认证（PL-4 修复后）：读取即钥匙串自有单次认证——查询带全新
//     LAContext（localizedReason 为提示文案，kSecUseOperationPrompt 自 macOS 11
//     起弃用），由 Keychain 自行发起唯一一次弹窗；调用方不再预认证
//     （macOS 26 实测 kSecUseAuthenticationContext 复用已认证结果不生效，
//     App 侧预认证 + 读取再认证 = 双弹窗，docs/KNOWN-ISSUES.md PL-4）
//   - 存在性探测（PL-4 双源修复）：itemExists 查询带 kSecUseAuthenticationUIFail
//     ——2026-10-03 真机实证 macOS 26 上元数据查询亦触发完整 ACL 认证 UI（启动
//     路径 refreshTouchIDStatus → itemExists 曾致启动后 ~1s 自动弹窗），探测
//     禁止弹 UI，失败直接返回状态码由调用方按三态语义解释（docs/KNOWN-ISSUES.md
//     PL-4 双源①）
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

    /// 解锁认证提示文案（LAContext.localizedReason，与既有中文文案风格一致；
    /// kSecUseOperationPrompt 自 macOS 11 起弃用，改用本字段）。
    /// PL-4 修复后读取由钥匙串自有单次认证发起，本文案即该唯一一次弹窗的提示。
    static let unlockPrompt = "解锁密码库"

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

    /// 项是否存在。只查属性不取数据（kSecReturnData=false），且探测禁止弹认证
    /// UI（全新 LAContext + interactionNotAllowed=true——2026-10-03 真机 log
    /// stream 实证：macOS 26 上对挂 biometryCurrentSet ACL 的项做元数据查询亦
    /// 触发完整认证 UI，见 docs/KNOWN-ISSUES.md PL-4 双源①；此处「不弹窗」由
    /// interactionNotAllowed 显式保证，Q-2 已闭环。kSecUseAuthenticationUI =
    /// kSecUseAuthenticationUIFail 自 macOS 11 弃用，改用本字段）。返回语义三态：
    ///   - 查询成功 → true（项存在）
    ///   - errSecAuthFailed / errSecInteractionNotAllowed → true（项物理存在但
    ///     认证被锁；探测无 UI 直接返回该码）。「存在」≠「可读」，stale 终判
    ///     以 read 失败为准（docs/08 §4.1）。返回 true 使 TouchIDStatus 保持
    ///     .enabled——LockView 按钮不消失，用户点按后由 read 弹单次认证。
    ///   - errSecItemNotFound → false（项不存在 / 指纹集变更清理路径）
    /// 其他未预期状态码 → 记日志并返回 false（保守：不把未知错误当「存在」）。
    func itemExists(vaultUUID: String, useDataProtection: Bool = true) -> Bool {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(
            Self.queryForExists(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary,
            &item)
        switch status {
        case errSecSuccess:
            return true
        case errSecAuthFailed, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            DiagLog.append("Keychain.itemExists 失败 status=\(status)（\(vaultUUID.prefix(8))…）")
            return false
        }
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
    func save(key: Data, vaultUUID: String, requireBiometry: Bool = true,
              useDataProtection: Bool = true) throws {
        guard key.count == Self.keyLength else {
            throw BiometricKeychainError.invalidKeyLength(key.count)
        }

        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
            kSecValueData as String: key,
        ]
        if useDataProtection {
            attributes[kSecUseDataProtectionKeychain as String] = true
        }

        if requireBiometry {
            // D-4 裁定：WhenUnlockedThisDeviceOnly + biometryCurrentSet 组合。
            // 注意：kSecAttrAccessControl 与 kSecAttrAccessible 互斥——同时指定
            // SecItemAdd 必返回 errSecParam(-50)（2026-09-27 真机实证，BUG-2）。
            // 可访问性已包含在 ACL 对象（kSecAttrAccessibleWhenUnlockedThisDeviceOnly），
            // 此处只能设置 kSecAttrAccessControl。
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
            SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary)
            status = SecItemAdd(attributes as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            DiagLog.append("Keychain.save 失败 status=\(status) requireBiometry=\(requireBiometry) useDP=\(useDataProtection)")
            throw Self.mapStatus(status)
        }
    }

    /// 读取 K_bio。钥匙串自有单次认证（PL-4 修复后）：查询带全新 LAContext
    /// （localizedReason 见 unlockPrompt，kSecUseOperationPrompt 自 macOS 11 起
    /// 弃用），由 Keychain 自行发起唯一一次认证弹窗；调用方无需预认证
    /// （删除 App 侧 evaluatePolicy——macOS 26 上 kSecUseAuthenticationContext
    /// 复用已认证结果不生效，预认证 + 读取再认证 = 双弹窗）。
    /// 取消 / 指纹集失效 → .authFailed → 4002 降级（docs/08 §4.1，语义不变）。
    func read(vaultUUID: String, useDataProtection: Bool = true) throws -> Data {
        let query = Self.queryForRead(vaultUUID: vaultUUID, useDataProtection: useDataProtection)

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            DiagLog.append("Keychain.read 失败 status=\(status)（\(vaultUUID.prefix(8))…）")
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
    func delete(vaultUUID: String, useDataProtection: Bool = true) throws -> Bool {
        let status = SecItemDelete(Self.baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection) as CFDictionary)
        switch status {
        case errSecSuccess:
            return true
        case errSecItemNotFound:
            // 幂等：已不存在视为成功
            return false
        default:
            DiagLog.append("Keychain.delete 失败 status=\(status)（\(vaultUUID.prefix(8))…）")
            throw Self.mapStatus(status)
        }
    }

    // MARK: - 内部

    /// 读取查询构造（内部可见的最小可测 seam）：定位 + 返回数据 + 全新
    /// LAContext（localizedReason = unlockPrompt）。不含密钥材料，单测据此
    /// 断言查询携带由 Keychain 自有单次认证所需的 LAContext。
    static func queryForRead(vaultUUID: String, useDataProtection: Bool) -> [String: Any] {
        var query = baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection)
        query[kSecReturnData as String] = true
        // 全新未认证 LAContext：不携带任何已认证结果，由 Keychain 自行发起
        // 唯一一次认证；localizedReason 即弹窗提示文案（kSecUseOperationPrompt
        // 自 macOS 11 起弃用，改用此字段）。
        let context = LAContext()
        context.localizedReason = Self.unlockPrompt
        query[kSecUseAuthenticationContext as String] = context
        return query
    }

    /// 存在性探测查询构造（内部可见的最小可测 seam）：定位 + 禁止认证弹 UI
    /// （全新 LAContext + interactionNotAllowed=true——探测不得打扰用户，需认证
    /// 时立即返回 errSecInteractionNotAllowed / errSecAuthFailed，由 itemExists
    /// 按三态语义解释）。kSecUseAuthenticationUI = kSecUseAuthenticationUIFail
    /// 自 macOS 11 弃用，改用本字段（与 PL-4 弃用 kSecUseOperationPrompt 改
    /// localizedReason 同式）。2026-10-03 真机 log stream 实证：macOS 26 上
    /// 元数据查询亦触发完整 ACL 认证 UI（PL-4 双源①，启动路径
    /// refreshTouchIDStatus → itemExists 曾致启动后 ~1s 自动弹窗）。不含密钥
    /// 材料，单测据此断言查询携带 interactionNotAllowed 的 LAContext。
    static func queryForExists(vaultUUID: String, useDataProtection: Bool) -> [String: Any] {
        var query = baseQuery(vaultUUID: vaultUUID, useDataProtection: useDataProtection)
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        return query
    }

    /// 定位查询（service + account，不含返回数据开关与认证上下文）。
    private static func baseQuery(vaultUUID: String, useDataProtection: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: vaultUUID,
        ]
        // 数据保护钥匙串（iOS 语义，macOS 10.15+）：2026-09-27 真机实测，
        // 沙盒 App 走文件型登录钥匙串的 biometryCurrentSet ACL 与 DP 钥匙串
        // 均 -34018（ad-hoc 签名无 application-identifier）——待加
        // keychain-access-groups entitlement 后再定生产组合。
        // useDataProtection=false 为单测缝隙（无签名 CLI 可跑文件钥匙串）。
        if useDataProtection {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
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
