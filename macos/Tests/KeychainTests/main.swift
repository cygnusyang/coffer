// KeychainTests/main.swift —— BiometricKeychain 单元测试（docs/08 §9 T03 验收①）。
//
// 编译运行：tools/run_keychain_tests.sh
//
// 环境适配（docs/08 T03 验收①）：
//   - 本机真 Keychain 上跑：save/read/delete 往返 + DuplicateItem 覆盖 + delete 幂等
//   - 无 Touch ID 机器走 requireBiometry=false 的「无 accessControl 测试路径」，
//     读写无需认证弹窗，可全自动化
//   - CI 无 Keychain（errSecMissingEntitlement 等）时探针失败 → 整体 SKIP（exit 0）
//   - 有 Touch ID 硬件时加跑 biometryCurrentSet 真路径（只验证写入/存在/删除，
//     读取会弹真实认证框无法自动化，属 T05 真机项）

import Foundation
import LocalAuthentication
import Security

var passed = 0
var failed = 0

func check(_ condition: Bool, _ name: String) {
    if condition {
        passed += 1
        print("✓ \(name)")
    } else {
        failed += 1
        print("✗ \(name)")
    }
}

/// CSPRNG 生成 32B 测试密钥（与 Rust 侧 K_bio 同规格）。
func randomKey() -> Data {
    var bytes = [UInt8](repeating: 0, count: BiometricKeychain.keyLength)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes 失败：\(status)")
    return Data(bytes)
}

let keychain = BiometricKeychain()
// 随机 account：不污染真实库的项（service 相同、account 隔离，docs/08 §3.3）
let uuid = UUID().uuidString
defer { _ = try? keychain.delete(vaultUUID: uuid) }

// ---- 0. Keychain 可用性探针：无 Keychain 环境（CI）整体 SKIP ----
do {
    try keychain.save(key: randomKey(), vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
    try keychain.delete(vaultUUID: uuid)
} catch BiometricKeychainError.unexpected(let status) {
    print("SKIP：当前环境 Keychain 不可用（OSStatus \(status)），单元测试跳过。")
    exit(0)
} catch {
    print("✗ Keychain 探针失败：\(error)")
    exit(1)
}
// ---- 7. 接口枚举补充（2026-09-27 排障要求）：覆盖此前未断言的行为 ----
// 7a. itemExists 三段：不存在 → 存在 → 删除后不存在
check(keychain.itemExists(vaultUUID: uuid, useDataProtection: false) == false, "接口枚举：初始 itemExists → false")
try keychain.save(key: randomKey(), vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
check(keychain.itemExists(vaultUUID: uuid, useDataProtection: false), "接口枚举：save 后 itemExists → true")
try keychain.delete(vaultUUID: uuid, useDataProtection: false)
check(keychain.itemExists(vaultUUID: uuid, useDataProtection: false) == false, "接口枚举：delete 后 itemExists → false")

// 7b. invalidKeyLength 错误携带实际长度（Equatable 语义）
do {
    try keychain.save(key: Data(repeating: 0, count: 31), vaultUUID: uuid,
                      requireBiometry: false, useDataProtection: false)
    check(false, "接口枚举：31B 应被拒绝")
} catch BiometricKeychainError.invalidKeyLength(let n) {
    check(n == 31, "接口枚举：invalidKeyLength 携带实际长度 31")
} catch {
    check(false, "接口枚举：31B 抛出了非预期错误 \(error)")
}

// 7c. 错误枚举 Equatable（跨层映射依赖它）
check(BiometricKeychainError.itemNotFound == BiometricKeychainError.itemNotFound, "接口枚举：itemNotFound Equatable")
check(BiometricKeychainError.unexpected(-34018) == BiometricKeychainError.unexpected(-34018), "接口枚举：unexpected Equatable")
check(BiometricKeychainError.itemNotFound != BiometricKeychainError.authFailed, "接口枚举：不同 case 不相等")

// 7d. isBiometricsAvailable 返回 Bool（值随设备，不断言真假）
_ = BiometricKeychain.isBiometricsAvailable()
check(true, "接口枚举：isBiometricsAvailable 可调用")

// 7e. 未启用时 read → itemNotFound（读接口错误路径）
do {
    _ = try keychain.read(vaultUUID: uuid + "-nonexistent", useDataProtection: false)
    check(false, "接口枚举：读不存在项应抛错")
} catch BiometricKeychainError.itemNotFound {
    check(true, "接口枚举：读不存在项 → itemNotFound")
} catch {
    check(false, "接口枚举：读不存在项抛出了非预期错误 \(error)")
}

print("—— Keychain 探针通过，开始断言 ——")

// ---- 1. save → read 往返 ----
let key1 = randomKey()
try keychain.save(key: key1, vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
let read1 = try keychain.read(vaultUUID: uuid, useDataProtection: false)
check(read1 == key1, "save → read 往返（32B 一致）")

// ---- 2. itemExists（属性查询，无数据返回）----
check(keychain.itemExists(vaultUUID: uuid), "itemExists → true")

// ---- 3. DuplicateItem 覆盖：二次 save 后读到的是新值 ----
let key2 = randomKey()
check(key1 != key2, "两次随机 K_bio 不同（sanity）")
try keychain.save(key: key2, vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
let read2 = try keychain.read(vaultUUID: uuid, useDataProtection: false)
check(read2 == key2, "DuplicateItem 覆盖后读到新值")

// ---- 4. delete 幂等 ----
check(try keychain.delete(vaultUUID: uuid, useDataProtection: false), "delete 首次返回 true（实际删除）")
check(!keychain.itemExists(vaultUUID: uuid, useDataProtection: false), "delete 后 itemExists → false")
check(try keychain.delete(vaultUUID: uuid, useDataProtection: false) == false, "delete 幂等（二次 delete 静默成功）")

// ---- 5. 删除后读取 → itemNotFound ----
do {
    _ = try keychain.read(vaultUUID: uuid, useDataProtection: false)
    check(false, "删除后读取应抛 itemNotFound")
} catch BiometricKeychainError.itemNotFound {
    check(true, "删除后读取 → itemNotFound")
} catch {
    check(false, "删除后读取抛了非预期错误：\(error)")
}

// ---- 6. 多库隔离（docs/08 §3.3）：两个 account 互不干扰 ----
let uuidA = UUID().uuidString
let uuidB = UUID().uuidString
let keyA = randomKey()
let keyB = randomKey()
defer { _ = try? keychain.delete(vaultUUID: uuidA) }
defer { _ = try? keychain.delete(vaultUUID: uuidB) }
try keychain.save(key: keyA, vaultUUID: uuidA, requireBiometry: false, useDataProtection: false)
try keychain.save(key: keyB, vaultUUID: uuidB, requireBiometry: false, useDataProtection: false)
check(try keychain.read(vaultUUID: uuidA, useDataProtection: false) == keyA, "多库隔离：A 读回 A")
check(try keychain.read(vaultUUID: uuidB, useDataProtection: false) == keyB, "多库隔离：B 读回 B")
try keychain.delete(vaultUUID: uuidA, useDataProtection: false)
check(
    !keychain.itemExists(vaultUUID: uuidA, useDataProtection: false) && keychain.itemExists(vaultUUID: uuidB, useDataProtection: false),
    "多库隔离：删 A 不影响 B"
)

// ---- 7. K_bio 长度防御（docs/08 D-3：32B 硬约束）----
do {
    try keychain.save(key: Data([0x01, 0x02, 0x03]), vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
    check(false, "非 32B 写入应抛 invalidKeyLength")
} catch BiometricKeychainError.invalidKeyLength {
    check(true, "非 32B 写入 → invalidKeyLength")
} catch {
    check(false, "非 32B 写入抛了非预期错误：\(error)")
}

// ---- 8. biometryCurrentSet 真路径（有 Touch ID 硬件才跑；不验证读取—— ----
//      读取会弹真实认证框，无法自动化，属 T05 真机项 docs/08 §9）----
if BiometricKeychain.isBiometricsAvailable() {
    let key = randomKey()
    do {
        try keychain.save(key: key, vaultUUID: uuid, requireBiometry: true)
        check(keychain.itemExists(vaultUUID: uuid), "biometryCurrentSet 项写入 + 存在")
        try keychain.delete(vaultUUID: uuid)
        check(!keychain.itemExists(vaultUUID: uuid), "biometryCurrentSet 项删除")
    } catch BiometricKeychainError.unexpected(let status) {
        // 已知局限：挂 ACL 的 item 要求签名 + entitlement 的宿主（ad-hoc 裸二进制
        // 报 errSecMissingEntitlement -34018）。生产路径由 Coffer.app（沙盒 +
        // 签名）承担，此分支留 T05 真机验证（docs/08 §5 T-1 / §9 T05）。
        print("SKIP：biometryCurrentSet 真路径需签名宿主（OSStatus \(status)），留 T05 真机验证。")
    }
} else {
    print("SKIP：本机无 Touch ID，biometryCurrentSet 真路径留 T05 真机验证（docs/08 Q-3）。")
}

// ---- 9. PL-4 哨兵（2026-10-02）：钥匙串自有单次认证 ----
// 9a. 新签名：read 不再接收已认证 LAContext（编译期即证明调用方无需预认证）；
//     未预认证直读无 ACL 项（useDataProtection=false）应成功。
let sentinelKey = randomKey()
try keychain.save(key: sentinelKey, vaultUUID: uuid, requireBiometry: false, useDataProtection: false)
let sentinelRead = try keychain.read(vaultUUID: uuid, useDataProtection: false)
check(sentinelRead == sentinelKey, "哨兵：未预认证直读无 ACL 项成功（读取不依赖 evaluatePolicy）")
try keychain.delete(vaultUUID: uuid, useDataProtection: false)

// 9b. 读取查询带全新 LAContext 且 localizedReason 非空（最小可测 seam：
//     queryForRead 内部可见；kSecUseOperationPrompt 自 macOS 11 弃用，
//     改用 LAContext.localizedReason。不断言文案字面量——self-referential）
let readQuery = BiometricKeychain.queryForRead(vaultUUID: uuid, useDataProtection: false)
let readCtx = readQuery[kSecUseAuthenticationContext as String] as? LAContext
check((readCtx?.localizedReason.isEmpty) == false,
      "哨兵：读取查询带全新 LAContext 且 localizedReason 非空")

print("")
print(failed == 0
      ? "KEYCHAIN TESTS OK —— \(passed) 项断言全部通过"
      : "KEYCHAIN TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
