//! macOS Keychain GenericPassword **只读**封装（MCP escrow 托管，docs/29 §4.1 / §4.3 G1c）。
//!
//! 背景：cf-mcp 是 `#![forbid(unsafe_code)]` 的 crate，而托管 mcp_key 存于 macOS
//! Keychain，读取必须经 Security framework FFI——故把**唯一的 unsafe 面**隔离在本
//! sys crate，对外只暴露安全封装（`Result<Option<Vec<u8>>>`），调用方无需 unsafe
//! （cf-mcp → cf-uds-sys 先例同构，docs/29 §4.1）。
//!
//! 只读边界：写/删路径（save/delete）v2.2.0 由 App Swift 侧 `McpEscrowKeychain.swift`
//! 承担（docs/29 §4.2），本 crate 只实现读取。
//!
//! 平台：`target_os = "macos"`（docs/29 §4.1 明确 macOS）。非 macOS 下无可用安全
//! 存储，返回 [`EscrowKeychainError::Unsupported`]（调用方据此拒绝托管、不落明文，
//! docs/30 §1.2）。
//!
//! 零网络：本 crate 只读本机 Keychain，无任何网络能力（docs/27 D-4 零网络新口径：
//! 本机内存储访问允许、不违背「不去云端」）。
//!
//! 载荷纪律（docs/30 §1.2）：密钥材料只在返回值 `Ok(Some(Vec<u8>))` 中出现；
//! [`EscrowKeychainError`] 不携带任何密钥材料，Debug/Display 均不泄露。

#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::fmt;

// 注意：security-framework-sys 的 `OSStatus` 别名是私有（base.rs:1），FFI 返回
// 类型解析到底层 `i32`，故本 crate 一律用 `i32` 表达错误码。
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};

// 以下 FFI 符号仅 macOS 读取路径使用（core-foundation-sys / security-framework-sys
// 本身全平台可编译，但本 crate 的调用点只在 macOS 分支）。
#[cfg(target_os = "macos")]
use core_foundation_sys::base::{kCFAllocatorDefault, CFIndex, CFRelease, CFTypeRef};
#[cfg(target_os = "macos")]
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataRef};
#[cfg(target_os = "macos")]
use core_foundation_sys::dictionary::{
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreate,
};
#[cfg(target_os = "macos")]
use core_foundation_sys::number::kCFBooleanTrue;
#[cfg(target_os = "macos")]
use core_foundation_sys::string::{
    kCFStringEncodingUTF8, CFStringCreateWithCString, CFStringRef,
};
#[cfg(target_os = "macos")]
use security_framework_sys::item::{
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecReturnData, kSecUseDataProtectionKeychain,
};
#[cfg(target_os = "macos")]
use security_framework_sys::keychain_item::SecItemCopyMatching;

/// Keychain 读取错误。
///
/// 载荷纪律（docs/30 §1.2）：本类型**不携带任何密钥材料**——`Vec<u8>` 只在
/// `Ok(Some(..))` 返回值中出现；错误路径不落明文、Debug/Display 不泄露。
#[derive(Debug)]
pub enum EscrowKeychainError {
    /// 入参非法（空字符串 / 含内嵌 NUL 等），调用前校验失败。
    InvalidArgument(&'static str),
    /// 平台不可用（非 macOS；调用方据此拒绝托管）。
    Unsupported,
    /// Core Foundation 层失败（对象创建 / 取数失败）。
    Platform(&'static str),
    /// Keychain 返回非 item-not-found 的 OSStatus（含原始错误码与可读描述）。
    OsStatus { code: i32, description: String },
}

impl EscrowKeychainError {
    /// 由 OSStatus 构造错误（含错误码与可读描述）。纯逻辑，便于单测。
    fn os_status(code: i32) -> Self {
        Self::OsStatus {
            code,
            description: os_status_description(code),
        }
    }
}

impl fmt::Display for EscrowKeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => {
                write!(f, "cf-escrow-keychain: invalid argument: {msg}")
            }
            Self::Unsupported => write!(
                f,
                "cf-escrow-keychain: keychain escrow unsupported on this platform"
            ),
            Self::Platform(msg) => write!(f, "cf-escrow-keychain: platform error: {msg}"),
            Self::OsStatus { code, description } => {
                write!(f, "cf-escrow-keychain: keychain OSStatus {code} ({description})")
            }
        }
    }
}

impl std::error::Error for EscrowKeychainError {}

/// 常用 OSStatus 的可读描述（未识别码回退为带码字符串）。
/// `errSec*` 常量遵循 Apple 命名（驼峰），非 Rust 全大写；仅作匹配模式使用。
#[allow(non_upper_case_globals)]
fn os_status_description(code: i32) -> String {
    match code {
        errSecSuccess => "errSecSuccess".to_string(),
        -50 => "errSecParam (parameter error)".to_string(),
        -25291 => "errSecNotAvailable (no keychain available)".to_string(),
        -25293 => "errSecAuthFailed (authentication failed)".to_string(),
        -25299 => "errSecDuplicateItem".to_string(),
        errSecItemNotFound => "errSecItemNotFound".to_string(),
        -25308 => "errSecInteractionNotAllowed (user interaction not allowed)".to_string(),
        -34018 => "errSecMissingEntitlement (missing keychain entitlement)".to_string(),
        other => format!("unrecognized OSStatus {other}"),
    }
}

/// 纯逻辑：把 `SecItemCopyMatching` 的 OSStatus 归类为三态。
///
/// - `Ok(Some(()))`：成功（`result` 承载数据）。
/// - `Ok(None)`：条目不存在（`errSecItemNotFound`，-25300 → 调用方显示「未托管」）。
/// - `Err(..)`：其余 OSStatus（fail-closed，docs/30 §1.2）。
///
/// `errSec*` 常量遵循 Apple 命名（驼峰），非 Rust 全大写；仅作匹配模式使用。
#[allow(non_upper_case_globals)]
fn classify_status(status: i32) -> Result<Option<()>, EscrowKeychainError> {
    match status {
        errSecSuccess => Ok(Some(())),
        errSecItemNotFound => Ok(None),
        other => Err(EscrowKeychainError::os_status(other)),
    }
}

/// 读 Keychain GenericPassword（只读，三态返回）。
///
/// - `Ok(Some(data))`：条目存在且读取成功（`data` 即托管密钥材料）。
/// - `Ok(None)`：条目不存在（`errSecItemNotFound`，-25300；调用方显示「未托管」）。
/// - `Err(..)`：其余 OSStatus / CF 层失败（须 fail-closed）。
///
/// 查询条件（docs/29 §5.1 / D-2）：`kSecClassGenericPassword` +
/// `kSecAttrService` + `kSecAttrAccount` + `kSecAttrAccessGroup`；
/// `kSecUseDataProtectionKeychain = true`（macOS 10.15+ 数据保护钥匙串，
/// 与 Swift 侧写入路径 `McpEscrowKeychain.swift` 同口径）。
#[cfg(target_os = "macos")]
pub fn read_generic_password(
    service: &str,
    account: &str,
    access_group: &str,
) -> Result<Option<Vec<u8>>, EscrowKeychainError> {
    // 入参校验：fail-fast，不触 FFI（空串在 CF 层会以 errSecParam 回退，但
    // 显式拒绝更清晰；内嵌 NUL 由 CString 拒绝）。
    if service.is_empty() {
        return Err(EscrowKeychainError::InvalidArgument("service is empty"));
    }
    if account.is_empty() {
        return Err(EscrowKeychainError::InvalidArgument("account is empty"));
    }
    if access_group.is_empty() {
        return Err(EscrowKeychainError::InvalidArgument("access_group is empty"));
    }

    let service_cf = cf_string(service)?;
    let account_cf = cf_string(account)?;
    let access_group_cf = cf_string(access_group)?;

    // SAFETY：读 Security framework 提供的 extern 常量（kSec* / kCFBooleanTrue）
    // 在 Rust 中属 unsafe 操作（extern static 不受类型系统约束）——此处只取指针
    // 值（CFStringRef/CFBooleanRef）交给 CFDictionaryCreate 拷贝，不解引用。
    let keys: [CFTypeRef; 6] = unsafe {
        [
            kSecClass as CFTypeRef,
            kSecAttrService as CFTypeRef,
            kSecAttrAccount as CFTypeRef,
            kSecAttrAccessGroup as CFTypeRef,
            kSecReturnData as CFTypeRef,
            kSecUseDataProtectionKeychain as CFTypeRef,
        ]
    };
    let values: [CFTypeRef; 6] = unsafe {
        [
            kSecClassGenericPassword as CFTypeRef,
            service_cf as CFTypeRef,
            account_cf as CFTypeRef,
            access_group_cf as CFTypeRef,
            kCFBooleanTrue as CFTypeRef,
            kCFBooleanTrue as CFTypeRef,
        ]
    };

    // SAFETY：CFDictionaryCreate 按 create 规则返回 +1 的 CFDictionaryRef（保留
    // keys/values）；keys/values 数组在调用期间存活。null 表示分配失败。
    let query = unsafe {
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    };
    // query 已 retain 三个 CFString（无论创建成败，本函数都持有本地 +1 引用）——
    // 统一在此释放，防泄漏。
    // SAFETY：三个 CFString 均来自本函数 cf_string 的成功返回（非空）。
    unsafe {
        CFRelease(service_cf as CFTypeRef);
        CFRelease(account_cf as CFTypeRef);
        CFRelease(access_group_cf as CFTypeRef);
    }
    if query.is_null() {
        return Err(EscrowKeychainError::Platform(
            "CFDictionaryCreate returned null",
        ));
    }

    let mut result: CFTypeRef = std::ptr::null();
    // SAFETY：query 是有效 CFDictionaryRef（本函数返回前 CFRelease）；result 是
    // 栈上有效写缓冲。返回 errSecSuccess 时 result 为 +1 的 CFDataRef（拷贝后须
    // CFRelease）；其余状态 result 未写入、不得读取。
    let status = unsafe { SecItemCopyMatching(query, &mut result) };
    // SAFETY：query 的 +1 引用到此释放（本函数不再使用）。
    unsafe { CFRelease(query as CFTypeRef) };

    match classify_status(status)? {
        None => Ok(None),
        Some(()) => {
            if result.is_null() {
                // 不应发生（errSecSuccess + kSecReturnData=true 必有数据），防御性拒绝。
                return Err(EscrowKeychainError::Platform(
                    "errSecSuccess but result is null",
                ));
            }
            let data_ref = result as CFDataRef;
            // SAFETY：result 为有效 CFDataRef（errSecSuccess 契约）；下述只读调用
            // 不修改 Keychain。CFDataGetBytePtr 返回的指针在 CFRelease 前有效。
            let len = unsafe { CFDataGetLength(data_ref) };
            let ptr = unsafe { CFDataGetBytePtr(data_ref) };
            if ptr.is_null() {
                // SAFETY：release 本函数持有的 +1 引用。
                unsafe { CFRelease(result) };
                return Err(EscrowKeychainError::Platform(
                    "CFDataGetBytePtr returned null",
                ));
            }
            let data = if len <= 0 {
                Vec::new()
            } else {
                // SAFETY：len>0 时有效 CFData 保证 ptr 指向 len 字节连续内存
                // （CFData 不可变，只读借用即可，无需拷贝所有权转移）。
                let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                slice.to_vec()
            };
            // SAFETY：release 本函数持有的 +1 引用（数据已拷贝出）。
            unsafe { CFRelease(result) };
            Ok(Some(data))
        }
    }
}

/// 非 macOS：无可用安全存储，明确 `Unsupported`（调用方据此拒绝托管、不落明文）。
#[cfg(not(target_os = "macos"))]
pub fn read_generic_password(
    _service: &str,
    _account: &str,
    _access_group: &str,
) -> Result<Option<Vec<u8>>, EscrowKeychainError> {
    Err(EscrowKeychainError::Unsupported)
}

/// 由 `&str` 创建 CFStringRef（+1 引用，调用方负责 `CFRelease`）。
///
/// 入参含内嵌 NUL → [`EscrowKeychainError::InvalidArgument`]；分配失败 → `Platform`。
#[cfg(target_os = "macos")]
fn cf_string(value: &str) -> Result<CFStringRef, EscrowKeychainError> {
    let cstr = std::ffi::CString::new(value)
        .map_err(|_| EscrowKeychainError::InvalidArgument("string contains interior NUL"))?;
    // SAFETY：cstr 在本调用期间存活；kCFStringEncodingUTF8 按字节拷贝进新 CFString
    //（+1 引用，调用方负责释放）。
    let s = unsafe {
        CFStringCreateWithCString(kCFAllocatorDefault, cstr.as_ptr(), kCFStringEncodingUTF8)
    };
    if s.is_null() {
        Err(EscrowKeychainError::Platform(
            "CFStringCreateWithCString returned null",
        ))
    } else {
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三态映射纯逻辑：errSecSuccess → 成功；errSecItemNotFound → `Ok(None)`；
    /// 其余 OSStatus → `Err(OsStatus)`（含原始错误码）。
    #[test]
    fn classify_status_maps_three_states() {
        assert_eq!(classify_status(errSecSuccess).unwrap(), Some(()));
        assert_eq!(classify_status(errSecItemNotFound).unwrap(), None);
        assert!(matches!(
            classify_status(-50),
            Err(EscrowKeychainError::OsStatus { code: -50, .. })
        ));
        assert!(classify_status(-25293).is_err());
        assert!(classify_status(-25308).is_err());
    }

    /// 错误描述含原始错误码与可读文本（调用方可操作，fail-closed 不吞错误）。
    #[test]
    fn os_status_description_is_readable() {
        let e = EscrowKeychainError::os_status(-34018);
        let msg = e.to_string();
        assert!(msg.contains("-34018"), "必须含原始错误码: {msg}");
        assert!(msg.contains("errSecMissingEntitlement"), "必须含可读名: {msg}");
    }

    /// 载荷纪律（docs/30 §1.2）：错误类型不携带密钥材料——Debug/Display 均不泄露。
    /// 结构性保证：`EscrowKeychainError` 无任何可容纳数据的字段；本测试守卫未来
    /// 误引入数据字段时的回归（对照 challenge_does_not_store_plaintext 同型）。
    #[test]
    fn error_debug_never_contains_key_material() {
        let probe = "top-secret-escrow-key-material-00000000000000000000000000000000";
        let err = EscrowKeychainError::os_status(-25300);
        assert!(
            !format!("{err:?}").contains(probe),
            "Debug 表示不得泄露密钥材料"
        );
        assert!(
            !format!("{err}").contains(probe),
            "Display 表示不得泄露密钥材料"
        );
    }

    /// 入参校验 fail-fast：空串 / 内嵌 NUL 在触 FFI 前即拒绝（纯逻辑，不碰钥匙串）。
    #[cfg(target_os = "macos")]
    #[test]
    fn empty_or_nul_inputs_rejected() {
        assert!(matches!(
            read_generic_password("", "acct", "grp"),
            Err(EscrowKeychainError::InvalidArgument(_))
        ));
        assert!(matches!(
            read_generic_password("svc", "", "grp"),
            Err(EscrowKeychainError::InvalidArgument(_))
        ));
        assert!(matches!(
            read_generic_password("svc", "acct", ""),
            Err(EscrowKeychainError::InvalidArgument(_))
        ));
        assert!(matches!(
            read_generic_password("svc\0nul", "acct", "grp"),
            Err(EscrowKeychainError::InvalidArgument(_))
        ));
    }

    /// 非 macOS：read 明确 `Unsupported`（调用方据此跳过，不静默假成功）。
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn read_unsupported_off_macos() {
        assert!(matches!(
            read_generic_password("svc", "acct", "grp"),
            Err(EscrowKeychainError::Unsupported)
        ));
    }

    /// 真 Keychain 往返集成测试——**真机/签名环境执行**：需有效签名身份 +
    /// `keychain-access-groups` entitlement（数据保护钥匙串访问），参照
    /// `tools/run_keychain_tests.sh` 先例。普通 `cargo test` 跳过（`#[ignore]`）：
    /// ```text
    /// PATH=~/.cargo/bin:$PATH cargo test -p cf-escrow-keychain -- --ignored
    /// ```
    /// 无签名 / 无 entitlement 的环境（CI 沙盒）此处 `SecItemAdd` 即失败——这正是
    /// 标 `#[ignore]` 的原因，勿在常规门禁中开启。
    #[cfg(target_os = "macos")]
    mod keychain_integration {
        use super::*;
        use core_foundation_sys::data::CFDataCreate;
        use core_foundation_sys::dictionary::CFDictionaryRef;
        use security_framework_sys::item::kSecValueData;
        use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};

        /// 测试辅助：由（键,值）对列表构建 CFDictionary（+1，调用方 CFRelease）。
        fn test_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> CFDictionaryRef {
            let keys: Vec<CFTypeRef> = pairs.iter().map(|(k, _)| *k).collect();
            let values: Vec<CFTypeRef> = pairs.iter().map(|(_, v)| *v).collect();
            // SAFETY：测试辅助，数组在调用期间存活；返回值 +1 由调用方释放。
            unsafe {
                CFDictionaryCreate(
                    kCFAllocatorDefault,
                    keys.as_ptr(),
                    values.as_ptr(),
                    pairs.len() as CFIndex,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                )
            }
        }

        /// 测试辅助：CFString（+1，调用方 CFRelease）。
        fn test_cf_string(s: &str) -> CFStringRef {
            let cstr = std::ffi::CString::new(s).expect("no interior NUL");
            // SAFETY：测试辅助，cstr 调用期间存活。
            unsafe {
                CFStringCreateWithCString(kCFAllocatorDefault, cstr.as_ptr(), kCFStringEncodingUTF8)
            }
        }

        /// 写入属性（与 Swift 侧 McpEscrowKeychain 同口径：DataProtectionKeychain +
        /// access group）。返回 +1 CFDictionaryRef，调用方 CFRelease。
        fn write_attributes(service: &str, account: &str, group: &str, data: &[u8]) -> CFDictionaryRef {
            let service_cf = test_cf_string(service);
            let account_cf = test_cf_string(account);
            let group_cf = test_cf_string(group);
            // SAFETY：测试辅助，CFDataCreate 拷贝 data 字节，+1 由下方释放。
            let data_cf = unsafe {
                CFDataCreate(kCFAllocatorDefault, data.as_ptr(), data.len() as CFIndex)
            };
            // SAFETY：读 extern 常量（kSec* / kCFBooleanTrue）在 Rust 中属 unsafe
            // 操作；只取指针值交给 CFDictionaryCreate，不解引用（同生产路径）。
            let pairs: [(CFTypeRef, CFTypeRef); 6] = unsafe {
                [
                    (kSecClass as CFTypeRef, kSecClassGenericPassword as CFTypeRef),
                    (kSecAttrService as CFTypeRef, service_cf as CFTypeRef),
                    (kSecAttrAccount as CFTypeRef, account_cf as CFTypeRef),
                    (kSecAttrAccessGroup as CFTypeRef, group_cf as CFTypeRef),
                    (kSecValueData as CFTypeRef, data_cf as CFTypeRef),
                    (kSecUseDataProtectionKeychain as CFTypeRef, kCFBooleanTrue as CFTypeRef),
                ]
            };
            let dict = test_dict(&pairs);
            // SAFETY：dict 已 retain 四个 CF 对象，释放本地 +1 引用。
            unsafe {
                CFRelease(service_cf as CFTypeRef);
                CFRelease(account_cf as CFTypeRef);
                CFRelease(group_cf as CFTypeRef);
                CFRelease(data_cf as CFTypeRef);
            }
            dict
        }

        /// 删除查询（幂等；与读取同口径定位）。
        fn delete_query(service: &str, account: &str, group: &str) -> CFDictionaryRef {
            let service_cf = test_cf_string(service);
            let account_cf = test_cf_string(account);
            let group_cf = test_cf_string(group);
            // SAFETY：读 extern 常量属 unsafe 操作；只取指针值，不解引用。
            let pairs: [(CFTypeRef, CFTypeRef); 5] = unsafe {
                [
                    (kSecClass as CFTypeRef, kSecClassGenericPassword as CFTypeRef),
                    (kSecAttrService as CFTypeRef, service_cf as CFTypeRef),
                    (kSecAttrAccount as CFTypeRef, account_cf as CFTypeRef),
                    (kSecAttrAccessGroup as CFTypeRef, group_cf as CFTypeRef),
                    (kSecUseDataProtectionKeychain as CFTypeRef, kCFBooleanTrue as CFTypeRef),
                ]
            };
            let dict = test_dict(&pairs);
            // SAFETY：dict 已 retain 三个 CFString，释放本地 +1 引用。
            unsafe {
                CFRelease(service_cf as CFTypeRef);
                CFRelease(account_cf as CFTypeRef);
                CFRelease(group_cf as CFTypeRef);
            }
            dict
        }

        /// 写入 → 读取逐字节一致；删除后 read 须 `Ok(None)`（吊销即独立吊销，
        /// docs/30 §1.2）。多库隔离由 account=vault_uuid 定位覆盖（此处用唯一化
        /// account 验证条目定位不串库）。
        #[test]
        #[ignore = "真机/签名环境执行：需 keychain-access-groups entitlement + 签名身份"]
        fn real_keychain_roundtrip() {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before epoch")
                .as_nanos();
            let service = format!("cn.coffer.escrow-test.{nanos}");
            let account = format!("vault-{nanos}");
            let access_group = "A6DS985SJJ.app.coffer.Coffer";
            let secret: &[u8] = b"mcp-key-material-for-roundtrip-test";

            let attrs = write_attributes(&service, &account, access_group, secret);
            // SAFETY：attrs 为有效属性字典（+1，调用后释放）；无 result 出参。
            let status = unsafe { SecItemAdd(attrs, std::ptr::null_mut()) };
            // SAFETY：attrs +1 引用释放。
            unsafe { CFRelease(attrs as CFTypeRef) };
            assert_eq!(
                status,
                errSecSuccess,
                "SecItemAdd 失败（无签名/entitlement 环境此处即红）: status={status}"
            );

            let got = read_generic_password(&service, &account, access_group)
                .expect("read must succeed in signed env")
                .expect("item must exist after write");
            assert_eq!(got, secret, "roundtrip 必须逐字节一致");

            let del = delete_query(&service, &account, access_group);
            // SAFETY：del 为有效查询字典（+1，调用后释放）。
            let status = unsafe { SecItemDelete(del) };
            // SAFETY：del +1 引用释放。
            unsafe { CFRelease(del as CFTypeRef) };
            assert_eq!(status, errSecSuccess, "SecItemDelete 失败: status={status}");

            assert!(
                read_generic_password(&service, &account, access_group)
                    .expect("read must succeed after delete")
                    .is_none(),
                "删除后 read 须 Ok(None)"
            );
        }
    }
}
