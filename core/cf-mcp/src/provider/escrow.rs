//! MCP 解锁托管 Keychain 读取抽象（docs/29 §4.2，G3a）。
//!
//! # 职责
//!
//! [`VaultEscrowStore`] trait 是 cf-mcp（**唯一消费者**，docs/29 §4.2）对
//! MCP 托管条目的读取抽象：给定库 UUID，返回该库的 mcp_key（32 字节）。
//! 平台实现：
//!
//! - **macOS**：[`MacKeychainEscrow`] 调 `cf-escrow-keychain` sys crate 读
//!   Keychain GenericPassword（service / access group 见 docs/29 §5.1 冻结
//!   字面量）。cf-mcp 是 `#![forbid(unsafe_code)]` crate，Keychain FFI（unsafe）
//!   隔离在 sys crate（cf-mcp → cf-uds-sys 先例同构，docs/29 §4.1）。
//! - **非 macOS**：[`UnsupportedEscrow`] 返回 `Err(Other)`（无可用安全存储，
//!   端口预留——Secret Service → 内核 keyring → 均无则拒绝，不落明文文件，
//!   docs/29 §9 开放问题 7；docs/30 §1.2）。
//!
//! # 写路径
//!
//! **v2.2.0 不实现**（docs/29 §4.2）：save/delete 由 App Swift 侧
//! `McpEscrowKeychain.swift` 承担（与 `BiometricKeychain.swift` 同构，
//! docs/29 §5）。
//!
//! # 载荷纪律（docs/30 §1.2）
//!
//! 密钥材料只在返回值 `Ok(Some([u8; 32]))` 中出现；[`EscrowError`] 不携带
//! 任何密钥材料（只有 kind + 描述文本），Debug/Display 均不泄露。
//!
//! # 错误语义（fail-closed，docs/29 §6.2 / D-4）
//!
//! - `Ok(Some(key))`：托管存在且可读 → 调用方 `unlock_with_mcp_key`；
//! - `Ok(None)`：托管**不存在**（`errSecItemNotFound`）→ 合法的 env 兜底分支；
//! - `Err(..)`：读取失败（ACL / 签名 / 内容非法）→ **须 fail-closed**（CLI
//!   报错退出 1，不回退 env——防掩盖签名 / ACL 问题，docs/30 §1.3）。
//!
//! # access group 兼容（BUG-33）
//!
//! App 自改名后把托管条目写入当前 bundle id 对应的组
//! `A6DS985SJJ.top.cygnusyang.coffer`，而本模块曾冻结在改名前的旧组
//! `A6DS985SJJ.app.coffer.Coffer` → 查询全落 `errSecItemNotFound` →
//! `Ok(None)` → 误走 env 兜底（表现为「未启用 MCP 解锁托管」）。
//!
//! 修复口径：**只扩大读取面**——[`access_group_candidates`] 返回
//! [主组（当前 bundle id）, legacy 组（改名前的历史条目）]，按序试读：
//! 首条命中即返回，主组 `Ok(None)` 才继续 legacy，任何 `Err` 立即
//! fail-closed。Keychain 条目与 App 写入路径**不动**（非破坏性格式变更，
//! 旧版 helper 与历史条目均不受影响）。

use std::fmt;

use cf_session::MCP_KEYCHAIN_SERVICE;

/// 主 Keychain access group：当前 App bundle id（`top.cygnusyang.coffer`）对应的组。
///
/// 与 `macos/Coffer/Coffer.entitlements` 及 App 写入路径
/// `macos/Coffer/Platform/McpEscrowKeychain.swift:67` 同组——托管条目**实际所在**
/// 的组（BUG-33：此处曾停在改名前的旧组，导致读取全落 `errSecItemNotFound`）。
/// 组内二进制读取静默放行，无跨组同意弹窗（docs/29 §9 风险 1 实证）。
pub const ESCROW_ACCESS_GROUP: &str = "A6DS985SJJ.top.cygnusyang.coffer";

/// legacy Keychain access group：App 改名（bundle id `app.coffer.Coffer` →
/// `top.cygnusyang.coffer`）之前写入的托管条目所在组。
///
/// 仅作**读取兜底**：保留它以让老库的托管条目仍可解锁，不迁移、不删除
/// Keychain 条目（非破坏性）。App 新写入一律进 [`ESCROW_ACCESS_GROUP`]。
pub const ESCROW_ACCESS_GROUP_LEGACY: &str = "A6DS985SJJ.app.coffer.Coffer";

/// 读取候选 access group，顺序为 **[主组, legacy 组]**。
///
/// 读取按此顺序试：主组命中即返回；主组 `Ok(None)`（条目不存在）才继续
/// legacy；任一候选返回错误立即 fail-closed（见 [`VaultEscrowStore::read_mcp_key`]
/// 的错误语义，绝不因兜底而掩盖缺 entitlement / ACL 问题）。
pub fn access_group_candidates() -> [&'static str; 2] {
    [ESCROW_ACCESS_GROUP, ESCROW_ACCESS_GROUP_LEGACY]
}

/// Escrow 错误类别（docs/29 §4.2 冻结：三类）。
///
/// CLI 取密流程（docs/29 §6.2）对三类**均 fail-closed 退出 1**，类别只用于
/// 面向调用方的可操作提示分档。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowErrorKind {
    /// 条目存在但内容非法（如长度 ≠ 32）——非有效 mcp_key，建议重建托管。
    NotFound,
    /// Keychain 读取被拒（缺 entitlement / ACL / 签名问题）——检查 CLI 签名
    /// 与 App 同 bundle 同身份（docs/29 D-6）。
    AccessDenied,
    /// 平台不可用 / 其他底层失败。
    Other,
}

/// Escrow 读取错误（docs/29 §4.2）。
///
/// 载荷纪律：**不携带任何密钥材料**——只有类别 + 描述文本，Debug/Display
/// 均不泄露（docs/30 §1.2；结构性保证同 cf-escrow-keychain 的
/// `error_debug_never_contains_key_material` 守卫）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowError {
    kind: EscrowErrorKind,
    message: String,
}

impl EscrowError {
    /// 按类别 + 可操作描述构造（调用方保证 `message` 不含密钥材料）。
    #[must_use]
    pub fn new(kind: EscrowErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// 条目存在但内容非法（docs/29 §6.2 fail-closed 分支）。
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(EscrowErrorKind::NotFound, message)
    }

    /// Keychain 读取被拒（缺 entitlement / ACL / 签名问题）。
    #[must_use]
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new(EscrowErrorKind::AccessDenied, message)
    }

    /// 平台不可用 / 其他底层失败。
    #[must_use]
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(EscrowErrorKind::Other, message)
    }

    /// 错误类别（供调用方按类分档提示）。
    #[must_use]
    pub fn kind(&self) -> EscrowErrorKind {
        self.kind
    }
}

impl fmt::Display for EscrowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            EscrowErrorKind::NotFound => "not found",
            EscrowErrorKind::AccessDenied => "access denied",
            EscrowErrorKind::Other => "other",
        };
        write!(f, "escrow {kind}: {}", self.message)
    }
}

impl std::error::Error for EscrowError {}

/// MCP 托管读取抽象（docs/29 §4.2，D-5 冻结签名）。
///
/// `Send + Sync`：trait 实例跨线程安全（CLI 单线程持有，保持与
/// [`super::SecretProvider`] 同界）。**只读**：写路径归 App Swift 侧。
pub trait VaultEscrowStore: Send + Sync {
    /// 读某库的 mcp_key。
    ///
    /// - `Ok(Some(key))` = 托管存在且可读（`key` 为 32 字节 mcp_key）；
    /// - `Ok(None)` = 托管**不存在**（`errSecItemNotFound`；调用方走 env 兜底）；
    /// - `Err(..)` = 读取失败（ACL / 签名 / 内容非法等，**须 fail-closed**）。
    ///
    /// # 载荷纪律
    ///
    /// `key` 是 Copy 数组，调用方负责用后 zeroize（docs/30 §1.2 内存纪律）。
    fn read_mcp_key(&self, vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError>;
}

// ---------------------------------------------------------------------------
// macOS 实现（真路径，写归 App Swift；docs/29 §4.2 / D-6 同 bundle 分发）
// ---------------------------------------------------------------------------

/// macOS Keychain escrow 实现（docs/29 §4.2）。
///
/// 查询条件（docs/29 §5.1 / D-2）：`kSecClassGenericPassword` +
/// service `cn.coffer.mcp-escrow` + account `vault_uuid` +
/// access group 按 [`access_group_candidates`] 顺序试读（主组
/// `A6DS985SJJ.top.cygnusyang.coffer` → legacy 组
/// `A6DS985SJJ.app.coffer.Coffer`；BUG-33 改名兼容，数据保护
/// Keychain 同口径，由 `cf-escrow-keychain` 承载 FFI）。
///
/// 本类型零字段（无状态适配器）；`read_mcp_key` 的 FFI 调用隔离在
/// `cf-escrow-keychain`（unsafe 面，cf-mcp 保持 `forbid(unsafe_code)`）。
#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MacKeychainEscrow;

#[cfg(target_os = "macos")]
impl MacKeychainEscrow {
    /// 纯逻辑：把 `cf-escrow-keychain` 的三态结果映射为 trait 三态。
    ///
    /// 单独成函数便于单测（不触 FFI）：
    /// - `Ok(Some(data))`：长度 ≠ 32 → `Err(NotFound)`（条目存在但内容非法，
    ///   **fail-closed**，不回落 env——半写/损坏条目须重建托管而非静默兜底）；
    ///   长度合法 → `Ok(Some([u8; 32]))`；
    /// - `Ok(None)` → `Ok(None)`（托管不存在，合法 env 兜底分支）；
    /// - `Err(..)` → 按错误码归类（-34018 缺 entitlement / -25293 auth /
    ///   -25308 interaction 属 `AccessDenied`，其余 `Other`）。
    fn map_read(
        r: Result<Option<Vec<u8>>, cf_escrow_keychain::EscrowKeychainError>,
    ) -> Result<Option<[u8; 32]>, EscrowError> {
        let data = match r {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(None),
            Err(e) => return Err(Self::map_err(e)),
        };
        match <[u8; 32]>::try_from(data.as_slice()) {
            Ok(key) => Ok(Some(key)),
            Err(_) => Err(EscrowError::not_found(format!(
                "keychain item exists but is not a {}-byte mcp_key (len {})",
                32,
                data.len()
            ))),
        }
    }

    /// 按 [`access_group_candidates`] 顺序试读，命中或失败即停（BUG-33）。
    ///
    /// `read` 注入单次 Keychain 查询（参数为 `(account, access_group)`；
    /// 生产为 `cf_escrow_keychain::read_generic_password`，单测为闭包），故本函数
    /// 可完全不触 FFI 地覆盖三态 × 多候选的组合：
    ///
    /// - `Ok(Some(_))`：命中 → 经 [`map_read`] 校验长度后返回（内容非法
    ///   同样按 `Err` 返回，不再试后续候选）；
    /// - `Ok(None)`：该组无条目 → 继续下一个候选（主组无、legacy 有 = 改名前的
    ///   历史条目仍可解锁；全部无 → `Ok(None)` 走 env 兜底）；
    /// - `Err(..)`：立即返回 `Err`（**fail-closed**，不试 legacy——兜底不得
    ///   掩盖缺 entitlement / ACL / 签名问题，docs/30 §1.3）。
    fn read_with(
        vault_uuid: &str,
        read: impl Fn(&str, &str) -> Result<Option<Vec<u8>>, cf_escrow_keychain::EscrowKeychainError>,
    ) -> Result<Option<[u8; 32]>, EscrowError> {
        for access_group in access_group_candidates() {
            match Self::map_read(read(vault_uuid, access_group)) {
                Ok(Some(key)) => return Ok(Some(key)),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// 把 `cf-escrow-keychain` 错误归类为 [`EscrowError`]（fail-closed，类别
    /// 只影响调用方可操作提示分档）。
    fn map_err(e: cf_escrow_keychain::EscrowKeychainError) -> EscrowError {
        use cf_escrow_keychain::EscrowKeychainError;

        match e {
            // 无 entitlement（-34018）/ 认证失败（-25293）/ 交互被禁（-25308）：
            // 签名 / ACL / 分发问题 → AccessDenied（docs/29 D-6 排查指引）。
            EscrowKeychainError::OsStatus { code: -34018, .. }
            | EscrowKeychainError::OsStatus { code: -25293, .. }
            | EscrowKeychainError::OsStatus { code: -25308, .. } => {
                EscrowError::access_denied(format!("keychain read denied: {e}"))
            }
            // 其余 OSStatus / CF 层失败 → Other（含原始码，调用方可操作）。
            EscrowKeychainError::OsStatus { .. }
            | EscrowKeychainError::Platform(_)
            | EscrowKeychainError::InvalidArgument(_) => {
                EscrowError::other(format!("keychain read failed: {e}"))
            }
            // 非 macOS 在本 cfg 分支不可达（非 macOS 用 UnsupportedEscrow），
            // 但仍显式归类，不静默吞错误。
            EscrowKeychainError::Unsupported => {
                EscrowError::other(format!("keychain escrow unsupported: {e}"))
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl VaultEscrowStore for MacKeychainEscrow {
    fn read_mcp_key(&self, vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError> {
        Self::read_with(vault_uuid, |account, access_group| {
            cf_escrow_keychain::read_generic_password(MCP_KEYCHAIN_SERVICE, account, access_group)
        })
    }
}

// ---------------------------------------------------------------------------
// 非 macOS 实现（端口预留：无可用安全存储，明确拒绝，不落明文文件）
// ---------------------------------------------------------------------------

/// 非 macOS 占位实现（docs/29 §4.2 端口预留）。
///
/// Linux Secret Service / 内核 keyring 实现 v2.2.0 不提供（docs/29 §9 开放
/// 问题 7）；本实现返回 `Err(Other)`（fail-closed），调用方据此拒绝托管、
/// **不落明文文件**（docs/30 §1.2）。
#[cfg(not(target_os = "macos"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedEscrow;

#[cfg(not(target_os = "macos"))]
impl VaultEscrowStore for UnsupportedEscrow {
    fn read_mcp_key(&self, _vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError> {
        Err(EscrowError::other(
            "MCP escrow unsupported on this platform (macOS Keychain required)",
        ))
    }
}

/// 平台默认 escrow store 工厂（CLI 取密流程用，docs/29 §6.2）。
///
/// - macOS：[`MacKeychainEscrow`]（Keychain 读，D-6 同 bundle 分发）；
/// - 其他：无可用安全存储 → [`UnsupportedEscrow`]（fail-closed 拒绝托管）。
#[cfg(target_os = "macos")]
pub fn platform_escrow() -> MacKeychainEscrow {
    MacKeychainEscrow
}

/// 平台默认 escrow store 工厂（非 macOS 端口预留，docs/29 §9 开放问题 7）。
#[cfg(not(target_os = "macos"))]
pub fn platform_escrow() -> UnsupportedEscrow {
    UnsupportedEscrow
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cf_escrow_keychain::EscrowKeychainError;

    /// 三态映射（不触 FFI，纯逻辑）：
    /// - 合法 32 字节 → `Ok(Some(key))` 逐字节一致；
    /// - `Ok(None)` → `Ok(None)`（托管不存在，合法 env 兜底分支）；
    /// - 非法长度（31/33/空）→ `Err(NotFound)`（fail-closed，不回落 env）。
    #[cfg(target_os = "macos")]
    #[test]
    fn map_read_maps_three_states_and_rejects_bad_length() {
        let key = [0x42u8; 32];
        let ok = MacKeychainEscrow::map_read(Ok(Some(key.to_vec())))
            .expect("valid 32-byte key must map to Ok(Some)")
            .expect("must be Some");
        assert_eq!(ok, key);

        assert!(
            MacKeychainEscrow::map_read(Ok(None))
                .expect("Ok(None) must map to Ok(None)")
                .is_none(),
            "item not found → Ok(None)"
        );

        for bad in [31usize, 33, 0] {
            let e = MacKeychainEscrow::map_read(Ok(Some(vec![0xAB; bad])))
                .expect_err("bad length must be Err (fail-closed)");
            assert_eq!(e.kind(), EscrowErrorKind::NotFound, "len {bad}");
            assert!(e.message.contains("not a 32-byte mcp_key"), "len {bad}: {}", e.message);
        }
    }

    /// 构造指定 OSStatus 的 cf-escrow-keychain 错误（测试用；enum 变体字段公开）。
    #[cfg(target_os = "macos")]
    fn os_err(code: i32) -> EscrowKeychainError {
        EscrowKeychainError::OsStatus {
            code,
            description: format!("test osstatus {code}"),
        }
    }

    /// 错误归类：-34018（缺 entitlement）/ -25293（auth）/ -25308（interaction）
    /// → `AccessDenied`；其余 OSStatus / CF 层失败 → `Other`。
    #[cfg(target_os = "macos")]
    #[test]
    fn map_err_classifies_osstatus() {
        let denied = [-34018, -25293, -25308];
        for code in denied {
            let e = MacKeychainEscrow::map_err(os_err(code));
            assert_eq!(
                e.kind(),
                EscrowErrorKind::AccessDenied,
                "code {code} must be AccessDenied"
            );
            assert!(
                !format!("{e:?}").contains("key-material"),
                "Debug 不得泄露密钥材料"
            );
        }
        let others = [-50, -25291, -25299];
        for code in others {
            let e = MacKeychainEscrow::map_err(os_err(code));
            assert_eq!(e.kind(), EscrowErrorKind::Other, "code {code} must be Other");
        }
        // InvalidArgument / Unsupported → Other（fail-closed，不静默吞错误）。
        for e in [
            EscrowKeychainError::InvalidArgument("bad"),
            EscrowKeychainError::Platform("cf failed"),
            EscrowKeychainError::Unsupported,
        ] {
            assert_eq!(
                MacKeychainEscrow::map_err(e).kind(),
                EscrowErrorKind::Other,
                "non-OsStatus failures must be Other"
            );
        }
    }

    /// 候选读组顺序（BUG-33）：**主组在前**（当前 App bundle id
    /// `top.cygnusyang.coffer` 对应的组，App 写入路径 McpEscrowKeychain.swift:67），
    /// **legacy 组在后**（改名前的 `app.coffer.Coffer` 组，仅兜底历史条目）。
    ///
    /// 断言字面量而非仅互相引用——防止常量被改成「两个相同的组」或顺序被对调
    /// 后测试仍然自洽（BUG-33 的正是「读到旧组」这类静默错配）。
    #[test]
    fn access_group_candidates_put_current_group_first() {
        assert_eq!(
            access_group_candidates(),
            [
                "A6DS985SJJ.top.cygnusyang.coffer",
                "A6DS985SJJ.app.coffer.Coffer"
            ],
            "候选顺序须为 [当前组, legacy 组]"
        );
        // 下面两行是**别名自检**（常量名 ↔ 候选表位置的绑定），本身近乎恒真；
        // 防漂移的主断言是上面那条字面量比较——改常量值或换顺序，主断言必红。
        assert_eq!(access_group_candidates()[0], ESCROW_ACCESS_GROUP);
        assert_eq!(access_group_candidates()[1], ESCROW_ACCESS_GROUP_LEGACY);
    }

    /// 按候选顺序读取的可测核心（`read_with`，不触 FFI）：记录每次实际被查的
    /// access group，便于断言「是否继续下一个候选」。
    #[cfg(target_os = "macos")]
    struct ReadLog {
        groups: std::cell::RefCell<Vec<String>>,
    }

    #[cfg(target_os = "macos")]
    impl ReadLog {
        fn new() -> Self {
            Self {
                groups: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn called(&self) -> Vec<String> {
            self.groups.borrow().clone()
        }
    }

    /// 期望的候选组序列（String 形式，与 [`ReadLog::called`] 直接比较）。
    #[cfg(target_os = "macos")]
    fn expected_groups(groups: &[&str]) -> Vec<String> {
        groups.iter().map(|g| (*g).to_string()).collect()
    }

    /// 主组 `Ok(None)` + legacy `Ok(Some(32B))` → 命中 legacy（改名前的历史
    /// 条目仍可读，向后兼容），且主组先被查。
    #[cfg(target_os = "macos")]
    #[test]
    fn read_with_falls_back_to_legacy_group_on_not_found() {
        let log = ReadLog::new();
        let key = [0x5Au8; 32];
        let got = MacKeychainEscrow::read_with("uuid-1", |account, group| {
            assert_eq!(account, "uuid-1", "account 须为 vault_uuid");
            log.groups.borrow_mut().push(group.to_string());
            if group == ESCROW_ACCESS_GROUP {
                Ok(None)
            } else {
                Ok(Some(key.to_vec()))
            }
        })
        .expect("legacy 组命中须 Ok(Some)")
        .expect("must be Some");
        assert_eq!(got, key);
        assert_eq!(
            log.called(),
            expected_groups(&[ESCROW_ACCESS_GROUP, ESCROW_ACCESS_GROUP_LEGACY]),
            "须先查主组、再兜底查 legacy 组"
        );
    }

    /// 主组 `Ok(Some)` → 直接返回，**legacy 不被调用**（不做无谓的第二次
    /// Keychain 查询）。
    #[cfg(target_os = "macos")]
    #[test]
    fn read_with_returns_immediately_on_current_group_hit() {
        let log = ReadLog::new();
        let key = [0x11u8; 32];
        let got = MacKeychainEscrow::read_with("uuid-1", |_, group| {
            log.groups.borrow_mut().push(group.to_string());
            Ok(Some(key.to_vec()))
        })
        .expect("主组命中须 Ok(Some)")
        .expect("must be Some");
        assert_eq!(got, key);
        assert_eq!(
            log.called(),
            expected_groups(&[ESCROW_ACCESS_GROUP]),
            "主组命中后不得再查 legacy 组"
        );
    }

    /// 主组返回**坏长度**数据（31 字节）→ `Err(NotFound)` 且 **不查 legacy**。
    ///
    /// 守卫的是 `map_read` 与 `read_with` 的组合语义：坏长度不是「条目不存在」，
    /// 若 `map_read` 被改成把非法长度降级为 `Ok(None)`，本函数就会**静默转去
    /// 读 legacy 组**，把半写 / 损坏的托管条目掩盖成另一个组的命中（fail-closed 被破坏）。
    /// 单测在 map_read 层无法捕获这类改动——只有 `read_with` 层能锁住「不得兜底」。
    #[cfg(target_os = "macos")]
    #[test]
    fn read_with_bad_length_on_current_group_does_not_fall_back() {
        let log = ReadLog::new();
        let e = MacKeychainEscrow::read_with("uuid-1", |_, group| {
            log.groups.borrow_mut().push(group.to_string());
            Ok(Some(vec![0u8; 31]))
        })
        .expect_err("坏长度须 Err（fail-closed，不得降级为 Ok(None)）");
        assert_eq!(
            e.kind(),
            EscrowErrorKind::NotFound,
            "条目存在但内容非法 → NotFound"
        );
        assert_eq!(
            log.called(),
            expected_groups(&[ESCROW_ACCESS_GROUP]),
            "坏长度不得触发 legacy 兜底"
        );
    }

    /// 主组 `Err(-34018)`（缺 entitlement）→ `AccessDenied` 且 **不查 legacy**
    /// （fail-closed：绝不因兜底而掩盖 entitlement / ACL 错误）。
    #[cfg(target_os = "macos")]
    #[test]
    fn read_with_fails_closed_without_trying_legacy_group() {
        let log = ReadLog::new();
        let e = MacKeychainEscrow::read_with("uuid-1", |_, group| {
            log.groups.borrow_mut().push(group.to_string());
            Err(os_err(-34018))
        })
        .expect_err("读取失败须 Err（fail-closed）");
        assert_eq!(e.kind(), EscrowErrorKind::AccessDenied);
        assert_eq!(
            log.called(),
            expected_groups(&[ESCROW_ACCESS_GROUP]),
            "错误不得触发 legacy 兜底"
        );
    }

    /// 主组 `Ok(None)` + legacy `Ok(None)` → `Ok(None)`（两处均无条目，
    /// 调用方走合法的 env 兜底分支）。
    #[cfg(target_os = "macos")]
    #[test]
    fn read_with_returns_none_when_no_candidate_has_item() {
        let log = ReadLog::new();
        let r = MacKeychainEscrow::read_with("uuid-1", |_, group| {
            log.groups.borrow_mut().push(group.to_string());
            Ok(None)
        })
        .expect("两处均 not found 须 Ok(None)");
        assert!(r.is_none(), "无条目须 Ok(None)");
        assert_eq!(
            log.called(),
            expected_groups(&[ESCROW_ACCESS_GROUP, ESCROW_ACCESS_GROUP_LEGACY]),
            "两个候选均须被查过"
        );
    }

    /// 非 macOS：`UnsupportedEscrow` 恒 `Err(Other)`（fail-closed，不落明文）。
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_escrow_rejects_all_reads() {
        let e = UnsupportedEscrow
            .read_mcp_key("any-uuid")
            .expect_err("non-macOS must reject escrow reads");
        assert_eq!(e.kind(), EscrowErrorKind::Other);
        assert!(
            !format!("{e}").contains("key-material"),
            "Display 不得泄露密钥材料"
        );
    }

    /// `EscrowError` 可操作展示 + 载荷纪律结构性守卫：
    /// - Display 分档（`escrow access denied`）+ 描述文本；
    /// - **结构性守卫**：Debug 表示恰好等于 `kind` + `message` 两个字段——
    ///   未来若有人误加密钥材料字段（如 `key: [u8; 32]`），此断言立即变红。
    ///   （message 由调用方提供，属显式输入；本类型自身不持有密钥材料。）
    #[test]
    fn escrow_error_is_actionable_and_never_carries_key_material() {
        let e = EscrowError::access_denied("denied while reading mcp key");
        assert_eq!(e.kind(), EscrowErrorKind::AccessDenied);
        let display = e.to_string();
        assert!(display.contains("escrow access denied"), "{display}");
        assert_eq!(
            format!("{e:?}"),
            "EscrowError { kind: AccessDenied, message: \"denied while reading mcp key\" }",
            "Debug 不得携带 kind/message 之外的字段（含密钥材料）"
        );
    }

    /// 真 Keychain 读取冒烟——**真机/签名环境执行**（docs/29 D-6：同 bundle
    /// 同身份 + keychain-access-groups entitlement）。普通 `cargo test` 跳过
    /// （`#[ignore]`）：
    /// ```text
    /// PATH=~/.cargo/bin:$PATH cargo test -p cf-mcp escrow -- --ignored
    /// ```
    /// 无签名 / 无 entitlement 环境此处读非存在条目即 `Err(-34018)`（缺
    /// entitlement → AccessDenied，fail-closed），这正是标 `#[ignore]` 的原因。
    /// 完整写→读→删往返由 cf-escrow-keychain 的 `real_keychain_roundtrip`
    /// （同 `#[ignore]`）承担；此处只冒烟「签名环境读非存在条目 = Ok(None)」。
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "真机/签名环境执行：需 keychain-access-groups entitlement + 签名身份"]
    fn mac_keychain_escrow_real_read_smoke() {
        let escrow = MacKeychainEscrow;
        let r = escrow.read_mcp_key("00000000-0000-4000-8000-000000000000");
        match r {
            // 签名环境：该非存在条目必然 Ok(None)（组内无此条目）。
            Ok(None) => {}
            // 无签名/entitlement 环境：-34018 → AccessDenied（fail-closed 正确）。
            Err(e) if e.kind() == EscrowErrorKind::AccessDenied => {}
            other => panic!("unexpected real-read result: {other:?}"),
        }
    }
}
