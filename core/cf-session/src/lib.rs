//! # cf-session —— 会话与应用服务
//!
//! 解锁 / 锁定、用例编排、权限门禁、空闲计时判定、TOTP 验证。
//!
//! ## 对应设计文档
//!
//! - `docs/02-概要设计.md` §4.3（会话与锁定模型）
//! - `docs/03-详细设计.md` §2（密钥层次）、§7（TOTP）、§11（内存安全与自动锁定）
//! - `docs/07-macOS纵切设计.md` §2.2（T02：真实解锁流 / VaultSession / 用例编排）
//!
//! ## 职责边界
//!
//! 本 crate 是**唯一持有 DEK 的模块**（经 [`unlock`] 编排解出后仅以
//! `SubKeys` 形态存于 `ItemStore`，跨 FFI 永不出现）。定时器放在平台侧：
//! 本 crate 只提供时间注入的纯逻辑（[`idle`]）。
//!
//! ## 模块划分（T02 + docs/08 T01）
//!
//! - [`unlock`]：`create_vault`（建库）与 `open_vault`（打开会话）编排；
//!   解锁数据流：NFC 归一化 → Argon2id（参数从 header 读）→ wrapped_dek
//!   解封 → verifier 校验 → `SubKeys::derive` → `ItemStore::open`
//! - [`unlock_bio`]：生物识别（Touch ID）DEK 封装通道（docs/08 v0.2）——
//!   `new_biometric_unwrap_key` / `enable_biometric` / `disable_biometric`
//!   / `unlock_with_biometric` 的会话层内核，AAD 钉库与错误码纪律见其
//!   模块文档
//! - [`vault`]：`VaultSession`——持有 `Mutex<Option<UnlockedState>>`，
//!   `lock()` 置 `None` 触发全链路 `ZeroizeOnDrop` 内存清零
//! - [`idle`]：空闲超时判定的纯函数（时间由平台注入，可测试）
//! - [`usecase`]：条目 CRUD（四类完整 + 只读兜底）与标题搜索编排
//! - [`types`]：跨模块的会话层数据结构（`VaultInfo` / `ItemDetails` / `TotpCode`）
//!
//! ## 错误统一（docs/07 §5 C-6）
//!
//! 本 crate 不再自持错误类型：[`SessionError`] 即 [`cf_domain::CfError`]
//! 的类型别名。解锁路径上的错误合并纪律见 [`unlock`] 模块文档。
//!
//! ## 内存清零边界（docs/07 §2.2）
//!
//! | 位置 | 策略 |
//! | --- | --- |
//! | 主密码 | unlock/create 内 `Zeroizing` 包装，返回前清零 |
//! | DEK / 子密钥 | `SessionKey` / `SubKeys` ZeroizeOnDrop；`lock()` 置 state=None 触发 drop |
//! | 条目明文 | 每次查询临时解密，随返回值生命周期结束；不常驻缓存 |
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod idle;
pub mod types;
pub mod unlock;
pub mod unlock_bio;
pub mod usecase;
pub mod vault;

#[cfg(test)]
mod tests_support;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_totp::TotpConfig;

pub use types::{BiometricStatus, ItemDetails, TotpCode, VaultInfo};
pub use unlock::{create_vault, create_vault_with_kdf, open_vault};
pub use unlock_bio::{new_biometric_unwrap_key, K_BIO_LEN};
pub use vault::VaultSession;

/// 会话层错误类型（docs/07 §5 C-6 统一）。
///
/// 即 [`cf_domain::CfError`]：错误码表见 `docs/03-详细设计.md` §12，
/// UI 层按 [`cf_domain::CfError::code`] 做本地化，不解析消息文本。
pub type SessionError = cf_domain::CfError;

/// 会话层结果别名。
pub type SessionResult<T> = Result<T, SessionError>;

/// `cf-totp` 错误 → 统一错误（3001 TotpError）。
///
/// 载荷仅含算法层摘要（如"密钥过短"），不含密钥材料。
pub(crate) fn totp_error(e: cf_totp::TotpError) -> SessionError {
    cf_domain::CfError::TotpError(e.to_string())
}

/// 当前 Unix 秒；系统时钟早于 epoch 时返回错误（不猜测）。
pub(crate) fn unix_now() -> SessionResult<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| cf_domain::CfError::StorageError("system clock before unix epoch".into()))?
        .as_secs() as i64)
}

/// 常量时间比较，防止验证码 / verifier 比对的时序侧信道。
///
/// 委托 `subtle` 实现：`ConstantTimeEq` 对切片逐元素异或折叠，
/// 不按首个差异字节提前返回（`subtle` 的文档示例即为此用途）。
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// TOTP 会话：一个条目的动态口令验证器
///
/// 时间窗口容错遵循 RFC 6238 §5.2：验证时检查当前窗口及
/// 相邻窗口（默认 ±1 窗口 = ±30s，可配置），防止设备间轻微时钟漂移。
#[derive(Debug, Clone)]
pub struct TotpSession {
    /// TOTP 配置（来自 cf-totp）
    pub totp_config: TotpConfig,
    /// 容错窗口数（默认 ±1 = ±period 秒）
    pub drift_windows: u32,
}

impl TotpSession {
    /// 创建 TOTP 会话，默认 ±1 窗口容错
    #[must_use]
    pub fn new(config: TotpConfig) -> Self {
        Self {
            totp_config: config,
            drift_windows: 1,
        }
    }

    /// 生成当前时间窗口的验证码
    pub fn generate(&self) -> SessionResult<String> {
        self.totp_config.generate().map_err(totp_error)
    }

    /// 验证用户输入的验证码（带时间漂移容错）
    ///
    /// 遍历 `[-drift_windows, +drift_windows]` 范围内的每个计数器，
    /// 任一匹配即通过。
    pub fn verify(&self, code: &str) -> SessionResult<bool> {
        let current = self.current_counter()?;

        for delta in -(self.drift_windows as i64)..=(self.drift_windows as i64) {
            let counter = (current as i64 + delta).max(0) as u64;
            let expected = self
                .totp_config
                .generate_for_counter(counter)
                .map_err(totp_error)?;
            if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 当前时间计数器（时间可注入测试见 `counter_at`）
    fn current_counter(&self) -> SessionResult<u64> {
        let now = unix_now()?;
        Ok((now.max(0) as u64) / u64::from(self.totp_config.period))
    }

    /// 指定 Unix 时间戳对应的计数器（纯函数，供测试与平台侧复用）
    #[must_use]
    pub fn counter_at(&self, unix_secs: u64) -> u64 {
        unix_secs / u64::from(self.totp_config.period)
    }

    /// 距下一个窗口的剩余秒数（供 UI 显示倒计时）
    #[must_use]
    pub fn secs_until_next_window(&self, unix_secs: u64) -> u64 {
        let period = u64::from(self.totp_config.period);
        period - (unix_secs % period)
    }
}

/// 遗留 TOTP 门禁骨架（M1 阶段的 `Session`，T02 前的唯一会话形态）。
///
/// T02 之后真实解锁流走 [`VaultSession`]；本结构仅保留给既有 TOTP
/// 单元测试与离线验证场景使用——其 `unlocked` 门禁不含密钥材料，
/// 不构成安全边界。新代码请使用 [`VaultSession`]。
pub struct Session {
    /// 解锁状态门禁
    unlocked: bool,
    /// 各条目的 TOTP 会话（UUID → 会话）
    totp_sessions: HashMap<String, TotpSession>,
}

impl Session {
    /// 创建锁定状态的会话
    #[must_use]
    pub fn new() -> Self {
        Self {
            unlocked: false,
            totp_sessions: HashMap::new(),
        }
    }

    /// 权限门禁：所有数据访问用例必须先通过此检查
    ///
    /// 门禁在 Rust 侧强制执行，不依赖 UI 状态管理（见设计 §4.3）。
    pub fn require_unlocked(&self) -> SessionResult<()> {
        if self.unlocked {
            Ok(())
        } else {
            Err(cf_domain::CfError::VaultLocked)
        }
    }

    /// 解锁保险库（遗留骨架：只翻转门禁，无密钥材料）
    pub fn unlock(&mut self) -> SessionResult<()> {
        self.unlocked = true;
        Ok(())
    }

    /// 锁定保险库并清除会话内的敏感数据
    pub fn lock(&mut self) {
        self.unlocked = false;
        self.totp_sessions.clear();
    }

    /// 注册条目的 TOTP 会话（解锁后，密钥由 cf-store 解密取得）
    pub fn register_totp_session(&mut self, item_uuid: &str, session: TotpSession) {
        self.totp_sessions.insert(item_uuid.to_string(), session);
    }

    /// 从存储加载一条 TOTP 记录并注册为该条目的会话。
    ///
    /// 完整链路：`cf-store` 解密密钥（AAD 钉死在 totp 行 uuid 上）
    /// → 构造 [`TotpConfig`] → 注册到本条目名下。
    /// 新代码请直接使用 [`VaultSession::totp_code`]（`field_key` 由
    /// 解锁态 `SubKeys` 注入）。
    ///
    /// # 算法支持
    ///
    /// 当前仅支持 `sha1`；`sha256` / `sha512` 记录返回
    /// [`CfError::Validation`]——显式拒绝而非静默按 SHA-1 计算
    /// （错误算法算出的码必然不匹配服务端）。
    pub fn load_totp_from_store(
        &mut self,
        store: &cf_store::TotpStore,
        totp_uuid: &str,
    ) -> SessionResult<()> {
        self.require_unlocked()?;

        let meta = store
            .totp_meta(totp_uuid)?
            .ok_or(cf_domain::CfError::ItemNotFound)?;

        if meta.algo != "sha1" {
            return Err(cf_domain::CfError::Validation(format!(
                "unsupported TOTP algorithm: {}",
                meta.algo
            )));
        }

        let secret = store
            .totp_secret(totp_uuid)?
            .ok_or(cf_domain::CfError::ItemNotFound)?;

        let config =
            TotpConfig::new(secret.to_vec(), meta.period, meta.digits).map_err(totp_error)?;
        self.register_totp_session(&meta.item_uuid, TotpSession::new(config));
        Ok(())
    }

    /// 生成指定条目当前的 TOTP 验证码（FR-5.4 / FR-5.6）
    pub fn generate_item_totp(&self, item_uuid: &str) -> SessionResult<String> {
        self.require_unlocked()?;
        let session = self
            .totp_sessions
            .get(item_uuid)
            .ok_or(cf_domain::CfError::ItemNotFound)?;
        session.generate()
    }

    /// 验证指定条目的 TOTP 验证码
    pub fn verify_item_totp(&self, item_uuid: &str, code: &str) -> SessionResult<bool> {
        self.require_unlocked()?;
        let session = self
            .totp_sessions
            .get(item_uuid)
            .ok_or(cf_domain::CfError::ItemNotFound)?;
        session.verify(code)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-5.1: TOTP 生成走通
    #[test]
    fn test_generate_item_totp() {
        let mut session = Session::new();
        session.unlock().unwrap();

        let config = TotpConfig::new(vec![1u8; 20], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));

        let code = session.generate_item_totp("item-1").unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    /// 门禁规则：未解锁时数据访问被拒绝（§4.3，错误码 1001）
    #[test]
    fn test_locked_vault_rejects_access() {
        let mut session = Session::new();
        let config = TotpConfig::new(vec![1u8; 20], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));

        assert_eq!(
            session.generate_item_totp("item-1"),
            Err(cf_domain::CfError::VaultLocked)
        );
        assert_eq!(
            session.verify_item_totp("item-1", "123456"),
            Err(cf_domain::CfError::VaultLocked)
        );
    }

    /// 门禁规则：锁定后会话数据被清除，且门禁优先于会话查找
    #[test]
    fn test_lock_clears_sessions() {
        let mut session = Session::new();
        session.unlock().unwrap();
        let config = TotpConfig::new(vec![1u8; 20], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));
        session.lock();

        // 门禁优先：锁定状态直接拒绝，不泄露会话是否存在（§4.3）
        assert_eq!(
            session.generate_item_totp("item-1"),
            Err(cf_domain::CfError::VaultLocked)
        );

        // 重新解锁后会话已清除
        session.unlock().unwrap();
        assert!(matches!(
            session.generate_item_totp("item-1"),
            Err(cf_domain::CfError::ItemNotFound)
        ));
    }

    /// FR-5.2: 自产自验 —— 同一窗口内生成的码必须验证通过
    #[test]
    fn test_verify_own_code() {
        let mut session = Session::new();
        session.unlock().unwrap();
        let config = TotpConfig::new(vec![7u8; 32], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));

        let code = session.generate_item_totp("item-1").unwrap();
        assert!(session.verify_item_totp("item-1", &code).unwrap());
    }

    /// 错误码不存在时验证失败（不 panic）
    #[test]
    fn test_verify_rejects_wrong_code() {
        let mut session = Session::new();
        session.unlock().unwrap();
        let config = TotpConfig::new(vec![7u8; 32], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));

        assert!(!session
            .verify_item_totp("item-1", "000000")
            .unwrap_or(false));
    }

    /// 未注册的条目返回明确错误
    #[test]
    fn test_unknown_item_error() {
        let mut session = Session::new();
        session.unlock().unwrap();

        assert!(matches!(
            session.generate_item_totp("no-such-item"),
            Err(cf_domain::CfError::ItemNotFound)
        ));
    }

    /// 倒计时计算：窗口边界行为
    #[test]
    fn test_secs_until_next_window() {
        let config = TotpConfig::new(vec![1u8; 20], 30, 6).unwrap();
        let s = TotpSession::new(config);

        assert_eq!(s.counter_at(59), 1);
        assert_eq!(s.secs_until_next_window(59), 1);
        assert_eq!(s.secs_until_next_window(60), 30);
        assert_eq!(s.secs_until_next_window(89), 1);
    }

    /// 常量时间比较：等长与不等长
    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"12345"));
    }

    /// 敏感数据清零（NFR-SEC-04 模式验证）
    #[test]
    fn test_zeroize_pattern() {
        use zeroize::{Zeroize, Zeroizing};

        let mut secret = String::from("sensitive-master-password");
        secret.zeroize();
        assert!(secret.is_empty());

        // Zeroizing 包装：drop 时自动清零
        let wrapped = Zeroizing::new(vec![1u8; 32]);
        assert_eq!(wrapped.len(), 32);
    }

    // ---------- cf-session ↔ cf-store 全链路集成 ----------

    use cf_crypto::aead::SessionKey;
    use cf_store::TotpStore;
    use rusqlite::Connection;

    /// 搭建含一条 TOTP 记录的内存存储
    fn store_with_totp(secret: &[u8]) -> (TotpStore, String, String) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);")
            .unwrap();

        let item_uuid = uuid::Uuid::from_bytes([2; 16]).to_string();
        let totp_uuid = uuid::Uuid::from_bytes([1; 16]).to_string();
        conn.execute(
            "INSERT INTO items (uuid) VALUES (?1)",
            rusqlite::params![item_uuid],
        )
        .unwrap();

        let key = SessionKey::new([0x55u8; 32]);
        let store = TotpStore::new(conn, key).unwrap();
        store
            .insert_totp(
                &totp_uuid,
                &item_uuid,
                secret,
                "sha1",
                6,
                30,
                Some("GitHub"),
                None,
            )
            .unwrap();

        (store, totp_uuid, item_uuid)
    }

    /// 全链路：解锁 → 从存储解密密钥 → 生成验证码 → 自验通过
    #[test]
    fn full_chain_unlock_load_generate_verify() {
        let secret = b"0123456789abcdef0123"; // 20 字节
        let (store, totp_uuid, item_uuid) = store_with_totp(secret);

        let mut session = Session::new();
        session.unlock().unwrap();
        session.load_totp_from_store(&store, &totp_uuid).unwrap();

        // 生成 → 自验（FR-5.1 / FR-5.6 链路）
        let code = session.generate_item_totp(&item_uuid).unwrap();
        assert_eq!(code.len(), 6);
        assert!(session.verify_item_totp(&item_uuid, &code).unwrap());

        // 存储里取出的密钥与会话内一致（解密往返正确性）
        let from_store = store.totp_secret(&totp_uuid).unwrap().unwrap();
        assert_eq!(&from_store[..], secret);
    }

    /// 门禁前置：未解锁时从存储加载被拒绝
    #[test]
    fn load_from_store_requires_unlock() {
        let (store, totp_uuid, _item) = store_with_totp(b"0123456789abcdef0123");

        let mut session = Session::new();
        assert_eq!(
            session.load_totp_from_store(&store, &totp_uuid),
            Err(cf_domain::CfError::VaultLocked)
        );
    }

    /// 存储中不存在的记录 → 明确错误
    #[test]
    fn load_from_store_missing_record() {
        let (store, _totp_uuid, _item) = store_with_totp(b"0123456789abcdef0123");

        let mut session = Session::new();
        session.unlock().unwrap();
        assert!(matches!(
            session.load_totp_from_store(&store, "missing-uuid"),
            Err(cf_domain::CfError::ItemNotFound)
        ));
    }

    /// 非 SHA-1 算法记录 → 显式拒绝（不静默按 SHA-1 计算）
    #[test]
    fn load_rejects_unsupported_algo() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);")
            .unwrap();
        let item_uuid = uuid::Uuid::from_bytes([2; 16]).to_string();
        let totp_uuid = uuid::Uuid::from_bytes([1; 16]).to_string();
        conn.execute(
            "INSERT INTO items (uuid) VALUES (?1)",
            rusqlite::params![item_uuid],
        )
        .unwrap();

        let key = SessionKey::new([0x55u8; 32]);
        let store = TotpStore::new(conn, key).unwrap();
        store
            .insert_totp(
                &totp_uuid,
                &item_uuid,
                b"0123456789abcdef0123",
                "sha256",
                6,
                30,
                None,
                None,
            )
            .unwrap();

        let mut session = Session::new();
        session.unlock().unwrap();
        let err = session
            .load_totp_from_store(&store, &totp_uuid)
            .unwrap_err();
        assert_eq!(err.code(), 1012, "不支持算法应报 Validation(1012)");
        assert!(err.to_string().contains("sha256"), "{err}");
    }
}
