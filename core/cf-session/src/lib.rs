//! # cf-session —— 会话与应用服务 (M1: TOTP 集成)
//!
//! 解锁 / 锁定、用例编排、权限门禁、TOTP 验证。
//!
//! ## 对应设计文档
//!
//! - `docs/02-概要设计.md` §4.3（会话与锁定模型）
//! - `docs/03-详细设计.md` §7（TOTP 实现）、§11（内存安全与自动锁定）
//!
//! ## 职责边界
//!
//! 本 crate 是**唯一持有 DEK 的模块**（待实现，M1 后续阶段）。
//! 定时器放在平台侧：本 crate 只提供时间注入的纯逻辑。
//!
//! ## 状态
//!
//! TOTP 会话验证已实现（FR-5.1/FR-5.2 核心路径）；
//! DEK 管理与解锁编排待实现。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cf_totp::TotpConfig;
use std::collections::HashMap;

/// 会话层错误类型
///
/// 注：cf-domain 尚未实现（M1 待办），错误类型暂由本 crate 自持，
/// 待 cf-domain 落地后迁移并统一。
#[derive(Debug, Clone, PartialEq)]
pub enum SessionError {
    /// 保险库处于锁定状态
    Locked,
    /// TOTP 会话不存在（未加载或 UUID 错误）
    TotpSessionNotFound(String),
    /// TOTP 计算失败（透传自 cf-totp）
    Totp(cf_totp::TotpError),
    /// 存储层失败（cf-store 错误的 Display 摘要）。
    ///
    /// 存字符串而非 `CfStoreError` 本身：后者含 `rusqlite::Error`，
    /// 未实现 `Clone` / `PartialEq`，而会话层错误需要可比较（测试与
    /// 门禁判断）。会话层不需要对存储错误做结构化分支，摘要足够；
    /// 完整错误链在 cf-store 侧记录。
    Store(String),
    /// 存储中的 TOTP 算法本实现尚不支持（当前仅 SHA-1）
    UnsupportedAlgo(String),
    /// 系统时钟早于 Unix epoch（时钟回拨到 1970 前）
    ClockBeforeEpoch,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "vault is locked"),
            Self::TotpSessionNotFound(uuid) => {
                write!(f, "TOTP session not found for item: {}", uuid)
            }
            Self::Totp(e) => write!(f, "TOTP error: {}", e),
            Self::Store(s) => write!(f, "store error: {}", s),
            Self::UnsupportedAlgo(a) => write!(f, "unsupported TOTP algorithm: {}", a),
            Self::ClockBeforeEpoch => write!(f, "system clock before Unix epoch"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<cf_totp::TotpError> for SessionError {
    fn from(e: cf_totp::TotpError) -> Self {
        SessionError::Totp(e)
    }
}

impl From<cf_store::CfStoreError> for SessionError {
    fn from(e: cf_store::CfStoreError) -> Self {
        SessionError::Store(e.to_string())
    }
}

/// 会话层结果别名
pub type SessionResult<T> = Result<T, SessionError>;

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
    pub fn new(config: TotpConfig) -> Self {
        Self {
            totp_config: config,
            drift_windows: 1,
        }
    }

    /// 生成当前时间窗口的验证码
    pub fn generate(&self) -> SessionResult<String> {
        Ok(self.totp_config.generate()?)
    }

    /// 验证用户输入的验证码（带时间漂移容错）
    ///
    /// 遍历 `[-drift_windows, +drift_windows]` 范围内的每个计数器，
    /// 任一匹配即通过。
    pub fn verify(&self, code: &str) -> SessionResult<bool> {
        let current = self.current_counter()?;

        for delta in -(self.drift_windows as i64)..=(self.drift_windows as i64) {
            let counter = (current as i64 + delta).max(0) as u64;
            let expected = self.totp_config.generate_for_counter(counter)?;
            if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// 当前时间计数器（时间可注入测试见 `counter_at`）
    fn current_counter(&self) -> SessionResult<u64> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionError::ClockBeforeEpoch)?;

        Ok(duration.as_secs() / u64::from(self.totp_config.period))
    }

    /// 指定 Unix 时间戳对应的计数器（纯函数，供测试与平台侧复用）
    pub fn counter_at(&self, unix_secs: u64) -> u64 {
        unix_secs / u64::from(self.totp_config.period)
    }

    /// 距下一个窗口的剩余秒数（供 UI 显示倒计时）
    pub fn secs_until_next_window(&self, unix_secs: u64) -> u64 {
        let period = u64::from(self.totp_config.period);
        period - (unix_secs % period)
    }
}

/// 常量时间比较，防止验证码比对的时序侧信道。
///
/// 委托 `subtle` 实现：`ConstantTimeEq` 对切片逐元素异或折叠，
/// 不按首个差异字节提前返回（`subtle` 的文档示例即为此用途）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// 主会话结构（DEK 持有者，M1 后续阶段完成解锁编排）
pub struct Session {
    /// 解锁状态门禁
    unlocked: bool,
    /// 各条目的 TOTP 会话（UUID → 会话）
    totp_sessions: HashMap<String, TotpSession>,
}

impl Session {
    /// 创建锁定状态的会话
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
            Err(SessionError::Locked)
        }
    }

    /// 解锁保险库
    ///
    /// 注：主密码验证与 DEK 解密待 M1 后续阶段实现，
    /// 当前只翻转门禁状态供下游用例联调。
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
    /// 完整链路：`cf-store` 解密密钥（AAD 钉死在 item_uuid 上）
    /// → 构造 [`TotpConfig`] → 注册到本条目名下。
    ///
    /// # 参数
    ///
    /// - `store`：已打开的 [`cf_store::TotpStore`]（持有字段密钥）
    /// - `totp_uuid`：TOTP 记录的 UUID（`totp` 表主键）
    ///
    /// # 前置条件
    ///
    /// 必须已解锁（门禁检查）。记录不存在或解密失败返回相应错误。
    ///
    /// # 算法支持
    ///
    /// 当前仅支持 `sha1`（`cf-totp` 已实现部分）；`sha256` / `sha512`
    /// 记录返回 [`SessionError::UnsupportedAlgo`]——显式拒绝而非静默
    /// 按 SHA-1 计算（错误算法算出的码必然不匹配服务端）。
    pub fn load_totp_from_store(
        &mut self,
        store: &cf_store::TotpStore,
        totp_uuid: &str,
    ) -> SessionResult<()> {
        self.require_unlocked()?;

        let meta = store
            .totp_meta(totp_uuid)?
            .ok_or_else(|| SessionError::TotpSessionNotFound(totp_uuid.to_string()))?;

        if meta.algo != "sha1" {
            return Err(SessionError::UnsupportedAlgo(meta.algo));
        }

        let secret = store
            .totp_secret(totp_uuid)?
            .ok_or_else(|| SessionError::TotpSessionNotFound(totp_uuid.to_string()))?;

        let config = TotpConfig::new(secret.to_vec(), meta.period, meta.digits)?;
        self.register_totp_session(&meta.item_uuid, TotpSession::new(config));
        Ok(())
    }

    /// 生成指定条目当前的 TOTP 验证码（FR-5.4 / FR-5.6）
    pub fn generate_item_totp(&self, item_uuid: &str) -> SessionResult<String> {
        self.require_unlocked()?;
        let session = self
            .totp_sessions
            .get(item_uuid)
            .ok_or_else(|| SessionError::TotpSessionNotFound(item_uuid.to_string()))?;
        session.generate()
    }

    /// 验证指定条目的 TOTP 验证码
    pub fn verify_item_totp(&self, item_uuid: &str, code: &str) -> SessionResult<bool> {
        self.require_unlocked()?;
        let session = self
            .totp_sessions
            .get(item_uuid)
            .ok_or_else(|| SessionError::TotpSessionNotFound(item_uuid.to_string()))?;
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
    use zeroize::{Zeroize, Zeroizing};

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

    /// 门禁规则：未解锁时数据访问被拒绝（§4.3）
    #[test]
    fn test_locked_vault_rejects_access() {
        let mut session = Session::new();
        let config = TotpConfig::new(vec![1u8; 20], 30, 6).unwrap();
        session.register_totp_session("item-1", TotpSession::new(config));

        assert_eq!(
            session.generate_item_totp("item-1"),
            Err(SessionError::Locked)
        );
        assert_eq!(
            session.verify_item_totp("item-1", "123456"),
            Err(SessionError::Locked)
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
        assert_eq!(session.generate_item_totp("item-1"), Err(SessionError::Locked));

        // 重新解锁后会话已清除
        session.unlock().unwrap();
        assert!(matches!(
            session.generate_item_totp("item-1"),
            Err(SessionError::TotpSessionNotFound(_))
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

        assert!(!session.verify_item_totp("item-1", "000000").unwrap_or(false));
    }

    /// 未注册的条目返回明确错误
    #[test]
    fn test_unknown_item_error() {
        let mut session = Session::new();
        session.unlock().unwrap();

        assert!(matches!(
            session.generate_item_totp("no-such-item"),
            Err(SessionError::TotpSessionNotFound(_))
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
        conn.execute("INSERT INTO items (uuid) VALUES (?1)", rusqlite::params![item_uuid])
            .unwrap();

        let key = SessionKey::new([0x55u8; 32]);
        let store = TotpStore::new(conn, key).unwrap();
        store
            .insert_totp(&totp_uuid, &item_uuid, secret, "sha1", 6, 30, Some("GitHub"), None)
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
            Err(SessionError::Locked)
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
            Err(SessionError::TotpSessionNotFound(_))
        ));
    }

    /// 非 SHA-1 算法记录 → 显式拒绝（不静默按 SHA-1 计算）
    #[test]
    fn load_rejects_unsupported_algo() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);").unwrap();
        let item_uuid = uuid::Uuid::from_bytes([2; 16]).to_string();
        let totp_uuid = uuid::Uuid::from_bytes([1; 16]).to_string();
        conn.execute("INSERT INTO items (uuid) VALUES (?1)", rusqlite::params![item_uuid]).unwrap();

        let key = SessionKey::new([0x55u8; 32]);
        let store = TotpStore::new(conn, key).unwrap();
        store
            .insert_totp(&totp_uuid, &item_uuid, b"0123456789abcdef0123", "sha256", 6, 30, None, None)
            .unwrap();

        let mut session = Session::new();
        session.unlock().unwrap();
        assert_eq!(
            session.load_totp_from_store(&store, &totp_uuid),
            Err(SessionError::UnsupportedAlgo("sha256".to_string()))
        );
    }
}
