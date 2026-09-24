//! # cf-store —— 存储引擎 (SQLite + 字段级 AEAD)
//!
//! SQLite schema、加密字段读写、事务。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §3（存储层设计）
//! - `docs/03-详细设计.md` §2.5（字段级 AEAD 与 AAD 构造）
//!
//! ## 职责边界
//!
//! 负责「加密后的数据怎么落盘」，**不做字段级业务校验**（那是 `cf-domain`
//! 的职责，待其实现后迁移）。所有加密操作委托 `cf-crypto::aead`。
//!
//! ## TOTP 字段加密（M1）
//!
//! TOTP 共享密钥以 `enc_secret` BLOB 落盘，格式为
//! `nonce(24) ‖ ct ‖ tag(16)`，AAD 按 §2.5 构造：
//! `item_uuid_bytes(16) ‖ 0x00 ‖ b"enc_totp_secret"`。
//!
//! 解密出的明文密钥用 `Zeroizing` 包装返回，离开作用域即清零
//! （NFR-SEC-04）。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cf_crypto::aead::{build_field_aad, open, seal, SessionKey, SEALED_MIN_LEN};
use rusqlite::Connection;
use zeroize::Zeroizing;

/// 列名常量：TOTP 共享密钥的 AAD 中的列标识。
///
/// 与 §2.5 的 AAD 规则对齐：列名参与 AAD，密文被搬到其他列无法解密。
pub const COLUMN_TOTP_SECRET: &str = "enc_totp_secret";

/// cf-store 错误类型。
///
/// 注：cf-domain 尚未实现，错误类型暂由本 crate 自持（与 cf-session
/// 同样的策略），待 cf-domain 落地后统一迁移。
#[derive(Debug, thiserror::Error)]
pub enum CfStoreError {
    /// SQLite 操作失败。
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    /// 加密 / 解密失败（透传 cf-crypto；解密失败不区分原因）。
    #[error("crypto error: {0}")]
    Crypto(#[from] cf_crypto::CfCryptoError),
    /// UUID 字符串无法解析为 16 字节（AAD 构造前置条件）。
    #[error("invalid uuid: {0}")]
    UuidParse(String),
    /// 数据格式不合法（如密文长度不足）。
    #[error("corrupt data: {0}")]
    CorruptData(String),
}

/// cf-store 结果别名。
pub type CfStoreResult<T> = Result<T, CfStoreError>;

/// TOTP 条目的元数据（解密后的密钥单独取，见 [`TotpStore::totp_secret`]）。
#[derive(Debug, Clone, PartialEq)]
pub struct TotpMeta {
    /// 条目内 TOTP 记录的 UUID（主键）。
    pub uuid: String,
    /// 所属 Login 条目的 UUID。
    pub item_uuid: String,
    /// 哈希算法：`sha1` / `sha256` / `sha512`（RFC 6238 §5.1）。
    pub algo: String,
    /// 验证码位数（6 或 8）。
    pub digits: u8,
    /// 时间窗口秒数（默认 30）。
    pub period: u32,
    /// 发行方显示名（可选，otpauth URI 的 issuer）。
    pub issuer: Option<String>,
    /// 账户名（可选，otpauth URI 的 accountname）。
    pub account: Option<String>,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

/// TOTP 加密存储。
///
/// `field_key` 由上层（`cf-session`，唯一 DEK 持有者）在解锁后注入；
/// 本类型不缓存明文密钥之外的状态，`drop` 时 `field_key` 自动清零。
pub struct TotpStore {
    conn: Connection,
    field_key: SessionKey,
}

impl TotpStore {
    /// 打开存储并确保 schema 就绪。
    pub fn new(conn: Connection, field_key: SessionKey) -> CfStoreResult<Self> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS totp (
                uuid        TEXT PRIMARY KEY,
                item_uuid   TEXT NOT NULL REFERENCES items(uuid),
                enc_secret  BLOB NOT NULL,
                algo        TEXT NOT NULL DEFAULT 'sha1',
                digits      INTEGER NOT NULL DEFAULT 6,
                period      INTEGER NOT NULL DEFAULT 30,
                issuer      TEXT,
                account     TEXT,
                created_at  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_totp_item_uuid ON totp(item_uuid);
            "#,
        )?;
        Ok(Self { conn, field_key })
    }

    /// 新增一条 TOTP 记录，共享密钥以 AEAD 加密落盘。
    ///
    /// # 参数
    ///
    /// - `uuid` / `item_uuid`：TOTP 记录与所属条目的 UUID（TEXT 形式）
    /// - `plain_secret`：Base32 解码后的原始密钥字节（≥ 10 字节，校验在
    ///   `cf-totp` 的 URI 解析侧完成；此处只负责加密存储）
    #[allow(clippy::too_many_arguments)]
    pub fn insert_totp(
        &self,
        uuid: &str,
        item_uuid: &str,
        plain_secret: &[u8],
        algo: &str,
        digits: u8,
        period: u32,
        issuer: Option<&str>,
        account: Option<&str>,
    ) -> CfStoreResult<()> {
        let item_uuid_bytes = uuid_bytes(item_uuid)?;
        let aad = build_field_aad(&item_uuid_bytes, COLUMN_TOTP_SECRET);
        let enc_secret = seal(&self.field_key, &aad, plain_secret)?;
        let created_at = unix_now()?;

        self.conn.execute(
            "INSERT INTO totp
                (uuid, item_uuid, enc_secret, algo, digits, period, issuer, account, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                uuid,
                item_uuid,
                enc_secret,
                algo,
                i64::from(digits),
                i64::from(period),
                issuer,
                account,
                created_at
            ],
        )?;
        Ok(())
    }

    /// 读取 TOTP 元数据（不含密钥）。记录不存在时返回 `None`。
    pub fn totp_meta(&self, uuid: &str) -> CfStoreResult<Option<TotpMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT uuid, item_uuid, algo, digits, period, issuer, account, created_at
             FROM totp WHERE uuid = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![uuid])?;

        match rows.next()? {
            Some(row) => Ok(Some(TotpMeta {
                uuid: row.get(0)?,
                item_uuid: row.get(1)?,
                algo: row.get(2)?,
                digits: u8::try_from(row.get::<_, i64>(3)?)
                    .map_err(|_| CfStoreError::CorruptData("digits out of range".into()))?,
                period: u32::try_from(row.get::<_, i64>(4)?)
                    .map_err(|_| CfStoreError::CorruptData("period out of range".into()))?,
                issuer: row.get(5)?,
                account: row.get(6)?,
                created_at: row.get(7)?,
            })),
            None => Ok(None),
        }
    }

    /// 解密并返回 TOTP 共享密钥明文。
    ///
    /// 返回值用 `Zeroizing` 包装：调用方用完即清零。
    /// 记录不存在返回 `None`；密文损坏返回解密失败（不区分原因，
    /// 见 `cf-crypto::aead` 的信息泄露纪律）。
    pub fn totp_secret(&self, uuid: &str) -> CfStoreResult<Option<Zeroizing<Vec<u8>>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT item_uuid, enc_secret FROM totp WHERE uuid = ?1")?;
        let mut rows = stmt.query(rusqlite::params![uuid])?;

        match rows.next()? {
            Some(row) => {
                let item_uuid: String = row.get(0)?;
                let enc_secret: Vec<u8> = row.get(1)?;

                if enc_secret.len() < SEALED_MIN_LEN {
                    return Err(CfStoreError::CorruptData(
                        "enc_secret shorter than nonce+tag".into(),
                    ));
                }

                let item_uuid_bytes = uuid_bytes(&item_uuid)?;
                let aad = build_field_aad(&item_uuid_bytes, COLUMN_TOTP_SECRET);
                let plain = open(&self.field_key, &aad, &enc_secret)?;
                Ok(Some(Zeroizing::new(plain)))
            }
            None => Ok(None),
        }
    }

    /// 删除 TOTP 记录。
    pub fn delete_totp(&self, uuid: &str) -> CfStoreResult<()> {
        self.conn
            .execute("DELETE FROM totp WHERE uuid = ?1", rusqlite::params![uuid])?;
        Ok(())
    }

    /// 列出某条目下的全部 TOTP 记录 UUID（按创建时间排序）。
    pub fn totp_uuids_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT uuid FROM totp WHERE item_uuid = ?1 ORDER BY created_at ASC",
        )?;
        let mut rows = stmt.query(rusqlite::params![item_uuid])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(row.get(0)?);
        }
        Ok(out)
    }
}

/// UUID TEXT → 16 字节（AAD 构造前置条件）。
fn uuid_bytes(uuid: &str) -> CfStoreResult<[u8; 16]> {
    let parsed = uuid::Uuid::parse_str(uuid)
        .map_err(|_| CfStoreError::UuidParse(uuid.to_string()))?;
    Ok(*parsed.as_bytes())
}

/// 当前 Unix 秒。系统时钟早于 epoch 时返回错误（不猜测）。
fn unix_now() -> CfStoreResult<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CfStoreError::CorruptData(format!("clock before epoch: {}", e)))?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid(seed: u8) -> String {
        // 确定性 UUID（仅测试用）：bytes = seed 重复 16 次
        uuid::Uuid::from_bytes([seed; 16]).to_string()
    }

    fn store() -> TotpStore {
        let conn = Connection::open_in_memory().unwrap();
        // items 外键引用的宿主表：最小化建表，并插入测试用宿主条目
        conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);").unwrap();
        for seed in 2u8..=5 {
            conn.execute("INSERT INTO items (uuid) VALUES (?1)", rusqlite::params![uuid::Uuid::from_bytes([seed; 16]).to_string()])
                .unwrap();
        }
        let key = SessionKey::new([0x55u8; 32]);
        TotpStore::new(conn, key).unwrap()
    }

    /// 插入 → 读取密钥：往返一致
    #[test]
    fn insert_and_read_secret_roundtrip() {
        let s = store();
        let secret = b"0123456789abcdef0123"; // 20 字节

        s.insert_totp(
            &test_uuid(1),
            &test_uuid(2),
            secret,
            "sha1",
            6,
            30,
            Some("GitHub"),
            Some("alice@example.com"),
        )
        .unwrap();

        let got = s.totp_secret(&test_uuid(1)).unwrap().unwrap();
        assert_eq!(&got[..], secret);
    }

    /// 元数据往返一致
    #[test]
    fn meta_roundtrip() {
        let s = store();
        s.insert_totp(
            &test_uuid(1),
            &test_uuid(2),
            b"0123456789",
            "sha256",
            8,
            60,
            Some("GitHub"),
            None,
        )
        .unwrap();

        let meta = s.totp_meta(&test_uuid(1)).unwrap().unwrap();
        assert_eq!(meta.algo, "sha256");
        assert_eq!(meta.digits, 8);
        assert_eq!(meta.period, 60);
        assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
        assert!(meta.account.is_none());
    }

    /// 落盘的是密文：数据库里读出的 BLOB ≠ 明文，且长度符合 sealed 格式
    #[test]
    fn stored_blob_is_ciphertext() {
        let s = store();
        let secret = b"plain-totp-secret";

        s.insert_totp(&test_uuid(1), &test_uuid(2), secret, "sha1", 6, 30, None, None)
            .unwrap();

        let blob: Vec<u8> = s
            .conn
            .query_row("SELECT enc_secret FROM totp WHERE uuid = ?1", rusqlite::params![test_uuid(1)], |r| r.get(0))
            .unwrap();

        assert_ne!(blob, secret, "密钥明文不得出现在数据库中");
        assert_eq!(blob.len(), 24 + secret.len() + 16);
    }

    /// 不存在的记录 → None
    #[test]
    fn missing_record_returns_none() {
        let s = store();
        assert!(s.totp_meta(&test_uuid(9)).unwrap().is_none());
        assert!(s.totp_secret(&test_uuid(9)).unwrap().is_none());
    }

    /// 删除后读取为 None
    #[test]
    fn delete_removes_record() {
        let s = store();
        s.insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();

        s.delete_totp(&test_uuid(1)).unwrap();
        assert!(s.totp_meta(&test_uuid(1)).unwrap().is_none());
    }

    /// 错误的字段密钥 → 解密失败（Crypto 错误，不区分原因）
    #[test]
    fn wrong_key_fails_to_decrypt() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);").unwrap();
        conn.execute(
            "INSERT INTO items (uuid) VALUES (?1)",
            rusqlite::params![uuid::Uuid::from_bytes([2; 16]).to_string()],
        )
        .unwrap();

        let good_key = SessionKey::new([0x55u8; 32]);
        let writer = TotpStore::new(conn, good_key).unwrap();
        writer
            .insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();

        // 同一连接、错误密钥：记录可见但解密必须失败
        let wrong_key = SessionKey::new([0x56u8; 32]);
        let attacker = TotpStore::new(writer.conn, wrong_key).unwrap();

        let result = attacker.totp_secret(&test_uuid(1));
        assert!(matches!(result, Err(CfStoreError::Crypto(_))));
    }

    /// 无效 item UUID 字符串 → UuidParse 错误（AAD 需要 16 字节）
    #[test]
    fn invalid_uuid_rejected() {
        let s = store();
        let result = s.insert_totp(&test_uuid(1), "not-a-uuid", b"0123456789", "sha1", 6, 30, None, None);
        assert!(matches!(result, Err(CfStoreError::UuidParse(_))));
    }

    /// 按 item 列出：多条记录按创建时间返回
    #[test]
    fn list_uuids_for_item() {
        let s = store();
        s.insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();
        s.insert_totp(&test_uuid(3), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();
        s.insert_totp(&test_uuid(4), &test_uuid(5), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();

        let uuids = s.totp_uuids_for_item(&test_uuid(2)).unwrap();
        assert_eq!(uuids.len(), 2);
        assert!(uuids.contains(&test_uuid(1)));
        assert!(uuids.contains(&test_uuid(3)));
    }

    /// 密文搬到别的 item（不同 AAD）→ 解密失败（防跨行搬运）
    #[test]
    fn ciphertext_pinned_to_item_uuid() {
        let s = store();
        s.insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();

        // 直接把 A 条目的密文 UPDATE 到 B 条目（模拟攻击者在库文件里搬密文）
        s.conn
            .execute(
                "UPDATE totp SET item_uuid = ?1 WHERE uuid = ?2",
                rusqlite::params![test_uuid(5), test_uuid(1)],
            )
            .unwrap();

        assert!(matches!(
            s.totp_secret(&test_uuid(1)),
            Err(CfStoreError::Crypto(_))
        ));
    }
}
