//! totp 表仓库（`docs/07-macOS纵切设计.md` §2.1 / §5 冲突清单 C-2）。
//!
//! 原 `cf-store` 单体 `TotpStore` 迁入改造：
//!
//! - **对齐 DDL**：`issuer` / `account` 明文 TEXT 改为 `enc_issuer` /
//!   `enc_account` 加密 BLOB（C-2 裁定：以 DDL 为准）；`created_at` 列
//!   保留（DDL 已回补，docs/03 v1.3）；
//! - **schema 统一**：不再自建表，改由 [`crate::schema::init`] 幂等建齐
//!   全部 11 张表；
//! - `enc_secret` 的 AAD 语义保持既有行为：钉死在**条目** uuid 上
//!   （`item_uuid ‖ 0x00 ‖ b"enc_totp_secret"`），既有测试语义不回退；
//! - 新增的 `enc_issuer` / `enc_account` AAD 钉死在 **totp 行** uuid 上
//!   （一 item 可有多条 totp，行级钉死更强）。
//!
//! `TotpStore` 保留为兼容门面（持自有连接 + 单一 `field_key`）；
//! 新代码请用 [`TotpRepo`]（借用连接，可参与 [`crate::ItemStore::with_tx`]）。

use cf_crypto::aead::{build_field_aad, open, seal, SessionKey, SEALED_MIN_LEN};
use cf_crypto::subkeys::SubKeys;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::{uuid_bytes, unix_now};

/// `enc_secret` 的 AAD 列名（既有常量，保持兼容）。
pub const COLUMN_TOTP_SECRET: &str = "enc_totp_secret";
/// `enc_issuer` 的 AAD 列名（C-2：新加密列）。
pub const COLUMN_TOTP_ISSUER: &str = "enc_issuer";
/// `enc_account` 的 AAD 列名（C-2：新加密列）。
pub const COLUMN_TOTP_ACCOUNT: &str = "enc_account";

/// totp 表 + 索引 DDL 片段（docs/03 §3.1；与 [`crate::schema`] 全量 DDL
/// 中的 totp 定义逐字一致，`TotpStore` 独立打开路径专用）。
const TOTP_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS totp (
    uuid        TEXT PRIMARY KEY,
    item_uuid   TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_secret  BLOB NOT NULL,
    algo        TEXT NOT NULL DEFAULT 'sha1',
    digits      INTEGER NOT NULL DEFAULT 6,
    period      INTEGER NOT NULL DEFAULT 30,
    enc_issuer  BLOB,
    enc_account BLOB,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_totp_item ON totp(item_uuid);
"#;

/// TOTP 条目的元数据（解密后的密钥单独取，见 [`TotpRepo::totp_secret`]）。
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
    /// 发行方显示名（可选，otpauth URI 的 issuer；解密后）。
    pub issuer: Option<String>,
    /// 账户名（可选，otpauth URI 的 accountname；解密后）。
    pub account: Option<String>,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

/// totp 表仓库（借用连接，可参与事务）。
pub struct TotpRepo<'a> {
    conn: &'a Connection,
    field_key: &'a SessionKey,
}

impl<'a> TotpRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self {
            conn,
            field_key: &subkeys.field_key,
        }
    }

    /// 新增一条 TOTP 记录，共享密钥 / issuer / account 全部 AEAD 加密落盘。
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
        let enc_secret = seal(self.field_key, &aad, plain_secret).crypto()?;

        let enc_issuer = seal_optional(self.field_key, uuid, COLUMN_TOTP_ISSUER, issuer)?;
        let enc_account = seal_optional(self.field_key, uuid, COLUMN_TOTP_ACCOUNT, account)?;
        let created_at = unix_now()?;

        self.conn
            .execute(
                "INSERT INTO totp
                    (uuid, item_uuid, enc_secret, algo, digits, period,
                     enc_issuer, enc_account, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    uuid,
                    item_uuid,
                    enc_secret,
                    algo,
                    i64::from(digits),
                    i64::from(period),
                    enc_issuer,
                    enc_account,
                    created_at
                ],
            )
            .store()?;
        Ok(())
    }

    /// 读取 TOTP 元数据（issuer / account 已解密）。记录不存在返回 `None`。
    pub fn totp_meta(&self, uuid: &str) -> CfStoreResult<Option<TotpMeta>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, algo, digits, period, enc_issuer, enc_account, created_at
                 FROM totp WHERE uuid = ?1",
            )
            .store()?;
        let mut rows = stmt.query(rusqlite::params![uuid]).store()?;

        match rows.next().store()? {
            Some(row) => {
                let totp_uuid: String = row.get(0).store()?;
                let item_uuid: String = row.get(1).store()?;
                let enc_issuer: Option<Vec<u8>> = row.get(5).store()?;
                let enc_account: Option<Vec<u8>> = row.get(6).store()?;
                Ok(Some(TotpMeta {
                    uuid: totp_uuid.clone(),
                    item_uuid,
                    algo: row.get(2).store()?,
                    digits: u8::try_from(row.get::<_, i64>(3).store()?).map_err(|_| {
                        CfError::Corrupted("digits out of range".into())
                    })?,
                    period: u32::try_from(row.get::<_, i64>(4).store()?).map_err(|_| {
                        CfError::Corrupted("period out of range".into())
                    })?,
                    issuer: open_optional(self.field_key, &totp_uuid, COLUMN_TOTP_ISSUER, enc_issuer)?,
                    account: open_optional(self.field_key, &totp_uuid, COLUMN_TOTP_ACCOUNT, enc_account)?,
                    created_at: row.get(7).store()?,
                }))
            }
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
            .prepare("SELECT item_uuid, enc_secret FROM totp WHERE uuid = ?1")
            .store()?;
        let mut rows = stmt.query(rusqlite::params![uuid]).store()?;

        match rows.next().store()? {
            Some(row) => {
                let item_uuid: String = row.get(0).store()?;
                let enc_secret: Vec<u8> = row.get(1).store()?;

                if enc_secret.len() < SEALED_MIN_LEN {
                    return Err(CfError::Corrupted(
                        "enc_secret shorter than nonce+tag".into(),
                    ));
                }

                let item_uuid_bytes = uuid_bytes(&item_uuid)?;
                let aad = build_field_aad(&item_uuid_bytes, COLUMN_TOTP_SECRET);
                let plain = open(self.field_key, &aad, &enc_secret).crypto()?;
                Ok(Some(Zeroizing::new(plain)))
            }
            None => Ok(None),
        }
    }

    /// 删除 TOTP 记录。
    pub fn delete_totp(&self, uuid: &str) -> CfStoreResult<()> {
        self.conn
            .execute("DELETE FROM totp WHERE uuid = ?1", rusqlite::params![uuid])
            .store()?;
        Ok(())
    }

    /// 列出某条目下的全部 TOTP 记录 UUID（按创建时间排序）。
    pub fn totp_uuids_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uuid FROM totp WHERE item_uuid = ?1 ORDER BY created_at ASC")
            .store()?;
        let mut rows = stmt.query(rusqlite::params![item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().store()? {
            out.push(row.get(0).store()?);
        }
        Ok(out)
    }
}

/// 可空列加密：`None` → SQL NULL。
fn seal_optional(
    key: &SessionKey,
    record_uuid: &str,
    column: &str,
    plain: Option<&str>,
) -> CfStoreResult<Option<Vec<u8>>> {
    match plain {
        None => Ok(None),
        Some(s) => {
            let uuid_b = uuid_bytes(record_uuid)?;
            let aad = build_field_aad(&uuid_b, column);
            Ok(Some(seal(key, &aad, s.as_bytes()).crypto()?))
        }
    }
}

/// 可空列解密：SQL NULL → `None`。
fn open_optional(
    key: &SessionKey,
    record_uuid: &str,
    column: &str,
    sealed: Option<Vec<u8>>,
) -> CfStoreResult<Option<String>> {
    match sealed {
        None => Ok(None),
        Some(ct) => {
            let uuid_b = uuid_bytes(record_uuid)?;
            let aad = build_field_aad(&uuid_b, column);
            let plain = open(key, &aad, &ct).crypto()?;
            let s = String::from_utf8(plain)
                .map_err(|_| CfError::Corrupted("totp column not utf-8".into()))?;
            Ok(Some(s))
        }
    }
}

/// TOTP 加密存储（兼容门面：持自有连接，原有 API 签名不变）。
///
/// `field_key` 由上层（`cf-session`，唯一 DEK 持有者）在解锁后注入；
/// `drop` 时 `field_key` 自动清零。新代码请改用 [`TotpRepo`]。
pub struct TotpStore {
    conn: Connection,
    /// 单一 field_key 包装成 SubKeys 视图（只有 field_key 参与 totp 读写，
    /// 其余子密钥为全零占位且从不使用；SessionKey 本身 ZeroizeOnDrop）。
    subkeys: SubKeys,
}

impl TotpStore {
    /// 打开存储并确保 totp 表就绪。
    ///
    /// **兼容性说明**：本类型是 T01 之前的独立打开路径（cf-session 现有
    /// 用法依赖"宿主 items 表已由调用方准备"的约定），故这里只建 totp
    /// 表与索引（docs/03 §3.1 DDL 片段），**不**执行全量
    /// [`crate::schema::init`]——后者会在极简宿主表上因缺列而失败。
    /// 真实保险库路径（T02 的解锁流）应使用 [`crate::ItemStore::open`]，
    /// 其 [`crate::schema::init`] 幂等建齐全部 11 张表，且 totp DDL
    /// 与本片段完全一致（重复执行无冲突）。
    pub fn new(conn: Connection, field_key: SessionKey) -> CfStoreResult<Self> {
        conn.execute_batch(TOTP_DDL).store()?;
        Ok(Self {
            conn,
            subkeys: SubKeys {
                meta_key: SessionKey::new([0u8; 32]),
                item_key: SessionKey::new([0u8; 32]),
                field_key,
                file_key: SessionKey::new([0u8; 32]),
                hist_key: SessionKey::new([0u8; 32]),
                manifest_key: SessionKey::new([0u8; 32]),
                attach_mac_key: SessionKey::new([0u8; 32]),
            },
        })
    }

    fn repo(&self) -> TotpRepo<'_> {
        TotpRepo::new(&self.conn, &self.subkeys)
    }

    /// 新增一条 TOTP 记录（见 [`TotpRepo::insert_totp`]）。
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
        self.repo().insert_totp(uuid, item_uuid, plain_secret, algo, digits, period, issuer, account)
    }

    /// 读取 TOTP 元数据（见 [`TotpRepo::totp_meta`]）。
    pub fn totp_meta(&self, uuid: &str) -> CfStoreResult<Option<TotpMeta>> {
        self.repo().totp_meta(uuid)
    }

    /// 解密并返回 TOTP 共享密钥明文（见 [`TotpRepo::totp_secret`]）。
    pub fn totp_secret(&self, uuid: &str) -> CfStoreResult<Option<Zeroizing<Vec<u8>>>> {
        self.repo().totp_secret(uuid)
    }

    /// 删除 TOTP 记录（见 [`TotpRepo::delete_totp`]）。
    pub fn delete_totp(&self, uuid: &str) -> CfStoreResult<()> {
        self.repo().delete_totp(uuid)
    }

    /// 列出某条目下的全部 TOTP 记录 UUID（见 [`TotpRepo::totp_uuids_for_item`]）。
    pub fn totp_uuids_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<String>> {
        self.repo().totp_uuids_for_item(item_uuid)
    }
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
            conn.execute(
                "INSERT INTO items (uuid) VALUES (?1)",
                rusqlite::params![uuid::Uuid::from_bytes([seed; 16]).to_string()],
            )
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

    /// 元数据往返一致（issuer / account 现为加密列，解密后语义不变）
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
        assert!(meta.created_at > 0, "C-2 回补的 created_at 必须写入");
    }

    /// 落盘的是密文：enc_secret / enc_issuer / enc_account 三个 BLOB
    /// 全部 ≠ 明文，且长度符合 sealed 格式
    #[test]
    fn stored_blob_is_ciphertext() {
        let s = store();
        let secret = b"plain-totp-secret";

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

        let enc_secret: Vec<u8> = s
            .conn
            .query_row(
                "SELECT enc_secret FROM totp WHERE uuid = ?1",
                rusqlite::params![test_uuid(1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(enc_secret, secret, "密钥明文不得出现在数据库中");
        assert_eq!(enc_secret.len(), 24 + secret.len() + 16);

        // C-2：issuer / account 也必须是密文
        let enc_issuer: Vec<u8> = s
            .conn
            .query_row(
                "SELECT enc_issuer FROM totp WHERE uuid = ?1",
                rusqlite::params![test_uuid(1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(enc_issuer, b"GitHub", "issuer 明文不得出现在数据库中");
        assert_eq!(enc_issuer.len(), 24 + "GitHub".len() + 16);

        let enc_account: Vec<u8> = s
            .conn
            .query_row(
                "SELECT enc_account FROM totp WHERE uuid = ?1",
                rusqlite::params![test_uuid(1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(enc_account, b"alice@example.com", "account 明文不得出现在数据库中");
    }

    /// 可空加密列：None 落盘为 SQL NULL，读回 None
    #[test]
    fn null_columns_round_trip_as_null() {
        let s = store();
        s.insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();
        let n: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM totp WHERE uuid=?1 AND enc_issuer IS NULL AND enc_account IS NULL",
                rusqlite::params![test_uuid(1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        let meta = s.totp_meta(&test_uuid(1)).unwrap().unwrap();
        assert!(meta.issuer.is_none() && meta.account.is_none());
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

    /// 错误的字段密钥 → 解密失败（CryptoError，不区分原因）
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
        assert!(matches!(result, Err(CfError::CryptoError)));
    }

    /// 无效 item UUID 字符串 → Corrupted（AAD 需要 16 字节）
    #[test]
    fn invalid_uuid_rejected() {
        let s = store();
        let result = s.insert_totp(&test_uuid(1), "not-a-uuid", b"0123456789", "sha1", 6, 30, None, None);
        assert!(matches!(result, Err(CfError::Corrupted(_))));
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
            Err(CfError::CryptoError)
        ));
    }

    /// issuer 密文搬到别的 totp 行（不同 AAD）→ 解密失败（防跨行搬运）
    #[test]
    fn issuer_ciphertext_pinned_to_totp_uuid() {
        let s = store();
        s.insert_totp(&test_uuid(1), &test_uuid(2), b"0123456789", "sha1", 6, 30, Some("GitHub"), None)
            .unwrap();
        s.insert_totp(&test_uuid(3), &test_uuid(2), b"0123456789", "sha1", 6, 30, None, None)
            .unwrap();

        s.conn
            .execute(
                "UPDATE totp SET enc_issuer=(SELECT enc_issuer FROM totp WHERE uuid=?1) WHERE uuid=?2",
                rusqlite::params![test_uuid(1), test_uuid(3)],
            )
            .unwrap();

        assert!(matches!(
            s.totp_meta(&test_uuid(3)),
            Err(CfError::CryptoError)
        ));
    }
}
