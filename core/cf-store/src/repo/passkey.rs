//! passkeys 表仓库（FR-10.2 / FR-10.5 内核，docs/17 §4.1 PK1，v0.5.0）。
//!
//! DDL 随 fmt-v1 冻结建齐（[`crate::schema`]，零迁移）；本仓库为纯增量。
//!
//! ## 密文纪律（与全仓库层统一约定对齐）
//!
//! - 全部 `enc_*` 列 AEAD 密文 BLOB 落盘，子密钥 = `field_key`，AAD =
//!   `field_aad("passkeys", 行uuid, 列名)`（表名命名空间，O-1）；
//! - `rp_id_hmac = HMAC-SHA256(passkey_idx_key, rp_id)`（第 10 把子密钥
//!   `cf/passkey-idx/v1`，docs/17 §3.3 D-3）——锁定态下 rpId 不落明文由
//!   HMAC 索引保证（docs/01 §5-J 红线）。本版**只写不查**（查询面随 ADP
//!   重启时再暴露，D-3）；
//! - 私钥编码 = PKCS#8 DER（docs/17 §3.1 D-1，唯一不可逆候选，用户已
//!   批准）；`algorithm` 列存 COSE alg 编号（-7 = ES256）。
//!
//! ## FR-10.2 红线：私钥永不展示
//!
//! 本仓库**不提供任何私钥读路径**——[`PasskeyMeta`] 无私钥字段，
//! 查询面只有元数据；`enc_private_key` 的解密在本版没有任何调用方
//! （明文只在导入那一刻入库，结构上不存在私钥展示面）。
//!
//! ## 错误码（docs/17 §5，零新增）
//!
//! 校验失败（非 ES256 / rpId 为空 / 凭据 ID 为空 / 私钥为空）→
//! [`CfError::Validation`]（1012）；行不存在 → [`CfError::ItemNotFound`]
//! （1011，items 仓库「影响行数为 0 → ItemNotFound」同款）；密文损坏 →
//! [`CfError::CryptoError`]（1005 族，不区分原因）。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cf_crypto::aead::{open, seal, SessionKey, SEALED_MIN_LEN};
use cf_crypto::subkeys::SubKeys;
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::Sha256;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::{field_aad, uuid_bytes};

/// `enc_rp_id` 的 AAD 列名。
pub const COLUMN_PASSKEY_RP_ID: &str = "enc_rp_id";
/// `enc_rp_name` 的 AAD 列名。
pub const COLUMN_PASSKEY_RP_NAME: &str = "enc_rp_name";
/// `enc_user_name` 的 AAD 列名。
pub const COLUMN_PASSKEY_USER_NAME: &str = "enc_user_name";
/// `enc_user_handle` 的 AAD 列名。
pub const COLUMN_PASSKEY_USER_HANDLE: &str = "enc_user_handle";
/// `enc_credential_id` 的 AAD 列名。
pub const COLUMN_PASSKEY_CREDENTIAL_ID: &str = "enc_credential_id";
/// `enc_private_key` 的 AAD 列名（D-1：PKCS#8 DER）。
pub const COLUMN_PASSKEY_PRIVATE_KEY: &str = "enc_private_key";

/// COSE alg 编号：ES256（WebAuthn 唯一支持的签名算法，docs/17 §3.1）。
pub const COSE_ALG_ES256: i64 = -7;

/// Passkey 元数据（docs/17 §4.1 冻结契约，FFI 可见）。
///
/// **无私钥字段**——FR-10.2 红线的结构化落点：凭据 ID 非密钥，允许
/// 展示（base64）；`enc_private_key` / `enc_user_handle` 不出现在任何
/// 查询返回值中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyMeta {
    /// passkey 行 UUID（主键）。
    pub uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// Relying Party ID（解密后明文，如 `github.com`）。
    pub rp_id: String,
    /// RP 显示名（可选，解密后）。
    pub rp_name: Option<String>,
    /// 用户名（可选，解密后）。
    pub user_name: Option<String>,
    /// 凭据 ID（base64；非密钥，FR-10.2 允许展示）。
    pub credential_id_b64: String,
    /// COSE alg 编号（-7 = ES256）。
    pub algorithm: i64,
    /// 签名计数器（DDL 默认 0）。
    pub sign_count: i64,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
    /// 最后使用时间（Unix 秒；本版无断言路径，恒 `None`）。
    pub last_used_at: Option<i64>,
}

/// Passkey 明文载荷（导入路径专用，docs/17 §4.1 冻结契约）。
///
/// `private_key_pkcs8` 须为 D-1 归一化后的 PKCS#8 DER（校验在导入侧
/// cf-importer 完成，仓库层只做非空与算法判定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    /// Relying Party ID（明文）。
    pub rp_id: String,
    /// RP 显示名（可选）。
    pub rp_name: Option<String>,
    /// 用户名（可选）。
    pub user_name: Option<String>,
    /// user handle（原始字节）。
    pub user_handle: Vec<u8>,
    /// 凭据 ID（原始字节）。
    pub credential_id: Vec<u8>,
    /// 私钥（PKCS#8 DER，D-1 归一化后）。
    pub private_key_pkcs8: Vec<u8>,
    /// COSE alg 编号（仅接受 [`COSE_ALG_ES256`]）。
    pub algorithm: i64,
    /// 签名计数器（不得为负）。
    pub sign_count: i64,
}

type HmacSha256 = Hmac<Sha256>;

/// passkeys 表仓库（借用连接，可参与事务）。
pub struct PasskeyRepo<'a> {
    conn: &'a Connection,
    field_key: &'a SessionKey,
    passkey_idx_key: &'a SessionKey,
}

impl<'a> PasskeyRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self {
            conn,
            field_key: &subkeys.field_key,
            passkey_idx_key: &subkeys.passkey_idx_key,
        }
    }

    /// 新增一条 passkey 记录，全部敏感列 AEAD 加密落盘，并写
    /// `rp_id_hmac`（D-3）。
    ///
    /// `now` 由调用方显式传入（导入路径须逐条目确定性时间戳，docs/17
    /// §4.1）；返回新生成的 passkey 行 UUID（UUIDv7）。**调用方须包在
    /// [`crate::ItemStore::with_tx`] 内**（与 attachments 同款纪律）。
    ///
    /// # 错误
    ///
    /// - 非 ES256 / rpId 为空 / 凭据 ID 为空 / 私钥为空 / sign_count
    ///   为负 / item_uuid 非法 → [`CfError::Validation`]（1012）；
    /// - 条目不存在（外键）→ [`CfError::StorageError`]。
    pub fn add(&self, item_uuid: &str, record: &PasskeyRecord, now: i64) -> CfStoreResult<String> {
        // 边界校验快失败（先于任何密码运算）
        uuid_bytes(item_uuid)?;
        if record.rp_id.trim().is_empty() {
            return Err(CfError::Validation(
                "passkey rp_id must not be empty".into(),
            ));
        }
        if record.credential_id.is_empty() {
            return Err(CfError::Validation(
                "passkey credential_id must not be empty".into(),
            ));
        }
        if record.private_key_pkcs8.is_empty() {
            return Err(CfError::Validation(
                "passkey private_key must not be empty".into(),
            ));
        }
        if record.sign_count < 0 {
            return Err(CfError::Validation(
                "passkey sign_count must not be negative".into(),
            ));
        }
        if record.algorithm != COSE_ALG_ES256 {
            return Err(CfError::Validation(format!(
                "passkey algorithm {alg} is not ES256 ({COSE_ALG_ES256})",
                alg = record.algorithm
            )));
        }

        let passkey_uuid = uuid::Uuid::now_v7().to_string();

        let enc_rp_id =
            self.seal_column(&passkey_uuid, COLUMN_PASSKEY_RP_ID, record.rp_id.as_bytes())?;
        let enc_rp_name = self.seal_optional(
            &passkey_uuid,
            COLUMN_PASSKEY_RP_NAME,
            record.rp_name.as_deref(),
        )?;
        let enc_user_name = self.seal_optional(
            &passkey_uuid,
            COLUMN_PASSKEY_USER_NAME,
            record.user_name.as_deref(),
        )?;
        let enc_user_handle = self.seal_column(
            &passkey_uuid,
            COLUMN_PASSKEY_USER_HANDLE,
            &record.user_handle,
        )?;
        let enc_credential_id = self.seal_column(
            &passkey_uuid,
            COLUMN_PASSKEY_CREDENTIAL_ID,
            &record.credential_id,
        )?;
        let enc_private_key = self.seal_column(
            &passkey_uuid,
            COLUMN_PASSKEY_PRIVATE_KEY,
            &record.private_key_pkcs8,
        )?;
        let rp_id_hmac = rp_id_hmac(self.passkey_idx_key, record.rp_id.as_bytes());

        // enc_public_key 本版不落（可由私钥推导，ADP 重启时再定）；
        // last_used_at 恒 NULL（无断言路径，DDL 可空列）
        self.conn
            .execute(
                "INSERT INTO passkeys
                    (uuid, item_uuid, enc_rp_id, enc_rp_name, enc_user_name,
                     enc_user_handle, enc_credential_id, enc_private_key,
                     enc_public_key, algorithm, sign_count, created_at,
                     last_used_at, rp_id_hmac)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, NULL, ?12)",
                rusqlite::params![
                    passkey_uuid,
                    item_uuid,
                    enc_rp_id,
                    enc_rp_name,
                    enc_user_name,
                    enc_user_handle,
                    enc_credential_id,
                    enc_private_key,
                    record.algorithm,
                    record.sign_count,
                    now,
                    rp_id_hmac,
                ],
            )
            .store()?;

        Ok(passkey_uuid)
    }

    /// 列出某条目下的全部 passkey 元数据（created_at 升序）。
    ///
    /// 条目不存在返回空 `Vec`（存在性门禁由会话层承担——与
    /// attachments 的 `list_for_item` 同语义）。
    pub fn list_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<PasskeyMeta>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, enc_rp_id, enc_rp_name, enc_user_name,
                        enc_credential_id, algorithm, sign_count, created_at, last_used_at
                 FROM passkeys WHERE item_uuid = ?1 ORDER BY created_at, uuid",
            )
            .store()?;
        let mut rows = stmt.query(rusqlite::params![item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().store()? {
            let passkey_uuid: String = row.get(0).store()?;
            let item: String = row.get(1).store()?;
            let enc_rp_id: Vec<u8> = row.get(2).store()?;
            let enc_rp_name: Option<Vec<u8>> = row.get(3).store()?;
            let enc_user_name: Option<Vec<u8>> = row.get(4).store()?;
            let enc_credential_id: Vec<u8> = row.get(5).store()?;
            out.push(PasskeyMeta {
                rp_id: self.open_string(&passkey_uuid, COLUMN_PASSKEY_RP_ID, &enc_rp_id)?,
                rp_name: self.open_optional(&passkey_uuid, COLUMN_PASSKEY_RP_NAME, enc_rp_name)?,
                user_name: self.open_optional(
                    &passkey_uuid,
                    COLUMN_PASSKEY_USER_NAME,
                    enc_user_name,
                )?,
                credential_id_b64: BASE64.encode(self.open_bytes(
                    &passkey_uuid,
                    COLUMN_PASSKEY_CREDENTIAL_ID,
                    &enc_credential_id,
                )?),
                uuid: passkey_uuid,
                item_uuid: item,
                algorithm: row.get(6).store()?,
                sign_count: row.get(7).store()?,
                created_at: row.get(8).store()?,
                last_used_at: row.get(9).store()?,
            });
        }
        Ok(out)
    }

    /// 删除 passkey 记录（FR-10.5；纯 DB 行，无文件面副作用）。
    ///
    /// 行不存在 → [`CfError::ItemNotFound`]（1011）。条目硬删的级联由
    /// DDL 外键 `ON DELETE CASCADE` 承担，不在本方法职责内。
    pub fn remove(&self, passkey_uuid: &str) -> CfStoreResult<()> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM passkeys WHERE uuid = ?1",
                rusqlite::params![passkey_uuid],
            )
            .store()?;
        if affected == 0 {
            return Err(CfError::ItemNotFound);
        }
        Ok(())
    }

    /// 加密封装：AAD 钉死在 passkey 行 uuid（全仓库层统一约定）。
    fn seal_column(&self, uuid: &str, column: &str, plain: &[u8]) -> CfStoreResult<Vec<u8>> {
        let aad = field_aad("passkeys", uuid, column)?;
        seal(self.field_key, &aad, plain).crypto()
    }

    /// 可空列加密：`None` → SQL NULL。
    fn seal_optional(
        &self,
        uuid: &str,
        column: &str,
        plain: Option<&str>,
    ) -> CfStoreResult<Option<Vec<u8>>> {
        match plain {
            None => Ok(None),
            Some(s) => Ok(Some(self.seal_column(uuid, column, s.as_bytes())?)),
        }
    }

    /// 解密列明文（字节）。
    ///
    /// 密文短于 nonce+tag → [`CfError::Corrupted`]（1005，结构性损坏，
    /// totp 同款预检）；AEAD 校验不过（篡改 / 跨行搬运 / 错误密钥）→
    /// [`CfError::CryptoError`]（1008，不区分原因）。
    fn open_bytes(&self, uuid: &str, column: &str, sealed: &[u8]) -> CfStoreResult<Vec<u8>> {
        if sealed.len() < SEALED_MIN_LEN {
            return Err(CfError::Corrupted(format!(
                "passkey {column} shorter than nonce+tag"
            )));
        }
        let aad = field_aad("passkeys", uuid, column)?;
        open(self.field_key, &aad, sealed).crypto()
    }

    /// 解密列明文（UTF-8 字符串）。
    fn open_string(&self, uuid: &str, column: &str, sealed: &[u8]) -> CfStoreResult<String> {
        let plain = self.open_bytes(uuid, column, sealed)?;
        String::from_utf8(plain).map_err(|_| CfError::Corrupted("passkey column not utf-8".into()))
    }

    /// 可空列解密：SQL NULL → `None`。
    fn open_optional(
        &self,
        uuid: &str,
        column: &str,
        sealed: Option<Vec<u8>>,
    ) -> CfStoreResult<Option<String>> {
        match sealed {
            None => Ok(None),
            Some(ct) => Ok(Some(self.open_string(uuid, column, &ct)?)),
        }
    }
}

/// `rp_id_hmac = HMAC-SHA256(passkey_idx_key, rp_id)`（docs/17 §3.3 D-3）。
///
/// 实现说明：按 RFC 2104 §2 将 32 字节子密钥**零填充**到 HMAC 分组长度
/// （64B）后走 infallible 的 `Mac::new`——与 `new_from_slice` 逐字节
/// 等价（cf-audit `password_fingerprint` 同款，不可达错误分支被结构性
/// 消除，本 crate 禁 unwrap/expect）。
fn rp_id_hmac(key: &SessionKey, rp_id: &[u8]) -> Vec<u8> {
    let mut padded = [0u8; 64]; // HMAC-SHA256 分组长度
    padded[..key.as_bytes().len()].copy_from_slice(key.as_bytes());
    let mut mac = <HmacSha256 as KeyInit>::new(GenericArray::from_slice(&padded));
    mac.update(rp_id);
    mac.finalize().into_bytes().to_vec()
}
