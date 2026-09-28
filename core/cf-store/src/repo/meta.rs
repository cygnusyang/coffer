//! meta 表键值读写（`docs/03-详细设计.md` §3.1 / docs/07 §2.1）。
//!
//! meta 表存库级元数据（多为明文，便于锁定时读取）。约定：
//!
//! - 标量整数以 **i64 小端（LE）** 编码进 BLOB（对齐 §3.1 预置行注释）；
//! - `item_count` 是已知元数据泄露项（`03` §3.5），明文存储是有意为之；
//! - `record_count` / `root_mac` 完整性校验（防删除/防回滚，docs/07 §5 C-4
//!   → v0.2 T04 落地，NFR-REL-02/03）：[`MetaRepo::bump_integrity`] 在每个
//!   写事务末尾重算基线，[`MetaRepo::verify_integrity`] 在解锁时校验，
//!   MAC 密钥为第 9 把子密钥 `root_mac_key`（不落盘，库文件篡改不可伪造）。
//!
//! ## root_mac 计算（docs/09 §2 v0.2-T04 冻结）
//!
//! `root_mac = HMAC-SHA256(root_mac_key, LE(record_count) ‖ LE(schema_version))`：
//! - `record_count` 为 **items 表行数**（COUNT(*)，见 [`MetaRepo::bump_integrity`]）；
//! - `schema_version` 取 `cf_format::FORMAT_VERSION`（跨 crate 引用防漂移），
//!   两端均按 i64 小端编码（与 meta 表既有 i64-LE 约定一致）；
//! - 存储形态与 meta 既有风格一致：record_count 走 i64-LE BLOB
//!   （`set_i64`），root_mac 走 base64 文本（对齐 header/content_mac 的
//!   base64 惯例）。

use base64::Engine as _;
use cf_crypto::aead::SessionKey;
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::Sha256;

use crate::error::{CfStoreResult, RusqliteResultExt};

/// meta 键：schema 版本（`schema.rs` 写入与校验）。
pub const KEY_SCHEMA_VERSION: &str = "schema_version";
/// meta 键：库名显示名（明文，锁定时展示用）。
pub const KEY_VAULT_DISPLAY_NAME: &str = "vault_display_name";
/// meta 键：条目计数（docs/07 §2.1：with_tx 维护增量）。
pub const KEY_ITEM_COUNT: &str = "item_count";
/// meta 键：记录计数（防删除检测；v0.2 启用，C-4）。
pub const KEY_RECORD_COUNT: &str = "record_count";
/// meta 键：根 MAC（防回滚检测；v0.2 启用，C-4）。
pub const KEY_ROOT_MAC: &str = "root_mac";
/// meta 键：上次成功备份时间（Unix 秒；FR-8.5 备份提醒，docs/09 §2.2）。
///
/// 打点方为 cf-exporter 的 `export_backup` 成功路径（明文元数据，无需
/// 解锁态）；缺行 = 从未备份过。
pub const KEY_LAST_BACKUP_AT: &str = "last_backup_at";

/// root MAC 字节长度（HMAC-SHA256 输出，`root_mac_key` 为 32 字节子密钥）。
const ROOT_MAC_LEN: usize = 32;

/// HMAC-SHA256 实例别名（与 cf-audit watchtower 同构）。
type HmacSha256 = Hmac<Sha256>;

/// meta 表键值仓库。
pub struct MetaRepo<'a> {
    conn: &'a Connection,
}

impl<'a> MetaRepo<'a> {
    /// 构造仓库（绑定连接）。
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// 读取原始值；键不存在返回 `None`。
    pub fn get(&self, key: &str) -> CfStoreResult<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT value FROM meta WHERE key = ?1").store()?;
        let mut rows = stmt.query([key]).store()?;
        match rows.next().store()? {
            Some(row) => Ok(Some(row.get(0).store()?)),
            None => Ok(None),
        }
    }

    /// 写入原始值（UPSERT）。
    pub fn set(&self, key: &str, value: &[u8]) -> CfStoreResult<()> {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )
            .store()?;
        Ok(())
    }

    /// 读取 i64（小端编码）；键不存在或值长度非法返回 `None`。
    pub fn get_i64(&self, key: &str) -> CfStoreResult<Option<i64>> {
        match self.get(key)? {
            None => Ok(None),
            Some(blob) if blob.len() == 8 => Ok(Some(i64::from_le_bytes(
                blob.as_slice().try_into().unwrap_or([0; 8]),
            ))),
            Some(_) => Ok(None),
        }
    }

    /// 写入 i64（小端编码，UPSERT）。
    pub fn set_i64(&self, key: &str, value: i64) -> CfStoreResult<()> {
        self.set(key, &value.to_le_bytes())
    }

    /// 读取 `meta.item_count`；未初始化视为 0。
    pub fn item_count(&self) -> CfStoreResult<i64> {
        Ok(self.get_i64(KEY_ITEM_COUNT)?.unwrap_or(0))
    }

    /// `meta.item_count` 增量维护（delta 可为负；须在条目写入事务内调用）。
    pub fn add_item_count(&self, delta: i64) -> CfStoreResult<i64> {
        let next = self.item_count()? + delta;
        self.set_i64(KEY_ITEM_COUNT, next)?;
        Ok(next)
    }

    /// 读取库名显示名（明文元数据，锁定态展示用）。
    pub fn vault_display_name(&self) -> CfStoreResult<Option<String>> {
        match self.get(KEY_VAULT_DISPLAY_NAME)? {
            None => Ok(None),
            Some(blob) => Ok(Some(String::from_utf8_lossy(&blob).into_owned())),
        }
    }

    /// 写入库名显示名。
    pub fn set_vault_display_name(&self, name: &str) -> CfStoreResult<()> {
        self.set(KEY_VAULT_DISPLAY_NAME, name.as_bytes())
    }

    /// 读取上次成功备份时间（Unix 秒）；从未备份过返回 `None`。
    pub fn last_backup_at(&self) -> CfStoreResult<Option<i64>> {
        self.get_i64(KEY_LAST_BACKUP_AT)
    }

    /// 写入上次成功备份时间（Unix 秒；由备份导出成功路径调用）。
    pub fn set_last_backup_at(&self, unix_secs: i64) -> CfStoreResult<()> {
        self.set_i64(KEY_LAST_BACKUP_AT, unix_secs)
    }

    // ------------------------------------------------------------ 完整性校验
    // （NFR-REL-02/03，docs/09 §2 v0.2-T04，docs/07 §5 C-4 落地）

    /// 受保护条目计数：`items` 表行数（COUNT(*)）。
    ///
    /// 口径裁决（v0.2-T04）：**只计 items 表**。理由：record_count 的语义是
    /// 「条目记录数」，与 §3.1 预置行注释及 meta.item_count 的条目口径对齐；
    /// attachments / history / fields 等从表均以 `ON DELETE CASCADE` 挂在
    /// items 下，条目删除必然级联可见，单独纳入只增加口径漂移面。
    fn record_count_actual(&self) -> CfStoreResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .store()
    }

    /// 重算完整性基线并写入 meta 两行（NFR-REL-02/03）。
    ///
    /// `record_count = COUNT(*) FROM items`；
    /// `root_mac = HMAC-SHA256(root_mac_key, LE(record_count) ‖ LE(schema_version))`。
    ///
    /// 由 [`crate::ItemStore::with_tx`] 在事务闭包成功后统一调用（单点实现，
    /// SQLite 事务保证与业务写入同生共死：本函数失败自动 ROLLBACK）。
    pub fn bump_integrity(&self, key: &SessionKey) -> CfStoreResult<()> {
        let count = self.record_count_actual()?;
        self.set_i64(KEY_RECORD_COUNT, count)?;
        let mac_b64 = base64::engine::general_purpose::STANDARD
            .encode(root_mac_bytes(key, count));
        self.set(KEY_ROOT_MAC, mac_b64.as_bytes())
    }

    /// 校验完整性基线（NFR-REL-02/03，解锁路径调用）。
    ///
    /// - 两行**任一缺失** → 自举：按 `COUNT(*)` 初始化写入（旧库兼容，
    ///   无需格式迁移）；
    /// - `record_count` 行与 items 表实际行数不符（绕过 with_tx 的直接
    ///   删除/插入）→ [`CfError::Corrupted`]；
    /// - `root_mac` 与以当前基线重算的 HMAC 不符（base64 恒定时间比较）→
    ///   [`CfError::Corrupted`]；调用方（cf-session）归一为 1002。
    ///
    /// 自举分支会产生写入：解锁连接以读写模式打开，可安全落盘。
    pub fn verify_integrity(&self, key: &SessionKey) -> CfStoreResult<()> {
        let stored_count = self.get_i64(KEY_RECORD_COUNT)?;
        let stored_mac = self.get(KEY_ROOT_MAC)?;
        let (stored_count, stored_mac) = match (stored_count, stored_mac) {
            (Some(c), Some(m)) => (c, m),
            // 任一行缺失 → 自举（旧库兼容语义，docs/07 §5 C-4）
            _ => return self.bump_integrity(key),
        };

        let fresh_count = self.record_count_actual()?;
        if stored_count != fresh_count {
            return Err(cf_domain::CfError::Corrupted(
                "record_count does not match items table".into(),
            ));
        }

        // 存储形态：base64 文本。非法 UTF-8 / 非法 base64 / 长度不符
        // 均按「MAC 不匹配」同语义处理（Corrupted），不泄露形态细节。
        let mac_text = std::str::from_utf8(&stored_mac).map_err(|_| {
            cf_domain::CfError::Corrupted("root mac value is corrupt".into())
        })?;
        let mac_bytes = base64::engine::general_purpose::STANDARD
            .decode(mac_text)
            .map_err(|_| cf_domain::CfError::Corrupted("root mac value is corrupt".into()))?;
        if mac_bytes.len() != ROOT_MAC_LEN {
            return Err(cf_domain::CfError::Corrupted(
                "root mac value is corrupt".into(),
            ));
        }

        // 恒定时间比较（Mac::verify_slice 内部用 subtle），防时序侧信道
        let mut mac = hmac_sha256(key.as_bytes());
        mac.update(&fresh_count.to_le_bytes());
        mac.update(&i64::from(cf_format::FORMAT_VERSION).to_le_bytes());
        mac.verify_slice(&mac_bytes).map_err(|_| {
            cf_domain::CfError::Corrupted("root mac mismatch".into())
        })
    }
}

/// 由 32 字节子密钥构造 HMAC-SHA256 实例。
///
/// 按 RFC 2104 §2 将 32 字节密钥**零填充**到 HMAC 分组长度（64B）后走
/// infallible 的 `Mac::new`——两者逐字节等价（HMAC 对短密钥即零填充到
/// 分组长度），与 cf-audit watchtower 的既有模式一致，不可达错误分支被
/// 结构性消除。
fn hmac_sha256(key: &[u8; 32]) -> HmacSha256 {
    const HMAC_SHA256_BLOCK_LEN: usize = 64;
    let mut padded = [0u8; HMAC_SHA256_BLOCK_LEN];
    padded[..key.len()].copy_from_slice(key);
    <HmacSha256 as KeyInit>::new(GenericArray::from_slice(&padded))
}

/// 计算完整性根 MAC（docs/09 §2 v0.2-T04 冻结公式）。
///
/// `HMAC-SHA256(root_mac_key, LE(record_count) ‖ LE(schema_version))`，
/// schema_version 取 `cf_format::FORMAT_VERSION`，两端 i64 小端编码。
fn root_mac_bytes(key: &SessionKey, record_count: i64) -> [u8; ROOT_MAC_LEN] {
    let mut mac = hmac_sha256(key.as_bytes());
    mac.update(&record_count.to_le_bytes());
    mac.update(&i64::from(cf_format::FORMAT_VERSION).to_le_bytes());
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; ROOT_MAC_LEN];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        conn
    }

    /// 原始键值往返
    #[test]
    fn 原始键值往返() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        assert!(meta.get("nope").unwrap().is_none());
        meta.set("k", b"v1").unwrap();
        meta.set("k", b"v2").unwrap(); // UPSERT 覆盖
        assert_eq!(meta.get("k").unwrap().unwrap(), b"v2");
    }

    /// i64 小端往返
    #[test]
    fn i64往返() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        meta.set_i64(KEY_ITEM_COUNT, 42).unwrap();
        assert_eq!(meta.get_i64(KEY_ITEM_COUNT).unwrap(), Some(42));
        meta.set_i64(KEY_ITEM_COUNT, -7).unwrap();
        assert_eq!(meta.get_i64(KEY_ITEM_COUNT).unwrap(), Some(-7));
    }

    /// item_count 初始为 0，增量可正可负
    #[test]
    fn 条目计数增量维护() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        assert_eq!(meta.item_count().unwrap(), 0);
        assert_eq!(meta.add_item_count(3).unwrap(), 3);
        assert_eq!(meta.add_item_count(-1).unwrap(), 2);
        assert_eq!(meta.item_count().unwrap(), 2);
    }

    /// 库名显示名往返（UTF-8）
    #[test]
    fn 库名往返() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        assert!(meta.vault_display_name().unwrap().is_none());
        meta.set_vault_display_name("我的密码库").unwrap();
        assert_eq!(meta.vault_display_name().unwrap().as_deref(), Some("我的密码库"));
    }

    /// 上次备份时间：缺行 = 从未备份，写入后可读回（FR-8.5）
    #[test]
    fn 上次备份时间往返() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        assert!(meta.last_backup_at().unwrap().is_none(), "新库从未备份");
        meta.set_last_backup_at(1_700_000_000).unwrap();
        meta.set_last_backup_at(1_700_000_100).unwrap(); // 二次备份覆盖
        assert_eq!(meta.last_backup_at().unwrap(), Some(1_700_000_100));
    }

    // ------------------------------------------------------------ 完整性校验

    /// 完整性校验用的 32 字节测试密钥（任意常量，非生产密钥）。
    fn root_mac_test_key() -> cf_crypto::aead::SessionKey {
        cf_crypto::aead::SessionKey::new([0x5au8; 32])
    }

    /// 直接向 items 表插一行（绕过 with_tx，构造计数漂移用）。
    fn insert_item_row_raw(conn: &Connection, uuid: &str) {
        conn.execute(
            "INSERT INTO items (uuid, category, enc_title, created_at, updated_at)
             VALUES (?1, 'login', x'00', 1, 1)",
            [uuid],
        )
        .unwrap();
    }

    /// bump → verify 往返：空库基线为 (0, mac)，校验通过
    #[test]
    fn bump后verify往返通过() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        let key = root_mac_test_key();

        // 未 bump 前两行缺失 → verify 自举（旧库兼容路径）
        meta.verify_integrity(&key).unwrap();
        assert_eq!(meta.get_i64(KEY_RECORD_COUNT).unwrap(), Some(0));
        assert!(meta.get(KEY_ROOT_MAC).unwrap().is_some());

        // 再次 verify（非缺失路径）依旧通过
        meta.verify_integrity(&key).unwrap();
    }

    /// 条目增删后基线随之重算：旧 MAC 失效、重新 bump 后恢复
    #[test]
    fn 条目增删后旧基线失效重新bump后恢复() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        let key = root_mac_test_key();

        meta.bump_integrity(&key).unwrap();
        let mac_before = meta.get(KEY_ROOT_MAC).unwrap().unwrap();

        insert_item_row_raw(&conn, "u1");
        // record_count 行仍为 0，实际行数 1 → 校验失败（防删除）
        assert!(matches!(
            meta.verify_integrity(&key),
            Err(cf_domain::CfError::Corrupted(_))
        ));

        // 重新 bump：计数变 1，MAC 变化，恢复一致
        meta.bump_integrity(&key).unwrap();
        assert_eq!(meta.get_i64(KEY_RECORD_COUNT).unwrap(), Some(1));
        assert_ne!(meta.get(KEY_ROOT_MAC).unwrap().unwrap(), mac_before);
        meta.verify_integrity(&key).unwrap();

        // 删除条目后同理：未 bump → 失败；bump → 恢复
        conn.execute("DELETE FROM items WHERE uuid = 'u1'", []).unwrap();
        assert!(matches!(
            meta.verify_integrity(&key),
            Err(cf_domain::CfError::Corrupted(_))
        ));
        meta.bump_integrity(&key).unwrap();
        meta.verify_integrity(&key).unwrap();
    }

    /// 直接 SQL 篡改 record_count 行 → verify 失败
    #[test]
    fn 篡改record_count行verify失败() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        let key = root_mac_test_key();
        meta.bump_integrity(&key).unwrap();

        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'record_count'",
            [2_i64.to_le_bytes().as_slice()],
        )
        .unwrap();
        assert!(matches!(
            meta.verify_integrity(&key),
            Err(cf_domain::CfError::Corrupted(_))
        ));
    }

    /// 直接 SQL 篡改 root_mac 行（合法 base64 但值错误）→ verify 失败
    #[test]
    fn 篡改root_mac行verify失败() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        let key = root_mac_test_key();
        meta.bump_integrity(&key).unwrap();

        // 用另一把密钥重算出「结构合法但值不同」的 MAC 文本
        let other = base64::engine::general_purpose::STANDARD
            .encode(root_mac_bytes(&cf_crypto::aead::SessionKey::new([0x01u8; 32]), 0));
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'root_mac'",
            [other.as_bytes()],
        )
        .unwrap();
        assert!(matches!(
            meta.verify_integrity(&key),
            Err(cf_domain::CfError::Corrupted(_))
        ));
    }

    /// 直接 SQL 篡改 root_mac 行（非法 base64 文本）→ verify 失败而非自举
    #[test]
    fn root_mac行损坏按篡改处理() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        let key = root_mac_test_key();
        meta.bump_integrity(&key).unwrap();

        conn.execute("UPDATE meta SET value = x'ff' WHERE key = 'root_mac'", [])
            .unwrap();
        assert!(matches!(
            meta.verify_integrity(&key),
            Err(cf_domain::CfError::Corrupted(_))
        ));
    }

    /// 删除任一行 → verify 自举重建（旧库兼容语义），且重建后校验通过
    #[test]
    fn 删除任一行后verify自举重建() {
        let key = root_mac_test_key();

        // 删 record_count 行
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        meta.bump_integrity(&key).unwrap();
        insert_item_row_raw(&conn, "u1");
        meta.bump_integrity(&key).unwrap();
        conn.execute("DELETE FROM meta WHERE key = 'record_count'", []).unwrap();
        meta.verify_integrity(&key).unwrap();
        assert_eq!(meta.get_i64(KEY_RECORD_COUNT).unwrap(), Some(1));

        // 删 root_mac 行
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        meta.bump_integrity(&key).unwrap();
        conn.execute("DELETE FROM meta WHERE key = 'root_mac'", []).unwrap();
        meta.verify_integrity(&key).unwrap();
        assert!(meta.get(KEY_ROOT_MAC).unwrap().is_some());
    }

    /// 不同密钥算出的 MAC 互不通过（密钥绑定，非固定值）
    #[test]
    fn 不同密钥的基线互不通过() {
        let conn = repo();
        let meta = MetaRepo::new(&conn);
        meta.bump_integrity(&root_mac_test_key()).unwrap();
        assert!(matches!(
            meta.verify_integrity(&cf_crypto::aead::SessionKey::new([0x33u8; 32])),
            Err(cf_domain::CfError::Corrupted(_))
        ));
    }
}
