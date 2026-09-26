//! meta 表键值读写（`docs/03-详细设计.md` §3.1 / docs/07 §2.1）。
//!
//! meta 表存库级元数据（多为明文，便于锁定时读取）。约定：
//!
//! - 标量整数以 **i64 小端（LE）** 编码进 BLOB（对齐 §3.1 预置行注释）；
//! - `item_count` 是已知元数据泄露项（`03` §3.5），明文存储是有意为之；
//! - `record_count` / `root_mac` 的防删除/防回滚校验推后 v0.2（docs/07 §5 C-4），
//!   本仓库层只提供键值读写原语。

use rusqlite::Connection;

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
}
