//! tags 表仓库（`docs/07-macOS纵切设计.md` §2.1）。
//!
//! 与 fields / urls 相同的"按 item 批量替换"模式。`enc_name` 用
//! `field_key` 加密，AAD 钉死在（tags 表, 标签行 uuid, 列名）上（见
//! [`crate::repo`] 模块文档映射表）。

use cf_crypto::aead::{open, seal};
use cf_crypto::subkeys::SubKeys;
use cf_domain::secret::SecretString;
use rusqlite::Connection;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::url::require_item;
use crate::repo::field_aad;

/// 列名常量（AAD 成分）。
pub const COLUMN_TAG_NAME: &str = "enc_name";

/// tags 表一行（写入形态）。
#[derive(Debug, Clone)]
pub struct TagRow {
    /// 标签行 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 标签名（明文输入）。
    pub name: String,
}

/// tags 表一行（读出形态：名称已解密）。
#[derive(Debug)]
pub struct TagDecrypted {
    /// 标签行 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 解密后的标签名。
    pub name: SecretString,
}

/// tags 表仓库。
pub struct TagsRepo<'a> {
    conn: &'a Connection,
    subkeys: &'a SubKeys,
}

impl<'a> TagsRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self { conn, subkeys }
    }

    /// 按条目批量替换标签（删旧插新）。
    pub fn replace_for_item(&self, item_uuid: &str, tags: &[TagRow]) -> CfStoreResult<()> {
        require_item(self.conn, item_uuid)?;
        self.conn
            .execute("DELETE FROM tags WHERE item_uuid=?1", [item_uuid])
            .store()?;
        for t in tags {
            let enc_name = seal(
                &self.subkeys.field_key,
                &field_aad("tags", &t.uuid, COLUMN_TAG_NAME)?,
                t.name.as_bytes(),
            )
            .crypto()?;
            self.conn
                .execute(
                    "INSERT INTO tags (uuid, item_uuid, enc_name) VALUES (?1, ?2, ?3)",
                    rusqlite::params![t.uuid, t.item_uuid, enc_name],
                )
                .store()?;
        }
        Ok(())
    }

    /// 读出条目全部标签，名称解密。
    pub fn read_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<TagDecrypted>> {
        let mut stmt = self
            .conn
            .prepare("SELECT uuid, item_uuid, enc_name FROM tags WHERE item_uuid=?1")
            .store()?;
        let mut rows = stmt.query([item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let uuid: String = r.get(0).store()?;
            let enc_name: Vec<u8> = r.get(2).store()?;
            let plain = open(
                &self.subkeys.field_key,
                &field_aad("tags", &uuid, COLUMN_TAG_NAME)?,
                &enc_name,
            )
            .crypto()?;
            let name = String::from_utf8(plain)
                .map_err(|_| CfError::Corrupted("tag name not utf-8".into()))?;
            out.push(TagDecrypted {
                uuid,
                item_uuid: r.get(1).store()?,
                name: SecretString::from_exposed(name),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Connection, SubKeys) {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        (conn, keys)
    }

    fn item(conn: &Connection, uuid: &str) {
        conn.execute(
            "INSERT INTO items (uuid, category, created_at, updated_at, enc_title)
             VALUES (?1, 'login', 0, 0, x'00')",
            rusqlite::params![uuid],
        )
        .unwrap();
    }

    fn tag(seed: u8, item: &str, name: &str) -> TagRow {
        TagRow {
            uuid: uuid::Uuid::from_bytes([seed; 16]).to_string(),
            item_uuid: item.to_owned(),
            name: name.to_owned(),
        }
    }

    /// 批量替换写入 → 读出：往返一致
    #[test]
    fn 标签往返一致() {
        let (conn, keys) = setup();
        let repo = TagsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        repo.replace_for_item("i-1", &[tag(1, "i-1", "工作"), tag(2, "i-1", "重要")])
            .unwrap();

        let got = repo.read_for_item("i-1").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name.expose(), "工作");
        assert_eq!(got[1].name.expose(), "重要");
    }

    /// 标签名明文不落盘；密文跨标签行搬运解密失败
    #[test]
    fn 标签密文钉死在行上() {
        let (conn, keys) = setup();
        let repo = TagsRepo::new(&conn, &keys);
        item(&conn, "i-1");
        repo.replace_for_item("i-1", &[tag(1, "i-1", "机密标签甲"), tag(2, "i-1", "另一个")])
            .unwrap();

        let raw: Vec<u8> = conn
            .query_row("SELECT enc_name FROM tags WHERE uuid=?1", rusqlite::params![uuid::Uuid::from_bytes([1; 16]).to_string()], |r| r.get(0))
            .unwrap();
        assert!(!raw.windows("机密标签甲".len()).any(|w| w == "机密标签甲".as_bytes()));

        // 把标签 1 的密文搬到标签 2（不同 AAD）→ 解密失败
        conn.execute(
            "UPDATE tags SET enc_name=(SELECT enc_name FROM tags WHERE uuid=?1) WHERE uuid=?2",
            rusqlite::params![uuid::Uuid::from_bytes([1; 16]).to_string(), uuid::Uuid::from_bytes([2; 16]).to_string()],
        )
        .unwrap();
        assert!(matches!(
            repo.read_for_item("i-1"),
            Err(CfError::CryptoError)
        ));
    }

    /// 替换覆盖 + 条目不存在报 ItemNotFound
    #[test]
    fn 替换语义与存在性校验() {
        let (conn, keys) = setup();
        let repo = TagsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        repo.replace_for_item("i-1", &[tag(1, "i-1", "旧")]).unwrap();
        repo.replace_for_item("i-1", &[tag(2, "i-1", "新"), tag(3, "i-1", "再加")])
            .unwrap();
        assert_eq!(repo.read_for_item("i-1").unwrap().len(), 2);

        assert!(matches!(
            repo.replace_for_item("ghost", &[tag(1, "ghost", "x")]),
            Err(CfError::ItemNotFound)
        ));
    }
}
