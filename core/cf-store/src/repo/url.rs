//! urls 表仓库（`docs/07-macOS纵切设计.md` §2.1）。
//!
//! 与 fields 相同的"按 item 批量替换"模式。`enc_label` / `enc_url` 用
//! `field_key` 加密，AAD 钉死在（urls 表, 各 url 行 uuid, 列名）上（见
//! [`crate::repo`] 模块文档映射表）。

use cf_crypto::aead::{open, seal};
use cf_crypto::subkeys::SubKeys;
use cf_domain::secret::SecretString;
use rusqlite::Connection;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::field_aad;

/// 列名常量（AAD 成分）。
pub const COLUMN_URL_LABEL: &str = "enc_label";
/// 列名常量（AAD 成分）。
pub const COLUMN_URL: &str = "enc_url";

/// urls 表一行（写入形态）。
#[derive(Debug, Clone)]
pub struct UrlRow {
    /// URL 行 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 标签（如"登录页"），可为空。
    pub label: Option<String>,
    /// URL 明文。
    pub url: String,
    /// 是否主 URL。
    pub is_primary: bool,
    /// 排序位置。
    pub position: i64,
}

/// urls 表一行（读出形态：label / url 已解密）。
#[derive(Debug)]
pub struct UrlDecrypted {
    /// URL 行 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 解密后的标签。
    pub label: Option<SecretString>,
    /// 解密后的 URL。
    pub url: SecretString,
    /// 是否主 URL。
    pub is_primary: bool,
    /// 排序位置。
    pub position: i64,
}

/// urls 表仓库。
pub struct UrlsRepo<'a> {
    conn: &'a Connection,
    subkeys: &'a SubKeys,
}

impl<'a> UrlsRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self { conn, subkeys }
    }

    /// 按条目批量替换 URL（删旧插新）。
    pub fn replace_for_item(&self, item_uuid: &str, urls: &[UrlRow]) -> CfStoreResult<()> {
        require_item(self.conn, item_uuid)?;
        self.conn
            .execute("DELETE FROM urls WHERE item_uuid=?1", [item_uuid])
            .store()?;
        for u in urls {
            let enc_url = seal(
                &self.subkeys.field_key,
                &field_aad("urls", &u.uuid, COLUMN_URL)?,
                u.url.as_bytes(),
            )
            .crypto()?;
            let enc_label = match &u.label {
                Some(l) => {
                    let aad = field_aad("urls", &u.uuid, COLUMN_URL_LABEL)?;
                    Some(seal(&self.subkeys.field_key, &aad, l.as_bytes()).crypto()?)
                }
                None => None,
            };
            self.conn
                .execute(
                    "INSERT INTO urls (uuid, item_uuid, enc_label, enc_url, is_primary, position)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        u.uuid,
                        u.item_uuid,
                        enc_label,
                        enc_url,
                        i64::from(u.is_primary),
                        u.position
                    ],
                )
                .store()?;
        }
        Ok(())
    }

    /// 读出条目全部 URL（按 position 升序），label / url 解密。
    pub fn read_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<UrlDecrypted>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, enc_label, enc_url, is_primary, position
                 FROM urls WHERE item_uuid=?1 ORDER BY position ASC",
            )
            .store()?;
        let mut rows = stmt.query([item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let uuid: String = r.get(0).store()?;

            let enc_url: Vec<u8> = r.get(3).store()?;
            let url = open(
                &self.subkeys.field_key,
                &field_aad("urls", &uuid, COLUMN_URL)?,
                &enc_url,
            )
            .crypto()?;
            let url = String::from_utf8(url)
                .map_err(|_| CfError::Corrupted("url not utf-8".into()))?;

            let label = match r.get::<_, Option<Vec<u8>>>(2).store()? {
                Some(ct) => {
                    let plain = open(
                        &self.subkeys.field_key,
                        &field_aad("urls", &uuid, COLUMN_URL_LABEL)?,
                        &ct,
                    )
                    .crypto()?;
                    let plain = String::from_utf8(plain)
                        .map_err(|_| CfError::Corrupted("url label not utf-8".into()))?;
                    Some(plain)
                }
                None => None,
            };

            out.push(UrlDecrypted {
                uuid,
                item_uuid: r.get(1).store()?,
                label: label.map(SecretString::from_exposed),
                url: SecretString::from_exposed(url),
                is_primary: r.get::<_, i64>(4).store()? != 0,
                position: r.get(5).store()?,
            });
        }
        Ok(out)
    }
}

/// 条目必须已存在（外键目标），否则 `ItemNotFound`。
pub(crate) fn require_item(conn: &Connection, item_uuid: &str) -> CfStoreResult<()> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM items WHERE uuid=?1",
            [item_uuid],
            |r| r.get(0),
        )
        .store()?;
    if exists == 0 {
        Err(CfError::ItemNotFound)
    } else {
        Ok(())
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

    fn url(seed: u8, item: &str, u: &str, label: Option<&str>) -> UrlRow {
        UrlRow {
            uuid: uuid::Uuid::from_bytes([seed; 16]).to_string(),
            item_uuid: item.to_owned(),
            label: label.map(str::to_owned),
            url: u.to_owned(),
            is_primary: seed == 1,
            position: i64::from(seed),
        }
    }

    /// 批量替换写入 → 读出：往返一致（含 label 加密）
    #[test]
    fn url往返一致() {
        let (conn, keys) = setup();
        let repo = UrlsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        repo.replace_for_item(
            "i-1",
            &[
                url(1, "i-1", "https://github.com/login", Some("登录页")),
                url(2, "i-1", "https://github.com/settings", None),
            ],
        )
        .unwrap();

        let got = repo.read_for_item("i-1").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].url.expose(), "https://github.com/login");
        assert_eq!(got[0].label.as_ref().unwrap().expose(), "登录页");
        assert!(got[0].is_primary);
        assert!(got[1].label.is_none());
    }

    /// URL 与标签明文不落盘
    #[test]
    fn url与标签明文不落盘() {
        let (conn, keys) = setup();
        let repo = UrlsRepo::new(&conn, &keys);
        item(&conn, "i-1");
        repo.replace_for_item("i-1", &[url(1, "i-1", "https://secret.example/path", Some("密标"))])
            .unwrap();

        let raw: Vec<u8> = conn
            .query_row("SELECT enc_url FROM urls", [], |r| r.get(0))
            .unwrap();
        assert!(!raw.windows("secret.example".len()).any(|w| w == b"secret.example"));
        let lbl: Option<Vec<u8>> = conn
            .query_row("SELECT enc_label FROM urls", [], |r| r.get(0))
            .unwrap();
        let lbl = lbl.unwrap();
        assert!(!lbl.windows("密标".len()).any(|w| w == "密标".as_bytes()));
    }

    /// 替换覆盖 + 空替换清空 + 条目不存在报 ItemNotFound
    #[test]
    fn 替换语义与存在性校验() {
        let (conn, keys) = setup();
        let repo = UrlsRepo::new(&conn, &keys);
        item(&conn, "i-1");

        repo.replace_for_item("i-1", &[url(1, "i-1", "https://old.example", None)])
            .unwrap();
        repo.replace_for_item("i-1", &[url(2, "i-1", "https://new.example", None)])
            .unwrap();
        let got = repo.read_for_item("i-1").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].url.expose(), "https://new.example");

        repo.replace_for_item("i-1", &[]).unwrap();
        assert!(repo.read_for_item("i-1").unwrap().is_empty());

        assert!(matches!(
            repo.replace_for_item("ghost", &[url(1, "ghost", "https://x", None)]),
            Err(CfError::ItemNotFound)
        ));
    }
}
