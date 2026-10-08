//! item_origins 表仓库（D-3 origin 绑定，docs/31 §5.3）。
//!
//! 与 tags / urls 相同的「按 item 批量替换」模式：`replace_for_item`
//! 删旧插新，`read_for_item` 按条目读出。值与 `designation` / `category`
//! 同款**明文 TEXT** 落盘——origin 绑定非敏感（站点地址，如
//! `https://example.com`），且是填充匹配的查询面，无需加密。
//!
//! `kind` 列存 `exact` / `subdomain` / `domain`（[`OriginBindingKind::as_str`]）；
//! 未知 kind 文本读路径视为数据损坏（三型冻结，不静默猜测，镜像
//! items 表 `state_from_i64` 语义）。

use cf_domain::origin::{OriginBinding, OriginBindingKind};
use rusqlite::Connection;

use crate::error::{CfStoreResult, RusqliteResultExt};
use crate::repo::url::require_item;

/// item_origins 表一行（写入形态）。
#[derive(Debug, Clone)]
pub struct OriginBindingRow {
    /// 绑定行 ID。
    pub uuid: String,
    /// 所属条目 ID。
    pub item_uuid: String,
    /// 绑定类型。
    pub kind: OriginBindingKind,
    /// 绑定值（语义随 kind，见 [`cf_domain::origin::OriginBinding`]）。
    pub value: String,
}

/// item_origins 表仓库。
pub struct OriginBindingRepo<'a> {
    conn: &'a Connection,
}

impl<'a> OriginBindingRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// 按条目批量替换绑定（删旧插新）。
    pub fn replace_for_item(
        &self,
        item_uuid: &str,
        rows: &[OriginBindingRow],
    ) -> CfStoreResult<()> {
        require_item(self.conn, item_uuid)?;
        self.conn
            .execute("DELETE FROM item_origins WHERE item_uuid=?1", [item_uuid])
            .store()?;
        for r in rows {
            self.conn
                .execute(
                    "INSERT INTO item_origins (uuid, item_uuid, kind, value)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![r.uuid, r.item_uuid, r.kind.as_str(), r.value],
                )
                .store()?;
        }
        Ok(())
    }

    /// 读出条目全部绑定（kind 文本 → 枚举）。
    pub fn read_for_item(&self, item_uuid: &str) -> CfStoreResult<Vec<OriginBinding>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, value FROM item_origins WHERE item_uuid=?1")
            .store()?;
        let mut rows = stmt.query([item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let kind_str: String = r.get(0).store()?;
            let kind = OriginBindingKind::from_str(&kind_str).ok_or_else(|| {
                cf_domain::CfError::Corrupted(format!("unknown origin binding kind {kind_str:?}"))
            })?;
            out.push(OriginBinding {
                kind,
                value: r.get(1).store()?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_domain::CfError;

    fn setup() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        conn
    }

    fn item(conn: &Connection, uuid: &str) {
        conn.execute(
            "INSERT INTO items (uuid, category, created_at, updated_at, enc_title)
             VALUES (?1, 'login', 0, 0, x'00')",
            rusqlite::params![uuid],
        )
        .unwrap();
    }

    fn row(seed: u8, item: &str, kind: OriginBindingKind, value: &str) -> OriginBindingRow {
        OriginBindingRow {
            uuid: uuid::Uuid::from_bytes([seed; 16]).to_string(),
            item_uuid: item.to_owned(),
            kind,
            value: value.to_owned(),
        }
    }

    /// 批量替换写入 → 读出：kind + value 往返一致
    #[test]
    fn 绑定往返一致() {
        let conn = setup();
        let repo = OriginBindingRepo::new(&conn);
        item(&conn, "i-1");

        repo.replace_for_item(
            "i-1",
            &[
                row(1, "i-1", OriginBindingKind::Exact, "https://example.com"),
                row(2, "i-1", OriginBindingKind::Subdomain, "example.com"),
                row(3, "i-1", OriginBindingKind::Domain, "example.org"),
            ],
        )
        .unwrap();

        let got = repo.read_for_item("i-1").unwrap();
        assert_eq!(
            got,
            vec![
                OriginBinding {
                    kind: OriginBindingKind::Exact,
                    value: "https://example.com".to_owned()
                },
                OriginBinding {
                    kind: OriginBindingKind::Subdomain,
                    value: "example.com".to_owned()
                },
                OriginBinding {
                    kind: OriginBindingKind::Domain,
                    value: "example.org".to_owned()
                },
            ]
        );
    }

    /// 替换覆盖旧绑定；无绑定条目读为空
    #[test]
    fn 替换语义与空读() {
        let conn = setup();
        let repo = OriginBindingRepo::new(&conn);
        item(&conn, "i-1");
        item(&conn, "i-2");

        repo.replace_for_item(
            "i-1",
            &[row(1, "i-1", OriginBindingKind::Domain, "old.example")],
        )
        .unwrap();
        repo.replace_for_item(
            "i-1",
            &[row(2, "i-1", OriginBindingKind::Domain, "new.example")],
        )
        .unwrap();
        assert_eq!(
            repo.read_for_item("i-1").unwrap(),
            vec![OriginBinding {
                kind: OriginBindingKind::Domain,
                value: "new.example".to_owned()
            }]
        );

        assert!(repo.read_for_item("i-2").unwrap().is_empty());
    }

    /// 未知 kind 文本 → Corrupted（数据被篡改时不猜测）
    #[test]
    fn 未知kind报损坏() {
        let conn = setup();
        let repo = OriginBindingRepo::new(&conn);
        item(&conn, "i-1");
        conn.execute(
            "INSERT INTO item_origins (uuid, item_uuid, kind, value)
             VALUES ('o1', 'i-1', 'regex', 'x')",
            [],
        )
        .unwrap();

        assert!(matches!(
            repo.read_for_item("i-1"),
            Err(CfError::Corrupted(_))
        ));
    }

    /// 写入不存在条目 → ItemNotFound；硬删条目级联清绑定
    #[test]
    fn 存在性校验与级联删除() {
        let conn = setup();
        let repo = OriginBindingRepo::new(&conn);
        item(&conn, "i-1");

        assert!(matches!(
            repo.replace_for_item("ghost", &[row(1, "ghost", OriginBindingKind::Domain, "x")]),
            Err(CfError::ItemNotFound)
        ));

        repo.replace_for_item(
            "i-1",
            &[row(1, "i-1", OriginBindingKind::Domain, "x.example")],
        )
        .unwrap();
        conn.execute("DELETE FROM items WHERE uuid='i-1'", [])
            .unwrap();
        assert!(repo.read_for_item("i-1").unwrap().is_empty());
    }
}
