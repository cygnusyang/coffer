//! items 表仓库（`docs/07-macOS纵切设计.md` §2.1）。
//!
//! insert / update / get / list（分页、按 state+category 过滤）/
//! soft_delete / restore / set_favorite。`enc_title` 用 `item_key` 加解密，
//! AAD = `field_aad("items", item_uuid, "enc_title")`（表名命名空间，O-1）。
//!
//! 本仓库只操作 items 表；fields / urls / tags / sections 由各自仓库
//! 按 item 批量替换（update 语义 = 删旧插新）。

use cf_crypto::aead::{open, seal};
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use rusqlite::Connection;

use crate::error::{CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::{field_aad, unix_now};

/// items 表 `enc_title` 列名（AAD 成分）。
pub const COLUMN_ITEM_TITLE: &str = "enc_title";

/// items 表一行（不含解密后的标题）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    /// 条目 ID（UUIDv7 文本）。
    pub uuid: String,
    /// 条目类别（snake_case 名）。
    pub category: ItemCategory,
    /// 条目状态。
    pub state: ItemState,
    /// 是否收藏。
    pub is_favorite: bool,
    /// 收藏排序索引（来自 1PUX favIndex）。
    pub fav_index: i64,
    /// 创建时间（Unix 秒 UTC）。
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）。
    pub updated_at: i64,
    /// 移入回收站时间；仅 state = Trashed 时有意义。
    pub trashed_at: Option<i64>,
    /// 排序位置。
    pub position: i64,
}

/// 条目 + 解密后的标题（get / list 的返回单元）。
#[derive(Debug)]
pub struct ItemWithTitle {
    /// 行数据（不含密文）。
    pub row: ItemRow,
    /// 解密后的标题（`SecretString`，析构清零）。
    pub title: SecretString,
}

/// 列表过滤条件（docs/03 §3.2 关键查询模式）。
#[derive(Debug, Clone, Default)]
pub struct ItemListFilter {
    /// 按状态过滤；`None` 不过滤。
    pub state: Option<ItemState>,
    /// 按类别过滤；`None` 不过滤。
    pub category: Option<ItemCategory>,
    /// 分页偏移；`None` 视为 0。
    pub offset: Option<i64>,
    /// 每页上限；`None` 不限量。
    pub limit: Option<i64>,
}

/// items 表仓库。
pub struct ItemsRepo<'a> {
    conn: &'a Connection,
    subkeys: &'a SubKeys,
}

impl<'a> ItemsRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self { conn, subkeys }
    }

    fn item_key(&self) -> &cf_crypto::aead::SessionKey {
        &self.subkeys.item_key
    }

    /// 加密标题（AAD 钉死在 items 表 + 条目 uuid + enc_title 列）。
    fn seal_title(&self, item_uuid: &str, title: &SecretString) -> CfStoreResult<Vec<u8>> {
        let aad = field_aad("items", item_uuid, COLUMN_ITEM_TITLE)?;
        seal(self.item_key(), &aad, title.expose().as_bytes()).crypto()
    }

    /// 解密标题（AAD 不匹配 → 解密失败，不区分原因）。
    fn open_title(&self, item_uuid: &str, enc_title: &[u8]) -> CfStoreResult<SecretString> {
        let aad = field_aad("items", item_uuid, COLUMN_ITEM_TITLE)?;
        let plain = open(self.item_key(), &aad, enc_title).crypto()?;
        let s = String::from_utf8(plain)
            .map_err(|_| cf_domain::CfError::Corrupted("title not utf-8".into()))?;
        Ok(SecretString::from_exposed(s))
    }

    /// 新增条目（标题加密落盘）。
    ///
    /// uuid 重复返回 [`CfError::Validation`]（不暴露 SQLite 约束错误）。
    pub fn insert(&self, row: &ItemRow, title: &SecretString) -> CfStoreResult<()> {
        if self.get_row(&row.uuid)?.is_some() {
            return Err(cf_domain::CfError::Validation("item already exists".into()));
        }
        let enc_title = self.seal_title(&row.uuid, title)?;
        self.conn
            .execute(
                "INSERT INTO items
                    (uuid, category, state, is_favorite, fav_index,
                     created_at, updated_at, trashed_at, enc_title, position)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    row.uuid,
                    row.category.as_str(),
                    state_to_i64(row.state),
                    i64::from(row.is_favorite),
                    row.fav_index,
                    row.created_at,
                    row.updated_at,
                    row.trashed_at,
                    enc_title,
                    row.position,
                ],
            )
            .store()?;
        Ok(())
    }

    /// 更新行数据（不涉及标题；标题改动用 [`ItemsRepo::update_title`]）。
    ///
    /// 条目不存在返回 [`CfError::ItemNotFound`]。
    pub fn update_row(&self, row: &ItemRow) -> CfStoreResult<()> {
        let n = self
            .conn
            .execute(
                "UPDATE items SET category=?2, state=?3, is_favorite=?4, fav_index=?5,
                    updated_at=?6, trashed_at=?7, position=?8
                 WHERE uuid=?1",
                rusqlite::params![
                    row.uuid,
                    row.category.as_str(),
                    state_to_i64(row.state),
                    i64::from(row.is_favorite),
                    row.fav_index,
                    row.updated_at,
                    row.trashed_at,
                    row.position,
                ],
            )
            .store()?;
        require_rows(n)
    }

    /// 更新标题（重新加密；AAD 钉死在原条目 uuid 上）。
    pub fn update_title(&self, uuid: &str, title: &SecretString) -> CfStoreResult<()> {
        if self.get_row(uuid)?.is_none() {
            return Err(cf_domain::CfError::ItemNotFound);
        }
        let enc_title = self.seal_title(uuid, title)?;
        let updated_at = unix_now()?;
        self.conn
            .execute(
                "UPDATE items SET enc_title=?2, updated_at=?3 WHERE uuid=?1",
                rusqlite::params![uuid, enc_title, updated_at],
            )
            .store()?;
        Ok(())
    }

    /// 读取单行（不含标题解密）。
    pub fn get_row(&self, uuid: &str) -> CfStoreResult<Option<ItemRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, category, state, is_favorite, fav_index,
                        created_at, updated_at, trashed_at, position
                 FROM items WHERE uuid = ?1",
            )
            .store()?;
        let mut rows = stmt.query([uuid]).store()?;
        match rows.next().store()? {
            Some(r) => Ok(Some(row_to_item(r)?)),
            None => Ok(None),
        }
    }

    /// 读取条目并解密标题；不存在返回 `None`。
    pub fn get(&self, uuid: &str) -> CfStoreResult<Option<ItemWithTitle>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, category, state, is_favorite, fav_index,
                        created_at, updated_at, trashed_at, position, enc_title
                 FROM items WHERE uuid = ?1",
            )
            .store()?;
        let mut rows = stmt.query([uuid]).store()?;
        match rows.next().store()? {
            Some(r) => {
                let row = row_to_item(r)?;
                let enc_title: Vec<u8> = r.get(9).store()?;
                let title = self.open_title(&row.uuid, &enc_title)?;
                Ok(Some(ItemWithTitle { row, title }))
            }
            None => Ok(None),
        }
    }

    /// 按过滤条件列出条目（updated_at DESC，docs/03 §3.2），解密标题。
    pub fn list(&self, filter: &ItemListFilter) -> CfStoreResult<Vec<ItemWithTitle>> {
        let mut sql = String::from(
            "SELECT uuid, category, state, is_favorite, fav_index,
                    created_at, updated_at, trashed_at, position, enc_title
             FROM items WHERE 1=1",
        );
        if filter.state.is_some() {
            sql.push_str(" AND state = ?");
        }
        if filter.category.is_some() {
            sql.push_str(" AND category = ?");
        }
        sql.push_str(" ORDER BY updated_at DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {offset}"));
        }

        // 参数按占位符出现顺序动态绑定
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(state) = filter.state {
            params.push(rusqlite::types::Value::Integer(state_to_i64(state)));
        }
        if let Some(category) = filter.category {
            params.push(rusqlite::types::Value::Text(category.as_str().to_owned()));
        }

        let mut stmt = self.conn.prepare(&sql).store()?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params)).store()?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().store()? {
            let row = row_to_item(r)?;
            let enc_title: Vec<u8> = r.get(9).store()?;
            let title = self.open_title(&row.uuid, &enc_title)?;
            out.push(ItemWithTitle { row, title });
        }
        Ok(out)
    }

    /// 软删（移入回收站）：state=2 + trashed_at；不存在返回 `ItemNotFound`。
    pub fn soft_delete(&self, uuid: &str, trashed_at: i64) -> CfStoreResult<()> {
        let n = self
            .conn
            .execute(
                "UPDATE items SET state=2, trashed_at=?2 WHERE uuid=?1",
                rusqlite::params![uuid, trashed_at],
            )
            .store()?;
        require_rows(n)
    }

    /// 从回收站恢复：state=0，trashed_at 清空。
    pub fn restore(&self, uuid: &str) -> CfStoreResult<()> {
        let n = self
            .conn
            .execute(
                "UPDATE items SET state=0, trashed_at=NULL WHERE uuid=?1",
                rusqlite::params![uuid],
            )
            .store()?;
        require_rows(n)
    }

    /// 设置/取消收藏。
    pub fn set_favorite(&self, uuid: &str, favorite: bool) -> CfStoreResult<()> {
        let n = self
            .conn
            .execute(
                "UPDATE items SET is_favorite=?2 WHERE uuid=?1",
                rusqlite::params![uuid, i64::from(favorite)],
            )
            .store()?;
        require_rows(n)
    }

    /// 硬删（外键级联清除 fields / urls / tags / sections / totp 等从表）。
    pub fn delete_hard(&self, uuid: &str) -> CfStoreResult<()> {
        let n = self
            .conn
            .execute("DELETE FROM items WHERE uuid=?1", rusqlite::params![uuid])
            .store()?;
        require_rows(n)
    }

    /// 统计指定状态的条目数；`state = None` 统计全部。
    pub fn count(&self, state: Option<ItemState>) -> CfStoreResult<i64> {
        match state {
            None => Ok(self
                .conn
                .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
                .store()?),
            Some(s) => Ok(self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM items WHERE state=?1",
                    rusqlite::params![state_to_i64(s)],
                    |r| r.get(0),
                )
                .store()?),
        }
    }
}

/// 影响行数为 0 → ItemNotFound（docs/07 §2.1：写操作前置校验）。
fn require_rows(n: usize) -> CfStoreResult<()> {
    if n == 0 {
        Err(cf_domain::CfError::ItemNotFound)
    } else {
        Ok(())
    }
}

/// `ItemState` ↔ DDL 整数（0=active 1=archived 2=trashed）。
pub(crate) fn state_to_i64(state: ItemState) -> i64 {
    match state {
        ItemState::Active => 0,
        ItemState::Archived => 1,
        ItemState::Trashed => 2,
    }
}

/// DDL 整数 → `ItemState`；未知值视为数据损坏。
fn state_from_i64(v: i64) -> CfStoreResult<ItemState> {
    match v {
        0 => Ok(ItemState::Active),
        1 => Ok(ItemState::Archived),
        2 => Ok(ItemState::Trashed),
        _ => Err(cf_domain::CfError::Corrupted("unknown item state".into())),
    }
}

/// 行 → `ItemRow`（列序与 get/get_row 的 SELECT 一致）。
fn row_to_item(r: &rusqlite::Row<'_>) -> CfStoreResult<ItemRow> {
    let category_str: String = r.get(1).store()?;
    let category = ItemCategory::from_str(&category_str).unwrap_or(ItemCategory::Custom);
    Ok(ItemRow {
        uuid: r.get(0).store()?,
        category,
        state: state_from_i64(r.get::<_, i64>(2).store()?)?,
        is_favorite: r.get::<_, i64>(3).store()? != 0,
        fav_index: r.get(4).store()?,
        created_at: r.get(5).store()?,
        updated_at: r.get(6).store()?,
        trashed_at: r.get(7).store()?,
        position: r.get(8).store()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CfError;

    fn setup() -> (Connection, SubKeys) {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        (conn, keys)
    }

    fn sample(uuid_seed: u8) -> (ItemRow, SecretString) {
        let row = ItemRow {
            uuid: uuid::Uuid::from_bytes([uuid_seed; 16]).to_string(),
            category: ItemCategory::Login,
            state: ItemState::Active,
            is_favorite: false,
            fav_index: 0,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            trashed_at: None,
            position: 0,
        };
        (row, SecretString::from_exposed("GitHub 登录"))
    }

    /// 插入 → 读取：行数据与解密标题往返一致
    #[test]
    fn 插入读取往返一致() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        repo.insert(&row, &title).unwrap();

        let got = repo.get(&row.uuid).unwrap().unwrap();
        assert_eq!(got.row, row);
        assert_eq!(got.title.expose(), "GitHub 登录");
    }

    /// 重复 uuid 插入被拒（Validation，而非裸约束错误）
    #[test]
    fn 重复插入被拒绝() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        repo.insert(&row, &title).unwrap();
        let result = repo.insert(&row, &title);
        assert!(matches!(result, Err(CfError::Validation(_))));
    }

    /// enc_title 落盘是密文：BLOB ≠ 明文，长度符合 nonce‖ct‖tag
    #[test]
    fn 标题落盘为密文() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        repo.insert(&row, &title).unwrap();

        let blob: Vec<u8> = conn
            .query_row(
                "SELECT enc_title FROM items WHERE uuid=?1",
                rusqlite::params![row.uuid],
                |r| r.get(0),
            )
            .unwrap();
        let plain = title.expose().as_bytes();
        assert_ne!(blob, plain, "标题明文不得出现在数据库中");
        assert_eq!(blob.len(), 24 + plain.len() + 16);
    }

    /// 密文搬到别的条目（不同 AAD）→ 解密失败（防跨行搬运）
    #[test]
    fn 密文跨行搬运解密失败() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (a, ta) = sample(1);
        let (b, _) = sample(2);
        repo.insert(&a, &ta).unwrap();
        repo.insert(&b, &SecretString::from_exposed("别的条目")).unwrap();

        conn.execute(
            "UPDATE items SET enc_title=(SELECT enc_title FROM items WHERE uuid=?1) WHERE uuid=?2",
            rusqlite::params![a.uuid, b.uuid],
        )
        .unwrap();

        let result = repo.get(&b.uuid);
        match result {
            Err(CfError::CryptoError) => {}
            other => panic!("期望 CryptoError，实际 {other:?}"),
        }
    }

    /// 列表：状态/类别过滤 + updated_at 倒序 + 分页
    #[test]
    fn 列表过滤与分页() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);

        let (mut a, ta) = sample(1);
        a.updated_at = 3_000;
        let (mut b, tb) = sample(2);
        b.updated_at = 2_000;
        b.category = ItemCategory::SecureNote;
        let (mut c, tc) = sample(3);
        c.updated_at = 1_000;
        c.state = ItemState::Archived;
        repo.insert(&a, &ta).unwrap();
        repo.insert(&b, &tb).unwrap();
        repo.insert(&c, &tc).unwrap();

        // 默认全部，updated_at 倒序
        let all = repo.list(&ItemListFilter::default()).unwrap();
        assert_eq!(
            all.iter().map(|i| i.row.uuid.clone()).collect::<Vec<_>>(),
            vec![a.uuid.clone(), b.uuid.clone(), c.uuid.clone()]
        );

        // 按状态过滤
        let archived = repo
            .list(&ItemListFilter { state: Some(ItemState::Archived), ..Default::default() })
            .unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].row.uuid, c.uuid);

        // 按类别过滤
        let notes = repo
            .list(&ItemListFilter { category: Some(ItemCategory::SecureNote), ..Default::default() })
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].row.uuid, b.uuid);

        // 分页
        let page = repo
            .list(&ItemListFilter { limit: Some(2), offset: Some(1), ..Default::default() })
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].row.uuid, b.uuid);
        assert_eq!(page[1].row.uuid, c.uuid);
    }

    /// 软删 → 恢复 → 收藏：状态迁移正确
    #[test]
    fn 软删恢复与收藏() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        repo.insert(&row, &title).unwrap();

        repo.soft_delete(&row.uuid, 1_234).unwrap();
        let got = repo.get_row(&row.uuid).unwrap().unwrap();
        assert_eq!(got.state, ItemState::Trashed);
        assert_eq!(got.trashed_at, Some(1_234));

        repo.restore(&row.uuid).unwrap();
        let got = repo.get_row(&row.uuid).unwrap().unwrap();
        assert_eq!(got.state, ItemState::Active);
        assert_eq!(got.trashed_at, None);

        repo.set_favorite(&row.uuid, true).unwrap();
        assert!(repo.get_row(&row.uuid).unwrap().unwrap().is_favorite);
    }

    /// 不存在的条目：get 返回 None；写操作返回 ItemNotFound（1011）
    #[test]
    fn 不存在条目写操作报未找到() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let missing = uuid::Uuid::from_bytes([9; 16]).to_string();

        assert!(repo.get(&missing).unwrap().is_none());

        let (mut row, title) = sample(1);
        row.uuid = missing.clone();
        assert!(matches!(repo.update_row(&row), Err(CfError::ItemNotFound)));
        assert!(matches!(repo.update_title(&missing, &title), Err(CfError::ItemNotFound)));
        assert!(matches!(repo.soft_delete(&missing, 0), Err(CfError::ItemNotFound)));
        assert!(matches!(repo.restore(&missing), Err(CfError::ItemNotFound)));
        assert!(matches!(repo.set_favorite(&missing, true), Err(CfError::ItemNotFound)));
        assert!(matches!(repo.delete_hard(&missing), Err(CfError::ItemNotFound)));
    }

    /// 硬删级联：从表行（此处以 totp 为例）随条目一起消失
    #[test]
    fn 硬删级联清除从表() {
        let (conn, keys) = setup();
        let items = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        items.insert(&row, &title).unwrap();

        conn.execute(
            "INSERT INTO totp (uuid, item_uuid, enc_secret, algo, digits, period, created_at)
             VALUES ('t1', ?1, x'00', 'sha1', 6, 30, 0)",
            rusqlite::params![row.uuid],
        )
        .unwrap();

        items.delete_hard(&row.uuid).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM totp WHERE item_uuid=?1", rusqlite::params![row.uuid], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "外键级联必须清除从表");
    }

    /// 未知 state 数值 → Corrupted（数据被篡改时不猜测）
    #[test]
    fn 未知状态值报损坏() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (row, title) = sample(1);
        repo.insert(&row, &title).unwrap();
        conn.execute("UPDATE items SET state=9 WHERE uuid=?1", rusqlite::params![row.uuid])
            .unwrap();

        assert!(matches!(repo.get(&row.uuid), Err(CfError::Corrupted(_))));
    }

    /// count 按状态统计
    #[test]
    fn 计数统计() {
        let (conn, keys) = setup();
        let repo = ItemsRepo::new(&conn, &keys);
        let (a, ta) = sample(1);
        let (mut b, tb) = sample(2);
        b.state = ItemState::Trashed;
        repo.insert(&a, &ta).unwrap();
        repo.insert(&b, &tb).unwrap();

        assert_eq!(repo.count(None).unwrap(), 2);
        assert_eq!(repo.count(Some(ItemState::Active)).unwrap(), 1);
        assert_eq!(repo.count(Some(ItemState::Trashed)).unwrap(), 1);
    }
}
