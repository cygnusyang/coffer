//! history 表仓库（FR-2.9 条目历史版本，docs/09 §3.3）。
//!
//! 快照载荷 = [`cf_domain::snapshot::ItemSnapshot`]（CBOR 序列化 →
//! `hist_key` AEAD 加密）。AAD 与全仓库层统一约定一致：
//! `history ‖ 0x00 ‖ history行uuid(16) ‖ 0x00 ‖ enc_snapshot`——密文钉死
//! 在（表, 行, 列）三维位置上，跨行搬运解密失败（O-1）。
//!
//! DDL 已在格式冻结 v1 的 11 表之内（`history` 表建而未用，本仓库首次
//! 启用它），零 schema 变更。版本号由 [`HistoryRepo::insert`] 内部按
//! `latest_version + 1` 分配，`UNIQUE(item_uuid, version)` 兜底防并发
//! 撞号；v0.2 不限量（查询按 version DESC，保留策略 v0.3 再议）。

use cf_crypto::aead::{open, seal};
use cf_crypto::subkeys::SubKeys;
use cf_domain::snapshot::ItemSnapshot;
use rusqlite::Connection;

use crate::error::{CfError, CfStoreResult, CryptoResultExt, RusqliteResultExt};
use crate::repo::{field_aad, uuid_bytes};

/// `enc_snapshot` 的 AAD 列名。
pub const COLUMN_HISTORY_SNAPSHOT: &str = "enc_snapshot";

/// 历史版本元数据（快照载荷按需经 [`HistoryRepo::snapshot`] 解密）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMeta {
    /// 历史行 UUID（主键）。
    pub uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// 版本号（条目内自增，1 起）。
    pub version: i64,
    /// 快照写入时间（Unix 秒）。
    pub created_at: i64,
}

/// history 表仓库（借用连接，可参与事务）。
pub struct HistoryRepo<'a> {
    conn: &'a Connection,
    hist_key: &'a cf_crypto::aead::SessionKey,
}

impl<'a> HistoryRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self {
            conn,
            hist_key: &subkeys.hist_key,
        }
    }

    /// 读取某条目当前最高版本号；无历史记录返回 `Ok(None)`。
    pub fn latest_version(&self, item_uuid: &str) -> CfStoreResult<Option<i64>> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(version) FROM history WHERE item_uuid = ?1",
                rusqlite::params![item_uuid],
                |r| r.get(0),
            )
            .store()?;
        Ok(v)
    }

    /// 写入一份历史快照：CBOR 序列化 → `hist_key` AEAD（AAD 钉
    /// history 行 uuid）→ 版本号 = `latest_version + 1`。
    ///
    /// 返回新生成的 history 行 uuid。**内容去重在编排层完成**
    /// （内容无变化的 update 不调用本方法），本仓库只负责忠实写入。
    pub fn insert(
        &self,
        item_uuid: &str,
        snapshot: &ItemSnapshot,
        now: i64,
    ) -> CfStoreResult<String> {
        uuid_bytes(item_uuid)?;

        let version = self.latest_version(item_uuid)?.unwrap_or(0) + 1;
        let history_uuid = uuid::Uuid::now_v7().to_string();

        let mut plain = Vec::new();
        ciborium::into_writer(snapshot, &mut plain)
            .map_err(|_| CfError::Corrupted("snapshot cbor serialize failed".into()))?;
        let aad = field_aad("history", &history_uuid, COLUMN_HISTORY_SNAPSHOT)?;
        let enc = seal(self.hist_key, &aad, &plain).crypto()?;

        self.conn
            .execute(
                "INSERT INTO history (uuid, item_uuid, version, created_at, enc_snapshot)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![history_uuid, item_uuid, version, now, enc],
            )
            .store()?;
        Ok(history_uuid)
    }

    /// 列出某条目的全部历史版本（version DESC）。
    pub fn list(&self, item_uuid: &str) -> CfStoreResult<Vec<HistoryMeta>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uuid, item_uuid, version, created_at
                 FROM history WHERE item_uuid = ?1 ORDER BY version DESC",
            )
            .store()?;
        let mut rows = stmt.query(rusqlite::params![item_uuid]).store()?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().store()? {
            out.push(HistoryMeta {
                uuid: row.get(0).store()?,
                item_uuid: row.get(1).store()?,
                version: row.get(2).store()?,
                created_at: row.get(3).store()?,
            });
        }
        Ok(out)
    }

    /// [`HistoryRepo::list`] 的编排便捷形态：**单次往返**同时判定条目
    /// 存在性——条目不存在返回 `Ok(None)`（供上层映射 ItemNotFound），
    /// 存在则返回其全部版本（可能为空）。
    ///
    /// 相比「get_row + list」省一次往返（1000 条目 list 基线的关键路径，
    /// docs/09 §3.3 测试要点 7）。有 history 行即意味着条目存在
    /// （外键 `ON DELETE CASCADE` 保证无孤儿行），仅空结果需要补一次
    /// 存在性查询来区分「无版本」与「条目不存在」。
    pub fn list_for_existing_item(
        &self,
        item_uuid: &str,
    ) -> CfStoreResult<Option<Vec<HistoryMeta>>> {
        let out = self.list(item_uuid)?;
        if !out.is_empty() {
            return Ok(Some(out));
        }
        let exists: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM items WHERE uuid = ?1",
                rusqlite::params![item_uuid],
                |r| r.get(0),
            )
            .store()?;
        if exists == 0 {
            Ok(None)
        } else {
            Ok(Some(Vec::new()))
        }
    }

    /// 解密并返回指定历史行的快照；行不存在返回 `Ok(None)`。
    ///
    /// 密文损坏 / AAD 不匹配（跨行搬运）→ 解密失败，不区分原因。
    pub fn snapshot(&self, history_uuid: &str) -> CfStoreResult<Option<ItemSnapshot>> {
        let mut stmt = self
            .conn
            .prepare("SELECT enc_snapshot FROM history WHERE uuid = ?1")
            .store()?;
        let mut rows = stmt.query(rusqlite::params![history_uuid]).store()?;

        let Some(row) = rows.next().store()? else {
            return Ok(None);
        };
        let enc: Vec<u8> = row.get(0).store()?;

        let aad = field_aad("history", history_uuid, COLUMN_HISTORY_SNAPSHOT)?;
        let plain = open(self.hist_key, &aad, &enc).crypto()?;
        let snap: ItemSnapshot = ciborium::from_reader(plain.as_slice())
            .map_err(|_| CfError::Corrupted("snapshot cbor deserialize failed".into()))?;
        Ok(Some(snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::FieldType;
    use cf_domain::item::ItemState;
    use cf_domain::totp_data::{TotpAlgo, TotpData};
    use rusqlite::Connection;

    fn setup() -> (Connection, SubKeys) {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        (conn, keys)
    }

    fn item_uuid(seed: u8) -> String {
        uuid::Uuid::from_bytes([seed; 16]).to_string()
    }

    fn sample_snapshot(item: &str) -> ItemSnapshot {
        ItemSnapshot {
            uuid: uuid::Uuid::parse_str(item).unwrap(),
            category: ItemCategory::Login,
            state: ItemState::Active,
            is_favorite: false,
            fav_index: 0,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            title: "GitHub 登录".to_owned(),
            urls: vec![cf_domain::snapshot::UrlEntrySnapshot {
                uuid: uuid::Uuid::now_v7(),
                label: Some("官网".to_owned()),
                url: "https://github.com".to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: vec!["工作".to_owned()],
            sections: vec![],
            fields: vec![cf_domain::snapshot::FieldSnapshot {
                uuid: uuid::Uuid::now_v7(),
                section_uuid: None,
                field_type: FieldType::Concealed,
                designation: Some(cf_domain::field::Designation::Password),
                name: "密码".to_owned(),
                value: Some("hunter2".to_owned()),
                position: 0,
            }],
            totp: Some(TotpData {
                secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                algo: TotpAlgo::Sha1,
                digits: 6,
                period: 30,
            }),
            attachments: vec![],
        }
    }

    fn host_item(conn: &Connection, uuid: &str) {
        conn.execute(
            "INSERT INTO items (uuid, category, state, is_favorite, fav_index,
                                created_at, updated_at, enc_title, position)
             VALUES (?1, 'login', 0, 0, 0, 0, 0, x'00', 0)",
            rusqlite::params![uuid],
        )
        .unwrap();
    }

    fn repo<'a>(conn: &'a Connection, keys: &'a SubKeys) -> HistoryRepo<'a> {
        HistoryRepo::new(conn, keys)
    }

    /// insert → snapshot：CBOR + AEAD 往返逐字段相等
    #[test]
    fn insert_snapshot往返一致() {
        let (conn, keys) = setup();
        let item = item_uuid(1);
        host_item(&conn, &item);

        let snap = sample_snapshot(&item);
        let r = repo(&conn, &keys);
        let h_uuid = r.insert(&item, &snap, 1_000).unwrap();

        let back = r.snapshot(&h_uuid).unwrap().unwrap();
        assert_eq!(back, snap);
    }

    /// 版本号自增：两次 insert 得 1、2；list 按 version DESC
    #[test]
    fn 版本号自增且列表倒序() {
        let (conn, keys) = setup();
        let item = item_uuid(2);
        host_item(&conn, &item);

        let r = repo(&conn, &keys);
        assert_eq!(r.latest_version(&item).unwrap(), None);

        let s1 = sample_snapshot(&item);
        r.insert(&item, &s1, 1_000).unwrap();
        let mut s2 = s1.clone();
        s2.title = "GitHub 登录（改）".to_owned();
        s2.updated_at = 2_000;
        r.insert(&item, &s2, 2_000).unwrap();

        assert_eq!(r.latest_version(&item).unwrap(), Some(2));

        let metas = r.list(&item).unwrap();
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].version, 2, "list 必须 version DESC");
        assert_eq!(metas[1].version, 1);
        assert_eq!(metas[1].created_at, 1_000);
    }

    /// 落盘是密文：enc_snapshot BLOB ≠ CBOR 明文，长度符合 nonce‖ct‖tag
    #[test]
    fn 落盘为密文() {
        let (conn, keys) = setup();
        let item = item_uuid(3);
        host_item(&conn, &item);

        let snap = sample_snapshot(&item);
        let h_uuid = repo(&conn, &keys).insert(&item, &snap, 1).unwrap();

        let mut cbor = Vec::new();
        ciborium::into_writer(&snap, &mut cbor).unwrap();

        let blob: Vec<u8> = conn
            .query_row(
                "SELECT enc_snapshot FROM history WHERE uuid = ?1",
                rusqlite::params![h_uuid],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(blob, cbor, "快照明文不得出现在数据库中");
        assert_eq!(blob.len(), 24 + cbor.len() + 16);
        // 全库扫描：明文标题不出现
        assert!(!blob.windows(cbor.len().min(blob.len())).any(|w| w == cbor.as_slice()));
    }

    /// 密文跨行搬运（同表不同 history 行）→ 解密失败（AAD 行级钉死）
    #[test]
    fn 密文跨行搬运解密失败() {
        let (conn, keys) = setup();
        let item = item_uuid(4);
        host_item(&conn, &item);

        let r = repo(&conn, &keys);
        let snap = sample_snapshot(&item);
        let h1 = r.insert(&item, &snap, 1).unwrap();
        let mut s2 = snap.clone();
        s2.title = "另一个版本".to_owned();
        let h2 = r.insert(&item, &s2, 2).unwrap();

        // 把 h1 的密文搬到 h2 行：AAD 不匹配 ⇒ 解密失败
        conn.execute(
            "UPDATE history SET enc_snapshot=(SELECT enc_snapshot FROM history WHERE uuid=?1)
             WHERE uuid=?2",
            rusqlite::params![h1, h2],
        )
        .unwrap();

        let result = r.snapshot(&h2);
        assert!(matches!(result, Err(CfError::CryptoError)));
    }

    /// 不同条目（item_uuid 不同）互不可见；不存在的行 → None
    #[test]
    fn 条目隔离与缺失行() {
        let (conn, keys) = setup();
        let a = item_uuid(5);
        let b = item_uuid(6);
        host_item(&conn, &a);
        host_item(&conn, &b);

        let r = repo(&conn, &keys);
        r.insert(&a, &sample_snapshot(&a), 1).unwrap();

        assert!(r.list(&b).unwrap().is_empty());
        assert_eq!(r.latest_version(&b).unwrap(), None);
        assert!(r.snapshot(&uuid::Uuid::now_v7().to_string()).unwrap().is_none());
    }

    /// 条目 uuid 非法 → Corrupted（AAD 需要 16 字节）
    #[test]
    fn 非法条目uuid被拒绝() {
        let (conn, keys) = setup();
        let result = repo(&conn, &keys).insert("not-a-uuid", &sample_snapshot(&item_uuid(1)), 1);
        assert!(matches!(result, Err(CfError::Corrupted(_))));
    }
}
