//! 条目历史版本编排（FR-2.9，docs/09 §3.3）。
//!
//! 语义（D-3 裁定）：
//!
//! - **快照**：`update_item_with_totp` 事务内、替换前，对当前完整状态
//!   构造 [`ItemSnapshot`]（CBOR → `hist_key` AEAD）写入 history 表；
//!   **内容无变化不写**（与最新版本做语义级比较，见
//!   [`snapshot_content_eq`]）——防高频保存把库撑爆；
//! - **回滚**：以历史快照构造 [`ItemDraft`] 走**正常 update 路径**——
//!   即"回滚"本身也是一次修改，当前状态先成为新版本（可再回滚回去）；
//! - **保留策略**：v0.2 不限量；快照明文只在 Rust 事务内流转，不跨 FFI。

use cf_domain::item::ItemDraft;
use cf_domain::snapshot::{FieldSnapshot, ItemSnapshot, SectionSnapshot, UrlEntrySnapshot};
use cf_domain::totp_data::{TotpAlgo, TotpData};
use cf_domain::CfError;
use cf_store::ItemStore;

use cf_domain::totp_data::TotpUpdate;

/// 历史版本条目（元数据；快照明文不外露，回滚是唯一消费路径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// 历史行 UUID。
    pub history_uuid: String,
    /// 版本号（条目内自增，1 起）。
    pub version: i64,
    /// 快照写入时间（Unix 秒）。
    pub created_at: i64,
}

/// 列出某条目的历史版本（version DESC）。条目不存在 →
/// [`CfError::ItemNotFound`]（1011）。
///
/// 走 [`cf_store::HistoryRepo::list_for_existing_item`] 单次往返
/// （1000 条目 list 性能基线的关键路径）。
pub fn list_history(store: &ItemStore, item_id: &str) -> Result<Vec<HistoryEntry>, CfError> {
    let Some(metas) = store.repos().history.list_for_existing_item(item_id)? else {
        return Err(CfError::ItemNotFound);
    };
    Ok(metas
        .into_iter()
        .map(|m| HistoryEntry {
            history_uuid: m.uuid,
            version: m.version,
            created_at: m.created_at,
        })
        .collect())
}

/// 回滚到指定历史版本：读快照 → 构造 `ItemDraft` → 走正常
/// [`super::items::update_item_with_totp`] 路径。
///
/// 快照含 TOTP → [`TotpUpdate::Replace`]（secret 在快照内，恰好走
/// Rust 侧闭环，不跨 FFI）；快照无 TOTP → [`TotpUpdate::Remove`]。
/// 回滚对 Trashed / Archived 条目被既有 update 状态门禁拒绝
/// （[`CfError::Validation`]，1012）。回滚本身写入一份新版本
/// （当前状态先成为快照），用户可"回滚回滚"。
pub fn restore_history(
    store: &mut ItemStore,
    item_id: &str,
    history_uuid: &str,
) -> Result<(), CfError> {
    let snapshot = {
        let repos = store.repos();
        if repos.items.get_row(item_id)?.is_none() {
            return Err(CfError::ItemNotFound);
        }
        repos
            .history
            .snapshot(history_uuid)?
            .ok_or(CfError::ItemNotFound)?
    };

    let draft = draft_from_snapshot(&snapshot)?;
    let totp = match snapshot.totp {
        Some(data) => TotpUpdate::Replace(data),
        None => TotpUpdate::Remove,
    };
    super::items::update_item_with_totp(store, item_id, &draft, totp)
}

/// 在 update 事务内写入"替换前"快照（FR-2.9 触发点）。
///
/// 由 [`super::items::update_item_with_totp`] 在既有行读取与状态门禁
/// 之后、替换写入之前调用；与主表写入同事务（NFR-REL-01）。内容与
/// 最新历史版本无差异时不写（[`snapshot_content_eq`]）。
pub(crate) fn snapshot_before_update(
    repos: &cf_store::Repos<'_>,
    item_id: &str,
    now: i64,
) -> Result<(), CfError> {
    let current = snapshot_current(repos, item_id)?;

    // 内容无变化不写：与最新版本的快照做语义级比较（行 uuid / 位置 /
    // 时间戳在每次"删旧插新"后都会再生，不能按字节比较）
    if let Some(latest) = repos.history.list(item_id)?.into_iter().next() {
        if let Some(previous) = repos.history.snapshot(&latest.uuid)? {
            if snapshot_content_eq(&previous, &current) {
                return Ok(());
            }
        }
    }

    repos.history.insert(item_id, &current, now)?;
    Ok(())
}

/// 读取条目当前完整状态并构造快照（须在事务内，读各从表明文）。
pub(crate) fn snapshot_current(
    repos: &cf_store::Repos<'_>,
    item_id: &str,
) -> Result<ItemSnapshot, CfError> {
    let found = repos.items.get(item_id)?.ok_or(CfError::ItemNotFound)?;
    let row = found.row;

    let urls = repos
        .urls
        .read_for_item(item_id)?
        .into_iter()
        .map(|u| {
            Ok::<UrlEntrySnapshot, CfError>(UrlEntrySnapshot {
                uuid: uuid::Uuid::parse_str(&u.uuid)
                    .map_err(|_| CfError::Corrupted("url uuid is not a valid uuid".into()))?,
                label: u.label.as_ref().map(|l| l.expose().to_owned()),
                url: u.url.expose().to_owned(),
                is_primary: u.is_primary,
                position: i32::try_from(u.position)
                    .map_err(|_| CfError::Corrupted("url position out of range".into()))?,
            })
        })
        .collect::<Result<Vec<_>, CfError>>()?;
    let tags = repos
        .tags
        .read_for_item(item_id)?
        .into_iter()
        .map(|t| t.name.expose().to_owned())
        .collect();
    let sections: Vec<SectionSnapshot> = repos
        .fields
        .read_sections_for_item(item_id)?
        .into_iter()
        .map(|s| {
            Ok::<SectionSnapshot, CfError>(SectionSnapshot {
                uuid: uuid::Uuid::parse_str(&s.uuid)
                    .map_err(|_| CfError::Corrupted("section uuid is not a valid uuid".into()))?,
                title: s.title.expose().to_owned(),
                position: i32::try_from(s.position)
                    .map_err(|_| CfError::Corrupted("section position out of range".into()))?,
            })
        })
        .collect::<Result<Vec<_>, CfError>>()?;
    let fields: Vec<FieldSnapshot> = repos
        .fields
        .read_fields_for_item(item_id)?
        .into_iter()
        .map(|f| {
            Ok::<FieldSnapshot, CfError>(FieldSnapshot {
                uuid: uuid::Uuid::parse_str(&f.uuid)
                    .map_err(|_| CfError::Corrupted("field uuid is not a valid uuid".into()))?,
                section_uuid: f
                    .section_uuid
                    .map(|s| {
                        uuid::Uuid::parse_str(&s).map_err(|_| {
                            CfError::Corrupted("section uuid is not a valid uuid".into())
                        })
                    })
                    .transpose()?,
                field_type: f.field_type,
                designation: f.designation,
                name: f.name.expose().to_owned(),
                value: f.value.as_ref().map(|v| v.expose().to_owned()),
                position: i32::try_from(f.position)
                    .map_err(|_| CfError::Corrupted("field position out of range".into()))?,
            })
        })
        .collect::<Result<Vec<_>, CfError>>()?;
    // v0.1 一条目至多一条 TOTP 记录（写入语义保证）；secret 只在此处
    // 进入快照并随 AEAD 落盘，不跨 FFI（docs/09 §3.3 风险 ②）
    let totp = match repos.totp.totp_uuids_for_item(item_id)?.into_iter().next() {
        Some(uuid) => {
            let meta = repos
                .totp
                .totp_meta(&uuid)?
                .ok_or(CfError::Corrupted("totp row missing".into()))?;
            let secret = repos
                .totp
                .totp_secret(&uuid)?
                .ok_or(CfError::Corrupted("totp row missing".into()))?;
            Some(TotpData {
                secret: secret.to_vec(),
                algo: algo_from_str(&meta.algo)?,
                digits: meta.digits,
                period: meta.period,
            })
        }
        None => None,
    };

    let origin_bindings = repos.origins.read_for_item(item_id)?;

    Ok(ItemSnapshot {
        uuid: uuid::Uuid::parse_str(&row.uuid)
            .map_err(|_| CfError::Corrupted("item uuid is not a valid uuid".into()))?,
        category: row.category,
        state: row.state,
        is_favorite: row.is_favorite,
        fav_index: row.fav_index,
        created_at: row.created_at,
        updated_at: row.updated_at,
        title: found.title.expose().to_owned(),
        urls,
        tags,
        sections,
        fields,
        totp,
        // 附件（FR-9）v0.2 未实现：快照恒为空
        attachments: Vec::new(),
        origin_bindings,
    })
}

/// 快照 → [`ItemDraft`]（回滚路径）。字段挂接的 `section_index` 由
/// 快照内 `section_uuid` 在 `sections` 列表中的下标反解。
///
/// `pub(crate)`：跨库复制（FR-2.10）复用同一「快照 → 草稿」组装，
/// 使复制载荷过同一套 `validate_item` 不变量。
pub(crate) fn draft_from_snapshot(snap: &ItemSnapshot) -> Result<ItemDraft, CfError> {
    let urls = snap
        .urls
        .iter()
        .map(|u| cf_domain::item::UrlDraft {
            label: u.label.clone(),
            url: u.url.clone(),
            is_primary: u.is_primary,
            position: u.position,
        })
        .collect();
    let sections = snap
        .sections
        .iter()
        .map(|s| cf_domain::item::SectionDraft {
            title: s.title.clone(),
            position: s.position,
        })
        .collect();
    let fields = snap
        .fields
        .iter()
        .map(|f| {
            // section_uuid → 草稿下标（快照的 sections 与字段同源，必能反解；
            // 反解失败视为数据损坏而非静默丢弃挂接关系）
            let section_index = match &f.section_uuid {
                None => None,
                Some(suuid) => Some(
                    snap.sections
                        .iter()
                        .position(|s| &s.uuid == suuid)
                        .ok_or_else(|| {
                            CfError::Corrupted("snapshot field references unknown section".into())
                        })?,
                ),
            };
            Ok::<cf_domain::item::FieldDraft, CfError>(cf_domain::item::FieldDraft {
                name: f.name.clone(),
                value: f.value.clone(),
                field_type: f.field_type,
                designation: f.designation.clone(),
                section_index,
                position: f.position,
            })
        })
        .collect::<Result<Vec<_>, CfError>>()?;

    Ok(ItemDraft {
        title: snap.title.clone(),
        category: snap.category,
        urls,
        tags: snap.tags.clone(),
        sections,
        fields,
        // draft.totp 在更新路径被忽略（以 TotpUpdate 三态参数为准），
        // 此处填 None 与语义对齐
        totp: None,
    })
}

/// 快照语义级内容比较（"内容无变化不写"判据）。
///
/// 忽略三类每次 update 都会再生的成分：行 uuid（fields/urls/sections
/// 删旧插新生成新 uuid）、position（草稿原样重提时不变，但为防御
/// 顺序扰动按序列比较即可）、`updated_at`（update 必然推进）。比较
/// 维度：类别 / 状态 / 收藏 / 标题 / 标签（多重集合）/ URL 序列 /
/// 分区序列（标题）/ 字段序列（名称、类型、语义、值、所属分区标题）/
/// TOTP 全量（含 secret）/ origin 绑定（D-3，序列比较）。
pub(crate) fn snapshot_content_eq(a: &ItemSnapshot, b: &ItemSnapshot) -> bool {
    if a.category != b.category
        || a.state != b.state
        || a.is_favorite != b.is_favorite
        || a.fav_index != b.fav_index
        || a.title != b.title
        || a.totp != b.totp
        // origin 绑定：序列比较（顺序对 best_match 优先级同档选首个有语义）
        || a.origin_bindings != b.origin_bindings
    {
        return false;
    }

    // 标签：多重集合比较（顺序无语义）
    let mut at = a.tags.clone();
    let mut bt = b.tags.clone();
    at.sort();
    bt.sort();
    if at != bt {
        return false;
    }

    // URL / 分区 / 字段：序列比较
    if a.urls.len() != b.urls.len()
        || a.urls
            .iter()
            .zip(b.urls.iter())
            .any(|(x, y)| x.label != y.label || x.url != y.url || x.is_primary != y.is_primary)
    {
        return false;
    }
    if a.sections.len() != b.sections.len()
        || a.sections
            .iter()
            .zip(b.sections.iter())
            .any(|(x, y)| x.title != y.title)
    {
        return false;
    }

    if a.fields.len() != b.fields.len() {
        return false;
    }
    for (x, y) in a.fields.iter().zip(b.fields.iter()) {
        let sx = section_title(a, &x.section_uuid);
        let sy = section_title(b, &y.section_uuid);
        if x.field_type != y.field_type
            || x.designation != y.designation
            || x.name != y.name
            || x.value != y.value
            || sx != sy
        {
            return false;
        }
    }
    true
}

/// 快照内分区 uuid → 分区标题（跨快照比较字段挂接关系用）。
fn section_title(snap: &ItemSnapshot, section_uuid: &Option<uuid::Uuid>) -> Option<String> {
    let suuid = section_uuid.as_ref()?;
    snap.sections
        .iter()
        .find(|s| &s.uuid == suuid)
        .map(|s| s.title.clone())
}

/// DDL 文本 → [`TotpAlgo`]（未知算法视为数据损坏，不静默按 SHA-1 算）。
fn algo_from_str(s: &str) -> Result<TotpAlgo, CfError> {
    match s {
        "sha1" => Ok(TotpAlgo::Sha1),
        "sha256" => Ok(TotpAlgo::Sha256),
        "sha512" => Ok(TotpAlgo::Sha512),
        other => Err(CfError::Corrupted(format!(
            "unknown totp algo in snapshot source: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft};
    use cf_domain::totp_data::TotpAlgo;
    use rusqlite::Connection;

    /// 内存库 + 固定子密钥的 ItemStore（不走解锁流，专注编排逻辑）。
    fn memory_store() -> ItemStore {
        let conn = Connection::open_in_memory().unwrap();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, subkeys).unwrap()
    }

    /// 最小 Login 草稿（满足模板必填：username + password）。
    fn login_draft(title: &str, password: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![],
            tags: vec!["工作".to_owned()],
            sections: vec![],
            fields: vec![
                FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "密码".to_owned(),
                    value: Some(password.to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    fn totp_data(secret: u8) -> TotpData {
        TotpData {
            secret: vec![secret; 20],
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 30,
        }
    }

    /// 创建 → 编辑 2 次 → history 有 2 个版本，version 递增、created_at 单调
    #[test]
    fn 编辑两次产生两个版本() {
        let mut store = memory_store();
        let id = super::super::items::create_item(&mut store, &login_draft("v0", "pw-0")).unwrap();

        let mut draft = login_draft("v1", "pw-1");
        super::super::items::update_item(&mut store, &id, &draft).unwrap();
        // 真实路径下时间戳可能同秒；单调性用 version 递增 + created_at 非降序断言
        draft.title = "v2".to_owned();
        super::super::items::update_item(&mut store, &id, &draft).unwrap();

        let entries = list_history(&store, &id).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].version, 2, "list 必须 version DESC");
        assert_eq!(entries[1].version, 1);
        assert!(entries[0].created_at >= entries[1].created_at);
    }

    /// 快照密文落盘：BLOB ≠ CBOR 明文；密文跨行搬运解密失败
    #[test]
    fn 快照密文落盘且行级钉死() {
        let mut store = memory_store();
        let id = super::super::items::create_item(&mut store, &login_draft("a", "pw")).unwrap();
        let mut draft = login_draft("b", "pw");
        draft.totp = None;
        super::super::items::update_item_with_totp(&mut store, &id, &draft, TotpUpdate::Keep)
            .unwrap();

        let conn = store.connection();
        let h_uuid: String = conn
            .query_row(
                "SELECT uuid FROM history ORDER BY version DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        // 当前条目状态序列化，断言密文 BLOB 不含其 CBOR 字节
        let repos = store.repos();
        let snap = snapshot_current(&repos, &id).unwrap();
        let mut cbor = Vec::new();
        ciborium::into_writer(&snap, &mut cbor).unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT enc_snapshot FROM history WHERE uuid = ?1",
                rusqlite::params![h_uuid],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(blob, cbor);
        assert!(!blob
            .windows(cbor.len().min(blob.len()))
            .any(|w| w == cbor.as_slice()));

        // 密文搬到另一行（伪造第二行）→ 解密失败
        conn.execute(
            "INSERT INTO history (uuid, item_uuid, version, created_at, enc_snapshot)
             VALUES (?1, ?2, 99, 0, (SELECT enc_snapshot FROM history WHERE uuid = ?3))",
            rusqlite::params![uuid::Uuid::now_v7().to_string(), id, h_uuid],
        )
        .unwrap();
        let forged: Vec<String> = conn
            .prepare("SELECT uuid FROM history WHERE version = 99")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(matches!(
            repos.history.snapshot(&forged[0]),
            Err(CfError::CryptoError)
        ));
    }

    /// 回滚：编辑改标题+改密码值+换 TOTP → 回滚到 v1 → 当前条目与 v1
    /// 逐字段相等，且 history 多出一条新版本（回滚本身是一次修改）
    ///
    /// 注：Login 类别的 username / password 为模板必填，编辑测试不能
    /// 删字段（validate_item 会拒绝），故以「改值」表达内容变更。
    #[test]
    fn 回滚后条目与历史版本一致且多出新版本() {
        let mut store = memory_store();
        let id =
            super::super::items::create_item(&mut store, &login_draft("初版", "pw-v1")).unwrap();

        // 编辑 1：改标题 + 改密码值 + 换 TOTP（Replace）
        let mut draft = login_draft("改版", "pw-v2");
        draft.urls = vec![cf_domain::item::UrlDraft {
            label: Some("新地址".to_owned()),
            url: "https://changed.example.com".to_owned(),
            is_primary: true,
            position: 0,
        }];
        super::super::items::update_item_with_totp(
            &mut store,
            &id,
            &draft,
            TotpUpdate::Replace(totp_data(0xAA)),
        )
        .unwrap();

        let entries = list_history(&store, &id).unwrap();
        assert_eq!(entries.len(), 1, "首个 update 落创建态 v1");
        let v1_uuid = entries[0].history_uuid.clone();

        // 回滚到 v1
        restore_history(&mut store, &id, &v1_uuid).unwrap();

        // 当前条目与 v1 逐字段相等
        let details = super::super::items::get_item(&store, &id).unwrap().unwrap();
        assert_eq!(details.title.expose(), "初版");
        let password = details
            .fields
            .iter()
            .find(|f| f.designation == Some(cf_domain::field::Designation::Password))
            .expect("回滚后应恢复密码字段");
        assert_eq!(password.value.as_ref().unwrap().expose(), "pw-v1");
        assert!(
            details.urls.is_empty(),
            "v1 无 URL，回滚后不应残留编辑期的 URL"
        );
        // v1 = 创建态：创建草稿无 TOTP → 回滚后应无 TOTP（Replace 语义）
        assert!(details.totp.is_none(), "v1 无 TOTP，回滚后不应残留");

        // history 多出一条新版本（回滚前状态先成为快照）
        let after = list_history(&store, &id).unwrap();
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].version, 2, "回滚产生的版本号最高");

        // 可再回滚：回滚到 v2（即"回滚回滚"）
        let v2_uuid = after[0].history_uuid.clone();
        restore_history(&mut store, &id, &v2_uuid).unwrap();
        let details2 = super::super::items::get_item(&store, &id).unwrap().unwrap();
        assert_eq!(details2.title.expose(), "改版");
        assert_eq!(details2.urls.len(), 1, "v2 的 URL 应恢复");
        let password2 = details2
            .fields
            .iter()
            .find(|f| f.designation == Some(cf_domain::field::Designation::Password))
            .unwrap();
        assert_eq!(password2.value.as_ref().unwrap().expose(), "pw-v2");
        // v2 = 编辑态：TOTP 是编辑时 Replace 进去的，回滚到 v2 应恢复
        let totp2 = details2.totp.expect("回滚到 v2 应恢复 TOTP");
        assert_eq!(totp2.algo, "sha1");
        assert_eq!(totp2.digits, 6);
        assert_eq!(list_history(&store, &id).unwrap().len(), 3);
    }

    /// 内容无变化的 update 不新增版本（语义级去重：每次 update 都会
    /// 再生行 uuid / updated_at，按内容比较，见 [`snapshot_content_eq`]）
    #[test]
    fn 内容无变化不写版本() {
        let mut store = memory_store();
        let draft_a = login_draft("状态A", "pw-A");
        let id = super::super::items::create_item(&mut store, &draft_a).unwrap();

        // update 回同一内容：写入 v1（创建态快照，首个 update 落基线）
        super::super::items::update_item(&mut store, &id, &draft_a).unwrap();
        let entries = list_history(&store, &id).unwrap();
        assert_eq!(entries.len(), 1, "首个 update 落创建态基线");
        assert_eq!(
            super::super::items::get_item(&store, &id)
                .unwrap()
                .unwrap()
                .title
                .expose(),
            "状态A"
        );

        // 再次 update 同一内容：不新增（pre-state == v1 快照内容）
        super::super::items::update_item(&mut store, &id, &draft_a).unwrap();
        assert_eq!(list_history(&store, &id).unwrap().len(), 1);

        // 内容变化 → B：pre-state 仍 == v1 → 不新增（B 的内容会成为
        // 下次 update 的 pre-state 被记录）
        let draft_b = login_draft("状态B", "pw-B");
        super::super::items::update_item(&mut store, &id, &draft_b).unwrap();
        assert_eq!(list_history(&store, &id).unwrap().len(), 1);

        // 再 update 回 B → pre-state == B → 新增 v2（内容为 B）
        super::super::items::update_item(&mut store, &id, &draft_b).unwrap();
        let entries = list_history(&store, &id).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].version, 2);

        // 校验 v2 快照内容确实是 B
        let v2 = {
            let repos = store.repos();
            repos
                .history
                .snapshot(&entries[0].history_uuid)
                .unwrap()
                .unwrap()
        };
        assert_eq!(v2.title, "状态B");
    }

    /// 同事务原子性：history 写入失败 → 主表更新一并回滚（NFR-REL-01）
    #[test]
    fn history写入失败整体回滚() {
        let mut store = memory_store();
        let id = super::super::items::create_item(&mut store, &login_draft("原子", "pw")).unwrap();

        // 注入失败：破坏 history 表 → 快照写入必败 → 整个 update 事务回滚
        store
            .connection()
            .execute("DROP TABLE history", [])
            .unwrap();
        let err = super::super::items::update_item(&mut store, &id, &login_draft("不应生效", "pw"));
        assert!(err.is_err(), "history 写入失败必须使 update 失败");

        // 主表未被部分提交：items 表读取不依赖 history 表，直接校验
        let got = store.repos().items.get(&id).unwrap().expect("条目应仍在");
        assert_eq!(got.title.expose(), "原子", "失败事务不得部分提交");
    }

    /// 硬删条目 → history 级联消失；软删 / 恢复不动 history
    #[test]
    fn 硬删级联软删保留() {
        let mut store = memory_store();
        let id = super::super::items::create_item(&mut store, &login_draft("级联", "pw")).unwrap();
        super::super::items::update_item(&mut store, &id, &login_draft("级联2", "pw2")).unwrap();
        assert_eq!(list_history(&store, &id).unwrap().len(), 1);

        // 软删 → 恢复：history 不动
        super::super::items::delete_item(&mut store, &id, false).unwrap();
        assert_eq!(list_history(&store, &id).unwrap().len(), 1);
        super::super::items::restore_item(&mut store, &id).unwrap();

        // 硬删 → history 级联消失
        super::super::items::delete_item(&mut store, &id, true).unwrap();
        assert!(list_history(&store, &id).is_err(), "条目已不存在（1011）");
        let n: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "外键 ON DELETE CASCADE 必须清空 history");
    }

    /// 对 Trashed 条目回滚 → 1012（既有 update 状态门禁承接）
    #[test]
    fn 回收站条目回滚被拒绝() {
        let mut store = memory_store();
        let id =
            super::super::items::create_item(&mut store, &login_draft("回收站", "pw")).unwrap();
        super::super::items::update_item(&mut store, &id, &login_draft("二版", "pw")).unwrap();
        let v1 = list_history(&store, &id).unwrap()[0].history_uuid.clone();

        super::super::items::delete_item(&mut store, &id, false).unwrap();
        let err = restore_history(&mut store, &id, &v1).unwrap_err();
        assert_eq!(err.code(), 1012);
    }

    /// 1000 条目 × 3 版本的 list 性能 < 200ms 基线（docs/09 §3.3 测试要点 7）
    #[test]
    fn 千条历史list性能基线() {
        let mut store = memory_store();
        let mut ids = Vec::with_capacity(1_000);
        for i in 0..1_000 {
            let id = super::super::items::create_item(
                &mut store,
                &login_draft(&format!("条目 {i}"), "pw"),
            )
            .unwrap();
            // 三次内容各异的编辑 → 每条目 3 个历史版本（首个 update 落
            // 创建态基线，其后每次真实变更各落一版）
            for round in 1..=3 {
                super::super::items::update_item(
                    &mut store,
                    &id,
                    &login_draft(&format!("条目 {i} 第{round}改"), "pw"),
                )
                .unwrap();
            }
            ids.push(id);
        }

        let start = std::time::Instant::now();
        let mut total = 0usize;
        for id in &ids {
            total += list_history(&store, id).unwrap().len();
        }
        let elapsed = start.elapsed();
        assert_eq!(total, 3_000);
        // 名义基线 200ms（docs/09 §3.3 测试要点 7），按机器实测吞吐校准
        let budget = crate::testing::perf_budget(200);
        assert!(
            elapsed < budget,
            "1000 条目 × 3 版本 list 耗时 {elapsed:?}，超出校准后的 200ms 基线（{budget:?}）"
        );
    }

    /// 不存在的条目 / 历史行 → 1011
    #[test]
    fn 缺失条目与历史行报未找到() {
        let store = memory_store();
        assert_eq!(
            list_history(&store, &uuid::Uuid::now_v7().to_string()).unwrap_err(),
            CfError::ItemNotFound
        );
    }
}
