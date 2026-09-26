//! 条目 CRUD 编排（docs/07 §2.2 `usecase/items.rs`）。
//!
//! 流程：`cf-domain::validate_item` 前置校验（校验失败**不落库**）→
//! `ItemStore::with_tx` 单事务写库（NFR-REL-01）。update 语义 = 整体替换：
//! 行数据 / 标题就地更新，fields / urls / tags / sections / totp 按
//! 「删旧插新」批量替换（仓库层天然覆盖字段增删改）。
//!
//! update 前读取旧快照，为 v0.2 的 history 表预留接口；v0.1 **不写**
//! history 表（docs/07 §2.2）。
//!
//! ## 条目类型覆盖（docs/07 §1.3）
//!
//! Login / Password / SecureNote / CreditCard 四类完整 CRUD；
//! 其余类别 + Custom 由 `ItemCategory` 兜底存储（导入只读展示），
//! 必填校验由 `validate_item` 的模板表驱动，此处无需按类别分支。

use cf_domain::item::{ItemDraft, ItemState, ItemSummary};
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, SectionRow, TagRow, UrlRow};
use cf_store::{ItemListFilter, ItemRow, ItemStore};

use crate::types::{FieldDetail, ItemDetails, SectionDetail, TotpDetail, UrlDetail};

/// 新建条目：校验 → 单事务写库（items + 从表 + meta.item_count）。
///
/// 返回新条目 ID（UUIDv7 文本）。校验失败（[`CfError::InvalidArgument`]）
/// 不产生任何写入。
pub fn create_item(store: &mut ItemStore, draft: &ItemDraft) -> Result<String, CfError> {
    cf_domain::validate::validate_item(draft)?;

    let item_uuid = uuid::Uuid::now_v7().to_string();
    let now = crate::unix_now()?;
    let title = SecretString::from_exposed(draft.title.clone());

    store.with_tx(|repos| {
        repos.items.insert(
            &ItemRow {
                uuid: item_uuid.clone(),
                category: draft.category,
                state: ItemState::Active,
                is_favorite: false,
                fav_index: 0,
                created_at: now,
                updated_at: now,
                trashed_at: None,
                position: 0,
            },
            &title,
        )?;
        write_children(repos, &item_uuid, draft)?;
        repos.meta.add_item_count(1)?;
        Ok(())
    })?;
    Ok(item_uuid)
}

/// 更新条目：读旧快照（v0.2 history 预留）→ 校验 → 单事务整体替换。
///
/// 条目不存在返回 [`CfError::ItemNotFound`]；校验失败不产生任何写入。
pub fn update_item(store: &mut ItemStore, item_id: &str, draft: &ItemDraft) -> Result<(), CfError> {
    cf_domain::validate::validate_item(draft)?;

    let now = crate::unix_now()?;
    let title = SecretString::from_exposed(draft.title.clone());

    store.with_tx(|repos| {
        // 旧快照：存在性检查 + v0.2 history 预留（v0.1 读取后即弃，不落 history 表）
        let old = repos.items.get_row(item_id)?.ok_or(CfError::ItemNotFound)?;
        let _ = old;

        repos.items.update_row(&ItemRow {
            uuid: item_id.to_owned(),
            category: draft.category,
            state: ItemState::Active,
            is_favorite: false,
            fav_index: 0,
            created_at: 0, // update_row 不覆盖 created_at，占位值无副作用
            updated_at: now,
            trashed_at: None,
            position: 0,
        })?;
        repos.items.update_title(item_id, &title)?;
        write_children(repos, item_id, draft)?;
        Ok(())
    })
}

/// 删除条目：软删（回收站）或硬删（级联清除从表）。
///
/// 硬删维护 `meta.item_count` 减量（软删不减：条目仍存在，仅状态迁移）。
pub fn delete_item(store: &mut ItemStore, item_id: &str, hard: bool) -> Result<(), CfError> {
    let now = crate::unix_now()?;
    store.with_tx(|repos| {
        if hard {
            repos.items.delete_hard(item_id)?;
            repos.meta.add_item_count(-1)?;
        } else {
            repos.items.soft_delete(item_id, now)?;
        }
        Ok(())
    })
}

/// 从回收站恢复条目（state → Active，trashed_at 清空）。
pub fn restore_item(store: &mut ItemStore, item_id: &str) -> Result<(), CfError> {
    store.with_tx(|repos| repos.items.restore(item_id))
}

/// 设置 / 取消收藏。
pub fn set_favorite(store: &mut ItemStore, item_id: &str, favorite: bool) -> Result<(), CfError> {
    store.with_tx(|repos| repos.items.set_favorite(item_id, favorite))
}

/// 列出条目（updated_at 倒序），按过滤条件；标题解密为 [`ItemSummary`]。
pub fn list_items(store: &ItemStore, filter: &ItemListFilter) -> Result<Vec<ItemSummary>, CfError> {
    let rows = store.repos().items.list(filter)?;
    rows.into_iter()
        .map(|it| to_summary(it.row, &it.title))
        .collect()
}

/// 读取条目完整详情（标题 / 字段 / URL / 标签 / 分区 / TOTP 元数据全解密）。
/// 条目不存在返回 `Ok(None)`。
pub fn get_item(store: &ItemStore, item_id: &str) -> Result<Option<ItemDetails>, CfError> {
    let repos = store.repos();
    let Some(found) = repos.items.get(item_id)? else {
        return Ok(None);
    };
    let row = found.row;

    let urls = repos
        .urls
        .read_for_item(item_id)?
        .into_iter()
        .map(|u| UrlDetail {
            uuid: u.uuid,
            label: u.label,
            url: u.url,
            is_primary: u.is_primary,
            position: u.position,
        })
        .collect();
    let tags = repos
        .tags
        .read_for_item(item_id)?
        .into_iter()
        .map(|t| t.name)
        .collect();
    let sections = repos
        .fields
        .read_sections_for_item(item_id)?
        .into_iter()
        .map(|s| SectionDetail {
            uuid: s.uuid,
            title: s.title,
            position: s.position,
        })
        .collect();
    let fields = repos
        .fields
        .read_fields_for_item(item_id)?
        .into_iter()
        .map(|f| FieldDetail {
            uuid: f.uuid,
            section_uuid: f.section_uuid,
            field_type: f.field_type,
            designation: f.designation,
            name: f.name,
            value: f.value,
            position: f.position,
        })
        .collect();
    // v0.1 一条目至多一条 TOTP 记录（由本层写入语义保证）；取创建最早的一条
    let totp = match repos.totp.totp_uuids_for_item(item_id)?.into_iter().next() {
        Some(uuid) => repos.totp.totp_meta(&uuid)?.map(|m| TotpDetail {
            uuid: m.uuid,
            algo: m.algo,
            digits: m.digits,
            period: m.period,
            issuer: m.issuer,
            account: m.account,
        }),
        None => None,
    };

    Ok(Some(ItemDetails {
        uuid: row.uuid,
        category: row.category,
        state: row.state,
        is_favorite: row.is_favorite,
        fav_index: row.fav_index,
        created_at: row.created_at,
        updated_at: row.updated_at,
        title: found.title,
        urls,
        tags,
        sections,
        fields,
        totp,
    }))
}

/// 按需取字段明文值（密码等敏感值，随取随走）。
///
/// 条目不存在返回 [`CfError::ItemNotFound`]；字段不存在返回 `Ok(None)`。
pub fn get_field_value(
    store: &ItemStore,
    item_id: &str,
    field_id: &str,
) -> Result<Option<SecretString>, CfError> {
    let repos = store.repos();
    if repos.items.get_row(item_id)?.is_none() {
        return Err(CfError::ItemNotFound);
    }
    for f in repos.fields.read_fields_for_item(item_id)? {
        if f.uuid == field_id {
            // SecretString 不可 Clone（有意设计）：此处显式复制明文一次，
            // 语义是「把值交给调用方」——暴露面与 get_item 相同
            return Ok(f
                .value
                .map(|v| SecretString::from_exposed(v.expose().to_owned())));
        }
    }
    Ok(None)
}

/// [`ItemRow`] + 解密标题 → [`ItemSummary`]（uuid 解析失败视为数据损坏）。
pub(crate) fn to_summary(row: ItemRow, title: &SecretString) -> Result<ItemSummary, CfError> {
    Ok(ItemSummary {
        uuid: uuid::Uuid::parse_str(&row.uuid)
            .map_err(|_| CfError::Corrupted("item uuid is not a valid uuid".into()))?,
        category: row.category,
        state: row.state,
        is_favorite: row.is_favorite,
        updated_at: row.updated_at,
        title: title.expose().to_owned(),
    })
}

/// 写入条目从表：sections → fields → urls → tags → totp（批量替换语义）。
///
/// 必须在 items 行已插入的事务内调用（外键约束）。
fn write_children(
    repos: &cf_store::Repos<'_>,
    item_uuid: &str,
    draft: &ItemDraft,
) -> Result<(), CfError> {
    // 分区：草稿下标 → 生成 uuid，供字段挂接引用
    let sections: Vec<SectionRow> = draft
        .sections
        .iter()
        .map(|s| SectionRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.to_owned(),
            title: s.title.clone(),
            position: i64::from(s.position),
        })
        .collect();
    repos
        .fields
        .replace_sections_for_item(item_uuid, &sections)?;

    let fields: Vec<FieldRow> = draft
        .fields
        .iter()
        .map(|f| FieldRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.to_owned(),
            section_uuid: f
                .section_index
                .and_then(|i| sections.get(i).map(|s| s.uuid.clone())),
            field_type: f.field_type,
            designation: f.designation.clone(),
            name: f.name.clone(),
            value: f.value.clone(),
            position: i64::from(f.position),
        })
        .collect();
    repos.fields.replace_fields_for_item(item_uuid, &fields)?;

    let urls: Vec<UrlRow> = draft
        .urls
        .iter()
        .map(|u| UrlRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.to_owned(),
            label: u.label.clone(),
            url: u.url.clone(),
            is_primary: u.is_primary,
            position: i64::from(u.position),
        })
        .collect();
    repos.urls.replace_for_item(item_uuid, &urls)?;

    let tags: Vec<TagRow> = draft
        .tags
        .iter()
        .map(|t| TagRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.to_owned(),
            name: t.clone(),
        })
        .collect();
    repos.tags.replace_for_item(item_uuid, &tags)?;

    // TOTP：整体替换（删旧插新），与 fields 等从表语义一致
    for old_uuid in repos.totp.totp_uuids_for_item(item_uuid)? {
        repos.totp.delete_totp(&old_uuid)?;
    }
    if let Some(t) = &draft.totp {
        repos.totp.insert_totp(
            &uuid::Uuid::now_v7().to_string(),
            item_uuid,
            &t.secret,
            algo_to_str(t.algo),
            t.digits,
            t.period,
            None, // issuer / account v0.1 暂不采集（otpauth 解析随 T03 引入）
            None,
        )?;
    }
    Ok(())
}

/// `TotpAlgo` → DDL 文本（`sha1` / `sha256` / `sha512`）。
fn algo_to_str(algo: cf_domain::totp_data::TotpAlgo) -> &'static str {
    match algo {
        cf_domain::totp_data::TotpAlgo::Sha1 => "sha1",
        cf_domain::totp_data::TotpAlgo::Sha256 => "sha256",
        cf_domain::totp_data::TotpAlgo::Sha512 => "sha512",
    }
}
