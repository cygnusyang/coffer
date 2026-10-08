//! 条目 CRUD 编排（docs/07 §2.2 `usecase/items.rs`）。
//!
//! 流程：`cf-domain::validate_item` 前置校验（校验失败**不落库**）→
//! `ItemStore::with_tx` 单事务写库（NFR-REL-01）。update 语义 = 整体替换：
//! 行数据 / 标题就地更新，fields / urls / tags / sections 按「删旧插新」
//! 批量替换（仓库层天然覆盖字段增删改）；TOTP 为显式三态
//! （[`TotpUpdate`]：Keep 保留既有加密行 / Replace 删旧插新 / Remove 删除），
//! 因 FFI 不下发 secret，更新默认 Keep 以免编辑静默丢失 TOTP。
//!
//! update 事务内、替换前对当前状态做快照写入 history 表（FR-2.9，
//! 编排见 [`history`]；内容无变化不写，见其模块文档）。
//!
//! ## 条目类型覆盖（docs/07 §1.3）
//!
//! Login / Password / SecureNote / CreditCard 四类完整 CRUD；
//! 其余类别 + Custom 由 `ItemCategory` 兜底存储（导入只读展示），
//! 必填校验由 `validate_item` 的模板表驱动，此处无需按类别分支。

use cf_domain::item::{ItemDraft, ItemState, ItemSummary};
use cf_domain::origin::OriginBinding;
use cf_domain::secret::SecretString;
use cf_domain::totp_data::TotpUpdate;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, SectionRow, TagRow, UrlRow};
use cf_store::{ItemListFilter, ItemRow, ItemStore};

use crate::types::{FieldDetail, ItemDetails, SectionDetail, TotpDetail, UrlDetail};

/// 新建条目：校验 → 单事务写库（items + 从表 + meta.item_count）。
///
/// 返回新条目 ID（UUIDv7 文本）。校验失败（[`CfError::InvalidArgument`]）
/// 不产生任何写入。origin 绑定恒为空（新条目无绑定）；带绑定新建走
/// [`create_item_with_origin_bindings`]。
pub fn create_item(store: &mut ItemStore, draft: &ItemDraft) -> Result<String, CfError> {
    create_item_with_origin_bindings(store, draft, Vec::new())
}

/// 新建条目并写入 origin 绑定（D-3，docs/31 §5.3）。
///
/// 语义与 [`create_item`] 一致，额外把 `origin_bindings` 随同一事务写入
/// `item_origins` 从表。供 broker `capture_save` 建条目 + 绑定站点用
/// （merge-time 接线；vault.rs 薄封装由组 E/组 A 收编）。
pub fn create_item_with_origin_bindings(
    store: &mut ItemStore,
    draft: &ItemDraft,
    origin_bindings: Vec<OriginBinding>,
) -> Result<String, CfError> {
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
        // create 路径的 TOTP 语义：草稿有则写入、无则不写（Option 无歧义，
        // 三态类型仅更新路径需要；Remove 对无旧行的新条目是空操作）
        let totp = draft
            .totp
            .clone()
            .map(TotpUpdate::Replace)
            .unwrap_or(TotpUpdate::Remove);
        write_children(repos, &item_uuid, draft, &totp, &origin_bindings)?;
        repos.meta.add_item_count(1)?;
        Ok(())
    })?;
    Ok(item_uuid)
}

/// 更新条目：替换前快照写 history（FR-2.9）→ 校验 → 单事务整体替换。
///
/// TOTP 语义（v0.2 裁定）：本入口为**默认保留**（[`TotpUpdate::Keep`]）——
/// FFI 刻意不下发 secret，调用方无法重提交原密钥，默认删旧会静默
/// 丢失 TOTP。三态显式控制走 [`update_item_with_totp`]。
///
/// 其余语义：条目不存在返回 [`CfError::ItemNotFound`]；校验失败不产生
/// 任何写入。draft 的 `totp` 字段在更新路径**始终忽略**（以显式三态
/// 参数为准），见 [`update_item_with_totp`] 文档。
///
/// 状态语义（QA 已知问题 #2 裁定）：update_item **只允许作用于 Active 态**
/// 条目。对 Trashed / Archived 条目返回
/// [`CfError::Validation`]（1012，附可操作提示）而不静默改状态——
/// 旧实现硬编码 `state: Active, trashed_at: None` 会把回收站条目
/// 「强制复活」。选 `Validation` 而非 `ItemNotFound` 的理由：条目真实
/// 存在，报「不存在」会误导调用方；1012 的定位正是「可操作的用户
/// 提示」（恢复后再编辑），语义最贴切。
///
/// 收藏语义（QA 已知问题 #1 裁定）：编辑内容**不改变收藏态**——
/// `is_favorite` / `fav_index` 从旧行继承，收藏的增减只走
/// [`set_favorite`]。
pub fn update_item(store: &mut ItemStore, item_id: &str, draft: &ItemDraft) -> Result<(), CfError> {
    update_item_with_totp(store, item_id, draft, TotpUpdate::Keep)
}

/// 更新条目（TOTP 三态显式版）。
///
/// [`TotpUpdate`] 语义：
///
/// - `Keep`：既有加密 TOTP 行**完全不动**（secret 不出会话层，调用方
///   无需也无法提供原密钥）；
/// - `Replace(data)`：删旧插新，写入 `data`（校验与 create 路径一致）；
/// - `Remove`：删除既有 TOTP 行。
///
/// ## draft.totp 在更新路径被忽略
///
/// 整体替换语义下 `ItemDraft.totp: Option<TotpData>` 的 `None` 无法区分
/// 「删」与「留」（歧义来源，见 [`TotpUpdate`] 模块文档），且 FFI 侧
/// 读回详情本就**不含** secret、调用方无法构造「原样重写」的草稿。
/// 故更新路径一律以 `totp` 参数为准，`draft.totp` 被显式清空后再校验，
/// 避免两个数据源互相矛盾。Replace 的载荷经同一套 TOTP 校验
/// （secret ≥ 10 字节、digits ∈ {6,8}、period > 0）。
pub fn update_item_with_totp(
    store: &mut ItemStore,
    item_id: &str,
    draft: &ItemDraft,
    totp: TotpUpdate,
) -> Result<(), CfError> {
    // 校验：draft.totp 以三态参数为准（Keep / Remove 时清空，Replace 时
    // 换成载荷），保证 replace 载荷过同一套校验、draft 携带的 totp 不生效
    let mut checked = draft.clone();
    match &totp {
        TotpUpdate::Replace(data) => checked.totp = Some(data.clone()),
        TotpUpdate::Keep | TotpUpdate::Remove => checked.totp = None,
    }
    cf_domain::validate::validate_item(&checked)?;

    let now = crate::unix_now()?;
    let title = SecretString::from_exposed(draft.title.clone());

    store.with_tx(|repos| {
        // 旧快照：存在性检查 + 状态门禁 + 收藏态继承源
        let old = repos.items.get_row(item_id)?.ok_or(CfError::ItemNotFound)?;
        if old.state != ItemState::Active {
            let state_name = match old.state {
                ItemState::Active => "活跃",
                ItemState::Trashed => "回收站",
                ItemState::Archived => "归档",
            };
            return Err(CfError::Validation(format!(
                "条目处于{state_name}状态，不能编辑；请先恢复为活跃状态"
            )));
        }

        // origin 绑定不在草稿内（ItemDraft 无该字段，避免全仓 78 处
        // 构造点 + cf-ffi/cf-mcp 越界）：编辑**保留**既有绑定（与收藏态
        // 继承同款语义）。显式改绑定走 [`set_item_origin_bindings`]。
        let old_bindings = repos.origins.read_for_item(item_id)?;

        // FR-2.9：替换前对当前状态做快照写入 history 表（同事务；
        // 内容无变化不写，见 usecase::history::snapshot_before_update）
        crate::usecase::history::snapshot_before_update(repos, item_id, now)?;

        repos.items.update_row(&ItemRow {
            uuid: item_id.to_owned(),
            category: draft.category,
            // 门禁保证此处必为 Active 且 trashed_at 为空；不硬编码，
            // 显式继承旧行以防未来状态机扩展时静默迁移
            state: old.state,
            // 编辑不改变收藏态（QA #1）：从旧行继承
            is_favorite: old.is_favorite,
            fav_index: old.fav_index,
            created_at: old.created_at, // 语义上不覆盖（update_row 也不写该列）
            updated_at: now,
            trashed_at: old.trashed_at,
            position: old.position,
        })?;
        repos.items.update_title(item_id, &title)?;
        write_children(repos, item_id, draft, &totp, &old_bindings)?;
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
    let origin_bindings = repos.origins.read_for_item(item_id)?;

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
        origin_bindings,
    }))
}

/// 显式改写条目 origin 绑定（D-3，docs/31 §5.3）。
///
/// 独立于 update_item 的专用入口（ItemDraft 不含绑定字段，见
/// [`update_item_with_totp`] 注释）：替换前写 history 快照（FR-2.9，
/// 绑定变化同样进版本历史）、事务内删旧插新、推进 `updated_at`。
///
/// 供 broker `capture_save` 对既有条目追加/改写绑定用。条目不存在 →
/// [`CfError::ItemNotFound`]。
pub fn set_item_origin_bindings(
    store: &mut ItemStore,
    item_id: &str,
    origin_bindings: Vec<OriginBinding>,
) -> Result<(), CfError> {
    let now = crate::unix_now()?;
    store.with_tx(|repos| {
        let old = repos.items.get_row(item_id)?.ok_or(CfError::ItemNotFound)?;
        crate::usecase::history::snapshot_before_update(repos, item_id, now)?;
        let rows: Vec<cf_store::repo::origin::OriginBindingRow> = origin_bindings
            .iter()
            .map(|b| cf_store::repo::origin::OriginBindingRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_id.to_owned(),
                kind: b.kind,
                value: b.value.clone(),
            })
            .collect();
        repos.origins.replace_for_item(item_id, &rows)?;
        repos.items.update_row(&ItemRow {
            uuid: item_id.to_owned(),
            category: old.category,
            state: old.state,
            is_favorite: old.is_favorite,
            fav_index: old.fav_index,
            created_at: old.created_at,
            updated_at: now,
            trashed_at: old.trashed_at,
            position: old.position,
        })?;
        Ok(())
    })
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
///
/// `totp` 控制 TOTP 从表写法：`Keep` 完全不动（既有加密行原样保留）、
/// `Replace` 删旧插新、`Remove` 删旧（create 路径无旧行，删除为空操作）。
///
/// `pub(crate)`：跨库复制（FR-2.10）在目标库事务内复用同一「删旧插新」
/// 写入语义，子表行 uuid 全部重新生成。
pub(crate) fn write_children(
    repos: &cf_store::Repos<'_>,
    item_uuid: &str,
    draft: &ItemDraft,
    totp: &TotpUpdate,
    origin_bindings: &[OriginBinding],
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

    // TOTP：三态显式（v0.2 裁定）。Keep 不动既有加密行；Replace / Remove
    // 均先删旧（Replace 再插新；create 路径无旧行，删除为空操作）
    match totp {
        TotpUpdate::Keep => {}
        TotpUpdate::Replace(t) => {
            for old_uuid in repos.totp.totp_uuids_for_item(item_uuid)? {
                repos.totp.delete_totp(&old_uuid)?;
            }
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
        TotpUpdate::Remove => {
            for old_uuid in repos.totp.totp_uuids_for_item(item_uuid)? {
                repos.totp.delete_totp(&old_uuid)?;
            }
        }
    }

    // origin 绑定：删旧插新（D-3）。调用方决定内容——create 传草稿带的
    // 绑定（或空）、update 传既有绑定（保留语义）、cross_copy 传快照绑定
    let binding_rows: Vec<cf_store::repo::origin::OriginBindingRow> = origin_bindings
        .iter()
        .map(|b| cf_store::repo::origin::OriginBindingRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.to_owned(),
            kind: b.kind,
            value: b.value.clone(),
        })
        .collect();
    repos.origins.replace_for_item(item_uuid, &binding_rows)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, UrlDraft};
    use cf_domain::origin::{OriginBinding, OriginBindingKind};
    use rusqlite::Connection;

    /// 内存库 + 固定子密钥的 ItemStore（不走解锁流，专注编排逻辑）。
    fn memory_store() -> ItemStore {
        let conn = Connection::open_in_memory().unwrap();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, subkeys).unwrap()
    }

    /// 最小 Login 草稿（满足模板必填：username + password）。
    fn login_draft(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![UrlDraft {
                label: None,
                url: "https://example.com".to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FieldDraft {
                    name: "username".to_owned(),
                    value: Some("alice".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "password".to_owned(),
                    value: Some("s3cret".to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    fn binding(kind: OriginBindingKind, value: &str) -> OriginBinding {
        OriginBinding {
            kind,
            value: value.to_owned(),
        }
    }

    /// create_item_with_origin_bindings → get_item：绑定写读一致
    #[test]
    fn create_with_bindings_round_trip() {
        let mut store = memory_store();
        let id = create_item_with_origin_bindings(
            &mut store,
            &login_draft("带绑定"),
            vec![
                binding(OriginBindingKind::Exact, "https://example.com"),
                binding(OriginBindingKind::Domain, "example.org"),
            ],
        )
        .unwrap();

        let d = get_item(&store, &id).unwrap().unwrap();
        assert_eq!(d.origin_bindings.len(), 2);
        assert_eq!(
            d.origin_bindings,
            vec![
                binding(OriginBindingKind::Exact, "https://example.com"),
                binding(OriginBindingKind::Domain, "example.org"),
            ]
        );
    }

    /// 普通 create_item：无绑定条目 → get_item 读回为空 Vec
    #[test]
    fn plain_create_has_empty_bindings() {
        let mut store = memory_store();
        let id = create_item(&mut store, &login_draft("无绑定")).unwrap();
        assert!(get_item(&store, &id)
            .unwrap()
            .unwrap()
            .origin_bindings
            .is_empty());
    }

    /// set_item_origin_bindings：显式替换绑定；get_item 读回一致
    #[test]
    fn set_bindings_replaces() {
        let mut store = memory_store();
        let id = create_item(&mut store, &login_draft("改绑定")).unwrap();

        set_item_origin_bindings(
            &mut store,
            &id,
            vec![binding(OriginBindingKind::Subdomain, "example.com")],
        )
        .unwrap();
        assert_eq!(
            get_item(&store, &id).unwrap().unwrap().origin_bindings,
            vec![binding(OriginBindingKind::Subdomain, "example.com")]
        );

        // 再替换：旧绑定被覆盖
        set_item_origin_bindings(&mut store, &id, Vec::new()).unwrap();
        assert!(get_item(&store, &id)
            .unwrap()
            .unwrap()
            .origin_bindings
            .is_empty());
    }

    /// update_item 保留既有绑定（ItemDraft 不含绑定字段，编辑不静默清空）
    #[test]
    fn update_preserves_bindings() {
        let mut store = memory_store();
        let id = create_item_with_origin_bindings(
            &mut store,
            &login_draft("原题"),
            vec![binding(OriginBindingKind::Exact, "https://example.com")],
        )
        .unwrap();

        // 编辑标题（update_item 整换语义下 bindings 不在草稿内 → 保留）
        let draft = login_draft("改题");
        update_item(&mut store, &id, &draft).unwrap();

        let d = get_item(&store, &id).unwrap().unwrap();
        assert_eq!(d.title.expose(), "改题");
        assert_eq!(
            d.origin_bindings,
            vec![binding(OriginBindingKind::Exact, "https://example.com")]
        );
    }

    /// set_item_origin_bindings 对不存在条目 → ItemNotFound
    #[test]
    fn set_bindings_missing_item() {
        let mut store = memory_store();
        let missing = uuid::Uuid::now_v7().to_string();
        assert!(matches!(
            set_item_origin_bindings(
                &mut store,
                &missing,
                vec![binding(OriginBindingKind::Domain, "example.com")]
            ),
            Err(CfError::ItemNotFound)
        ));
    }

    /// 旧库兼容负路径（docs/32 §4.4 / KNOWN-ISSUES B-1）：旧库无
    /// `item_origins` 表 → 重新打开（幂等建表）→ 既有条目不丢、读回
    /// 绑定为空、可正常写入绑定。
    #[test]
    fn old_vault_without_origins_table_upgrades_cleanly() {
        let mut conn = Connection::open_in_memory().unwrap();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        cf_store::schema::init(&mut conn).unwrap();
        // 模拟旧库：删掉 item_origins 表（旧版本 schema 不存在该表）
        conn.execute("DROP TABLE item_origins", []).unwrap();

        // 新代码打开（ItemStore::open 幂等建齐 12 表 → 表被重建为空）
        let mut store = ItemStore::open(conn, subkeys).unwrap();
        let id = create_item(&mut store, &login_draft("旧库条目")).unwrap();
        let d = get_item(&store, &id).unwrap().unwrap();
        assert_eq!(d.title.expose(), "旧库条目");
        assert!(d.origin_bindings.is_empty(), "旧库条目读回绑定必须为空");

        // 升级后可正常写入绑定（负路径的另一半：可写）
        set_item_origin_bindings(
            &mut store,
            &id,
            vec![binding(OriginBindingKind::Domain, "example.com")],
        )
        .unwrap();
        assert_eq!(
            get_item(&store, &id)
                .unwrap()
                .unwrap()
                .origin_bindings
                .len(),
            1
        );
    }
}
