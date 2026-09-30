//! 1PUX 导入（FR-7.1 含 `files/` 附件 + FR-7.4~7.7 预检报告，
//! `docs/09-版本开发计划.md` v0.3.0-T01）。
//!
//! ## 模块结构
//!
//! - [`model`]：1PUX JSON 数据模型（serde，官方键 / 合成样本键双兼容）；
//! - [`parser`]：ZIP 容器（`export.attributes` / `export.data` / `files/`）；
//! - [`mapping`]：categoryUuid 映射表 + 类型化 value 分派 →
//!   [`PuxItemModel`]；
//! - [`passkey`]：passkey 字段检测（docs/17 §4.2 PK2——桌面导出恒空
//!   快速路径，检出仅计数告警不落库）；
//! - [`precheck`]：预检报告（FR-7.4~7.7 冻结字段 + `passkey_count`
//!   增量）+ 可导入模型清单。
//!
//! ## 落库事务语义（设计裁决）
//!
//! **每条目一个 `with_tx`**：{item + fields + urls + totp + attachments 行}
//! 原子写入；附件密文文件在事务内先落盘（`AttachmentRepo::add` 的
//! 先文件后行纪律），单条目失败回滚、文件成孤儿 → 导入收尾统一
//! [`AttachmentRepo::cleanup_orphans`] 清理。条目固定「全部新建
//! （UUIDv7）」策略；ConflictPolicy 推后（与 CSV 导入同现状）。
//!
//! `fail_after_rows` 注入点在**条目事务内、附件写入之后**——保证能构造
//! 「文件已落盘、事务回滚」的孤儿场景（CSV 版注入点在行前，无此能力）。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`（crate 级）；生产代码禁 `unwrap`/`expect`；
//! 错误只用 `CfError` 既有变体。

pub mod mapping;
pub mod model;
pub mod parser;
pub mod passkey;
pub mod precheck;

use std::path::Path;

use cf_domain::field::{Designation, FieldType};
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, UrlRow};
use cf_store::{AttachmentRepo, ItemRow, ItemStore, Repos};

pub use mapping::{PuxFieldModel, PuxItemModel};
pub use model::PuxFileRef;
pub use passkey::{passkey_refs, PuxPasskeyRef};
pub use precheck::{NotImportedItem, PuxAnalysis, PuxPrecheckReport};

/// 1PUX 导入结果（FR-7.7 导入结果页素材）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuxImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（与本次导入同管线产出，FR-7.4 所见即所得）。
    pub report: PuxPrecheckReport,
}

/// 预检一个 1PUX 文件（只读、可反复调用；FR-7.4）。
///
/// # Errors
///
/// 文件不可读 / 非法 ZIP → [`CfError::Io`] / [`CfError::ImportUnknownFormat`]；
/// 必需成员缺失 / JSON 非法 / 超上限 → [`CfError::ImportFailed`]。
pub fn precheck_1pux(path: &Path) -> Result<PuxPrecheckReport, CfError> {
    precheck::read_and_analyze(path).map(|a| a.report)
}

/// 导入一个 1PUX 文件（每条目单事务；docs/09 v0.3.0-T01）。
///
/// 流程：打开 ZIP → 解析 → 映射 + 预检 → 逐条目 `with_tx` 写入
/// （items / fields / urls / totp / attachments，附件密文先落盘）→
/// 收尾 [`AttachmentRepo::cleanup_orphans`]。
///
/// `vault_dir` 是附件旁路文件目录（`attachments/`）的宿主目录，须与
/// 解锁保险库时的 vault 根目录一致。
///
/// # Errors
///
/// 解析 / 预检层整体拒绝（坏 ZIP / 缺成员 / 超上限）或任一条目事务
/// 失败时返回错误；失败条目回滚，已成功条目保留（每条目独立事务），
/// 孤儿附件文件已被收尾清理。
pub fn import_1pux(
    path: &Path,
    store: &mut ItemStore,
    vault_dir: &Path,
) -> Result<PuxImportResult, CfError> {
    import_1pux_with_options(path, store, vault_dir, &crate::ImportOptions::default())
}

/// [`import_1pux`] 的显式选项版本（测试注入回滚用）。
///
/// `fail_after_rows = Some(n)`：第 n（0 起）个条目的事务在**全部行与
/// 附件文件写入之后**注入失败 → 该事务回滚、附件文件成孤儿 → 收尾
/// 清理；之前的条目已提交保留。生产路径恒用 [`Default`]。
///
/// # Errors
///
/// 同 [`import_1pux`]。
pub fn import_1pux_with_options(
    path: &Path,
    store: &mut ItemStore,
    vault_dir: &Path,
    options: &crate::ImportOptions,
) -> Result<PuxImportResult, CfError> {
    let mut archive = parser::PuxArchive::open(path)?;
    let analysis = precheck::analyze(&mut archive)?;

    let result = write_all(&analysis.models, store, vault_dir, &mut archive, options);
    // 收尾：清理回滚遗留的孤儿附件文件（成功路径同样执行——幂等）
    AttachmentRepo::cleanup_orphans(vault_dir, store.connection())?;
    result.map(|imported_items| PuxImportResult {
        imported_items,
        report: analysis.report,
    })
}

/// 逐条目单事务写入全部模型。
fn write_all(
    models: &[PuxItemModel],
    store: &mut ItemStore,
    vault_dir: &Path,
    archive: &mut parser::PuxArchive,
    options: &crate::ImportOptions,
) -> Result<u32, CfError> {
    let mut imported: u32 = 0;
    for (i, m) in models.iter().enumerate() {
        let inject_fail = options.fail_after_rows == Some(u32::try_from(i).unwrap_or(u32::MAX));
        store
            .with_tx(|repos| write_pux_item(repos, m, i as i64, vault_dir, archive, inject_fail))?;
        imported += 1;
    }
    Ok(imported)
}

/// 把一条 [`PuxItemModel`] 写成完整条目（items + fields + urls + totp +
/// attachments 行，附件密文文件事务内先落盘）。须在 `with_tx` 内调用。
///
/// `inject_fail`：附件写入后注入失败（回滚 → 文件成孤儿）。
fn write_pux_item(
    repos: &Repos<'_>,
    model: &PuxItemModel,
    position: i64,
    vault_dir: &Path,
    archive: &mut parser::PuxArchive,
    inject_fail: bool,
) -> Result<(), CfError> {
    let item_uuid = uuid::Uuid::now_v7().to_string();
    let created_at = if model.created_at > 0 {
        model.created_at
    } else {
        crate::unix_now()?
    };
    let updated_at = if model.updated_at > 0 {
        model.updated_at
    } else {
        crate::unix_now()?
    };
    let row = ItemRow {
        uuid: item_uuid.clone(),
        category: model.category,
        state: model.state,
        is_favorite: model.is_favorite,
        fav_index: model.fav_index,
        created_at,
        updated_at,
        trashed_at: model.trashed_at,
        position,
    };
    repos
        .items
        .insert(&row, &SecretString::from_exposed(model.title.clone()))?;

    // 字段：Username（designation）/ Password（designation）/ Notes
    //（降级条目的全部数据已在 notes 内）+ sections 等普通字段
    let mut fields: Vec<FieldRow> = Vec::new();
    if let Some(username) = &model.username {
        fields.push(FieldRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.clone(),
            section_uuid: None,
            field_type: FieldType::Text,
            designation: Some(Designation::Username),
            name: "用户名".into(),
            value: Some(username.clone()),
            position: fields.len() as i64,
        });
    }
    if let Some(password) = &model.password {
        fields.push(FieldRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.clone(),
            section_uuid: None,
            field_type: FieldType::Concealed,
            designation: Some(Designation::Password),
            name: "密码".into(),
            value: Some(password.clone()),
            position: fields.len() as i64,
        });
    }
    if !model.notes.is_empty() {
        fields.push(FieldRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.clone(),
            section_uuid: None,
            field_type: FieldType::Multiline,
            designation: Some(Designation::NotesPlain),
            name: "备注".into(),
            value: Some(model.notes.clone()),
            position: fields.len() as i64,
        });
    }
    for f in &model.fields {
        fields.push(FieldRow {
            uuid: uuid::Uuid::now_v7().to_string(),
            item_uuid: item_uuid.clone(),
            section_uuid: None,
            field_type: f.field_type,
            designation: f.designation.clone(),
            name: f.name.clone(),
            value: f.value.clone(),
            position: fields.len() as i64,
        });
    }
    repos.fields.replace_fields_for_item(&item_uuid, &fields)?;

    // 多 URL → 多行，首条 is_primary（设计裁决）
    if !model.urls.is_empty() {
        let rows: Vec<UrlRow> = model
            .urls
            .iter()
            .enumerate()
            .map(|(i, (label, url))| UrlRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_uuid.clone(),
                label: label.clone(),
                url: url.clone(),
                is_primary: i == 0,
                position: i as i64,
            })
            .collect();
        repos.urls.replace_for_item(&item_uuid, &rows)?;
    }

    // TOTP（otpauth 解析成功才有；algo 固定 sha1，与 CSV 导入同裁定）
    if let Some(totp) = &model.totp {
        repos.totp.insert_totp(
            &uuid::Uuid::now_v7().to_string(),
            &item_uuid,
            &totp.secret,
            "sha1",
            totp.digits,
            totp.period,
            totp.issuer.as_deref(),
            totp.account.as_deref(),
        )?;
    }

    // 附件：密文文件事务内先落盘（AttachmentRepo 先文件后行纪律）
    let file = model.file.as_ref();
    let entry_name_opt = match (file, model.zip_entry.as_deref()) {
        (Some(_), Some(entry)) => Some(entry.to_owned()),
        (Some(f), None) => archive.resolve_file_entry(f),
        _ => None,
    };
    if let (Some(file), Some(entry_name)) = (file, entry_name_opt) {
        let content = archive.read_entry_content(&entry_name)?;
        repos
            .attachments
            .add(&item_uuid, file.filename.as_bytes(), &content, vault_dir)?;
    }

    // 故障注入点（测试用）：全部行与附件文件写入之后 → 回滚成孤儿
    if inject_fail {
        return Err(CfError::ImportFailed(format!(
            "注入的导入失败（第 {} 个条目事务内触发回滚）",
            position + 1
        )));
    }

    repos.meta.add_item_count(1)?;
    Ok(())
}
