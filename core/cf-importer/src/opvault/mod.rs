//! OPVault 导入（FR-7.3，docs/22 §2.2，T02）。
//!
//! ## 模块结构
//!
//! - [`model`]：`profile.js` / `folders.js` / `band_*.js` 明文 JSON 模型；
//! - [`parser`]：目录结构 + JS 前缀剥离 + band/文件夹读取（结构层 2001）；
//! - [`mapping`]：解密 + 字段映射（TC-OPV-09 码表，docs/24 §3）；
//! - [`precheck`]：预检报告（TC-OPV-05 语义偏差：结构不触密码）。
//!
//! ## 入口
//!
//! - [`precheck_opvault`]：结构预检，只读、不触密码、可反复调用；
//! - [`import_opvault`]：密码保护导入——解密钥链 → 全量解析 → 逐条目
//!   单事务落库（与 1PUX 同纪律，docs/22 §3.2）。
//!
//! ## 错误语义（docs/22 §4，零新增）
//!
//! | 场景 | 码 |
//! | --- | --- |
//! | 结构预检失败（非目录 / 缺 profile.js / JSON 非法） | 2001 `ImportUnknownFormat` |
//! | 密码错误 / 密钥链校验失败 / 解密 / 落库失败 | 2002 `ImportFailed` |
//!
//! 密码错误与数据损坏**不区分**（`OpvaultCryptoError::AuthFailed` 文案
//! 「密码错误或数据损坏」透传，不复用 1002 主密码文案——TC-OPV-03）。
//!
//! ## 硬性约束
//!
//! 生产代码禁 `unwrap`/`expect`；错误只用 `CfError` 既有变体；
//! 附件 out-of-scope（跳过 + 计数，TC-OPV-10）。

pub mod mapping;
pub mod model;
pub mod parser;
pub mod precheck;

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use cf_crypto::opvault::{derive_vault_keys, OpvaultKeys};
use cf_domain::field::{Designation, FieldType};
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, UrlRow};
use cf_store::{ItemRow, ItemStore, Repos};

pub use mapping::{MapOutcome, OpvaultFieldModel, OpvaultItemModel, OpvaultMapSignals};
pub use precheck::{NotImportedOpvaultItem, OpvaultPrecheckReport};

/// OPVault 导入结果（docs/22 §3.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpvaultImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（与本次导入同管线产出，TC-OPV-05 完整报告需密码）。
    pub report: OpvaultPrecheckReport,
}

/// 结构预检一个 opvault（只读、可反复调用；TC-OPV-05）。
///
/// 目录结构 + `profile.js` 元数据 + KDF 参数读数，**不触密码**、
/// 锁定态可预检。完整报告（条目/分类分布）需密码——由
/// [`import_opvault`] 产出（语义偏差，docs/22 §2.2.3）。
///
/// # Errors
///
/// 非 opvault 目录 / 缺 `default/profile.js` / profile.js 无法解析 →
/// [`CfError::Io`] / [`CfError::ImportUnknownFormat`]（2001，TC-OPV-06）。
pub fn precheck_opvault(path: &Path) -> Result<OpvaultPrecheckReport, CfError> {
    precheck::precheck_structure(path)
}

/// 密码保护导入一个 opvault（每条目单事务；TC-OPV-01/02/03）。
///
/// 流程：结构打开 → 密钥链派生（密码错 → 2002）→ 全量解密映射
/// （任一失败 → 2002，**all-or-nothing 不落明文**，TC-OPV-03/04）→
/// 逐条目 `with_tx` 写入（items / fields / urls / totp）→ meta 计数。
///
/// `vault_dir`：附件旁路目录宿主（**本版附件 out-of-scope**，参数保留为
/// 未来扩展位，docs/22 §2.2.3 / §3.2）。
///
/// # Errors
///
/// 结构层整体拒绝（2001）或密钥链 / 解密 / 映射 / 落库失败（2002）时
/// 返回错误；**失败不落任何条目**（解密映射先于写入完成）。
pub fn import_opvault(
    path: &Path,
    password: &str,
    store: &mut ItemStore,
    vault_dir: &Path,
) -> Result<OpvaultImportResult, CfError> {
    // 附件 out-of-scope：vault_dir 保留为未来扩展位，显式声明不使用
    let _ = vault_dir;

    let archive = parser::open_vault(path)?;
    let keys = derive_keys(&archive.profile, password)?;

    // 全量解密 + 映射（任一失败 → 2002，全部条目都不写入）
    let (models, mut report) = analyze(&archive, &keys)?;
    report.total_items = archive.items.len() as u32;
    report.folder_count = archive.folders.len() as u32;
    report.attachment_count = archive.attachment_count;
    report.other_profiles = archive.other_profiles.clone();
    report.band_file_count = parser::count_structure(path)?.band_file_count;

    let imported_items = write_all(&models, store)?;
    report.importable_items = models.len() as u32;
    report.warnings.push(format!(
        "附件 {count} 个为 out-of-scope（本版跳过不导入，TC-OPV-10）",
        count = archive.attachment_count
    ));

    Ok(OpvaultImportResult {
        imported_items,
        report,
    })
}

/// profile 密钥链派生（TC-OPV-02：密码 UTF-8 原始字节，勿追加 NUL）。
///
/// `profile.salt` 为 base64（16 字节）；解码失败 / 派生失败 → 2002。
fn derive_keys(
    profile: &model::ProfileMeta,
    password: &str,
) -> Result<OpvaultKeys, CfError> {
    let salt = base64::engine::general_purpose::STANDARD
        .decode(profile.salt.trim())
        .map_err(|e| {
            CfError::ImportFailed(format!("profile.salt base64 非法：{e}"))
        })?;
    derive_vault_keys(
        password.as_bytes(),
        &salt,
        profile.iterations,
        &profile.master_key,
        &profile.overview_key,
    )
    .map_err(|e| CfError::ImportFailed(format!("opvault 密钥链派生失败：{e}")))
}

/// 全量解密 + 映射（纯函数，不触库；任一失败 → 2002）。
fn analyze(
    archive: &parser::OpvaultArchive,
    keys: &OpvaultKeys,
) -> Result<(Vec<OpvaultItemModel>, OpvaultPrecheckReport), CfError> {
    let mut models: Vec<OpvaultItemModel> = Vec::new();
    let mut not_imported: Vec<NotImportedOpvaultItem> = Vec::new();
    let mut category_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut signals = OpvaultMapSignals::default();
    let mut warnings: Vec<String> = Vec::new();

    for item in &archive.items {
        let mut item_signals = OpvaultMapSignals::default();
        let (mapped, skipped) = map_one(item, keys, &mut item_signals, &mut warnings)?;
        if let Some(m) = mapped {
            *category_counts
                .entry(m.category.as_str().to_owned())
                .or_insert(0) += 1;
            models.push(m);
        }
        if let Some(s) = skipped {
            not_imported.push(s);
        }
        merge_signals(&mut signals, item_signals);
    }

    // 未导入项（Tombstone）汇总告警
    for n in &not_imported {
        warnings.push(format!(
            "条目 {}：{reason}",
            n.uuid,
            reason = n.reason
        ));
    }
    if signals.trashed_count > 0 {
        warnings.push(format!(
            "{} 个条目处于归档（trashed），按归档语义导入",
            signals.trashed_count
        ));
    }
    let mut unknown_field_types = signals.unknown_field_types.clone();
    unknown_field_types.sort();
    unknown_field_types.dedup();
    if !unknown_field_types.is_empty() {
        warnings.push(format!(
            "存在未识别的字段类型码（值已按 Text 降级保留）：{}",
            unknown_field_types.join(", ")
        ));
    }

    let report = OpvaultPrecheckReport {
        profile_name: archive.profile.profile_name.clone(),
        profile_uuid: archive.profile.uuid.clone(),
        iterations: archive.profile.iterations,
        password_hint: archive.profile.password_hint.clone(),
        band_file_count: 0, // 由调用方覆盖
        attachment_count: archive.attachment_count,
        other_profiles: archive.other_profiles.clone(),
        total_items: archive.items.len() as u32,
        importable_items: models.len() as u32,
        category_distribution: category_counts.into_iter().collect(),
        folder_count: archive.folders.len() as u32,
        trashed_items: signals.trashed_count,
        unknown_field_types,
        unknown_categories: signals.unknown_categories,
        not_imported,
        warnings,
    };
    Ok((models, report))
}

/// 映射单条目。
///
/// 返回 `(导入模型, 未导入项)`：Tombstone → `(None, Some(...))`（记入
/// 预检未导入清单，TC-OPV-11）；其余 → `(Some(model), None)`。
fn map_one(
    item: &model::RawItem,
    keys: &OpvaultKeys,
    signals: &mut OpvaultMapSignals,
    warnings: &mut Vec<String>,
) -> Result<(Option<OpvaultItemModel>, Option<NotImportedOpvaultItem>), CfError> {
    match mapping::map_item(item, keys, signals)? {
        MapOutcome::Imported(m) => {
            if signals.unknown_category {
                warnings.push(format!(
                    "条目 {}（{}）：分类码 {} 未识别，已降级导入为安全笔记（数据并入备注）",
                    m.source_uuid, m.title, item.category
                ));
            }
            Ok((Some(*m), None))
        }
        MapOutcome::Skipped(reason) => Ok((
            None,
            Some(NotImportedOpvaultItem {
                uuid: item.uuid.clone(),
                title: String::new(),
                reason,
            }),
        )),
    }
}

/// 合并单条目信号到汇总（去重由调用方负责）。
fn merge_signals(total: &mut OpvaultMapSignals, item: OpvaultMapSignals) {
    total.no_title |= item.no_title;
    total.unknown_category |= item.unknown_category;
    total.unknown_field_types.extend(item.unknown_field_types);
    total.unknown_categories.extend(item.unknown_categories);
    total.bad_totp |= item.bad_totp;
    total.trashed_count += item.trashed_count;
}

/// 逐条目单事务写入全部模型（TC-OPV-03：失败回滚该条，已成功保留——
/// 本版解密映射先于写入完成，写入层不产生硬失败）。
fn write_all(models: &[OpvaultItemModel], store: &mut ItemStore) -> Result<u32, CfError> {
    let mut imported: u32 = 0;
    for (i, m) in models.iter().enumerate() {
        store.with_tx(|repos| write_opvault_item(repos, m, i as i64))?;
        imported += 1;
    }
    Ok(imported)
}

/// 把一条 [`OpvaultItemModel`] 写成完整条目（items + fields + urls +
/// totp）。须在 `with_tx` 内调用（附件 out-of-scope，无附件写入）。
fn write_opvault_item(
    repos: &Repos<'_>,
    model: &OpvaultItemModel,
    position: i64,
) -> Result<(), CfError> {
    let item_uuid = uuid::Uuid::now_v7().to_string();
    let row = ItemRow {
        uuid: item_uuid.clone(),
        category: model.category,
        state: model.state,
        is_favorite: model.is_favorite,
        fav_index: model.fav_index,
        created_at: model.created_at,
        updated_at: model.updated_at,
        trashed_at: model.trashed_at,
        position,
    };
    repos
        .items
        .insert(&row, &SecretString::from_exposed(model.title.clone()))?;

    // 字段：Username（Text）/ Password（Concealed）/ Notes（Multiline）
    // + 普通字段（含 designation）
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

    // 多 URL → 多行，首条 is_primary（与 1PUX 同裁决）
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

    // TOTP（otpauth 解析成功才有；algo 固定 sha1，与 CSV/1PUX 同裁定）
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

    repos.meta.add_item_count(1)?;
    Ok(())
}
