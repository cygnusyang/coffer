//! # cf-importer —— 导入器
//!
//! 1PUX / CSV / opvault 三种格式的解析、字段映射与预检报告。
//!
//! ## 对应设计文档
//!
//! - `docs/07-macOS纵切设计.md` §3（CSV 导入设计）与 §7 T03 条目
//! - `docs/03-详细设计.md` §6（导入器设计）
//! - `docs/03-详细设计.md` §6.4（分类码与字段映射表）
//! - `docs/01-需求分析.md` §5-G（FR-7 数据导入）
//!
//! ## 职责边界
//!
//! **不直接管理事务语义之外的存储决策**——解析与映射产出中间表示
//! `ImportModel`；CSV 导入的落库编排（[`import_csv`]）通过
//! `cf-store::ItemStore::with_tx` 在**单事务**内完成，任一行硬错误
//! 整体回滚、零残留（NFR-REL-01 / NFR-REL-04）。
//!
//! 关键约束（docs/07 §3）：
//! 1. RFC 4180 自写解析器 + DoS 上限（50 MB / 10k 行 / 64 KiB 字段 /
//!    64 列），超限拒绝并指明行号；
//! 2. 9 列映射，未知列进预检报告不静默丢弃；
//! 3. 公式注入**不修改原值**仅告警（防护主战场在导出侧）；
//! 4. 坏 otpauth 单元格并入 Notes，不丢整行；
//! 5. v0.1 固定「全部新建（UUIDv7）」策略；重名仅预检提示；
//! 6. v0.1 仅 UTF-8（BOM 剥离）；GBK 回退推后（docs/07 §5 C-7）。
//!
//! ## 与设计文档的一处偏差（已上报，不静默）
//!
//! docs/07 §7 T03 的文件清单含 `core/cf-session/src/usecase/import_csv.rs`
//! （编排归 cf-session）。因 cf-session 正在并行开发（T02），为避免撞车，
//! 本任务将导入编排落在 [`import_csv`]（持 `&mut ItemStore` 门面，不经
//! cf-session 的任何新 API）；cf-session 侧后续可直接包一层薄委托。
//!
//! 支持格式：
//! - CSV —— **本任务实现**（1Password 9 列）
//! - 1PUX（JSON）—— v0.2+
//! - opvault —— 未定
//! - KeePass KDBX —— 读取链路冒烟已验证（见下方测试），实现推后
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

use std::path::Path;

use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, TagRow, UrlRow};
use cf_store::{ItemRow, ItemStore, Repos};

pub mod csv;
pub mod precheck;

pub use csv::mapping::{ImportModel, OtpauthData};
pub use precheck::{analyze_csv, read_and_analyze, CsvAnalysis, CsvPrecheckReport};

/// CSV 导入结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsvImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_rows: u32,
}

/// 导入选项。
///
/// `fail_after_rows` 是**显式的故障注入点**：在写入第 N 行（0 起）之前
/// 返回错误，令整个事务回滚。供测试与演练验证 all-or-nothing 语义
/// （docs/07 §7 T03 验收 ⑦），生产路径恒用 [`ImportOptions::default`]。
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportOptions {
    /// 在写入该下标（0 起）的行之前注入失败；`None` 表示不注入。
    pub fail_after_rows: Option<u32>,
}

/// 预检一个 CSV 文件（只读、可反复调用；docs/07 §2.3 `precheck_csv`）。
///
/// # Errors
///
/// 文件不存在 / 不可读 → [`CfError::Io`]；格式与上限问题 →
/// [`CfError::ImportFailed`] / [`CfError::ImportUnknownFormat`]。
pub fn precheck_csv(path: &Path) -> Result<CsvPrecheckReport, CfError> {
    precheck::read_and_analyze(path).map(|a| a.report)
}

/// 导入一个 1Password 9 列 CSV 文件（单事务 all-or-nothing）。
///
/// 流程：解析 → 映射 → `ItemStore::with_tx` 内逐行写入
/// （items / fields / urls / tags / totp）→ `meta.item_count` 增量。
/// 任一行硬错误（含 [`ImportOptions::fail_after_rows`] 注入）→
/// 整体 ROLLBACK，已有数据零影响。
///
/// 策略固定「全部新建（UUIDv7）」：CSV 无 uuid、无冲突语义；
/// ConflictPolicy 推后到 1PUX 导入（docs/07 §3.3）。
///
/// # Errors
///
/// 解析 / 映射失败（整个文件拒绝）或事务内任一行写入失败时返回，
/// 库保持导入前状态。
pub fn import_csv(path: &Path, store: &mut ItemStore) -> Result<CsvImportResult, CfError> {
    import_csv_with_options(path, store, &ImportOptions::default())
}

/// [`import_csv`] 的显式选项版本（测试注入回滚用）。
///
/// # Errors
///
/// 同 [`import_csv`]。
pub fn import_csv_with_options(
    path: &Path,
    store: &mut ItemStore,
    options: &ImportOptions,
) -> Result<CsvImportResult, CfError> {
    let analysis = precheck::read_and_analyze(path)?;
    import_models(&analysis.models, store, options)
}

/// 在单事务内把映射好的 [`ImportModel`] 列表全部写入（全部新建）。
///
/// 预检与导入复用同一条解析/映射管线（[`precheck::analyze_csv`]），
/// 调用方传入的 `models` 应来自该管线，保证报告与落库一致。
///
/// # Errors
///
/// 任一行写入失败或注入点触发 → 事务回滚并返回错误，零残留。
pub fn import_models(
    models: &[ImportModel],
    store: &mut ItemStore,
    options: &ImportOptions,
) -> Result<CsvImportResult, CfError> {
    store.with_tx(|repos| {
        for (i, model) in models.iter().enumerate() {
            if options.fail_after_rows == Some(u32::try_from(i).unwrap_or(u32::MAX)) {
                return Err(CfError::ImportFailed(format!(
                    "注入的导入失败（写入第 {} 行前触发回滚）",
                    i + 1
                )));
            }
            write_model(repos, model, i as i64)?;
        }
        repos.meta.add_item_count(models.len() as i64)?;
        Ok(CsvImportResult {
            imported_rows: u32::try_from(models.len()).unwrap_or(u32::MAX),
        })
    })
}

/// 把一条 [`ImportModel`] 写成完整条目（items + fields + urls + tags +
/// totp）。须在 `with_tx` 事务内调用。
fn write_model(repos: &Repos<'_>, model: &ImportModel, position: i64) -> Result<(), CfError> {
    let now = unix_now()?;
    let item_uuid = uuid::Uuid::now_v7().to_string();

    let state = if model.archived {
        ItemState::Archived
    } else {
        ItemState::Active
    };
    let row = ItemRow {
        uuid: item_uuid.clone(),
        category: ItemCategory::Login,
        state,
        is_favorite: model.is_favorite,
        fav_index: 0,
        created_at: now,
        updated_at: now,
        trashed_at: None,
        position,
    };
    repos
        .items
        .insert(&row, &SecretString::from_exposed(model.title.clone()))?;

    // 字段：Username（Text）/ Password（Concealed）/ Notes（Multiline），
    // 字段名对齐 cf-domain Login 模板的 default_name（用户名/密码/备注）。
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
    repos.fields.replace_fields_for_item(&item_uuid, &fields)?;

    // 主 URL（Website 列）
    if let Some(url) = &model.url {
        repos.urls.replace_for_item(
            &item_uuid,
            &[UrlRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_uuid.clone(),
                label: None,
                url: url.clone(),
                is_primary: true,
                position: 0,
            }],
        )?;
    }

    // 标签
    if !model.tags.is_empty() {
        let tags: Vec<TagRow> = model
            .tags
            .iter()
            .map(|t| TagRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_uuid.clone(),
                name: t.clone(),
            })
            .collect();
        repos.tags.replace_for_item(&item_uuid, &tags)?;
    }

    // TOTP（otpauth 解析成功才有；algo 固定 sha1，v0.1 裁定）
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

    Ok(())
}

/// 当前 Unix 秒。系统时钟早于 epoch 时返回错误（不猜测）。
fn unix_now() -> Result<i64, CfError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CfError::StorageError("system clock before unix epoch".into()))?
        .as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::CfError;
    use cf_store::ItemListFilter;

    use super::*;

    fn store() -> ItemStore {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, keys).unwrap()
    }

    /// 单条最小模型的写入往返（items + fields + meta 计数）
    #[test]
    fn 最小模型写入往返() {
        let mut st = store();
        let model = ImportModel {
            title: "最小条目".into(),
            url: None,
            username: Some("alice".into()),
            password: Some("pw".into()),
            totp: None,
            is_favorite: false,
            archived: false,
            tags: vec![],
            notes: String::new(),
        };
        let result = import_models(&[model], &mut st, &ImportOptions::default()).unwrap();
        assert_eq!(result.imported_rows, 1);

        let repos = st.repos();
        assert_eq!(repos.items.count(None).unwrap(), 1);
        assert_eq!(repos.meta.item_count().unwrap(), 1);
        let all = repos.items.list(&ItemListFilter::default()).unwrap();
        assert_eq!(all[0].title.expose(), "最小条目");
        let fields = repos.fields.read_fields_for_item(&all[0].row.uuid).unwrap();
        assert_eq!(fields.len(), 2, "无备注时不写备注字段");
    }

    /// 故障注入：第 2 行前失败 → 全部回滚、meta 计数不变（零残留）
    #[test]
    fn 故障注入整体回滚零残留() {
        let mut st = store();
        let models: Vec<ImportModel> = (0..3)
            .map(|i| ImportModel {
                title: format!("条目{i}"),
                url: None,
                username: None,
                password: None,
                totp: None,
                is_favorite: false,
                archived: false,
                tags: vec![],
                notes: String::new(),
            })
            .collect();

        let err = import_models(&models, &mut st, &ImportOptions { fail_after_rows: Some(1) })
            .unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("注入")));

        let repos = st.repos();
        assert_eq!(repos.items.count(None).unwrap(), 0, "回滚后不得有残留条目");
        assert_eq!(repos.meta.item_count().unwrap(), 0, "meta 计数必须随事务回滚");
    }

    /// KeePass KDBX 冒烟：构造最小内存数据库 → 保存 → 重新解析。
    ///
    /// 无真实样本时用 keepass crate 自身的 API 构造最小 KDBX 结构，证明：
    /// 1. `keepass` 依赖在 workspace 的 MSRV（1.85）下可编译；
    /// 2. `Database::save`（KDBX4）→ `Database::open` 往返可用；
    /// 3. 条目字段（Title / UserName / Password）在往返后保持原值。
    #[test]
    fn keepass_minimal_db_roundtrip() {
        use keepass::db::{fields, GroupMut};
        use keepass::{Database, DatabaseKey};

        // ---- 构造：空库 + 一个分组 + 一个条目 ----
        let mut db = Database::new();
        let mut root = db.root_mut();

        let mut group: GroupMut<'_> = root.add_group();
        group.name = "Imported From KeePass".into();

        let mut entry = group.add_entry();
        entry.set_unprotected(fields::TITLE, "GitHub");
        entry.set_unprotected(fields::USERNAME, "octocat");
        entry.set_protected(fields::PASSWORD, "s3cret!");

        let key = DatabaseKey::new().with_password("coffer-test");

        // ---- 保存到内存缓冲 ----
        let mut buf = Vec::new();
        db.save(&mut buf, key.clone()).unwrap();
        assert!(buf.len() > 64, "KDBX 序列化输出不应为空");

        // ---- 重新解析 ----
        let mut source = &buf[..];
        let reopened = Database::open(&mut source, key).unwrap();

        let root_after = reopened.root();
        let group_after = root_after
            .group_by_name("Imported From KeePass")
            .expect("分组名应在往返后保留");
        let entry_after = group_after
            .entry_by_name("GitHub")
            .expect("条目 Title 应在往返后保留");

        assert_eq!(entry_after.get(fields::USERNAME), Some("octocat"));
        // 受保护字段（Password）同样应还原
        assert_eq!(entry_after.get(fields::PASSWORD), Some("s3cret!"));
    }
}
