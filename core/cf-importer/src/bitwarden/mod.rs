//! Bitwarden JSON 导入（FR-10.1 第二数据源，docs/17 §4.2 PK2）。
//!
//! ## 模块结构
//!
//! - [`parser`]：JSON 解析 + DoS 上限（文件 ≤ 50 MB / items ≤ 10 000 /
//!   单字段 ≤ 64 KiB，超限报错指明条目）+ 加密导出拒绝；
//! - [`mapping`]：条目映射（login{username,password,uris,notes} 走既有
//!   字段映射语义）+ `fido2Credentials[]` → [`cf_store::PasskeyRecord`]
//!   （私钥归一化 PKCS#8，D-1）；
//! - [`precheck`]：预检报告（条目数 / passkey 行数 / 非 ES256 列表 /
//!   坏行逐条列出 / 「含密码且含 passkey」计数）+ 解析管线。
//!
//! ## D-6 FR-10.6 落地规则
//!
//! passkey 是条目的附属新数据（item_uuid 外键挂靠）。passkey 映射函数
//! 只接收 `fido2Credentials[]` 行本身、**结构上接触不到 login/password
//! 字段**——含 passkey 的条目照常携带密码字段入库，回环测试断言密码
//! 逐字节不变（tests/bitwarden_import.rs）。
//!
//! ## fido2Credentials 字段形态（【单源】，TCB-1 门禁）
//!
//! Bitwarden 官方未承诺导出 schema 对第三方互通（调研 v2 §4.1）。lead
//! 裁定（2026-09-29）：合成样本先行开发，真实导出样本逆向核对降级为
//! TCB-1 回归门禁。本解析器的容忍策略：
//!
//! - 行模型按「键名取值」而非严格 struct——未知键记 warning 不拒绝
//!   （schema 漂移不炸导入）；
//! - `encryptedPrivateKey` 携带可解析的 ES256 私钥编码（PKCS#8 / SEC1
//!   DER，base64）→ 归一化导入；EncString 密文形态（真实未加密导出的
//!   实际形态，attach key 不随导出解包）→ **显式列入坏行清单**（不
//!   静默丢弃），条目本体照常导入；
//! - 条目级未知顶层键由 serde 默认忽略（Bitwarden 导出含大量良性键，
//!   仅 fido2Credentials 行内键做告警——那是唯一的【单源】风险面）。
//!
//! ## 导入事务语义（镜像 1PUX）
//!
//! **每条目一个 `with_tx`**：{item + fields + urls + tags + totp +
//! passkeys 行} 原子写入；坏 passkey 行在预检已显式列出、导入时跳过
//! 该行不丢条目（FR-7.8 纪律 / TCB-7）；任一条目事务内硬失败回滚该条
//! 、已成功条目保留。条目固定「全部新建（UUIDv7）」策略。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`（crate 级）；生产代码禁 `unwrap`/`expect`；
//! 错误只用 `CfError` 既有变体（导入面：1012 校验 / 2001 格式不识别 /
//! 2002 导入失败；1001 锁定门禁在 FFI 层；1005/1008 两级口径属私钥
//! 解封读路径，docs/17 r2.2 §5——导入路径不触碰）零新增。

pub mod mapping;
pub mod parser;
pub mod precheck;

use cf_domain::field::{Designation, FieldType};
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, TagRow, UrlRow};
use cf_store::{ItemRow, ItemStore, Repos};

pub use mapping::{
    BwFieldModel, BwItemModel, BwPasskeyFailure, BwPasskeyFailureKind, BwPasskeyModel,
};
pub use precheck::{BwAnalysis, BwPrecheckReport};

/// Bitwarden 导入结果（与 1PUX 的 [`crate::pux::PuxImportResult`] 同体裁：
/// 结果页计数 + 与本次导入同管线产出的预检报告）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（FR-7.4 所见即所得同纪律）。
    pub report: BwPrecheckReport,
}

/// 逐条目单事务写入全部模型（镜像 1PUX 的 `write_all`）。
///
/// `fail_after_rows` 注入点在**条目事务内、全部行（含 passkey）写入之后**
/// ——保证「条目 + 其 passkey 行」整体回滚可测。
pub(crate) fn write_all(
    models: &[BwItemModel],
    store: &mut ItemStore,
    options: &crate::ImportOptions,
) -> Result<u32, CfError> {
    let mut imported: u32 = 0;
    for (i, m) in models.iter().enumerate() {
        let inject_fail = options.fail_after_rows == Some(u32::try_from(i).unwrap_or(u32::MAX));
        store.with_tx(|repos| write_bw_item(repos, m, i as i64, inject_fail))?;
        imported += 1;
    }
    Ok(imported)
}

/// 把一条 [`BwItemModel`] 写成完整条目（items + fields + urls + tags +
/// totp + passkeys 行）。须在 `with_tx` 内调用。
///
/// D-6：passkey 行只引用 `item_uuid` 外键，写入路径不读写字段表中的
/// password——密码保留由映射规则（互不触碰）+ 回环测试双面保证。
fn write_bw_item(
    repos: &Repos<'_>,
    model: &BwItemModel,
    position: i64,
    inject_fail: bool,
) -> Result<(), CfError> {
    let item_uuid = uuid::Uuid::now_v7().to_string();
    let now = crate::unix_now()?;
    let created_at = if model.created_at > 0 {
        model.created_at
    } else {
        now
    };
    let updated_at = if model.updated_at > 0 {
        model.updated_at
    } else {
        now
    };
    let row = ItemRow {
        uuid: item_uuid.clone(),
        category: model.category,
        state: model.state,
        is_favorite: model.is_favorite,
        fav_index: 0,
        created_at,
        updated_at,
        trashed_at: model.trashed_at,
        position,
    };
    repos
        .items
        .insert(&row, &SecretString::from_exposed(model.title.clone()))?;

    // 字段：Username / Password / Notes + 自定义字段（命名与 CSV/1PUX
    // 映射同款，对齐 cf-domain Login 模板 default_name）
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
            designation: None,
            name: f.name.clone(),
            value: f.value.clone(),
            position: fields.len() as i64,
        });
    }
    repos.fields.replace_fields_for_item(&item_uuid, &fields)?;

    // URL：login.uris 首条 is_primary（与 1PUX 多 URL 同裁决）
    if !model.urls.is_empty() {
        let rows: Vec<UrlRow> = model
            .urls
            .iter()
            .enumerate()
            .map(|(i, url)| UrlRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_uuid.clone(),
                label: None,
                url: url.clone(),
                is_primary: i == 0,
                position: i as i64,
            })
            .collect();
        repos.urls.replace_for_item(&item_uuid, &rows)?;
    }

    // 标签：folderId → folders[].name（Bitwarden 无标签面，文件夹就近映射）
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

    // passkey：附属数据挂靠（同事务；时间戳优先行 creationDate，
    // 缺失兜底条目时间再兜底当前时间——docs/17 §4.1 now 由调用方显式传入）
    for pk in &model.passkeys {
        let pk_now = if pk.created_at > 0 {
            pk.created_at
        } else {
            now
        };
        repos.passkeys.add(&item_uuid, &pk.record, pk_now)?;
    }

    // 故障注入点（测试用）：全部行写入之后 → 条目连同 passkey 行整体回滚
    if inject_fail {
        return Err(CfError::ImportFailed(format!(
            "注入的导入失败（第 {} 个条目事务内触发回滚）",
            position + 1
        )));
    }

    repos.meta.add_item_count(1)?;
    Ok(())
}
