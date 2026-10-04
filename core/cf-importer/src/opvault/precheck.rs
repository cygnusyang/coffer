//! OPVault 预检报告（TC-OPV-05，docs/22 §3.2，T02）。
//!
//! ## 预检语义（TC-OPV-05 显式偏差）
//!
//! - [`precheck_opvault`]：**只读、不触密码**——目录结构 + `profile.js`
//!   元数据 + KDF 参数（iterations / salt / masterKey / overviewKey）读数，
//!   band/folders 内容属解锁后内容（docs/24 §6），仅清点文件数；
//!   `folders.js`/`band_*.js` 属解锁后内容，仅清点文件数；
//! - **完整报告（条目/分类分布/未映射字段）需密码**——由
//!   [`super::import_opvault`] 解密后产出（报告 = 本次导入所见即所得，
//!   与 1PUX/CSV 同纪律）。
//!
//! 因此报告分两档：结构字段恒填充；全量分析字段仅 `import_opvault`
//! 填充，`precheck_opvault` 恒空（以文档标注语义边界）。

use std::path::Path;

use cf_domain::CfError;

use super::parser;

/// 一条未导入项（TC-OPV-11：Tombstone 099 逐条列出，不静默）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotImportedOpvaultItem {
    /// 原始条目 uuid。
    pub uuid: String,
    /// 标题（结构层无密码时不可知，为空字符串）。
    pub title: String,
    /// 未导入原因（人类可读）。
    pub reason: String,
}

/// OPVault 预检报告。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpvaultPrecheckReport {
    // ---- 结构 + profile 元数据（两档均填充） ----
    /// profile 名（`default`）。
    pub profile_name: String,
    /// profile UUID。
    pub profile_uuid: String,
    /// PBKDF2 迭代次数（KDF 参数，TC-OPV-05）。
    pub iterations: u32,
    /// 密码提示（profile.js 明文，官方不混淆）。
    pub password_hint: Option<String>,
    /// 存在的 `band_*.js` 文件数（0~16）。
    pub band_file_count: u32,
    /// 附件文件数（out-of-scope，跳过+计数，TC-OPV-10）。
    pub attachment_count: u32,
    /// 除 `default/` 外的其他 profile 目录（列出不导入，TC-OPV-10）。
    pub other_profiles: Vec<String>,

    // ---- 全量分析字段（仅 import_opvault 填充；precheck 恒空） ----
    /// 条目总数（含 Tombstone 等未导入项）。
    pub total_items: u32,
    /// 可导入条目数（含未知类别降级——计入导入成功）。
    pub importable_items: u32,
    /// 按类别分布（降级条目按 secure_note 计入）。
    pub category_distribution: Vec<(String, u32)>,
    /// 文件夹数（folders.js）。
    pub folder_count: u32,
    /// 归档（trashed）条目数。
    pub trashed_items: u32,
    /// 未识别的字段 type/k 码（去重排序；值已按 Text 降级保留）。
    pub unknown_field_types: Vec<String>,
    /// 未识别分类码清单：(条目 uuid, 原始分类码)。
    pub unknown_categories: Vec<(String, String)>,
    /// 未导入项逐条清单（TC-OPV-11）。
    pub not_imported: Vec<NotImportedOpvaultItem>,
    /// 告警文本。
    pub warnings: Vec<String>,
}

/// 结构预检（只读、不触密码；TC-OPV-05）。
///
/// 判定要素（docs/24 §6）：目录 + `profile.js` 存在且可解析（剥前缀）+
/// `iterations`/`salt`/`masterKey`/`overviewKey` 读数；band/folders 内容
/// 属解锁后内容，仅清点文件数。可反复调用，锁定态可预检。
///
/// # Errors
///
/// 目录不存在 / 缺 `default/profile.js` / profile.js 无法解析 →
/// [`CfError::Io`] / [`CfError::ImportUnknownFormat`]（2001，TC-OPV-06）。
pub fn precheck_structure(path: &Path) -> Result<OpvaultPrecheckReport, CfError> {
    let profile = parser::read_profile(path)?;
    let counts = parser::count_structure(path)?;
    let other_profiles = parser::list_other_profiles(path);
    let salt_ok = !profile.salt.is_empty();
    let keys_ok = !profile.master_key.is_empty() && !profile.overview_key.is_empty();

    let mut warnings: Vec<String> = Vec::new();
    if !salt_ok {
        warnings.push("profile.salt 缺失或为空——KDF 无法派生".into());
    }
    if !keys_ok {
        warnings.push("profile.masterKey/overviewKey 缺失——密钥链无法解开".into());
    }
    if !other_profiles.is_empty() {
        warnings.push(format!(
            "检测到 {} 个非 default profile（{}），本版仅导入 default/",
            other_profiles.len(),
            other_profiles.join(", ")
        ));
    }

    Ok(OpvaultPrecheckReport {
        profile_name: profile.profile_name,
        profile_uuid: profile.uuid,
        iterations: profile.iterations,
        password_hint: profile.password_hint,
        band_file_count: counts.band_file_count,
        attachment_count: counts.attachment_count,
        other_profiles,
        warnings,
        ..Default::default()
    })
}
