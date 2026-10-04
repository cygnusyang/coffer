//! OPVault 目录结构与 band/文件夹解析（docs/24 §1.1 布局，T02）。
//!
//! ## 目录布局（仲裁事实源 docs/24 §1.1）
//!
//! ```text
//! xxx.opvault/
//! └── default/                          # profile 目录（以含 profile.js 判定）
//!     ├── profile.js                    # "var profile=" + JSON + ";"（明文）
//!     ├── folders.js                    # "loadFolders(" + JSON + ")"（overview 加密）
//!     ├── band_0.js … band_F.js         # "ld(" + JSON + ");"（按 UUID 首字符分桶）
//!     └── <itemUUID>_<attachUUID>.attachment   # 附件（out-of-scope，跳过+计数）
//! ```
//!
//! 解析层只做**结构**与**明文 JSON** 读取；`k`/`o`/`d` 的 base64 内容原样
//! 保留（解密在 [`super::mapping`]）。结构非法 → 2001
//! [`CfError::ImportUnknownFormat`]（docs/22 §4）。
//!
//! ## 多 profile
//!
//! `.opvault` 根目录下每个含 `profile.js` 的子目录是一个 profile；取
//! `default/`（docs/22 已定），其余列出不导入（TC-OPV-10）。

use std::fs;
use std::path::Path;

use cf_domain::CfError;
use serde_json::Value;

use super::model::{ProfileMeta, RawFolder, RawItem};

/// 主 profile 目录名（docs/22 已定，其余列出不导入）。
pub const PROFILE_DIR: &str = "default";

/// `profile.js` 前缀（docs/24 §1.1：12 字节 + 尾分号）。
pub const PROFILE_PREFIX: &str = "var profile=";
/// `folders.js` 前缀。
pub const FOLDERS_PREFIX: &str = "loadFolders(";
/// `band_*.js` 前缀（3 字节）。
pub const BAND_PREFIX: &str = "ld(";
/// 附件文件后缀（首版 out-of-scope，跳过+计数，TC-OPV-10）。
pub const ATTACHMENT_EXT: &str = ".attachment";
/// band 文件前缀（`band_0.js` ~ `band_F.js`）。
pub const BAND_FILE_PREFIX: &str = "band_";

/// 一次完整打开的 opvault 内容（precheck 与 import 共用）。
#[derive(Debug)]
pub struct OpvaultArchive {
    /// `default/profile.js` 元数据。
    pub profile: ProfileMeta,
    /// `folders.js` 文件夹清单。
    pub folders: Vec<RawFolder>,
    /// 全部 band 条目（band_0~F 并集）。
    pub items: Vec<RawItem>,
    /// 附件文件数（out-of-scope，仅计数）。
    pub attachment_count: u32,
    /// 除 `default/` 外的其他 profile 目录名（列出不导入，TC-OPV-10）。
    pub other_profiles: Vec<String>,
}

/// 剥 JS 前缀 + 尾缀后解析 JSON 对象（docs/24 §1.1 前缀表）。
///
/// 宽容策略：
/// - 前缀缺失时不立即拒绝，改为从首个 `{` 到末个 `}` 截取（兼容无前缀变体）；
/// - 尾缀剥除容忍 `;`/`)` 任意组合（vendor 实测 `folders.js` 以 `);` 结尾，
///   官方文档记 `)`——两种形态都兼容）。
fn parse_js_object(content: &str, prefix: &str, _what: &str) -> Result<Value, CfError> {
    let body = match content.strip_prefix(prefix) {
        Some(rest) => rest
            .trim()
            .trim_end_matches([';', ')'])
            .trim_end(),
        None => {
            // 无前缀：尝试按花括号界定（宽容）
            match (content.find('{'), content.rfind('}')) {
                (Some(s), Some(e)) if e > s => &content[s..=e],
                _ => {
                    // `{what}` 缺少 JS 前缀「{prefix}」且无法定位 JSON 对象
                    return Err(CfError::ImportUnknownFormat);
                }
            }
        }
    };
    // `{what}` JSON 非法
    serde_json::from_str(body).map_err(|_| CfError::ImportUnknownFormat)
}

/// 解析 `profile.js` 内容（剥 `var profile=` 前缀 + 尾分号）。
///
/// # Errors
///
/// 前缀缺失 / JSON 非法 / 必需字段缺失 → 2001
/// [`CfError::ImportUnknownFormat`]。
pub fn parse_profile(content: &str) -> Result<ProfileMeta, CfError> {
    let v = parse_js_object(content, PROFILE_PREFIX, "profile.js")?;
    // profile.js 字段缺失或类型不符
    serde_json::from_value(v).map_err(|_| CfError::ImportUnknownFormat)
}

/// 解析 `folders.js` 内容（`loadFolders({...})`，UUID → 文件夹对象）。
///
/// # Errors
///
/// 同 [`parse_profile`]。
pub fn parse_folders(content: &str) -> Result<Vec<RawFolder>, CfError> {
    let v = parse_js_object(content, FOLDERS_PREFIX, "folders.js")?;
    let obj = v.as_object().ok_or(CfError::ImportUnknownFormat)?;
    let mut folders = Vec::with_capacity(obj.len());
    for (uuid, inner) in obj {
        // 条目 `{uuid}` 字段非法
        let mut folder: RawFolder =
            serde_json::from_value(inner.clone()).map_err(|_| CfError::ImportUnknownFormat)?;
        folder.uuid = uuid.clone();
        folders.push(folder);
    }
    Ok(folders)
}

/// 解析一个 `band_*.js` 内容（`ld({...});`，UUID → 条目对象）。
///
/// # Errors
///
/// 同 [`parse_profile`]。
pub fn parse_band(content: &str) -> Result<Vec<RawItem>, CfError> {
    let v = parse_js_object(content, BAND_PREFIX, "band_*.js")?;
    let obj = v.as_object().ok_or(CfError::ImportUnknownFormat)?;
    let mut items = Vec::with_capacity(obj.len());
    for (uuid, inner) in obj {
        // 条目 `{uuid}` 字段非法
        let mut item: RawItem =
            serde_json::from_value(inner.clone()).map_err(|_| CfError::ImportUnknownFormat)?;
        item.uuid = uuid.clone();
        items.push(item);
    }
    Ok(items)
}

/// 列出 `.opvault` 根目录下除 `default/` 外的其他 profile 目录名。
///
/// profile 目录判据 = 子目录且含 `profile.js`。
pub fn list_other_profiles(root: &Path) -> Vec<String> {
    let mut others: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == PROFILE_DIR || !path.is_dir() {
                continue;
            }
            if path.join("profile.js").is_file() {
                others.push(name);
            }
        }
    }
    others.sort();
    others
}

/// 结构预检（只读、不触密码；TC-OPV-05）——目录 + `profile.js` 元数据 +
/// KDF 参数 + band/附件文件清点。不解析 band/folders 内容（docs/24 §6：
/// 属解锁后内容，完整条目报告需密码）。
///
/// # Errors
///
/// 目录不存在 / 缺 `default/profile.js` / profile.js 无法解析 →
/// [`CfError::Io`] / [`CfError::ImportUnknownFormat`]（2001）。
pub fn read_profile(path: &Path) -> Result<ProfileMeta, CfError> {
    let profile_dir = path.join(PROFILE_DIR);
    if !profile_dir.is_dir() {
        // 不是 opvault 目录（缺少 default/profile.js）
        return Err(CfError::ImportUnknownFormat);
    }
    let content = fs::read_to_string(profile_dir.join("profile.js"))
        .map_err(|e| CfError::Io(format!("profile.js 读取失败：{e}")))?;
    parse_profile(&content)
}

/// 结构清点：band 文件数 / 附件数（不解析内容）。
pub struct StructureCounts {
    /// 存在的 `band_*.js` 文件数（0~16）。
    pub band_file_count: u32,
    /// 存在的 `.attachment` 文件数。
    pub attachment_count: u32,
}

/// 清点 band 文件与附件文件数量（只读目录项，不解析内容）。
///
/// # Errors
///
/// `default/` 不可读 → [`CfError::Io`]。
pub fn count_structure(path: &Path) -> Result<StructureCounts, CfError> {
    let profile_dir = path.join(PROFILE_DIR);
    let mut band_file_count: u32 = 0;
    let mut attachment_count: u32 = 0;
    let entries = fs::read_dir(&profile_dir)
        .map_err(|e| CfError::Io(format!("{PROFILE_DIR}/ 读取失败：{e}")))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(BAND_FILE_PREFIX) && name.ends_with(".js") {
            band_file_count += 1;
        } else if name.ends_with(ATTACHMENT_EXT) {
            attachment_count += 1;
        }
    }
    Ok(StructureCounts {
        band_file_count,
        attachment_count,
    })
}

/// 完整打开一个 opvault（import 共用）。
///
/// 结构层：目录 + profile.js + folders.js + 全部 band_*.js 均须可解析；
/// 任一失败 → 2001（docs/22 §4 结构预检）。
///
/// # Errors
///
/// 同 [`read_profile`]；band/folders 文件缺失或 JSON 非法 →
/// [`CfError::ImportUnknownFormat`]。
pub fn open_vault(path: &Path) -> Result<OpvaultArchive, CfError> {
    let profile_dir = path.join(PROFILE_DIR);
    let profile = read_profile(path)?;

    let mut folders: Vec<RawFolder> = Vec::new();
    let folders_path = profile_dir.join("folders.js");
    if folders_path.is_file() {
        let content = fs::read_to_string(&folders_path)
            .map_err(|e| CfError::Io(format!("folders.js 读取失败：{e}")))?;
        folders = parse_folders(&content)?;
    }

    let mut items: Vec<RawItem> = Vec::new();
    let entries = fs::read_dir(&profile_dir)
        .map_err(|e| CfError::Io(format!("{PROFILE_DIR}/ 读取失败：{e}")))?;
    let mut band_names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(BAND_FILE_PREFIX) && name.ends_with(".js") {
            band_names.push(name);
        }
    }
    band_names.sort();
    for name in band_names {
        let content = fs::read_to_string(profile_dir.join(&name))
            .map_err(|e| CfError::Io(format!("{name} 读取失败：{e}")))?;
        items.extend(parse_band(&content)?);
    }

    let counts = count_structure(path)?;
    let other_profiles = list_other_profiles(path);

    Ok(OpvaultArchive {
        profile,
        folders,
        items,
        attachment_count: counts.attachment_count,
        other_profiles,
    })
}
