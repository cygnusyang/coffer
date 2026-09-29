//! Bitwarden JSON 导出解析（DoS 上限 + 边界校验，docs/17 §4.2）。
//!
//! ## DoS 上限（docs/07 §3.1 口径 / docs/18 TCB-1）
//!
//! 文件 ≤ [`MAX_FILE_BYTES`]（50 MB）、条目数 ≤ [`MAX_ITEMS`]（10 000）、
//! 单字段（条目内任意字符串值的 UTF-8 字节数）≤ [`MAX_FIELD_BYTES`]
//! （64 KiB）；超限整体拒绝，条目级超限报错**指明条目 id**。
//!
//! 校验顺序：文件大小 → JSON 合法性（非 JSON → 2001 格式不识别）→
//! `items` 数组存在性（缺失 → 2001）→ 加密导出拒绝（`encrypted: true`
//! 的 password-protected 导出不得当明文入库）→ 条目数上限 → 单字段
//! 上限（逐条目走树，报错带条目 id）→ 类型化反序列化。
//!
//! ## 时间戳
//!
//! Bitwarden 导出时间为 RFC 3339 UTC（`2026-08-01T12:30:00.000Z`）。
//! 本 crate 无 chrono 依赖，[`parse_rfc3339_utc`] 手工解析 Z 结尾形态
//! （非 Z 偏移量不接受——返回 `None`，由映射层降级为条目时间兜底，
//! 不拒绝整个文件）。

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use cf_domain::CfError;

/// null → Default 的宽容反序列化：Bitwarden 导出对「无值」的集合键
/// 惯性输出显式 `null`（如 `"passwordHistory": null`），不能因此拒绝
/// 整个文件（宁可降级不可报错丢数据）。
fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// 导出文件大小上限（50 MB，docs/18 TCB-1）。
pub const MAX_FILE_BYTES: usize = 50 * 1024 * 1024;

/// 条目总数上限（10 000，docs/18 TCB-1）。
pub const MAX_ITEMS: usize = 10_000;

/// 单字段（条目内任意字符串值）大小上限（64 KiB，UTF-8 字节口径）。
pub const MAX_FIELD_BYTES: usize = 64 * 1024;

/// 导出顶层模型（解析所需最小字段集；未知键由 serde 默认忽略）。
#[derive(Debug, Deserialize)]
pub struct BwExport {
    /// `encrypted: true` 的 password-protected 导出在解析层整体拒绝。
    #[serde(default)]
    pub encrypted: Option<bool>,
    /// 文件夹清单（folderId → 名称，映射为标签）。
    #[serde(default, deserialize_with = "null_to_default")]
    pub folders: Vec<BwFolder>,
    /// 条目清单（**必需键**，缺失即格式不识别）。
    #[serde(default, deserialize_with = "null_to_default")]
    pub items: Vec<BwItem>,
}

/// 一个文件夹。
#[derive(Debug, Deserialize)]
pub struct BwFolder {
    /// 文件夹 ID。
    #[serde(default)]
    pub id: Option<String>,
    /// 文件夹名。
    #[serde(default)]
    pub name: Option<String>,
}

/// 一条 Bitwarden 条目。
///
/// `type` / `counter` 等数值键容忍数字与数字字符串两种形态（serde_json
/// `Value` 承载，由映射层解释）；其余按官方导出模型的最小集建模。
#[derive(Debug, Deserialize)]
pub struct BwItem {
    /// 条目 ID（报错定位 / 溯源）。
    #[serde(default)]
    pub id: Option<String>,
    /// 条目类型（1=login 2=secureNote 3=card 4=identity；容忍缺失）。
    #[serde(default, rename = "type")]
    pub item_type: Option<Value>,
    /// 标题（缺失映射层兜底 [`crate::csv::mapping::FALLBACK_TITLE`]）。
    #[serde(default)]
    pub name: Option<String>,
    /// 备注。
    #[serde(default)]
    pub notes: Option<String>,
    /// 收藏。
    #[serde(default)]
    pub favorite: Option<bool>,
    /// 登录面（username / password / uris / totp / fido2Credentials）。
    #[serde(default)]
    pub login: Option<BwLogin>,
    /// 卡片面（type 3；降级序列化进备注，不静默丢弃）。
    #[serde(default)]
    pub card: Option<Value>,
    /// 身份面（type 4；降级序列化进备注，不静默丢弃）。
    #[serde(default)]
    pub identity: Option<Value>,
    /// 自定义字段。
    #[serde(default, deserialize_with = "null_to_default")]
    pub fields: Vec<BwField>,
    /// 密码历史（FR-2.9 语义不同构——丢弃 + 预检计数，1PUX 同裁决）。
    #[serde(
        default,
        deserialize_with = "null_to_default",
        rename = "passwordHistory"
    )]
    pub password_history: Vec<Value>,
    /// 所属文件夹 ID（→ 标签）。
    #[serde(default, rename = "folderId")]
    pub folder_id: Option<String>,
    /// 创建时间（RFC 3339 UTC）。
    #[serde(default, rename = "creationDate")]
    pub creation_date: Option<String>,
    /// 修订时间（RFC 3339 UTC → updated_at）。
    #[serde(default, rename = "revisionDate")]
    pub revision_date: Option<String>,
    /// 删除时间（非空 = 回收站条目 → Trashed 语义）。
    #[serde(default, rename = "deletedDate")]
    pub deleted_date: Option<String>,
}

/// 登录面（仅 type 1 条目携带；映射层只在此取 username/password 等，
/// passkey 映射结构上接触不到本结构的 password——D-6）。
#[derive(Debug, Deserialize)]
pub struct BwLogin {
    /// URL 列表。
    #[serde(default, deserialize_with = "null_to_default")]
    pub uris: Vec<BwUri>,
    /// 旧版单 URL（部分老导出只有该键；`uris` 为空时兜底）。
    #[serde(default)]
    pub uri: Option<String>,
    /// 用户名。
    #[serde(default)]
    pub username: Option<String>,
    /// 密码（明文导出形态）。
    #[serde(default)]
    pub password: Option<String>,
    /// TOTP（otpauth URI 或裸 secret）。
    #[serde(default)]
    pub totp: Option<String>,
    /// fido2Credentials 行（【单源】面——以键值对承载，映射层对未知键
    /// 记 warning 不拒绝；docs/17 §4.2）。
    #[serde(
        default,
        deserialize_with = "null_to_default",
        rename = "fido2Credentials"
    )]
    pub fido2_credentials: Vec<serde_json::Map<String, Value>>,
}

/// 一条 URL。
#[derive(Debug, Deserialize)]
pub struct BwUri {
    /// URL 本体。
    #[serde(default)]
    pub uri: Option<String>,
}

/// 一条自定义字段。
#[derive(Debug, Deserialize)]
pub struct BwField {
    /// 字段类型（0=Text 1=Hidden 2=Boolean 3=Linked）。
    #[serde(default, rename = "type")]
    pub field_type: Option<Value>,
    /// 字段名。
    #[serde(default)]
    pub name: Option<String>,
    /// 字段值。
    #[serde(default)]
    pub value: Option<String>,
}

/// 读取并解析一个 Bitwarden JSON 导出文件。
///
/// # Errors
///
/// 文件不可读 → [`CfError::Io`]；超文件上限 / 加密导出 / 超条目数 /
/// 单字段超限 → [`CfError::ImportFailed`]；非 JSON / 缺 `items` →
/// [`CfError::ImportUnknownFormat`]。
pub fn parse_file(path: &Path) -> Result<BwExport, CfError> {
    let bytes = read_bounded_file(path)?;
    parse(&bytes)
}

/// 解析内存中的 Bitwarden JSON 导出字节流（解析管线复用）。
///
/// # Errors
///
/// 同 [`parse_file`]（去掉文件读取）。
pub fn parse(bytes: &[u8]) -> Result<BwExport, CfError> {
    let root: Value = serde_json::from_slice(bytes).map_err(|_| CfError::ImportUnknownFormat)?;

    if root.get("encrypted") == Some(&Value::Bool(true)) {
        return Err(CfError::ImportFailed(
            "该导出为加密形态（password-protected JSON），内容不可读——\
             请在 Bitwarden 中解密导出明文 JSON 后重试"
                .into(),
        ));
    }

    let Some(items) = root.get("items").and_then(Value::as_array) else {
        return Err(CfError::ImportUnknownFormat);
    };
    if items.len() > MAX_ITEMS {
        return Err(CfError::ImportFailed(format!(
            "Bitwarden 条目数 {} 超过上限 {MAX_ITEMS}，拒绝导入",
            items.len()
        )));
    }
    for item in items {
        check_field_sizes(item, item_label(item))?;
    }

    serde_json::from_value(root)
        .map_err(|e| CfError::ImportFailed(format!("Bitwarden 导出结构非法（键类型不符）：{e}")))
}

/// 读取文件（上限内），供 [`parse_file`] 与测试使用。
///
/// 防御性读取：metadata 快筛 + `take(max + 1)` 硬限宽（1PUX 的
/// `read_bounded` 同款纪律）。
pub(crate) fn read_bounded_file(path: &Path) -> Result<Vec<u8>, CfError> {
    let file =
        File::open(path).map_err(|e| CfError::Io(format!("打开 Bitwarden 导出失败：{e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| CfError::Io(format!("读取 Bitwarden 导出元信息失败：{e}")))?;
    if meta.len() > MAX_FILE_BYTES as u64 {
        return Err(CfError::ImportFailed(format!(
            "Bitwarden 导出文件大小 {} 字节超过上限 50 MB，拒绝导入",
            meta.len()
        )));
    }
    let mut limited = file.take(MAX_FILE_BYTES as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| CfError::Io(format!("读取 Bitwarden 导出失败：{e}")))?;
    if buf.len() > MAX_FILE_BYTES {
        return Err(CfError::ImportFailed(
            "Bitwarden 导出文件实际大小超过上限 50 MB，拒绝导入".into(),
        ));
    }
    Ok(buf)
}

/// 报错用的条目标签（有 id 用 id，无 id 用「第 N 个条目」）。
fn item_label(item: &Value) -> String {
    match item.get("id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_owned(),
        _ => "(无 id 条目)".to_owned(),
    }
}

/// 递归检查一个条目内全部字符串值 ≤ [`MAX_FIELD_BYTES`]（UTF-8 字节），
/// 超限报错指明条目。
fn check_field_sizes(value: &Value, label: String) -> Result<(), CfError> {
    match value {
        Value::String(s) => {
            if s.len() > MAX_FIELD_BYTES {
                return Err(CfError::ImportFailed(format!(
                    "条目 {label} 的某字段为 {} 字节，超过单字段上限 64 KiB，拒绝导入",
                    s.len()
                )));
            }
            Ok(())
        }
        Value::Array(items) => {
            for v in items {
                check_field_sizes(v, label.clone())?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                check_field_sizes(v, label.clone())?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// 解析 RFC 3339 UTC 时间戳（`YYYY-MM-DDTHH:MM:SS[.fff…]Z`）为 Unix 秒。
///
/// 仅接受 `Z`/`z` 结尾（Bitwarden 导出恒为 UTC）；带非零偏移量或字段
/// 越界返回 `None`（映射层降级为条目时间兜底，不拒绝文件）。
#[must_use]
pub fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let digit = |r: std::ops::Range<usize>| -> Option<i64> {
        let mut n: i64 = 0;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + i64::from(c - b'0');
        }
        Some(n)
    };
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digit(0..4)?, digit(5..7)?, digit(8..10)?);
    let (hour, minute, second) = (digit(11..13)?, digit(14..16)?, digit(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // 尾部：允许 `Z` / `z`；小数秒（`.` + 数字）后仍须 `Z`/`z`。
    let mut tail = &s[19..];
    if let Some(rest) = tail.strip_prefix('.') {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 {
            return None;
        }
        tail = &rest[digits_end..];
    }
    match tail {
        "Z" | "z" => {}
        _ => return None,
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant `days_from_civil`（公历日期 → 自 1970-01-01 的天数）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3339 解析：Z 结尾 / 小数秒 / 拒绝偏移量与越界。
    #[test]
    fn rfc3339_utc解析与拒绝() {
        assert_eq!(
            parse_rfc3339_utc("2026-08-01T12:30:00Z"),
            Some(1_785_587_400)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-08-01T12:30:00.000Z"),
            Some(1_785_587_400)
        );
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        // 非 Z 偏移量不接受（映射层兜底，不炸导入）
        assert_eq!(parse_rfc3339_utc("2026-08-01T12:30:00+08:00"), None);
        assert_eq!(parse_rfc3339_utc("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("2026-08-01T24:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("2026-08-01 12:30:00Z"), None);
        assert_eq!(parse_rfc3339_utc("短"), None);
    }

    /// 解析边界：非 JSON / 缺 items / 加密导出。
    #[test]
    fn 解析边界拒绝() {
        assert!(matches!(
            parse(b"not json"),
            Err(CfError::ImportUnknownFormat)
        ));
        assert!(matches!(
            parse(br#"{"foo":1}"#),
            Err(CfError::ImportUnknownFormat)
        ));
        let encrypted = br#"{"encrypted":true,"items":[]}"#;
        assert!(matches!(parse(encrypted), Err(CfError::ImportFailed(_))));
    }
}
