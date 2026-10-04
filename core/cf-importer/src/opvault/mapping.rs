//! OPVault 解密 + 字段映射（TC-OPV-09 码表，docs/24 §3，T02）。
//!
//! ## 流程（每条目）
//!
//! 1. `item_keys_decrypt(master_enc, master_mac, k)` → item 加密/MAC 钥；
//! 2. `opdata_decrypt(overview_enc, overview_mac, o)` → overview 明文
//!    （title / url / URLs）；
//! 3. `opdata_decrypt(item_crypto, item_mac, d)` → details 明文
//!    （notesPlain / fields / sections）。
//!
//! 解密 / 明文 JSON 解析失败 → 2002 [`CfError::ImportFailed`]（docs/22 §4，
//! 密码错误与数据损坏不区分——`OpvaultCryptoError::AuthFailed` 文案透传）。
//!
//! ## 字段类型码（TC-OPV-09 r1.4 冻结，docs/24 §3.1）
//!
//! | 码 | 含义 | Coffer 映射 |
//! | --- | --- | --- |
//! | T | Text | Text |
//! | P | Password | Concealed |
//! | E | Email | Email |
//! | N | Number | **Text**（数字按字符串，TC-OPV-09「Number→Text」） |
//! | R | Radio | Text |
//! | TEL | Telephone | Phone |
//! | C | Checkbox | Bool |
//! | U | URL | Url |
//! | I / B(Button) / S | Rust 额外观测 | Text 降级 + 报告 |
//! | 未知 | — | Text 降级 + 报告（不静默） |
//!
//! section 字段用 `k`（kind）码（docs/24 §3.2）：`concealed` / `string` /
//! `date` / `monthYear` / `menu` / `cctype` / `gender` / `email` / `phone` /
//! `URL` / `address`；未知 → Text + 报告。多行备注承载于 details 顶层
//! `notesPlain` 键（**非 designation**，TC-OPV-09）。
//!
//! ## 类别与状态
//!
//! - `category` 三位十进制码 → `cf_domain::category::from_opvault_code`；
//!   `099` Tombstone → 跳过（TC-OPV-11）；未知 → SecureNote 降级 + 报告。
//! - band `trashed: true` = **归档**（docs/24 §1.4 原文，TC-OPV-12）→
//!   `ItemState::Archived`（与 1PUX 的 `trashed`=回收站语义不同）。

use cf_crypto::opvault::{
    item_keys_decrypt, opdata_decrypt, OpvaultCryptoError, OpvaultKeys,
};
use cf_domain::category::{from_opvault_code, ItemCategory};
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::CfError;
use serde_json::Value;

use super::model::RawItem;
use crate::csv::mapping::{parse_otpauth, OtpauthData, FALLBACK_TITLE};

/// opvault Tombstone（已删除标记）分类码：跳过（docs/03 §6.4.1，TC-OPV-11）。
pub const CATEGORY_TOMBSTONE: u16 = 99;

/// 单条目映射产出的预检信号（报告素材）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpvaultMapSignals {
    /// 缺失标题（导入时兜底为 [`FALLBACK_TITLE`]）。
    pub no_title: bool,
    /// 分类码未识别（已降级 SecureNote，计入导入成功）。
    pub unknown_category: bool,
    /// 未识别的字段 type/k 码（值已按 Text 降级保留，不静默）。
    pub unknown_field_types: Vec<String>,
    /// 未识别的分类码清单（(条目 uuid, 原始分类码)）。
    pub unknown_categories: Vec<(String, String)>,
    /// otpauth URI 解析失败（原始值已并入 notes，不丢整条）。
    pub bad_totp: bool,
    /// 归档（trashed）条目计数。
    pub trashed_count: u32,
}

/// 单条目映射结果。
#[derive(Debug, Clone, PartialEq)]
pub enum MapOutcome {
    /// 正常产出导入模型（含未知类别降级——计入导入成功）。
    Imported(Box<OpvaultItemModel>),
    /// 跳过（Tombstone 等），理由进入预检未导入清单。
    Skipped(String),
}

/// 映射后的导入中间表示（编排层逐条目 `with_tx` 写入）。
#[derive(Debug, Clone, PartialEq)]
pub struct OpvaultItemModel {
    /// 原始条目 uuid（溯源用；落库固定新建 UUIDv7）。
    pub source_uuid: String,
    /// Coffer 类别（未知分类码降级为 SecureNote）。
    pub category: ItemCategory,
    /// 是否未知类别降级导入。
    pub degraded: bool,
    /// 标题（缺失兜底 [`FALLBACK_TITLE`]）。
    pub title: String,
    /// 条目状态（band `trashed:true` → Archived，OPVault 语义）。
    pub state: ItemState,
    /// 归档时间戳（trashed 时取 band `updated`，其余 None）。
    pub trashed_at: Option<i64>,
    /// 是否收藏（band `fave` > 0）。
    pub is_favorite: bool,
    /// 收藏排序索引（负值已钳为 0）。
    pub fav_index: i64,
    /// 创建时间（band `created`）。
    pub created_at: i64,
    /// 更新时间（band `updated`）。
    pub updated_at: i64,
    /// 用户名（designation=username 的第一个字段）。
    pub username: Option<String>,
    /// 密码（designation=password 的第一个字段）。
    pub password: Option<String>,
    /// TOTP（otpauth URI 解析成功才有）。
    pub totp: Option<OtpauthData>,
    /// URL 列表（overview `URLs[].u` 优先，回退 `url`；首条 is_primary）。
    pub urls: Vec<(Option<String>, String)>,
    /// 备注（details 顶层 `notesPlain`）。
    pub notes: String,
    /// 普通字段（非 username/password/TOTP 的 fields + sections 字段）。
    pub fields: Vec<OpvaultFieldModel>,
}

/// 普通字段中间表示。
#[derive(Debug, Clone, PartialEq)]
pub struct OpvaultFieldModel {
    /// 字段名（sections 字段落为 `分区标题 / 字段名`）。
    pub name: String,
    /// 数据类型（未知码按 Text 降级存值）。
    pub field_type: FieldType,
    /// 语义标识（designation 原样保留）。
    pub designation: Option<Designation>,
    /// 字段值。
    pub value: Option<String>,
}

/// 字段 type 码 → cf [`FieldType`]（TC-OPV-09 码表；未知 → None 调
/// 用方按 Text 降级 + 报告）。
#[must_use]
pub fn field_type_from_opvault_code(code: &str) -> Option<FieldType> {
    Some(match code {
        "T" => FieldType::Text,
        "P" => FieldType::Concealed,
        "E" => FieldType::Email,
        // Number→Text：数字字段按字符串存（TC-OPV-09「Number→Text」）
        "N" => FieldType::Text,
        "R" => FieldType::Text,
        "TEL" => FieldType::Phone,
        "C" => FieldType::Bool,
        "U" => FieldType::Url,
        _ => return None,
    })
}

/// section 字段 `k`（kind）码 → cf [`FieldType`]（docs/24 §3.2；未知 →
/// None 调用方按 Text 降级 + 报告）。
#[must_use]
pub fn section_kind_to_field_type(code: &str) -> Option<FieldType> {
    Some(match code {
        "concealed" => FieldType::Concealed,
        "string" => FieldType::Text,
        "date" => FieldType::Date,
        "monthYear" => FieldType::MonthYear,
        "menu" => FieldType::Text,
        "cctype" => FieldType::Text,
        "gender" => FieldType::Text,
        "email" => FieldType::Email,
        "phone" => FieldType::Phone,
        "URL" => FieldType::Url,
        // address 的 v 为嵌套对象（city/zip/…），Text 序列化保留
        "address" => FieldType::Text,
        _ => return None,
    })
}

/// 解密错误 → 2002 [`CfError::ImportFailed`]（密码错误与数据损坏不可区分）。
fn map_crypto_err(e: OpvaultCryptoError) -> CfError {
    CfError::ImportFailed(format!("opvault 解密失败：{e}"))
}

/// 标量 JSON 值 → 文本（对象 / 数组走 JSON 序列化保数据）。
fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<不可序列化值>".into()),
    }
}

/// 类别三态裁决。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CategoryDecision {
    /// 命中 docs/03 §6.4.1 表。
    Mapped(ItemCategory),
    /// 未知（含非数字）→ 降级 SecureNote。
    Degraded,
    /// 099 Tombstone → 跳过。
    Tombstone,
}

/// 分类码 → 三态裁决。
fn decide_category(code: &str) -> CategoryDecision {
    match code.parse::<u16>() {
        Ok(CATEGORY_TOMBSTONE) => CategoryDecision::Tombstone,
        Ok(c) => match from_opvault_code(c) {
            Some(cat) => CategoryDecision::Mapped(cat),
            None => CategoryDecision::Degraded,
        },
        Err(_) => CategoryDecision::Degraded,
    }
}

/// 解密 details JSON 并抽取 notesPlain（顶层键，TC-OPV-09）。
fn notes_from_details(details: &Value) -> String {
    details
        .get("notesPlain")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// 从 overview 明文抽取 URL 列表（`URLs[].u` 优先，回退 `url`；空过滤）。
fn urls_from_overview(overview: &Value) -> Vec<(Option<String>, String)> {
    let mut urls: Vec<(Option<String>, String)> = Vec::new();
    if let Some(arr) = overview.get("URLs").and_then(Value::as_array) {
        for u in arr {
            let url = u.get("u").and_then(Value::as_str).filter(|s| !s.is_empty());
            if let Some(url) = url {
                urls.push((None, url.to_owned()));
            }
        }
    }
    if urls.is_empty() {
        if let Some(url) = overview
            .get("url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            urls.push((None, url.to_owned()));
        }
    }
    urls
}

/// 把一条 OPVault 条目解密并映射为 [`MapOutcome`]（纯函数，不触库）。
///
/// # Errors
///
/// `k`/`o`/`d` 解密或明文 JSON 解析失败 → 2002
/// [`CfError::ImportFailed`]（TC-OPV-04：不落明文）。Tombstone → 不报错，
/// 返回 [`MapOutcome::Skipped`]。
pub fn map_item(
    item: &RawItem,
    keys: &OpvaultKeys,
    signals: &mut OpvaultMapSignals,
) -> Result<MapOutcome, CfError> {
    // ---- 解密链（任一失败 → 2002，整库 all-or-nothing） ----
    let item_keys = item_keys_decrypt(&keys.master_enc, &keys.master_mac, &item.k)
        .map_err(map_crypto_err)?;
    let overview_plain =
        opdata_decrypt(&keys.overview_enc, &keys.overview_mac, &item.o).map_err(map_crypto_err)?;
    let details_plain =
        opdata_decrypt(&item_keys.crypto_key, &item_keys.mac_key, &item.d).map_err(map_crypto_err)?;

    let overview: Value = serde_json::from_slice(&overview_plain).map_err(|e| {
        CfError::ImportFailed(format!("条目 {} overview 明文 JSON 非法：{e}", item.uuid))
    })?;
    let details: Value = serde_json::from_slice(&details_plain).map_err(|e| {
        CfError::ImportFailed(format!("条目 {} details 明文 JSON 非法：{e}", item.uuid))
    })?;

    map_decrypted(item, &overview, &details, signals)
}

/// 纯映射（已解密的 overview/details → 模型；不触密码学，便于单元测试）。
///
/// # Errors
///
/// 时间兜底走 [`crate::unix_now`]（系统时钟早于 epoch 时返回错误）；
/// 其余分支不产生硬错误。
pub(crate) fn map_decrypted(
    item: &RawItem,
    overview: &Value,
    details: &Value,
    signals: &mut OpvaultMapSignals,
) -> Result<MapOutcome, CfError> {
    // ---- 类别三态裁决 ----
    let (category, degraded) = match decide_category(&item.category) {
        CategoryDecision::Tombstone => {
            return Ok(MapOutcome::Skipped(format!(
                "分类码 {} 为 Tombstone（099，已删除标记），按官方语义跳过",
                item.category
            )));
        }
        CategoryDecision::Mapped(cat) => (cat, false),
        CategoryDecision::Degraded => {
            signals.unknown_category = true;
            signals
                .unknown_categories
                .push((item.uuid.clone(), item.category.clone()));
            (ItemCategory::SecureNote, true)
        }
    };

    // ---- 标题 / 状态 / 时间 ----
    let title = overview
        .get("title")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| FALLBACK_TITLE.to_owned());
    signals.no_title |= title == FALLBACK_TITLE;

    let trashed = item.trashed.unwrap_or(false);
    if trashed {
        signals.trashed_count += 1;
    }
    let state = if trashed {
        ItemState::Archived
    } else {
        ItemState::Active
    };
    let trashed_at = if trashed { Some(item.updated) } else { None };
    let created_at = if item.created > 0 {
        item.created
    } else {
        crate::unix_now()?
    };
    let updated_at = if item.updated > 0 {
        item.updated
    } else {
        crate::unix_now()?
    };
    let fav_index = item.fave.unwrap_or(0).max(0);
    let is_favorite = fav_index > 0;

    // ---- 字段抽取 ----
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut totp: Option<OtpauthData> = None;
    let mut notes_parts: Vec<String> = Vec::new();
    let mut fields: Vec<OpvaultFieldModel> = Vec::new();

    let notes = notes_from_details(details);
    if !notes.is_empty() {
        notes_parts.push(notes);
    }

    if let Some(arr) = details.get("fields").and_then(Value::as_array) {
        for f in arr {
            map_field(
                f,
                degraded,
                signals,
                &mut username,
                &mut password,
                &mut totp,
                &mut notes_parts,
                &mut fields,
            )?;
        }
    }
    if let Some(sections) = details.get("sections").and_then(Value::as_array) {
        for section in sections {
            let section_title = section
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if let Some(sec_fields) = section.get("fields").and_then(Value::as_array) {
                for f in sec_fields {
                    map_section_field(
                        &section_title,
                        f,
                        degraded,
                        signals,
                        &mut totp,
                        &mut notes_parts,
                        &mut fields,
                    )?;
                }
            }
        }
    }

    let urls = urls_from_overview(overview);
    let notes = notes_parts.join("\n");

    Ok(MapOutcome::Imported(Box::new(OpvaultItemModel {
        source_uuid: item.uuid.clone(),
        category,
        degraded,
        title,
        state,
        trashed_at,
        is_favorite,
        fav_index,
        created_at,
        updated_at,
        username,
        password,
        totp,
        urls,
        notes,
        fields,
    })))
}

/// 映射一个 details 顶层 field（type 码 + designation）。
#[allow(clippy::too_many_arguments)]
fn map_field(
    f: &Value,
    degraded: bool,
    signals: &mut OpvaultMapSignals,
    username: &mut Option<String>,
    password: &mut Option<String>,
    totp: &mut Option<OtpauthData>,
    notes_parts: &mut Vec<String>,
    fields: &mut Vec<OpvaultFieldModel>,
) -> Result<(), CfError> {
    let code = f.get("type").and_then(Value::as_str).unwrap_or_default();
    let value = f.get("value");
    let text = value.map(scalar_string).filter(|s| !s.is_empty());

    let designation = f
        .get("designation")
        .and_then(Value::as_str)
        .map(Designation::from_1p_str);

    // TOTP：designation 显式声明（业界实践 totp/otp，docs/22 §2.2.3）
    if matches!(designation, Some(Designation::Totp)) {
        let uri = text.clone().unwrap_or_default();
        return handle_totp(&uri, totp, signals, notes_parts);
    }

    match designation {
        // username / password 走 designation，≤各 1（降级条目无 designation
        // 结构，落入 `_` 分支按字段并入 notes）；多余保留为普通字段
        Some(Designation::Username) if username.is_none() && !degraded => *username = text,
        Some(Designation::Password) if password.is_none() && !degraded => *password = text,
        Some(Designation::NotesPlain) => {
            if let Some(t) = text {
                notes_parts.push(t);
            }
        }
        _ => {
            let field_type = match field_type_from_opvault_code(code) {
                Some(ft) => ft,
                None => {
                    if !code.is_empty() {
                        signals.unknown_field_types.push(code.to_owned());
                    }
                    FieldType::Text
                }
            };
            if degraded {
                if let Some(t) = text {
                    let name = f.get("name").and_then(Value::as_str).unwrap_or("字段");
                    notes_parts.push(format!("[field {name} ({code})] {t}"));
                }
            } else {
                fields.push(OpvaultFieldModel {
                    name: f.get("name").and_then(Value::as_str).unwrap_or("字段").to_owned(),
                    field_type,
                    designation,
                    value: text,
                });
            }
        }
    }
    Ok(())
}

/// 映射一个 section 字段（`k` kind 码，docs/24 §3.2）。
#[allow(clippy::too_many_arguments)]
fn map_section_field(
    section_title: &str,
    f: &Value,
    degraded: bool,
    signals: &mut OpvaultMapSignals,
    totp: &mut Option<OtpauthData>,
    notes_parts: &mut Vec<String>,
    fields: &mut Vec<OpvaultFieldModel>,
) -> Result<(), CfError> {
    let code = f.get("k").and_then(Value::as_str).unwrap_or_default();
    let value = f.get("v");
    let text = value.map(scalar_string).filter(|s| !s.is_empty());

    let designation = f
        .get("designation")
        .and_then(Value::as_str)
        .map(Designation::from_1p_str);

    // TOTP：designation 显式声明
    if matches!(designation, Some(Designation::Totp)) {
        let uri = text.clone().unwrap_or_default();
        return handle_totp(&uri, totp, signals, notes_parts);
    }

    let field_type = match section_kind_to_field_type(code) {
        Some(ft) => ft,
        None => {
            if !code.is_empty() {
                signals.unknown_field_types.push(code.to_owned());
            }
            FieldType::Text
        }
    };
    let name = match (section_title, f.get("name").and_then(Value::as_str)) {
        (s, Some(n)) if !s.is_empty() && !n.is_empty() => format!("{s} / {n}"),
        (s, None) if !s.is_empty() => s.to_owned(),
        (_, Some(n)) if !n.is_empty() => n.to_owned(),
        _ => "字段".to_owned(),
    };

    if degraded {
        if let Some(t) = text {
            notes_parts.push(format!("[section {name} ({code})] {t}"));
        }
    } else {
        fields.push(OpvaultFieldModel {
            name,
            field_type,
            designation,
            value: text,
        });
    }
    Ok(())
}

/// TOTP 处理：坏 otpauth 原值并入 notes，不丢整条（与 CSV/1PUX 同纪律）。
fn handle_totp(
    uri: &str,
    totp: &mut Option<OtpauthData>,
    signals: &mut OpvaultMapSignals,
    notes_parts: &mut Vec<String>,
) -> Result<(), CfError> {
    match parse_otpauth(uri) {
        Ok(data) => {
            if totp.is_none() {
                *totp = Some(data);
            }
        }
        Err(reason) => {
            signals.bad_totp = true;
            notes_parts.push(format!("[TOTP 无法解析（{reason}），已保留原始值] {uri}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn raw_item(category: &str, trashed: Option<bool>) -> RawItem {
        RawItem {
            category: category.into(),
            created: 1_700_000_000,
            updated: 1_700_001_000,
            tx: 0,
            folder: None,
            trashed,
            fave: None,
            uuid: "ITEM0000000000000000000000000001".into(),
            k: String::new(),
            o: String::new(),
            d: String::new(),
            hmac: None,
        }
    }

    fn map(o: serde_json::Value, d: serde_json::Value) -> (MapOutcome, OpvaultMapSignals) {
        let mut signals = OpvaultMapSignals::default();
        let item = raw_item("001", None);
        let outcome = map_decrypted(&item, &o, &d, &mut signals).expect("映射不应硬失败");
        (outcome, signals)
    }

    /// 取出 Imported 模型（否则 panic）。
    fn imported(outcome: MapOutcome) -> OpvaultItemModel {
        match outcome {
            MapOutcome::Imported(m) => *m,
            other => panic!("应导入而非 {other:?}"),
        }
    }

    // ---- TC-OPV-09 字段类型码矩阵 ----

    #[test]
    fn 字段类型码矩阵() {
        // 已知码按 TC-OPV-09 映射
        assert_eq!(field_type_from_opvault_code("T"), Some(FieldType::Text));
        assert_eq!(field_type_from_opvault_code("P"), Some(FieldType::Concealed));
        assert_eq!(field_type_from_opvault_code("E"), Some(FieldType::Email));
        // Number→Text（docs/24 §3.1：数字按字符串，非 FieldType::Number）
        assert_eq!(field_type_from_opvault_code("N"), Some(FieldType::Text));
        assert_eq!(field_type_from_opvault_code("R"), Some(FieldType::Text));
        assert_eq!(field_type_from_opvault_code("TEL"), Some(FieldType::Phone));
        assert_eq!(field_type_from_opvault_code("C"), Some(FieldType::Bool));
        assert_eq!(field_type_from_opvault_code("U"), Some(FieldType::Url));
        // Rust 额外观测 I/B(Button)/S 与未知码 → None（调用方 Text 降级 + 报告）
        assert_eq!(field_type_from_opvault_code("I"), None);
        assert_eq!(field_type_from_opvault_code("B"), None);
        assert_eq!(field_type_from_opvault_code("S"), None);
        assert_eq!(field_type_from_opvault_code("X"), None);
    }

    #[test]
    fn section_kind码矩阵() {
        assert_eq!(section_kind_to_field_type("concealed"), Some(FieldType::Concealed));
        assert_eq!(section_kind_to_field_type("string"), Some(FieldType::Text));
        assert_eq!(section_kind_to_field_type("date"), Some(FieldType::Date));
        assert_eq!(section_kind_to_field_type("monthYear"), Some(FieldType::MonthYear));
        assert_eq!(section_kind_to_field_type("menu"), Some(FieldType::Text));
        assert_eq!(section_kind_to_field_type("cctype"), Some(FieldType::Text));
        assert_eq!(section_kind_to_field_type("gender"), Some(FieldType::Text));
        assert_eq!(section_kind_to_field_type("email"), Some(FieldType::Email));
        assert_eq!(section_kind_to_field_type("phone"), Some(FieldType::Phone));
        assert_eq!(section_kind_to_field_type("URL"), Some(FieldType::Url));
        assert_eq!(section_kind_to_field_type("address"), Some(FieldType::Text));
        assert_eq!(section_kind_to_field_type("mystery"), None);
    }

    #[test]
    fn 登录字段designation与多类型() {
        let (o, s) = map(
            json!({"title": "示例", "url": "https://example.com"}),
            json!({
                "notesPlain": "备注内容",
                "fields": [
                    {"type": "T", "name": "username", "value": "alice", "designation": "username"},
                    {"type": "P", "name": "password", "value": "s3cret", "designation": "password"},
                    {"type": "E", "name": "邮箱", "value": "a@b.c"},
                    {"type": "N", "name": "次数", "value": 42},
                    {"type": "TEL", "name": "电话", "value": "13800000000"},
                    {"type": "C", "name": "记住我", "value": true},
                    {"type": "U", "name": "主页", "value": "https://home.example"}
                ]
            }),
        );
        let m = imported(o);
        assert_eq!(m.title, "示例");
        assert_eq!(m.username.as_deref(), Some("alice"));
        assert_eq!(m.password.as_deref(), Some("s3cret"));
        assert_eq!(m.notes, "备注内容");
        assert_eq!(m.urls, vec![(None, "https://example.com".into())]);
        assert!(s.unknown_field_types.is_empty(), "已知码不报告");
        let get = |name: &str| {
            m.fields
                .iter()
                .find(|f| f.name == name)
                .expect("字段应存在")
                .clone()
        };
        assert_eq!(get("邮箱").field_type, FieldType::Email);
        assert_eq!(get("邮箱").value.as_deref(), Some("a@b.c"));
        assert_eq!(get("次数").field_type, FieldType::Text, "Number→Text");
        assert_eq!(get("次数").value.as_deref(), Some("42"), "数字按字符串");
        assert_eq!(get("电话").field_type, FieldType::Phone);
        assert_eq!(get("记住我").field_type, FieldType::Bool);
        assert_eq!(get("记住我").value.as_deref(), Some("true"));
        assert_eq!(get("主页").field_type, FieldType::Url);
    }

    #[test]
    fn 未知类型码降级text并报告() {
        let (o, s) = map(
            json!({"title": "未知码"}),
            json!({"fields": [
                {"type": "I", "name": "图标", "value": "x"},
                {"type": "S", "name": "符号", "value": "y"},
                {"type": "ZZ", "name": "怪码", "value": "z"}
            ]}),
        );
        let m = imported(o);
        assert!(m.fields.iter().all(|f| f.field_type == FieldType::Text));
        let mut unknown = s.unknown_field_types.clone();
        unknown.sort();
        assert_eq!(unknown, vec!["I".to_owned(), "S".to_owned(), "ZZ".to_owned()]);
        // 值不丢
        assert!(m.fields.iter().any(|f| f.value.as_deref() == Some("z")));
    }

    #[test]
    fn section字段k码与分区名() {
        let (o, s) = map(
            json!({"title": "分区示例"}),
            json!({"sections": [{"title": "卡片", "fields": [
                {"k": "concealed", "name": "CVV", "v": "123"},
                {"k": "monthYear", "name": "有效期", "v": 203012},
                {"k": "address", "name": "地址", "v": {"city": "北京", "zip": "100000"}},
                {"k": "mystery", "name": "怪字段", "v": "?"}
            ]}]}),
        );
        let m = imported(o);
        assert_eq!(s.unknown_field_types, vec!["mystery".to_owned()]);
        let get = |name: &str| {
            m.fields
                .iter()
                .find(|f| f.name.contains(name))
                .expect("字段应存在")
                .clone()
        };
        assert!(get("CVV").name.contains("卡片"), "分区标题保留在字段名");
        assert_eq!(get("CVV").field_type, FieldType::Concealed);
        assert_eq!(get("有效期").field_type, FieldType::MonthYear);
        assert_eq!(get("地址").field_type, FieldType::Text);
        assert!(get("地址").value.as_deref().unwrap_or_default().contains("北京"), "嵌套对象序列化保留");
        assert_eq!(get("怪字段").field_type, FieldType::Text, "未知 k 降级 Text");
    }

    #[test]
    fn trashed条目映射归档态() {
        // TC-OPV-12：band `trashed:true` = 归档（OPVault 语义，非回收站）
        let mut signals = OpvaultMapSignals::default();
        let item = raw_item("001", Some(true));
        let o = json!({"title": "归档条目"});
        let d = json!({});
        let out = map_decrypted(&item, &o, &d, &mut signals).expect("映射不应失败");
        let m = imported(out);
        assert_eq!(m.state, ItemState::Archived);
        assert_eq!(m.trashed_at, Some(1_700_001_000), "取 band updated");
        assert_eq!(signals.trashed_count, 1);
    }

    #[test]
    fn tombstone099跳过() {
        let mut signals = OpvaultMapSignals::default();
        let item = raw_item("099", None);
        let out = map_decrypted(&item, &json!({}), &json!({}), &mut signals).expect("不应失败");
        assert!(matches!(out, MapOutcome::Skipped(_)));
        assert_eq!(signals.trashed_count, 0);
    }

    #[test]
    fn 未知类别降级_secure_note数据并入notes() {
        let mut item = raw_item("112", None);
        item.category = "112".into();
        let mut signals = OpvaultMapSignals::default();
        let out = map_decrypted(&item, &json!({"title": "怪类别"}), &json!({
            "notesPlain": "主体",
            "fields": [
                {"type": "T", "name": "username", "value": "u", "designation": "username"},
                {"type": "P", "name": "password", "value": "p", "designation": "password"}
            ]
        }), &mut signals).expect("不应失败");
        let m = imported(out);
        assert!(m.degraded);
        assert!(signals.unknown_category);
        assert_eq!(m.category, ItemCategory::SecureNote);
        assert!(m.username.is_none() && m.password.is_none(), "降级无 designation 结构");
        assert!(m.notes.contains("主体"));
        assert!(m.notes.contains("[field username (T)] u"));
        assert!(m.notes.contains("[field password (P)] p"));
        assert_eq!(signals.unknown_categories, vec![("ITEM0000000000000000000000000001".into(), "112".into())]);
    }

    #[test]
    fn totp设计ations与坏uri() {
        // 合法 otpauth → totp
        let (o, _) = map(
            json!({"title": "带TOTP"}),
            json!({"fields": [
                {"type": "T", "name": "动态码", "value": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "designation": "totp"}
            ]}),
        );
        let m = imported(o);
        assert!(m.totp.is_some(), "totp designation 应解析出 TOTP");

        // 坏 otpauth → 原值并入 notes，不丢整条
        let (o, s) = map(
            json!({"title": "坏TOTP"}),
            json!({"fields": [
                {"type": "T", "name": "动态码", "value": "not-a-uri", "designation": "otp"}
            ]}),
        );
        let m = imported(o);
        assert!(m.totp.is_none());
        assert!(s.bad_totp);
        assert!(m.notes.contains("not-a-uri"));
    }

    #[test]
    fn 缺失标题兜底() {
        let (o, s) = map(json!({"title": ""}), json!({}));
        let m = imported(o);
        assert_eq!(m.title, FALLBACK_TITLE);
        assert!(s.no_title);
    }
}
