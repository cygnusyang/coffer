//! 1PUX → Coffer 字段映射（FR-7.1 / FR-7.4~7.7，`docs/09` v0.3.0 冻结裁决）。
//!
//! ## categoryUuid 映射（docs/03 §6.4.1 opvault 权威表为基线）
//!
//! 1Password 官方 1PUX 文档未给出 `categoryUuid` 数值表（docs/03 §6.4.2
//! 「待真实样本校准」）。v0.3.0 冻结裁决：
//!
//! - 以 docs/03 §6.4.1 opvault 三位十进制表为基线（`001`~`005`、
//!   `100`~`111`），复用 `cf_domain::category::from_opvault_code`；
//! - **`004` → Identity**（opvault 与社区 1PUX 实践双源一致，高置信）；
//! - **`112` 与其他未知 categoryUuid → 降级导入 SecureNote**：
//!   notesPlain + loginFields + sections 全部序列化并入 notes 保数据，
//!   预检警告逐条列出（E-4），**计入导入成功**（docs/09 E-4/D-6）；
//! - `099`（opvault Tombstone，已删除标记）→ 跳过，列入预检未导入清单
//!   （FR-7.6 不静默丢弃）；
//! - 非数字 `categoryUuid` → 同未知降级（原始值保留在预检报告中）。
//!
//! ## 其他冻结裁决
//!
//! - username / password 走 designation（≤各 1，多余字段保留为普通字段）；
//! - 多 URL → `urls` 表多行（首条 is_primary）；
//! - `state`：`active`/`archived`/`trashed`；文档未列值容忍为 active 并警告；
//! - `passwordHistory` 丢弃 + 预检计数（FR-2.9 历史表语义不同构，不硬塞）；
//! - 分区字段值是**类型化对象**（官方）或**标量**（合成样本），按顶层
//!   key 分派；未知 key 计数不报错，值序列化保留。

use cf_domain::category::{from_opvault_code, ItemCategory};
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::CfError;
use serde_json::Value;

use super::model::{PuxFileRef, PuxItem, PuxSectionField};
use crate::csv::mapping::{parse_otpauth, OtpauthData, FALLBACK_TITLE};

/// opvault Tombstone（已删除标记）的分类码：跳过（docs/03 §6.4.1）。
pub const CATEGORY_TOMBSTONE: u16 = 99;

/// 单条目映射产出的预检信号（FR-7.4 报告素材）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemMapSignals {
    /// 缺失标题（导入时兜底为 [`FALLBACK_TITLE`]）。
    pub no_title: bool,
    /// categoryUuid 未识别（已降级 SecureNote）。
    pub unknown_category: bool,
    /// state 值文档未列（容忍为 active）。
    pub unknown_state: bool,
    /// 未知类型化 value 顶层 key（值已序列化保留）。
    pub unmapped_value_types: Vec<String>,
    /// 丢弃的密码历史条目数（FR-2.9 语义不同构）。
    pub password_history_dropped: u32,
    /// otpauth URI 解析失败（原始值已并入 notes，不丢整条）。
    pub bad_totp: bool,
}

/// 单条目映射结果。
#[derive(Debug, Clone, PartialEq)]
pub enum MapOutcome {
    /// 正常产出导入模型（含未知类别降级——计入导入成功）。
    /// Box：模型体积远大于跳过理由字符串，控制枚举尺寸差。
    Imported(Box<PuxItemModel>),
    /// 跳过（Tombstone 等），理由进入预检未导入清单。
    Skipped(String),
}

/// 映射后的导入中间表示（编排层在一个 `with_tx` 内写入一条）。
#[derive(Debug, Clone, PartialEq)]
pub struct PuxItemModel {
    /// 1PUX 原始条目 uuid（溯源用；落库固定新建 UUIDv7）。
    pub source_uuid: String,
    /// Coffer 类别（未知 categoryUuid 降级为 SecureNote）。
    pub category: ItemCategory,
    /// 是否未知类别降级导入。
    pub degraded: bool,
    /// 标题（缺失兜底 [`FALLBACK_TITLE`]）。
    pub title: String,
    /// 是否收藏（favIndex > 0）。
    pub is_favorite: bool,
    /// 收藏排序索引（负值已钳为 0）。
    pub fav_index: i64,
    /// 条目状态（trashed → 回收站语义）。
    pub state: ItemState,
    /// 移入回收站的时间戳（state=trashed 时为 updatedAt，其余 None）。
    pub trashed_at: Option<i64>,
    /// 创建时间（Unix 秒；≤ 0 时由编排层兜底为当前时间）。
    pub created_at: i64,
    /// 更新时间（Unix 秒）。
    pub updated_at: i64,
    /// 用户名（designation=username 的第一个 loginField）。
    pub username: Option<String>,
    /// 密码（designation=password 的第一个 loginField）。
    pub password: Option<String>,
    /// TOTP（otpauth URI 解析成功才有）。
    pub totp: Option<OtpauthData>,
    /// URL 列表（多 URL → 多行；首条 is_primary 由编排层处理）。
    pub urls: Vec<(Option<String>, String)>,
    /// 备注（notesPlain；降级条目追加 loginFields + sections 序列化）。
    pub notes: String,
    /// 普通字段（sections + 非 username/password 的 loginFields）。
    pub fields: Vec<PuxFieldModel>,
    /// 归一化附件引用（无附件为 None）。
    pub file: Option<PuxFileRef>,
    /// 解析层已定位的 ZIP 条目名（附件解析失败为 None → 未导入清单）。
    pub zip_entry: Option<String>,
}

/// 普通字段中间表示。
#[derive(Debug, Clone, PartialEq)]
pub struct PuxFieldModel {
    /// 字段名（分区字段落为 `分区标题 / 字段名`，保留分区语境）。
    pub name: String,
    /// 数据类型（未知码按 Text 降级存值，cf-domain 导入语义）。
    pub field_type: FieldType,
    /// 语义标识（loginFields 的 designation 原样保留）。
    pub designation: Option<Designation>,
    /// 字段值。
    pub value: Option<String>,
}

/// categoryUuid 三态裁决。
#[derive(Debug, Clone, PartialEq, Eq)]
enum CategoryDecision {
    /// 命中 docs/03 §6.4.1 表。
    Mapped(ItemCategory),
    /// 未知（含非数字）→ 降级 SecureNote。
    Degraded,
    /// 099 Tombstone → 跳过。
    Tombstone,
}

/// categoryUuid → 三态裁决（映射表见模块文档）。
fn decide_category(category_uuid: &str) -> CategoryDecision {
    match category_uuid.parse::<u16>() {
        Ok(CATEGORY_TOMBSTONE) => CategoryDecision::Tombstone,
        Ok(code) => match from_opvault_code(code) {
            Some(cat) => CategoryDecision::Mapped(cat),
            None => CategoryDecision::Degraded,
        },
        Err(_) => CategoryDecision::Degraded,
    }
}

/// 1P 字段类型码 → cf [`FieldType`]（双键兼容后的取值；未知码 → None，
/// 调用方按 Text 降级）。
#[must_use]
pub fn field_type_from_1p_code(code: &str) -> Option<FieldType> {
    Some(match code {
        "T" | "STRING" => FieldType::Text,
        "P" | "CONCEALED" => FieldType::Concealed,
        "U" | "URL" => FieldType::Url,
        "E" | "EMAIL" => FieldType::Email,
        "N" => FieldType::Number,
        "D" | "DATE" => FieldType::Date,
        "M" | "MONTHYEAR" => FieldType::MonthYear,
        // A=地址、C=卡号：cf-domain 无对应类型，Text 降级保值
        "A" | "C" => FieldType::Text,
        "B" => FieldType::Bool,
        _ => return None,
    })
}

/// Unix 秒 → `YYYY-MM-DD`（ proleptic Gregorian，Howard Hinnant
/// civil_from_days 算法；无 chrono 依赖，纯整数运算）。
#[must_use]
pub fn unix_sec_to_iso_date(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYYMM`（monthYear）→ `YYYY-MM`；月份越界返回原值文本。
#[must_use]
pub fn month_year_to_iso(v: i64) -> String {
    let (year, month) = (v / 100, v % 100);
    if (1..=12).contains(&month) {
        format!("{year:04}-{month:02}")
    } else {
        v.to_string()
    }
}

/// 类型化 value 分派结果。
#[derive(Debug, Default, PartialEq)]
struct ExtractedValue {
    /// 文本形态的值（None = 空值）。
    text: Option<String>,
    /// 分派出的类型（None = 沿用字段类型码提示）。
    field_type: Option<FieldType>,
    /// TOTP otpauth URI（value 为 {totp: ...} 时提取）。
    totp_uri: Option<String>,
    /// 未知顶层 key（值仍保留，仅计数）。
    unmapped_keys: Vec<String>,
}

/// 按 value 顶层形态分派（FR-7.4「无法映射的字段清单」素材产出点）。
///
/// 官方 1PUX 分区字段值为单键类型化对象（`{concealed}` / `{email}` /
/// `{address}` / `{totp}` / `{date}` / `{monthYear}` / `{creditCardNumber}` /
/// `{string}` / `{url}` / `{phone}` / `{menu}` / `{gender}` 等）；仓内合成
/// 样本为标量。未知 key：值序列化保留 + 计数，不报错不丢弃。
fn extract_value(value: &Value, type_hint: FieldType) -> ExtractedValue {
    let scalar = |s: String| ExtractedValue {
        text: Some(s),
        field_type: None,
        totp_uri: None,
        unmapped_keys: Vec::new(),
    };
    match value {
        Value::Null => ExtractedValue::default(),
        Value::String(s) => scalar(s.clone()),
        Value::Number(n) => scalar(n.to_string()),
        Value::Bool(b) => scalar(b.to_string()),
        Value::Object(obj) if obj.len() == 1 => {
            if let Some((key, inner)) = obj.iter().next() {
                match key.as_str() {
                "concealed" => {
                    let mut e = scalar(json_scalar_string(inner));
                    e.field_type = Some(FieldType::Concealed);
                    e
                }
                "email" => {
                    let addr = inner
                        .get("email_address")
                        .map(json_scalar_string)
                        .unwrap_or_default();
                    let mut e = scalar(addr);
                    e.field_type = Some(FieldType::Email);
                    e
                }
                "address" => {
                    // 官方形态 {street,city,state,zip,country}：非空段拼接
                    let parts: Vec<String> = ["street", "city", "state", "zip", "country"]
                        .iter()
                        .filter_map(|k| inner.get(*k))
                        .map(json_scalar_string)
                        .filter(|s| !s.is_empty())
                        .collect();
                    let mut e = scalar(parts.join(", "));
                    e.field_type = Some(FieldType::Text);
                    e
                }
                "totp" => ExtractedValue {
                    text: Some(json_scalar_string(inner)),
                    field_type: Some(FieldType::Totp),
                    totp_uri: Some(json_scalar_string(inner)),
                    unmapped_keys: Vec::new(),
                },
                "date" => {
                    let text = match inner.as_i64() {
                        Some(secs) => unix_sec_to_iso_date(secs),
                        None => json_scalar_string(inner),
                    };
                    let mut e = scalar(text);
                    e.field_type = Some(FieldType::Date);
                    e
                }
                "monthYear" => {
                    let text = match inner.as_i64() {
                        Some(v) => month_year_to_iso(v),
                        None => json_scalar_string(inner),
                    };
                    let mut e = scalar(text);
                    e.field_type = Some(FieldType::MonthYear);
                    e
                }
                "creditCardNumber" | "string" | "gender" => scalar(json_scalar_string(inner)),
                "url" => {
                    let mut e = scalar(json_scalar_string(inner));
                    e.field_type = Some(FieldType::Url);
                    e
                }
                "phone" => {
                    let mut e = scalar(json_scalar_string(inner));
                    e.field_type = Some(FieldType::Phone);
                    e
                }
                "menu" => scalar(json_scalar_string(inner)),
                other => ExtractedValue {
                    text: Some(serialize_value(value)),
                    field_type: Some(type_hint),
                    totp_uri: None,
                    unmapped_keys: vec![other.to_owned()],
                },
                }
            } else {
                // len == 1 守卫已保证可达；防御性兜底走多键路径
                ExtractedValue {
                    text: Some(serialize_value(value)),
                    field_type: Some(type_hint),
                    totp_uri: None,
                    unmapped_keys: vec!["(object)".to_owned()],
                }
            }
        }
        // 多键对象 / 数组：整体序列化保留 + 计数（不报错）
        Value::Object(_) | Value::Array(_) => ExtractedValue {
            text: Some(serialize_value(value)),
            field_type: Some(type_hint),
            totp_uri: None,
            unmapped_keys: vec![match value {
                Value::Object(o) => {
                    o.keys().next().map_or("(object)", String::as_str).to_owned()
                }
                _ => "(array)".to_owned(),
            }],
        },
    }
}

/// 标量 JSON 值 → 文本（对象 / 数组走 JSON 序列化保数据）。
fn json_scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => serialize_value(other),
    }
}

/// 序列化保留任意 JSON 值（不丢数据，供 notes / 普通字段存储）。
fn serialize_value(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "<不可序列化值>".to_owned())
}

/// 1P 类型码 / 类型化分派 → cf 字段类型。
fn resolve_field_type(code: Option<&str>, dispatched: Option<FieldType>) -> FieldType {
    dispatched.unwrap_or_else(|| {
        code.and_then(field_type_from_1p_code).unwrap_or(FieldType::Text)
    })
}

/// 映射一条 1PUX 条目 → [`MapOutcome`]。
///
/// 纯函数（不触库、不触 ZIP）；预检信号写入 `signals`。
///
/// # Errors
///
/// 仅在 otpauth URI 存在但 cf-totp 拒绝以外的情况下不返回错误——
/// 坏 otpauth 原值并入 notes 不丢整条（与 CSV 导入同纪律）。
/// 本函数当前不产生硬错误（保留 Result 以容纳未来边界）。
pub fn map_item(item: &PuxItem, signals: &mut ItemMapSignals) -> Result<MapOutcome, CfError> {
    // ---- categoryUuid 三态裁决 ----
    let (category, degraded) = match decide_category(&item.category_uuid) {
        CategoryDecision::Tombstone => {
            return Ok(MapOutcome::Skipped(format!(
                "categoryUuid {} 为 Tombstone（099，已删除标记），按官方语义跳过",
                item.category_uuid
            )));
        }
        CategoryDecision::Mapped(cat) => (cat, false),
        CategoryDecision::Degraded => {
            signals.unknown_category = true;
            (ItemCategory::SecureNote, true)
        }
    };

    // ---- 状态（trashed 按回收站语义；未列值容忍为 active） ----
    let (state, trashed_at) = match item.state.as_deref() {
        Some("active") | None => (ItemState::Active, None),
        Some("archived") => (ItemState::Archived, None),
        Some("trashed") => (ItemState::Trashed, Some(item.updated_at)),
        Some(_) => {
            signals.unknown_state = true;
            (ItemState::Active, None)
        }
    };

    // ---- 标题 / 收藏 ----
    let overview = item.overview.as_ref();
    let (title, no_title) = overview
        .and_then(|o| o.title.as_deref())
        .filter(|t| !t.is_empty())
        .map(|t| (t.to_owned(), false))
        .unwrap_or_else(|| (FALLBACK_TITLE.to_owned(), true));
    signals.no_title |= no_title;
    let is_favorite = item.fav_index > 0;
    let fav_index = item.fav_index.max(0);

    // ---- 多 URL（overview.urls 优先，缺失回退 overview.url） ----
    let mut urls: Vec<(Option<String>, String)> = Vec::new();
    if let Some(ov) = overview {
        for u in &ov.urls {
            if let Some(url) = u.url.as_deref().filter(|s| !s.is_empty()) {
                urls.push((u.label.clone().filter(|l| !l.is_empty()), url.to_owned()));
            }
        }
        if urls.is_empty() {
            if let Some(url) = ov.url.as_deref().filter(|s| !s.is_empty()) {
                urls.push((None, url.to_owned()));
            }
        }
    }

    // ---- 密码历史：丢弃 + 计数（FR-2.9 语义不同构，冻结裁决） ----
    signals.password_history_dropped += item.details.password_history.len() as u32;

    // ---- 字段抽取 ----
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut totp: Option<OtpauthData> = None;
    let mut notes_parts: Vec<String> = Vec::new();
    let mut fields: Vec<PuxFieldModel> = Vec::new();

    // notesPlain 是备注基线
    if let Some(np) = item.details.notes_plain.as_deref().filter(|s| !s.is_empty()) {
        notes_parts.push(np.to_owned());
    }

    for lf in &item.details.login_fields {
        let extracted = match &lf.value {
            Some(v) => {
                let hint = lf
                    .field_type
                    .as_deref()
                    .and_then(field_type_from_1p_code)
                    .unwrap_or(FieldType::Text);
                extract_value(v, hint)
            }
            None => ExtractedValue::default(),
        };
        signals.unmapped_value_types.extend(extracted.unmapped_keys.iter().cloned());

        let designation = lf
            .designation
            .as_deref()
            .map(Designation::from_1p_str);
        let text = extracted.text.clone().filter(|s| !s.is_empty());

        // TOTP：designation 或类型化分派（坏 otpauth 原值并入 notes）
        if extracted.totp_uri.is_some()
            || matches!(designation, Some(Designation::Totp))
        {
            let uri = extracted
                .totp_uri
                .clone()
                .or_else(|| text.clone())
                .unwrap_or_default();
            match parse_otpauth(&uri) {
                Ok(data) => {
                    if totp.is_none() {
                        totp = Some(data);
                    }
                }
                Err(reason) => {
                    signals.bad_totp = true;
                    notes_parts
                        .push(format!("[TOTP 无法解析（{reason}），已保留原始值] {uri}"));
                }
            }
            continue;
        }

        match designation {
            // username / password 走 designation，≤各 1（冻结裁决）；
            // 多余的同 designation 字段保留为普通字段不丢数据
            Some(Designation::Username) if username.is_none() => username = text,
            Some(Designation::Password) if password.is_none() && !degraded => password = text,
            Some(Designation::NotesPlain) => {
                if let Some(t) = text {
                    notes_parts.push(t);
                }
            }
            _ if degraded => {
                // 降级导入：一切字段值序列化并入 notes 保数据
                if let Some(t) = text {
                    let name = lf.name.clone().unwrap_or_else(|| "字段".into());
                    let type_code = lf.field_type.clone().unwrap_or_else(|| "?".into());
                    notes_parts.push(format!("[loginField {name} ({type_code})] {t}"));
                }
            }
            other => {
                fields.push(PuxFieldModel {
                    name: lf.name.clone().unwrap_or_else(|| "字段".into()),
                    field_type: resolve_field_type(lf.field_type.as_deref(), extracted.field_type),
                    designation: other,
                    value: text,
                });
            }
        }
    }

    for section in &item.details.sections {
        for f in &section.fields {
            map_section_field(section, f, degraded, signals, &mut totp, &mut notes_parts, &mut fields)?;
        }
    }

    // ---- 附件双形态归一 ----
    let file = normalize_file_ref(item);

    // 降级条目：username / password 也并入 notes（SecureNote 无 designation 结构）
    if degraded {
        if let Some(u) = username.take() {
            notes_parts.push(format!("[loginField username (T)] {u}"));
        }
        if let Some(p) = password.take() {
            notes_parts.push(format!("[loginField password (P)] {p}"));
        }
    }

    Ok(MapOutcome::Imported(Box::new(PuxItemModel {
        source_uuid: item.uuid.clone(),
        category,
        degraded,
        title,
        is_favorite,
        fav_index,
        state,
        trashed_at,
        created_at: item.created_at,
        updated_at: item.updated_at,
        username,
        password,
        totp,
        urls,
        notes: notes_parts.join("\n"),
        fields,
        file,
        zip_entry: None,
    })))
}

/// 映射一个分区字段（降级 → notes 序列化；正常 → 普通字段）。
#[allow(clippy::too_many_arguments)]
fn map_section_field(
    section: &super::model::PuxSection,
    f: &PuxSectionField,
    degraded: bool,
    signals: &mut ItemMapSignals,
    totp: &mut Option<OtpauthData>,
    notes_parts: &mut Vec<String>,
    fields: &mut Vec<PuxFieldModel>,
) -> Result<(), CfError> {
    let extracted = match &f.value {
        Some(v) => {
            let hint = f
                .field_type
                .as_deref()
                .and_then(field_type_from_1p_code)
                .unwrap_or(FieldType::Text);
            extract_value(v, hint)
        }
        None => ExtractedValue::default(),
    };
    signals.unmapped_value_types.extend(extracted.unmapped_keys.iter().cloned());
    let text = extracted.text.clone().filter(|s| !s.is_empty());

    // TOTP：类型化 {totp} 分派或 designation 显式声明
    if extracted.totp_uri.is_some() || matches!(f.designation.as_deref(), Some("totp") | Some("otp")) {
        let uri = extracted
            .totp_uri
            .clone()
            .or_else(|| text.clone())
            .unwrap_or_default();
        match parse_otpauth(&uri) {
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
        return Ok(());
    }

    let display_name = match (section.title.as_deref(), f.title.as_deref()) {
        (Some(st), Some(fn_)) => format!("{st} / {fn_}"),
        (Some(st), None) => st.to_owned(),
        (None, other) => other.unwrap_or("字段").to_owned(),
    };

    if degraded {
        if let Some(t) = text {
            let type_code = f.field_type.clone().unwrap_or_else(|| "?".into());
            notes_parts.push(format!("[section {display_name} ({type_code})] {t}"));
        }
    } else {
        fields.push(PuxFieldModel {
            name: display_name,
            field_type: resolve_field_type(f.field_type.as_deref(), extracted.field_type),
            designation: f.designation.as_deref().map(Designation::from_1p_str),
            value: text,
        });
    }
    Ok(())
}

/// 附件双形态归一（设计裁决：归一为 [`PuxFileRef`]）。
///
/// - 形态 A（合成样本）：`item.file{attrs:{fileName,size}, path}`；
/// - 形态 B（官方）：`details.documentAttributes{fileName,documentId,decryptedSize}`；
/// - 两形态并存时：documentId / filename / size 取官方键，ZIP 线索优先
///   用形态 A 的精确 `path`（回退 `files/<documentId>` 前缀枚举）。
#[must_use]
pub fn normalize_file_ref(item: &PuxItem) -> Option<PuxFileRef> {
    let doc = item.details.document_attributes.as_ref();
    let form_a = item.file.as_ref();

    let doc_id = doc.and_then(|d| d.document_id.clone()).filter(|s| !s.is_empty());
    let filename = doc
        .and_then(|d| d.file_name.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            form_a
                .and_then(|f| f.attrs.as_ref())
                .and_then(|a| a.file_name.clone())
                .filter(|s| !s.is_empty())
        })?;
    let size = doc
        .and_then(|d| d.decrypted_size)
        .or_else(|| form_a.and_then(|f| f.attrs.as_ref()).and_then(|a| a.size));
    let zip_entry_hint = form_a
        .and_then(|f| f.path.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("files/{}", doc_id.clone().unwrap_or_default()));

    Some(PuxFileRef {
        filename,
        document_id: doc_id,
        size,
        zip_entry_hint,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::pux::model::PuxItem;

    /// 构造 PuxItem（inline JSON，categoryUuid 用 docs/03 §6.4.1 真实码）。
    fn item_from_json(json: serde_json::Value) -> PuxItem {
        serde_json::from_value(json).expect("测试 JSON 必须合法")
    }

    fn map(json: serde_json::Value) -> (MapOutcome, ItemMapSignals) {
        let item = item_from_json(json);
        let mut signals = ItemMapSignals::default();
        let outcome = map_item(&item, &mut signals).expect("映射不应硬失败");
        (outcome, signals)
    }

    // ---- categoryUuid 映射表 ----

    #[test]
    fn 类别映射_001登录_004身份_112降级_099跳过() {
        // 001 → Login（opvault 基线）
        let (o, s) = map(json!({
            "uuid": "A1", "categoryUuid": "001", "state": "active",
            "overview": {"title": "登录条目"}, "details": {}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(m.category, ItemCategory::Login);
        assert!(!m.degraded);
        assert!(!s.unknown_category);

        // 004 → Identity（双源高置信）
        let (o, _) = map(json!({
            "uuid": "A2", "categoryUuid": "004", "state": "active",
            "overview": {"title": "身份"}, "details": {}
        }));
        assert!(matches!(&o, MapOutcome::Imported(m) if m.category == ItemCategory::Identity));

        // 112 → 未知 → 降级 SecureNote（预检警告素材，计入导入成功）
        let (o, s) = map(json!({
            "uuid": "A3", "categoryUuid": "112", "state": "active",
            "overview": {"title": "文档"}, "details": {}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("降级条目应计入导入成功而非 {other:?}"),
        };
        assert_eq!(m.category, ItemCategory::SecureNote);
        assert!(m.degraded);
        assert!(s.unknown_category);

        // 099 → Tombstone 跳过
        let (o, _) = map(json!({
            "uuid": "A4", "categoryUuid": "099", "state": "active",
            "overview": {"title": "墓碑"}, "details": {}
        }));
        assert!(matches!(o, MapOutcome::Skipped(_)));
    }

    #[test]
    fn 类别映射_非数字与全未知降级() {
        // 非数字 categoryUuid → 降级，原始值在 source 侧保留
        let (o, s) = map(json!({
            "uuid": "B1", "categoryUuid": "custom-x", "state": "active",
            "overview": {"title": "怪类别"}, "details": {}
        }));
        assert!(matches!(&o, MapOutcome::Imported(m) if m.degraded && m.category == ItemCategory::SecureNote));
        assert!(s.unknown_category);
    }

    // ---- Login 映射 ----

    #[test]
    fn 登录映射_designation双键与多url() {
        let (o, s) = map(json!({
            "uuid": "C1", "categoryUuid": "001", "state": "active",
            "favIndex": 3, "createdAt": 1_700_000_000, "updatedAt": 1_700_001_000,
            "overview": {
                "title": "GitHub",
                "urls": [
                    {"label": "", "url": "https://github.com"},
                    {"label": "管理后台", "url": "https://admin.github.com"}
                ]
            },
            "details": {
                "loginFields": [
                    // 官方 fieldType 键
                    {"designation": "username", "name": "username", "fieldType": "T", "value": "octocat"},
                    // 仓内合成样本 type 键
                    {"designation": "password", "name": "password", "type": "P", "value": "s3cret!"}
                ]
            }
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(m.category, ItemCategory::Login);
        assert_eq!(m.username.as_deref(), Some("octocat"));
        assert_eq!(m.password.as_deref(), Some("s3cret!"));
        assert_eq!(m.urls.len(), 2, "多 URL → urls 多行");
        assert_eq!(m.urls[1].0.as_deref(), Some("管理后台"));
        assert!(m.is_favorite, "favIndex > 0 视为收藏");
        assert_eq!(m.created_at, 1_700_000_000);
        assert!(!s.no_title);
    }

    #[test]
    fn 登录映射_多余username字段保留为普通字段() {
        let (o, _) = map(json!({
            "uuid": "C2", "categoryUuid": "001", "state": "active",
            "overview": {"title": "双用户名"},
            "details": {"loginFields": [
                {"designation": "username", "name": "username", "type": "T", "value": "first"},
                {"designation": "username", "name": "备用用户名", "type": "T", "value": "second"}
            ]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(m.username.as_deref(), Some("first"), "designation 走主字段");
        assert_eq!(m.fields.len(), 1, "多余 username 保留为普通字段");
        assert_eq!(m.fields[0].value.as_deref(), Some("second"));
        assert_eq!(m.fields[0].designation, Some(Designation::Username));
    }

    // ---- 类型化 value 分派 ----

    #[test]
    fn 分区字段_类型化value逐型分派() {
        let (o, s) = map(json!({
            "uuid": "D1", "categoryUuid": "002", "state": "active",
            "overview": {"title": "信用卡"},
            "details": {"sections": [{"title": "卡片", "fields": [
                {"title": "卡号", "type": "C", "value": {"creditCardNumber": "4111"}},
                {"title": "CVV", "type": "P", "value": {"concealed": "123"}},
                {"title": "邮箱", "type": "E", "value": {"email": {"email_address": "a@b.c"}}},
                {"title": "地址", "type": "A", "value": {"address": {"street": "路1", "city": "市", "zip": "100000", "country": "CN"}}},
                {"title": "有效期", "type": "M", "value": {"monthYear": 203012}},
                {"title": "生日", "type": "D", "value": {"date": 0}},
                {"title": "网址", "type": "U", "value": {"url": "https://bank.example"}},
                {"title": "电话", "type": "T", "value": {"phone": "13800000000"}},
                {"title": "菜单", "type": "T", "value": {"menu": "visa"}},
                {"title": "性别", "type": "T", "value": {"gender": "male"}},
                {"title": "普通", "type": "T", "value": {"string": "纯文本"}}
            ]}]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert!(s.unmapped_value_types.is_empty(), "已知类型不应计数：{:?}", s.unmapped_value_types);
        let get = |name: &str| m.fields.iter().find(|f| f.name.contains(name)).expect("字段应存在").clone();
        assert_eq!(get("卡号").value.as_deref(), Some("4111"));
        assert_eq!(get("卡号").field_type, FieldType::Text);
        assert_eq!(get("CVV").value.as_deref(), Some("123"));
        assert_eq!(get("CVV").field_type, FieldType::Concealed);
        assert_eq!(get("邮箱").value.as_deref(), Some("a@b.c"));
        assert_eq!(get("邮箱").field_type, FieldType::Email);
        assert_eq!(get("地址").value.as_deref(), Some("路1, 市, 100000, CN"));
        assert_eq!(get("有效期").value.as_deref(), Some("2030-12"));
        assert_eq!(get("有效期").field_type, FieldType::MonthYear);
        assert_eq!(get("生日").value.as_deref(), Some("1970-01-01"));
        assert_eq!(get("生日").field_type, FieldType::Date);
        assert_eq!(get("网址").value.as_deref(), Some("https://bank.example"));
        assert_eq!(get("网址").field_type, FieldType::Url);
        assert_eq!(get("电话").value.as_deref(), Some("13800000000"));
        assert_eq!(get("电话").field_type, FieldType::Phone);
        assert_eq!(get("菜单").value.as_deref(), Some("visa"));
        assert_eq!(get("性别").value.as_deref(), Some("male"));
        assert_eq!(get("普通").value.as_deref(), Some("纯文本"));
        // 分区标题保留在字段名里
        assert!(get("卡号").name.contains("卡片"));
    }

    #[test]
    fn 分区字段_未知类型key计数不报错() {
        let (o, s) = map(json!({
            "uuid": "D2", "categoryUuid": "003", "state": "active",
            "overview": {"title": "未知类型"},
            "details": {"sections": [{"title": "s", "fields": [
                {"title": "神秘值", "type": "T", "value": {"sshKey": {"privateKey": "..."}}}
            ]}]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(s.unmapped_value_types, vec!["sshKey".to_owned()]);
        let f = &m.fields[0];
        assert!(f.value.as_deref().is_some_and(|v| v.contains("privateKey")), "未知类型值序列化保留");
    }

    #[test]
    fn 分区字段_标量value按类型码降级() {
        // 仓内合成样本形态：value 是标量 + type 码
        let (o, _) = map(json!({
            "uuid": "D3", "categoryUuid": "001", "state": "active",
            "overview": {"title": "标量样本"},
            "details": {"sections": [{"title": "额外字段", "fields": [
                {"name": "port", "type": "N", "value": 5432},
                {"name": "pin", "type": "P", "value": "4321"},
                {"name": "神秘码", "type": "X", "value": "未知码按Text降级"}
            ]}]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(m.fields[0].value.as_deref(), Some("5432"));
        assert_eq!(m.fields[0].field_type, FieldType::Number);
        assert_eq!(m.fields[1].field_type, FieldType::Concealed);
        assert_eq!(m.fields[2].field_type, FieldType::Text, "未知码 Text 降级存值");
    }

    // ---- 降级导入（未知类别） ----

    #[test]
    fn 降级导入_全部字段序列化并入notes() {
        let (o, s) = map(json!({
            "uuid": "E1", "categoryUuid": "901", "state": "active",
            "overview": {"title": "SYNTH-Login", "url": "https://example1.com",
                         "urls": [{"label": "", "url": "https://example1.com"}]},
            "details": {
                "loginFields": [
                    {"designation": "username", "name": "username", "type": "T", "value": "user@example.com"},
                    {"designation": "password", "name": "password", "type": "P", "value": "P@ss"}
                ],
                "sections": [{"title": "额外字段", "fields": [
                    {"name": "credential", "type": "P", "value": "sk_live_x"}
                ]}]
            }
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert!(m.degraded);
        assert!(s.unknown_category);
        assert_eq!(m.category, ItemCategory::SecureNote);
        assert!(m.username.is_none() && m.password.is_none(), "降级条目无 designation 结构");
        assert!(m.fields.is_empty(), "降级条目字段全部并入 notes");
        assert!(m.notes.contains("[loginField username (T)] user@example.com"));
        assert!(m.notes.contains("[loginField password (P)] P@ss"));
        assert!(m.notes.contains("[section 额外字段 / credential (P)] sk_live_x"));
        assert_eq!(m.urls.len(), 1, "URL 仍走 urls 表");
    }

    // ---- 状态语义 ----

    #[test]
    fn 状态映射_active_archived_trashed与未列值容忍() {
        let (o, _) = map(json!({
            "uuid": "F1", "categoryUuid": "001", "state": "archived",
            "updatedAt": 1_700_000_000, "overview": {"title": "归档"}, "details": {}
        }));
        assert!(matches!(&o, MapOutcome::Imported(m) if m.state == ItemState::Archived && m.trashed_at.is_none()));

        // trashed → 回收站语义（state=Trashed + trashed_at=updatedAt）
        let (o, _) = map(json!({
            "uuid": "F2", "categoryUuid": "001", "state": "trashed",
            "updatedAt": 1_700_000_123, "overview": {"title": "回收"}, "details": {}
        }));
        assert!(matches!(&o, MapOutcome::Imported(m)
            if m.state == ItemState::Trashed && m.trashed_at == Some(1_700_000_123)));

        // 文档未列的 state 值：容忍为 active + 信号
        let (o, s) = map(json!({
            "uuid": "F3", "categoryUuid": "001", "state": "mystery",
            "overview": {"title": "怪状态"}, "details": {}
        }));
        assert!(matches!(&o, MapOutcome::Imported(m) if m.state == ItemState::Active));
        assert!(s.unknown_state);
    }

    // ---- passwordHistory 丢弃 + TOTP / 边界 ----

    #[test]
    fn 密码历史丢弃并计数() {
        let (_, s) = map(json!({
            "uuid": "G1", "categoryUuid": "001", "state": "active",
            "overview": {"title": "带历史"}, "details": {
                "passwordHistory": [
                    {"value": {"password": "old1"}, "time": 1},
                    {"value": {"password": "old2"}, "time": 2},
                    {"value": {"password": "old3"}, "time": 3}
                ]
            }
        }));
        assert_eq!(s.password_history_dropped, 3);
    }

    #[test]
    fn 分区字段totp解析与坏uri保留() {
        // 合法 otpauth → totp
        let (o, _) = map(json!({
            "uuid": "H1", "categoryUuid": "001", "state": "active",
            "overview": {"title": "带TOTP"},
            "details": {"sections": [{"title": "s", "fields": [
                {"title": "动态码", "type": "TOTP",
                 "value": {"totp": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"}}
            ]}]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert!(m.totp.is_some(), "totp 类型化分派应解析出 TOTP");

        // 坏 otpauth → 原值并入 notes，不丢整条
        let (o, s) = map(json!({
            "uuid": "H2", "categoryUuid": "001", "state": "active",
            "overview": {"title": "坏TOTP"},
            "details": {"sections": [{"title": "s", "fields": [
                {"title": "动态码", "type": "TOTP", "value": {"totp": "not-a-uri"}}
            ]}]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert!(m.totp.is_none());
        assert!(s.bad_totp);
        assert!(m.notes.contains("not-a-uri"));
    }

    #[test]
    fn 缺失标题兜底与空字段值() {
        let (o, s) = map(json!({
            "uuid": "I1", "categoryUuid": "001", "state": "active",
            "overview": {"title": "", "urls": [{"label": "", "url": ""}]},
            "details": {"loginFields": [
                {"designation": "username", "name": "username", "type": "T", "value": ""},
                {"designation": "password", "name": "password", "type": "P", "value": null}
            ]}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        assert_eq!(m.title, FALLBACK_TITLE);
        assert!(s.no_title);
        assert!(m.username.is_none() && m.password.is_none(), "空值不产生空字段");
        assert!(m.urls.is_empty(), "空 URL 不产生行");
    }

    // ---- 附件双形态归一 ----

    #[test]
    fn 附件归一_合成样本形态a() {
        let (o, _) = map(json!({
            "uuid": "J1", "categoryUuid": "001", "state": "active",
            "overview": {"title": "带附件"},
            "details": {},
            "file": {"attrs": {"fileName": "doc1.pdf", "size": 1025}, "path": "files/doc1.pdf"}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        let f = m.file.expect("应有附件");
        assert_eq!(f.filename, "doc1.pdf");
        assert_eq!(f.document_id, None);
        assert_eq!(f.size, Some(1025));
        assert_eq!(f.zip_entry_hint, "files/doc1.pdf");
    }

    #[test]
    fn 附件归一_官方形态b与前缀线索() {
        let (o, _) = map(json!({
            "uuid": "J2", "categoryUuid": "003", "state": "active",
            "overview": {"title": "官方文档"},
            "details": {"documentAttributes": {"fileName": "合同.pdf", "documentId": "DOCID42", "decryptedSize": 4096}}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        let f = m.file.expect("应有附件");
        assert_eq!(f.filename, "合同.pdf");
        assert_eq!(f.document_id.as_deref(), Some("DOCID42"));
        assert_eq!(f.size, Some(4096));
        assert_eq!(f.zip_entry_hint, "files/DOCID42", "官方形态用前缀线索");
    }

    #[test]
    fn 附件归一_双形态并存取官方键与精确路径() {
        let (o, _) = map(json!({
            "uuid": "J3", "categoryUuid": "003", "state": "active",
            "overview": {"title": "双形态"},
            "details": {"documentAttributes": {"fileName": "官方名.pdf", "documentId": "D9", "decryptedSize": 8}},
            "file": {"attrs": {"fileName": "样本名.pdf", "size": 1024}, "path": "files/D9___官方名.pdf"}
        }));
        let m = match o {
            MapOutcome::Imported(m) => m,
            other => panic!("应导入而非 {other:?}"),
        };
        let f = m.file.expect("应有附件");
        assert_eq!(f.filename, "官方名.pdf", "官方键优先");
        assert_eq!(f.size, Some(8));
        assert_eq!(f.zip_entry_hint, "files/D9___官方名.pdf", "精确路径优先于前缀枚举");
        assert_eq!(f.document_id.as_deref(), Some("D9"));
    }

    // ---- 日期转换 ----

    #[test]
    fn unix秒转iso日期() {
        assert_eq!(unix_sec_to_iso_date(0), "1970-01-01");
        assert_eq!(unix_sec_to_iso_date(1_700_000_000), "2023-11-14");
        assert_eq!(unix_sec_to_iso_date(951_782_400), "2000-02-29", "闰年");
        assert_eq!(unix_sec_to_iso_date(-86_400), "1969-12-31", "负时间戳");
    }

    #[test]
    fn 月份年转iso() {
        assert_eq!(month_year_to_iso(203012), "2030-12");
        assert_eq!(month_year_to_iso(199901), "1999-01");
        assert_eq!(month_year_to_iso(202013), "202013", "月份越界保留原值");
    }
}
