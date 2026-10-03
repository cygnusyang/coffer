//! Bitwarden 条目映射（docs/17 §4.2 mapping.rs）。
//!
//! - `login{username,password,uris,notes}` 走既有字段映射语义（CSV/1PUX
//!   同款 designation 与命名）；
//! - `fido2Credentials[]` → [`cf_store::PasskeyRecord`]（私钥归一化
//!   PKCS#8，D-1；非 ES256 拒绝——预检显式列出，不静默丢弃）；
//! - **D-6**：passkey 映射函数只接收 fido2 行键值对本身，结构上接触
//!   不到 login/password——密码保留由结构 + 回环测试双面保证；
//! - 未识别的条目类型（card / identity 等）降级为 SecureNote，原数据
//!   序列化并入备注（E-4 教训：宁可降级不可报错丢数据）。

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::Value;

use cf_domain::category::ItemCategory;
use cf_domain::field::FieldType;
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_store::{PasskeyRecord, COSE_ALG_ES256};

use super::parser::{parse_rfc3339_utc, BwExport, BwItem};
use crate::csv::mapping::{parse_otpauth, OtpauthData, FALLBACK_TITLE};

/// fido2Credentials 行的已知键（【单源】面：未知键记 warning 不拒绝）。
const FIDO2_KNOWN_KEYS: &[&str] = &[
    "credentialId",
    "keyType",
    "keyAlgorithm",
    "keyCurve",
    "rpId",
    "rpName",
    "userHandle",
    "userName",
    "userDisplayName",
    "counter",
    "discoverable",
    "creationDate",
    "encryptedPrivateKey",
    "encryptedUserKey",
];

/// 一条自定义字段的中间表示。
#[derive(Debug, Clone, PartialEq)]
pub struct BwFieldModel {
    /// 字段名（缺失兜底「字段」）。
    pub name: String,
    /// 数据类型（0=Text 1=Concealed 2=Boolean→Text；3=Linked 跳过）。
    pub field_type: FieldType,
    /// 字段值。
    pub value: Option<String>,
}

/// 一条可导入的 passkey（归一化后的明文载荷，导入路径专用）。
#[derive(Debug, Clone, PartialEq)]
pub struct BwPasskeyModel {
    /// 归一化后的记录（PKCS#8 私钥 / ES256）。
    pub record: PasskeyRecord,
    /// 行创建时间（Unix 秒；0 = 落库时兜底当前时间）。
    pub created_at: i64,
}

/// 坏 passkey 行的结构化分类（docs/17 r2.4 §9.1 L-2：按数据不按文案
/// ——reason 是给人看的展示层，分类判定只走枚举，措辞漂移不迁移）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BwPasskeyFailureKind {
    /// `keyAlgorithm` 显式给出且 ≠ `ecdsa`。
    KeyAlgorithmMismatch,
    /// `keyCurve` 显式给出且 ≠ `p256`。
    KeyCurveMismatch,
    /// rpId 缺失或为空。
    MissingRpId,
    /// credentialId 缺失或不是合法 base64。
    InvalidCredentialId,
    /// counter 不是非负整数。
    InvalidCounter,
    /// 缺失私钥字段 encryptedPrivateKey。
    MissingPrivateKey,
    /// 私钥为 Bitwarden EncString 加密形态（未加密导出亦不解包）。
    EncryptedPrivateKey,
    /// 私钥无法解析为 ES256（P-256）材料。
    UnparseablePrivateKey,
}

impl BwPasskeyFailureKind {
    /// 是否非 ES256 族（预检报告将其单独成列，docs/17 §4.2）。
    #[must_use]
    pub fn is_non_es256(self) -> bool {
        matches!(self, Self::KeyAlgorithmMismatch | Self::KeyCurveMismatch)
    }
}

/// 一条不可导入的 passkey 行（预检显式列出，FR-7.8 不静默丢弃）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwPasskeyFailure {
    /// 所属条目 ID（Bitwarden 原始 id）。
    pub item_id: String,
    /// 所属条目标题。
    pub item_title: String,
    /// 行在该条目 `fido2Credentials[]` 中的下标（0 起）。
    pub index: usize,
    /// 结构化分类（程序判定唯一依据，L-2）。
    pub kind: BwPasskeyFailureKind,
    /// 拒绝原因（人类可读，面向导入结果页；**不作分类依据**）。
    pub reason: String,
}

/// 条目映射信号（预检聚合用；passkey 坏行按类别分列——TCB-7）。
#[derive(Debug, Default)]
pub struct ItemSignals {
    /// 告警文本（未知 fido2 键、降级、坏 totp、未识别字段类型等）。
    pub warnings: Vec<String>,
    /// 非 ES256 passkey 行（docs/17 §4.2：非 ES256 列表）。
    pub non_es256: Vec<BwPasskeyFailure>,
    /// 其余坏 passkey 行（解析失败逐条列出）。
    pub bad_passkeys: Vec<BwPasskeyFailure>,
}

/// 条目映射的中间表示（导入编排直接消费）。
#[derive(Debug, Clone, PartialEq)]
pub struct BwItemModel {
    /// Bitwarden 原始条目 id（报错定位 / 溯源；缺失为空串）。
    pub source_id: String,
    /// 类别（type 1→Login 其余降级 SecureNote）。
    pub category: ItemCategory,
    /// 标题（缺失兜底 [`FALLBACK_TITLE`]）。
    pub title: String,
    /// 是否收藏。
    pub is_favorite: bool,
    /// 状态（deletedDate 非空 → Trashed）。
    pub state: ItemState,
    /// 移入回收站的时间戳（deletedDate 解析成功才有）。
    pub trashed_at: Option<i64>,
    /// 创建时间（Unix 秒；解析失败为 0，落库兜底当前时间）。
    pub created_at: i64,
    /// 修订时间（Unix 秒；解析失败为 0，落库兜底当前时间）。
    pub updated_at: i64,
    /// 用户名（login.username）。
    pub username: Option<String>,
    /// 密码（login.password；D-6：passkey 映射不读写此值）。
    pub password: Option<String>,
    /// TOTP（otpauth 解析成功才有）。
    pub totp: Option<OtpauthData>,
    /// URL 列表（login.uris，旧版 uri 键兜底）。
    pub urls: Vec<String>,
    /// 备注（notes + 降级序列化 + 坏 totp 原值）。
    pub notes: String,
    /// 自定义字段。
    pub fields: Vec<BwFieldModel>,
    /// 标签（folderId → folders[].name）。
    pub tags: Vec<String>,
    /// 可导入 passkey 行（坏行在 [`BwPasskeyFailure`] 显式列出）。
    pub passkeys: Vec<BwPasskeyModel>,
}

/// 映射整个导出（预检与导入共用的同一条管线，报告所见即导入所得）。
pub(crate) fn map_export(export: &BwExport) -> Result<Vec<(BwItemModel, ItemSignals)>, CfError> {
    let folders: HashMap<&str, &str> = export
        .folders
        .iter()
        .filter_map(|f| {
            let id = f.id.as_deref()?;
            let name = f.name.as_deref()?;
            Some((id, name))
        })
        .collect();

    let mut out = Vec::with_capacity(export.items.len());
    for item in &export.items {
        out.push(map_item(item, &folders)?);
    }
    Ok(out)
}

/// 映射一条 Bitwarden 条目。
///
/// # Errors
///
/// 仅当降级序列化（card / identity 非对象态）无法产出 JSON 时返回
/// [`CfError::ImportFailed`]——其余一律降级不拒绝。
pub(crate) fn map_item(
    item: &BwItem,
    folders: &HashMap<&str, &str>,
) -> Result<(BwItemModel, ItemSignals), CfError> {
    let mut signals = ItemSignals::default();

    let type_code = item.item_type.as_ref().and_then(value_as_i64);
    let is_login = type_code == Some(1);
    let degraded: Option<String> = match type_code {
        None | Some(1 | 2) => None,
        Some(3) => Some("card".to_owned()),
        Some(4) => Some("identity".to_owned()),
        Some(other) => Some(format!("type {other}")),
    };

    // 备注：notes + 降级序列化 + 坏 totp 原值（宁可降级不可丢数据，E-4）
    let mut notes = item.notes.clone().unwrap_or_default();
    if let Some(payload) = &degraded {
        let payload_value = match payload.as_str() {
            "card" => item.card.clone(),
            "identity" => item.identity.clone(),
            _ => None,
        };
        match payload_value {
            Some(Value::Object(map)) if !map.is_empty() => {
                let serialized = serde_json::to_string(&map)
                    .map_err(|e| CfError::ImportFailed(format!("降级序列化失败：{e}")))?;
                if !notes.is_empty() {
                    notes.push('\n');
                }
                notes.push_str(&format!("（{payload} 数据降级保留）{serialized}"));
                signals.warnings.push(format!(
                    "条目 {}（{}）：未识别的条目类型 {payload}，已降级导入为安全笔记（原数据并入备注，计入导入成功）",
                    item_id(item),
                    item.name.as_deref().unwrap_or("(无标题)")
                ));
            }
            _ => {
                signals.warnings.push(format!(
                    "条目 {}（{}）：条目类型 {payload} 无可映射数据，按安全笔记导入",
                    item_id(item),
                    item.name.as_deref().unwrap_or("(无标题)")
                ));
            }
        }
    }

    // 登录面：仅 type 1 取 username/password/urls/totp；passkey 映射独立
    // 于 login（D-6）——坏行只影响 passkey 行，条目本体照常导入
    let (username, password, urls, totp) = match &item.login {
        Some(login) if is_login => {
            let mut urls: Vec<String> = login
                .uris
                .iter()
                .filter_map(|u| u.uri.as_deref())
                .filter(|u| !u.is_empty())
                .map(str::to_owned)
                .collect();
            if urls.is_empty() {
                if let Some(uri) = login.uri.as_deref().filter(|u| !u.is_empty()) {
                    urls.push(uri.to_owned());
                }
            }
            let totp = login
                .totp
                .as_deref()
                .and_then(|raw| match parse_otpauth(raw) {
                    Ok(data) => Some(data),
                    Err(reason) => {
                        if !notes.is_empty() {
                            notes.push('\n');
                        }
                        notes.push_str(&format!("（One-time password 无法解析：{reason}）{raw}"));
                        signals.warnings.push(format!(
                            "条目 {}：TOTP 无法解析，原始值已并入备注，该条目仍导入",
                            item_id(item)
                        ));
                        None
                    }
                });
            (
                login.username.clone().filter(|s| !s.is_empty()),
                login.password.clone(),
                urls,
                totp,
            )
        }
        _ => (None, None, Vec::new(), None),
    };

    // passkey 行：坏行进 signals（预检显式列出，导入跳行不丢条目）
    let mut passkeys = Vec::new();
    if let Some(login) = &item.login {
        for (index, entry) in login.fido2_credentials.iter().enumerate() {
            match map_passkey_row(entry, item, index, &mut signals) {
                Ok(record) => {
                    // 行时间：creationDate → 条目 creationDate 兜底；
                    // 全缺失为 0，落库时兜底当前时间
                    let created_at = entry
                        .get("creationDate")
                        .and_then(Value::as_str)
                        .and_then(parse_rfc3339_utc)
                        .or_else(|| item.creation_date.as_deref().and_then(parse_rfc3339_utc))
                        .unwrap_or(0);
                    passkeys.push(BwPasskeyModel { record, created_at });
                }
                Err(failure) => {
                    if failure.kind.is_non_es256() {
                        signals.non_es256.push(failure);
                    } else {
                        signals.bad_passkeys.push(failure);
                    }
                }
            }
        }
    }

    // 自定义字段（0=Text 1=Hidden 2=Boolean 3=Linked——linked 语义不同构，
    // 记 warning 跳过该字段，不丢条目）
    let mut fields = Vec::new();
    for f in &item.fields {
        let name = f
            .name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "字段".to_owned());
        match f.field_type.as_ref().and_then(value_as_i64) {
            Some(1) => fields.push(BwFieldModel {
                name,
                field_type: FieldType::Concealed,
                value: f.value.clone(),
            }),
            Some(0 | 2) => fields.push(BwFieldModel {
                name,
                field_type: FieldType::Text,
                value: f.value.clone(),
            }),
            Some(3) => signals.warnings.push(format!(
                "条目 {}：自定义字段「{name}」为 Linked 类型（语义不同构），已跳过",
                item_id(item)
            )),
            _ => signals.warnings.push(format!(
                "条目 {}：自定义字段「{name}」类型未识别，按文本导入",
                item_id(item)
            )),
        }
    }

    // 标签：folderId → folders[].name；未知 folderId 记 warning
    let mut tags = Vec::new();
    if let Some(folder_id) = item.folder_id.as_deref().filter(|s| !s.is_empty()) {
        match folders.get(folder_id) {
            Some(name) => tags.push((*name).to_owned()),
            None => signals.warnings.push(format!(
                "条目 {}：folderId {folder_id} 在 folders 中不存在，文件夹归属丢弃（条目仍导入）",
                item_id(item)
            )),
        }
    }

    let trashed_at = item.deleted_date.as_deref().and_then(parse_rfc3339_utc);
    let state = if trashed_at.is_some() {
        ItemState::Trashed
    } else {
        ItemState::Active
    };

    let model = BwItemModel {
        source_id: item_id(item),
        category: if is_login {
            ItemCategory::Login
        } else {
            ItemCategory::SecureNote
        },
        title: item
            .name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| FALLBACK_TITLE.to_owned()),
        is_favorite: item.favorite == Some(true),
        state,
        trashed_at,
        created_at: item
            .creation_date
            .as_deref()
            .and_then(parse_rfc3339_utc)
            .unwrap_or(0),
        updated_at: item
            .revision_date
            .as_deref()
            .and_then(parse_rfc3339_utc)
            .unwrap_or(0),
        username,
        password,
        totp,
        urls,
        notes,
        fields,
        tags,
        passkeys,
    };
    Ok((model, signals))
}

/// 映射一条 fido2Credentials 行。
///
/// 成功 → 归一化的 [`PasskeyRecord`]；失败 → [`BwPasskeyFailure`]（预检
/// 显式列出，导入跳过该行不丢条目）。本函数只接收行键值对——**结构上
/// 接触不到 login/password**（D-6）。
fn map_passkey_row(
    entry: &serde_json::Map<String, Value>,
    item: &BwItem,
    index: usize,
    signals: &mut ItemSignals,
) -> Result<PasskeyRecord, BwPasskeyFailure> {
    let failure = |kind: BwPasskeyFailureKind, reason: String| BwPasskeyFailure {
        item_id: item_id(item),
        item_title: item
            .name
            .clone()
            .unwrap_or_else(|| FALLBACK_TITLE.to_owned()),
        index,
        kind,
        reason,
    };

    // 未知键：记 warning 不拒绝（【单源】schema 漂移容忍，docs/17 §4.2）
    for key in entry.keys() {
        if !FIDO2_KNOWN_KEYS.contains(&key.as_str()) {
            signals.warnings.push(format!(
                "条目 {}：fido2Credentials 含未识别字段「{key}」（已忽略，不影响已知字段导入）",
                item_id(item)
            ));
        }
    }

    // rpId：必需、非空（仓库层 1012 校验同口径，此处前置到预检）
    let rp_id = entry
        .get("rpId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| failure(BwPasskeyFailureKind::MissingRpId, "rpId 缺失或为空".into()))?
        .to_owned();

    // 算法：keyAlgorithm/keyCurve 显式给出非 ecdsa/p256 → 非 ES256 显式
    // 列出（TCB-7，分类按具体失配键区分——L-2）；两者缺失 → 容忍默认
    // ES256（私钥解析仍会把非 P-256 材料挡下）
    let algorithm = entry.get("keyAlgorithm").and_then(Value::as_str);
    let curve = entry.get("keyCurve").and_then(Value::as_str);
    if let Some(alg) = algorithm.filter(|s| *s != "ecdsa") {
        return Err(failure(
            BwPasskeyFailureKind::KeyAlgorithmMismatch,
            format!("非 ES256 算法（keyAlgorithm={alg:?}），Coffer 本版仅支持 ES256"),
        ));
    }
    if let Some(c) = curve.filter(|s| *s != "p256") {
        return Err(failure(
            BwPasskeyFailureKind::KeyCurveMismatch,
            format!("非 ES256 算法（keyCurve={c:?}），Coffer 本版仅支持 ES256"),
        ));
    }

    // credentialId：必需、base64 可解码（标准 / URL-safe、有无 padding 均容）
    let credential_id = entry
        .get("credentialId")
        .and_then(Value::as_str)
        .and_then(decode_b64_flexible)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            failure(
                BwPasskeyFailureKind::InvalidCredentialId,
                "credentialId 缺失或不是合法 base64".into(),
            )
        })?;

    // userHandle：可缺失（空字节向量落库）
    let user_handle = entry
        .get("userHandle")
        .and_then(Value::as_str)
        .and_then(decode_b64_flexible)
        .unwrap_or_default();

    // counter：缺省 0；须为非负整数（仓库层校验同口径）
    let sign_count = match entry.get("counter") {
        None | Some(Value::Null) => 0,
        Some(v) => v.as_i64().filter(|c| *c >= 0).ok_or_else(|| {
            failure(
                BwPasskeyFailureKind::InvalidCounter,
                "counter 不是非负整数".into(),
            )
        })?,
    };

    // 私钥：encryptedPrivateKey 必需。EncString（Bitwarden 真实导出形态，
    // attach key 不随导出解包）显式列为坏行；可解析的 ES256 编码归一化。
    let key_raw = entry
        .get("encryptedPrivateKey")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            failure(
                BwPasskeyFailureKind::MissingPrivateKey,
                "缺失私钥字段 encryptedPrivateKey（该行不可导入）".into(),
            )
        })?;
    if looks_like_encstring(key_raw) {
        return Err(failure(
            BwPasskeyFailureKind::EncryptedPrivateKey,
            "私钥为 Bitwarden 加密形态（EncString，未加密导出亦不解包该密钥）\
             ——本版无法导入此 passkey 行，条目本体照常导入"
                .into(),
        ));
    }
    let private_key_pkcs8 = decode_b64_flexible(key_raw)
        .and_then(|der| normalize_private_key(&der))
        .ok_or_else(|| {
            failure(
                BwPasskeyFailureKind::UnparseablePrivateKey,
                "私钥无法解析为 ES256（P-256）私钥（支持 PKCS#8 / SEC1 DER）".into(),
            )
        })?;

    // 用户名：userName 优先，userDisplayName 兜底
    let user_name = entry
        .get("userName")
        .and_then(Value::as_str)
        .or_else(|| entry.get("userDisplayName").and_then(Value::as_str))
        .map(str::to_owned)
        .filter(|s| !s.is_empty());
    let rp_name = entry
        .get("rpName")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty());

    Ok(PasskeyRecord {
        rp_id,
        rp_name,
        user_name,
        user_handle,
        credential_id,
        private_key_pkcs8,
        algorithm: COSE_ALG_ES256,
        sign_count,
    })
}

/// 条目 id（缺失为空串——报错定位退化为标题）。
fn item_id(item: &BwItem) -> String {
    item.id.clone().unwrap_or_default()
}

/// 解释数值键：数字或数字字符串（schema 漂移容忍）。
fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// 宽容 base64 解码：标准 / URL-safe × 有无 padding 全兼容
/// （Bitwarden 用 URL-safe 无 padding，合成样本可能用标准形态）。
#[must_use]
pub fn decode_b64_flexible(s: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
        .or_else(|| URL_SAFE.decode(s).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}

/// Bitwarden EncString 形态识别（`<type>.<iv>|<ct>[|<mac>]`）。
#[must_use]
pub fn looks_like_encstring(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && matches!(b[0], b'0'..=b'2') && b[1] == b'.' && s.contains('|')
}

/// 私钥归一化（D-1）：SEC1（RFC 5915）/ PKCS#8 DER → PKCS#8 DER，
/// 非 ES256（P-256）材料解析失败返回 `None`（上游显式列为坏行）。
///
/// 仅做解析与校验，无签名运行面（docs/17 §3.2 D-2；p256 依赖属
/// docs/17 §10 裁定 #6 已批准范围）。
#[must_use]
pub fn normalize_private_key(der: &[u8]) -> Option<Vec<u8>> {
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let key = p256::SecretKey::from_sec1_der(der)
        .or_else(|_| p256::SecretKey::from_pkcs8_der(der))
        .ok()?;
    key.to_pkcs8_der().ok().map(|doc| doc.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 与 fixtures 同一把合成测试密钥（PKCS#8 / SEC1 双编码）。
    const PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH1THtN9Yr04dr25YaOOECBiQSeZzztzz7gTfoKjZM0KhRANCAATJw2TFOn57PJ2qnEE5fkNqv+riQosBDzm3JeP1H9tVxVdCrzzBIu58KOXRc9gTX50LkGHG2XDfX+vgmt/Wv4dK";
    const SEC1_B64: &str = "MHcCAQEEIB9Ux7TfWK9OHa9uWGjjhAgYkEnmc87c8+4E36Co2TNCoAoGCCqGSM49AwEHoUQDQgAEycNkxTp+ezydqpxBOX5Dar/q4kKLAQ85tyXj9R/bVcVXQq88wSLufCjl0XPYE1+dC5Bhxtlw31/r4Jrf1r+HSg==";

    /// D-1：PKCS#8 与 SEC1 两种来源编码归一到同一 PKCS#8 DER 字节。
    #[test]
    fn 归一化双编码到同一pkcs8字节() {
        let pkcs8 = decode_b64_flexible(PKCS8_B64).unwrap();
        let sec1 = decode_b64_flexible(SEC1_B64).unwrap();
        let from_pkcs8 = normalize_private_key(&pkcs8).unwrap();
        let from_sec1 = normalize_private_key(&sec1).unwrap();
        assert_eq!(from_pkcs8, from_sec1, "两种编码归一到同一 PKCS#8");
        assert_eq!(from_pkcs8, pkcs8, "来源已是 PKCS#8 时逐字节不变");
        assert_ne!(from_sec1, sec1, "SEC1 输入必须被重编码为 PKCS#8");
    }

    /// 非 ES256 材料（截断 DER / 随机字节）解析失败 → None。
    #[test]
    fn 非es256材料归一化失败() {
        assert!(normalize_private_key(b"garbage-bytes").is_none());
        assert!(normalize_private_key(&[0x30, 0x00]).is_none());
        assert!(normalize_private_key(&[]).is_none());
    }

    /// 宽容 base64：标准 / URL-safe × 有无 padding。
    #[test]
    fn 宽容base64解码() {
        assert_eq!(
            decode_b64_flexible("dXNlci1oYW5kbGUtMQ").as_deref(),
            Some(b"user-handle-1".as_slice())
        );
        assert_eq!(
            decode_b64_flexible("dXNlci1oYW5kbGUtMQ==").as_deref(),
            Some(b"user-handle-1".as_slice())
        );
        // 含 + / 的标准形态（URL-safe 引擎解不了，标准引擎兜住）
        assert_eq!(decode_b64_flexible("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(decode_b64_flexible("!!"), None);
    }

    /// EncString 识别：Bitwarden 密文形态 vs DER base64。
    #[test]
    fn encstring识别() {
        assert!(looks_like_encstring("2.AbC123|xyz456|mac789"));
        assert!(looks_like_encstring("0.abc|def"));
        assert!(!looks_like_encstring(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH"
        ));
        assert!(!looks_like_encstring("2.no-pipe"));
        assert!(!looks_like_encstring(""));
    }

    /// L-2：非 ES256 族判定走枚举（reason 文案不参与分类）。
    #[test]
    fn 非es256族按枚举判定() {
        assert!(BwPasskeyFailureKind::KeyAlgorithmMismatch.is_non_es256());
        assert!(BwPasskeyFailureKind::KeyCurveMismatch.is_non_es256());
        assert!(!BwPasskeyFailureKind::EncryptedPrivateKey.is_non_es256());
        assert!(!BwPasskeyFailureKind::MissingRpId.is_non_es256());
        assert!(!BwPasskeyFailureKind::UnparseablePrivateKey.is_non_es256());
    }

    /// 把一条 fido2 行 JSON 送入分类唯一入口 [`map_passkey_row`]，返回失败
    /// 分类结果（哨兵只关注失败行——成功行按空转处置直接 panic）。
    fn classify_row(row: serde_json::Value) -> BwPasskeyFailure {
        let item: BwItem = serde_json::from_value(json!({
            "id": "bw-sentinel",
            "name": "Sentinel Item",
            "type": 1,
        }))
        .expect("哨兵条目 fixture 须可解析");
        let entry = row
            .as_object()
            .expect("哨兵行须为 JSON 对象")
            .clone();
        let mut signals = ItemSignals::default();
        match map_passkey_row(&entry, &item, 0, &mut signals) {
            Ok(_) => panic!("哨兵行应分类为不可导入失败"),
            Err(failure) => failure,
        }
    }

    /// PL-1（KNOWN-ISSUES.md）哨兵：L-2「按数据不按文案」的回归警戒——
    /// 同分类数据、不同 reason 文案 → 分类不变。若调用侧改回文本分类
    /// 且当前文案未变，现有三处测试全部测不出，本哨兵必然暴露。
    /// 输入经 [`map_passkey_row`]（分类唯一入口），不构造字面量。
    #[test]
    fn 同分类异reason文案分类不变() {
        // 非 ES256 族（is_non_es256 = true）：keyCurve p384 / p521 均 →
        // KeyCurveMismatch，reason 因内嵌曲线名而不同；其余字段给合法值
        let p384 = classify_row(json!({
            "rpId": "example.com",
            "credentialId": "Y3JlZC1pZC0x",
            "keyCurve": "p384",
        }));
        let p521 = classify_row(json!({
            "rpId": "example.com",
            "credentialId": "Y3JlZC1pZC0x",
            "keyCurve": "p521",
        }));
        assert_eq!(p384.kind, p521.kind, "同分类数据不同文案 → 分类一致");
        assert_eq!(p384.kind, BwPasskeyFailureKind::KeyCurveMismatch);
        assert_ne!(p384.reason, p521.reason, "reason 须随曲线名不同，否则哨兵空转");
        assert_eq!(p384.kind.is_non_es256(), p521.kind.is_non_es256());
        assert!(p384.kind.is_non_es256(), "KeyCurveMismatch 属非 ES256 族（真路径）");

        // 非 ES256 族：keyAlgorithm eddsa / rsa 同理（reason 内嵌算法名）
        let eddsa = classify_row(json!({
            "rpId": "example.com",
            "credentialId": "Y3JlZC1pZC0x",
            "keyAlgorithm": "eddsa",
        }));
        let rsa = classify_row(json!({
            "rpId": "example.com",
            "credentialId": "Y3JlZC1pZC0x",
            "keyAlgorithm": "rsa",
        }));
        assert_eq!(eddsa.kind, rsa.kind, "同分类数据不同文案 → 分类一致");
        assert_eq!(eddsa.kind, BwPasskeyFailureKind::KeyAlgorithmMismatch);
        assert_ne!(eddsa.reason, rsa.reason, "reason 须随算法名不同");
        assert!(eddsa.kind.is_non_es256());

        // 非 ES256 族之外（is_non_es256 = false）：缺 rpId → MissingRpId
        let missing_rp = classify_row(json!({
            "credentialId": "Y3JlZC1pZC0x",
        }));
        assert_eq!(missing_rp.kind, BwPasskeyFailureKind::MissingRpId);
        assert!(
            !missing_rp.kind.is_non_es256(),
            "MissingRpId 不属非 ES256 族（假路径）"
        );
    }
}
