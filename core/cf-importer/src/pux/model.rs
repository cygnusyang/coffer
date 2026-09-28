//! 1PUX JSON 数据模型（FR-7.1，`docs/09-版本开发计划.md` v0.3.0-T01）。
//!
//! 只建模导入所需的最小字段集：顶层 `accounts[].attrs/vaults[].attrs/items[]`。
//! 未收录的 JSON 键由 serde 默认行为忽略（1PUX 规范允许键扩展）。
//!
//! ## 官方键与仓内合成样本的双键兼容
//!
//! - `details.loginFields[]`：官方用 `fieldType` 键，仓内合成样本用 `type`
//!   ——`PuxLoginField::field_type` 以 `rename = "fieldType"` + `alias = "type"`
//!   兼容两种形态；
//! - `details.sections[].fields[]`：官方用 `title` 键，合成样本用 `name`
//!   ——`PuxSectionField::title` 同法兼容；
//! - 附件双形态：合成样本 `item.file = {attrs:{fileName,size}, path:"files/..."}`
//!   （[`PuxFileEntry`]），官方
//!   `details.documentAttributes{fileName,documentId,decryptedSize}`
//!   （[`PuxDocumentAttributes`]）——两者在映射层归一为
//!   [`PuxFileRef`]（见 `crate::pux::mapping`）。
//!
//! ## 容忍语义（docs/09 E-4 教训：宁可降级不可报错丢数据）
//!
//! - 除 `accounts` / `attrs` / `uuid` / `categoryUuid` 外全部字段
//!   `#[serde(default)]`——缺失不致命；
//! - `item.state` 文档未列的值（如 `trashed`）不在反序列化层拒绝，
//!   由映射层按语义处理。

use serde::Deserialize;
use serde_json::Value;

/// export.data 顶层模型（FR-7.1）。
#[derive(Debug, Deserialize)]
pub struct PuxModel {
    /// 账号列表（**必需键**，缺失即格式错误，由解析层整体拒绝）。
    pub accounts: Vec<PuxAccount>,
}

/// 一个 1Password 账号。
#[derive(Debug, Deserialize)]
pub struct PuxAccount {
    /// 账号属性（**必需键**，缺失即格式错误）。
    pub attrs: PuxAccountAttrs,
    /// 账号下可见的保险库（默认空）。
    #[serde(default)]
    pub vaults: Vec<PuxVault>,
}

/// 账号属性。
#[derive(Debug, Deserialize)]
pub struct PuxAccountAttrs {
    /// 账号显示名。
    #[serde(default)]
    pub name: Option<String>,
    /// 账号类型（官方 `P`/`E`/`U`；仅记录，不影响导入）。
    #[serde(default, rename = "type")]
    pub account_type: Option<String>,
}

/// 一个保险库。
#[derive(Debug, Deserialize)]
pub struct PuxVault {
    /// 保险库属性（**必需键**，缺失即格式错误）。
    pub attrs: PuxVaultAttrs,
    /// 保险库内条目（默认空）。
    #[serde(default)]
    pub items: Vec<PuxItem>,
}

/// 保险库属性。
#[derive(Debug, Deserialize)]
pub struct PuxVaultAttrs {
    /// 保险库 UUID。
    #[serde(default)]
    pub uuid: Option<String>,
    /// 保险库名称。
    #[serde(default)]
    pub name: Option<String>,
    /// 保险库类型（官方 `P`=个人 `E`=共享 `U`=自建；仅记录）。
    #[serde(default, rename = "type")]
    pub vault_type: Option<String>,
}

/// 一条 1PUX 条目。
#[derive(Debug, Deserialize)]
pub struct PuxItem {
    /// 条目原始 UUID（合成样本如 `IT0001`，非 RFC 4122；导入固定
    /// 「全部新建 UUIDv7」，原值仅作溯源记录）。
    pub uuid: String,
    /// 类别 UUID（官方文档未给出数值表；三位十进制，见
    /// `crate::pux::mapping` 的映射裁决）。
    #[serde(rename = "categoryUuid")]
    pub category_uuid: String,
    /// 状态：`active` / `archived` / `trashed`（文档未列值由映射层容忍）。
    #[serde(default)]
    pub state: Option<String>,
    /// 创建时间（Unix 秒；缺失按 0，落库时兜底为当前时间）。
    #[serde(default, rename = "createdAt")]
    pub created_at: i64,
    /// 更新时间（Unix 秒）。
    #[serde(default, rename = "updatedAt")]
    pub updated_at: i64,
    /// 收藏排序索引；> 0 视为已收藏。
    #[serde(default, rename = "favIndex")]
    pub fav_index: i64,
    /// 非加密概要（标题 / URL / 标签）。
    #[serde(default)]
    pub overview: Option<PuxOverview>,
    /// 加密明细（1PUX 导出已解密为明文 JSON）。
    #[serde(default)]
    pub details: PuxDetails,
    /// 附件形态 A（合成样本）：`{attrs:{fileName,size}, path:"files/..."}`。
    #[serde(default)]
    pub file: Option<PuxFileEntry>,
}

/// 条目概要。
#[derive(Debug, Deserialize)]
pub struct PuxOverview {
    /// 标题。
    #[serde(default)]
    pub title: Option<String>,
    /// 主 URL（`urls` 缺失时的兜底）。
    #[serde(default)]
    pub url: Option<String>,
    /// URL 列表（多 URL → cf `urls` 表多行）。
    #[serde(default, rename = "urls")]
    pub urls: Vec<PuxUrl>,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
}

/// 概要中的一条 URL。
#[derive(Debug, Deserialize)]
pub struct PuxUrl {
    /// URL 标签（可空）。
    #[serde(default)]
    pub label: Option<String>,
    /// URL 本体。
    #[serde(default)]
    pub url: Option<String>,
}

/// 条目明细。
#[derive(Debug, Default, Deserialize)]
pub struct PuxDetails {
    /// 登录字段（username / password / totp，designation 驱动）。
    #[serde(default, rename = "loginFields")]
    pub login_fields: Vec<PuxLoginField>,
    /// 纯文本备注。
    #[serde(default, rename = "notesPlain")]
    pub notes_plain: Option<String>,
    /// 自定义分区。
    #[serde(default)]
    pub sections: Vec<PuxSection>,
    /// 密码历史（FR-2.9 历史表语义不同构——**丢弃 + 预检计数**，
    /// docs/09 v0.3.0 冻结裁决）。
    #[serde(default, rename = "passwordHistory")]
    pub password_history: Vec<Value>,
    /// 附件形态 B（官方）：文档属性。
    #[serde(default, rename = "documentAttributes")]
    pub document_attributes: Option<PuxDocumentAttributes>,
}

/// 登录字段（`fieldType` 官方键 + `type` 合成样本键双兼容）。
#[derive(Debug, Deserialize)]
pub struct PuxLoginField {
    /// 语义标识（`username` / `password` / `totp` / `notesPlain` / …）。
    #[serde(default)]
    pub designation: Option<String>,
    /// 字段名。
    #[serde(default)]
    pub name: Option<String>,
    /// 字段类型码（官方 `fieldType`，合成样本 `type`；如 `T`/`P`）。
    #[serde(default, rename = "fieldType", alias = "type")]
    pub field_type: Option<String>,
    /// 字段值（官方 1PUX 可为类型化对象，见映射层分派）。
    #[serde(default)]
    pub value: Option<Value>,
}

/// 自定义分区。
#[derive(Debug, Deserialize)]
pub struct PuxSection {
    /// 分区标题。
    #[serde(default)]
    pub title: Option<String>,
    /// 分区名。
    #[serde(default)]
    pub name: Option<String>,
    /// 分区内字段。
    #[serde(default)]
    pub fields: Vec<PuxSectionField>,
}

/// 分区字段（`title` 官方键 + `name` 合成样本键双兼容）。
#[derive(Debug, Deserialize)]
pub struct PuxSectionField {
    /// 字段名。
    #[serde(default, alias = "name")]
    pub title: Option<String>,
    /// 语义标识（可选）。
    #[serde(default)]
    pub designation: Option<String>,
    /// 字段类型码（官方 `fieldType`，合成样本 `type`）。
    #[serde(default, rename = "fieldType", alias = "type")]
    pub field_type: Option<String>,
    /// 字段值（类型化对象或标量，见映射层分派）。
    #[serde(default)]
    pub value: Option<Value>,
}

/// 附件形态 B（官方）：`details.documentAttributes`。
#[derive(Debug, Deserialize)]
pub struct PuxDocumentAttributes {
    /// 文档 ID（zip 条目为 `files/<documentId>___<fileName>` 形态，
    /// 分隔符不硬编码——按 `files/<documentId>` 前缀枚举命中）。
    #[serde(default, rename = "documentId")]
    pub document_id: Option<String>,
    /// 文件名（明文）。
    #[serde(default, rename = "fileName")]
    pub file_name: Option<String>,
    /// 解密后大小（字节）。
    #[serde(default, rename = "decryptedSize")]
    pub decrypted_size: Option<i64>,
}

/// 附件形态 A（合成样本）：`item.file`。
#[derive(Debug, Deserialize)]
pub struct PuxFileEntry {
    /// 文件元数据。
    #[serde(default)]
    pub attrs: Option<PuxFileEntryAttrs>,
    /// ZIP 内相对路径（如 `files/doc1.pdf`）。
    #[serde(default)]
    pub path: Option<String>,
}

/// 形态 A 的文件元数据。
#[derive(Debug, Deserialize)]
pub struct PuxFileEntryAttrs {
    /// 文件名（明文）。
    #[serde(default, rename = "fileName")]
    pub file_name: Option<String>,
    /// 文件大小（字节）。
    #[serde(default)]
    pub size: Option<i64>,
}

/// 归一化后的附件引用（两种形态统一，映射层产物）。
///
/// `zip_entry_hint` 是解析层定位 ZIP 条目的线索：形态 A 为精确路径；
/// 形态 B 为 `files/<documentId>` 前缀（分隔符不硬编码，前缀枚举命中）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuxFileRef {
    /// 文件名（明文；落库为 `enc_filename` 明文来源）。
    pub filename: String,
    /// 官方形态的 documentId；合成样本形态为 `None`。
    pub document_id: Option<String>,
    /// 明文大小（字节；两形态都可能缺失）。
    pub size: Option<i64>,
    /// ZIP 条目定位线索。
    pub zip_entry_hint: String,
}
