//! 跨 FFI 数据类型（`Record` / `Enum`）与双向转换（docs/07 §2.3 types.rs）。
//!
//! ## 设计要点
//!
//! - **时间戳统一 `i64` Unix 秒**（规避 UniFFI u64 ↔ Swift UInt 与 Kotlin
//!   无符号坑，docs/07 §2.3 / docs/02 §5）。
//! - **敏感值暴露面**：读侧 `ItemDetails` 中 `Concealed` 字段只回掩码
//!   （`value = None`，docs/07 §4.2），真实值仅经 `get_field_value` /
//!   `totp_code` 按需取；写侧 `FfiTotpDraft.secret` 为共享密钥原始字节
//!   （建条目必须写入，Swift 侧 `Data`，随用随弃）。
//! - 上游 `cf_domain` / `cf-session` 类型不派生 UniFFI（分层禁止反向
//!   依赖），故此处逐一定义镜像类型并显式双向转换——转换即映射表，
//!   上游加字段时编译器会在此暴露遗漏。

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory as DomainItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{ItemDraft, ItemState, ItemSummary};
use cf_domain::totp_data::{TotpAlgo, TotpData, TotpUpdate};
use cf_domain::vault::Vault as DomainVaultBrief;
use cf_session::types::{
    FieldDetail, ItemDetails, SectionDetail, TotpCode, TotpDetail, UrlDetail, VaultInfo,
};
use cf_store::ItemListFilter as DomainItemListFilter;

use crate::error::FfiError;

// ============================================================ 枚举镜像

/// 条目状态镜像（docs/03 §3.1 items.state 0/1/2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiItemState {
    /// 正常
    Active,
    /// 已归档
    Archived,
    /// 回收站
    Trashed,
}

impl From<ItemState> for FfiItemState {
    fn from(s: ItemState) -> Self {
        match s {
            ItemState::Active => Self::Active,
            ItemState::Archived => Self::Archived,
            ItemState::Trashed => Self::Trashed,
        }
    }
}

impl From<FfiItemState> for ItemState {
    fn from(s: FfiItemState) -> Self {
        match s {
            FfiItemState::Active => Self::Active,
            FfiItemState::Archived => Self::Archived,
            FfiItemState::Trashed => Self::Trashed,
        }
    }
}

/// 条目类别镜像（22 类 + Custom 兜底，docs/03 §4.1 全表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiItemCategory {
    /// 登录
    Login,
    /// 密码
    Password,
    /// API 凭据
    ApiCredential,
    /// 服务器
    Server,
    /// 数据库
    Database,
    /// 信用卡
    CreditCard,
    /// 会员
    Membership,
    /// 护照
    Passport,
    /// 软件许可证
    SoftwareLicense,
    /// 户外许可
    OutdoorLicense,
    /// 安全笔记
    SecureNote,
    /// 无线路由器
    WirelessRouter,
    /// 银行账户
    BankAccount,
    /// 驾照
    DriverLicense,
    /// 身份
    Identity,
    /// 奖励计划
    RewardProgram,
    /// 文档
    Document,
    /// 邮箱账户
    EmailAccount,
    /// 社保号
    SocialSecurityNumber,
    /// 医疗记录
    MedicalRecord,
    /// SSH 密钥
    SshKey,
    /// 加密钱包
    CryptoWallet,
    /// 联系人
    Person,
    /// 未知类别兜底
    Custom,
}

impl From<DomainItemCategory> for FfiItemCategory {
    fn from(c: DomainItemCategory) -> Self {
        match c {
            DomainItemCategory::Login => Self::Login,
            DomainItemCategory::Password => Self::Password,
            DomainItemCategory::ApiCredential => Self::ApiCredential,
            DomainItemCategory::Server => Self::Server,
            DomainItemCategory::Database => Self::Database,
            DomainItemCategory::CreditCard => Self::CreditCard,
            DomainItemCategory::Membership => Self::Membership,
            DomainItemCategory::Passport => Self::Passport,
            DomainItemCategory::SoftwareLicense => Self::SoftwareLicense,
            DomainItemCategory::OutdoorLicense => Self::OutdoorLicense,
            DomainItemCategory::SecureNote => Self::SecureNote,
            DomainItemCategory::WirelessRouter => Self::WirelessRouter,
            DomainItemCategory::BankAccount => Self::BankAccount,
            DomainItemCategory::DriverLicense => Self::DriverLicense,
            DomainItemCategory::Identity => Self::Identity,
            DomainItemCategory::RewardProgram => Self::RewardProgram,
            DomainItemCategory::Document => Self::Document,
            DomainItemCategory::EmailAccount => Self::EmailAccount,
            DomainItemCategory::SocialSecurityNumber => Self::SocialSecurityNumber,
            DomainItemCategory::MedicalRecord => Self::MedicalRecord,
            DomainItemCategory::SshKey => Self::SshKey,
            DomainItemCategory::CryptoWallet => Self::CryptoWallet,
            DomainItemCategory::Person => Self::Person,
            DomainItemCategory::Custom => Self::Custom,
        }
    }
}

impl From<FfiItemCategory> for DomainItemCategory {
    fn from(c: FfiItemCategory) -> Self {
        match c {
            FfiItemCategory::Login => Self::Login,
            FfiItemCategory::Password => Self::Password,
            FfiItemCategory::ApiCredential => Self::ApiCredential,
            FfiItemCategory::Server => Self::Server,
            FfiItemCategory::Database => Self::Database,
            FfiItemCategory::CreditCard => Self::CreditCard,
            FfiItemCategory::Membership => Self::Membership,
            FfiItemCategory::Passport => Self::Passport,
            FfiItemCategory::SoftwareLicense => Self::SoftwareLicense,
            FfiItemCategory::OutdoorLicense => Self::OutdoorLicense,
            FfiItemCategory::SecureNote => Self::SecureNote,
            FfiItemCategory::WirelessRouter => Self::WirelessRouter,
            FfiItemCategory::BankAccount => Self::BankAccount,
            FfiItemCategory::DriverLicense => Self::DriverLicense,
            FfiItemCategory::Identity => Self::Identity,
            FfiItemCategory::RewardProgram => Self::RewardProgram,
            FfiItemCategory::Document => Self::Document,
            FfiItemCategory::EmailAccount => Self::EmailAccount,
            FfiItemCategory::SocialSecurityNumber => Self::SocialSecurityNumber,
            FfiItemCategory::MedicalRecord => Self::MedicalRecord,
            FfiItemCategory::SshKey => Self::SshKey,
            FfiItemCategory::CryptoWallet => Self::CryptoWallet,
            FfiItemCategory::Person => Self::Person,
            FfiItemCategory::Custom => Self::Custom,
        }
    }
}

/// 字段数据类型镜像（docs/03 §4.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFieldType {
    /// 单行文本
    Text,
    /// 需掩码显示（密码类）
    Concealed,
    /// 网址
    Url,
    /// 日期
    Date,
    /// 信用卡有效期 YYYY/MM
    MonthYear,
    /// 布尔
    Bool,
    /// 多行文本（备注）
    Multiline,
    /// 邮箱
    Email,
    /// 电话
    Phone,
    /// 数字
    Number,
    /// TOTP 一次性口令
    Totp,
    /// 导入时未知类型
    Unsupported,
}

impl From<FieldType> for FfiFieldType {
    fn from(t: FieldType) -> Self {
        match t {
            FieldType::Text => Self::Text,
            FieldType::Concealed => Self::Concealed,
            FieldType::Url => Self::Url,
            FieldType::Date => Self::Date,
            FieldType::MonthYear => Self::MonthYear,
            FieldType::Bool => Self::Bool,
            FieldType::Multiline => Self::Multiline,
            FieldType::Email => Self::Email,
            FieldType::Phone => Self::Phone,
            FieldType::Number => Self::Number,
            FieldType::Totp => Self::Totp,
            FieldType::Unsupported => Self::Unsupported,
        }
    }
}

impl From<FfiFieldType> for FieldType {
    fn from(t: FfiFieldType) -> Self {
        match t {
            FfiFieldType::Text => Self::Text,
            FfiFieldType::Concealed => Self::Concealed,
            FfiFieldType::Url => Self::Url,
            FfiFieldType::Date => Self::Date,
            FfiFieldType::MonthYear => Self::MonthYear,
            FfiFieldType::Bool => Self::Bool,
            FfiFieldType::Multiline => Self::Multiline,
            FfiFieldType::Email => Self::Email,
            FfiFieldType::Phone => Self::Phone,
            FfiFieldType::Number => Self::Number,
            FfiFieldType::Totp => Self::Totp,
            FfiFieldType::Unsupported => Self::Unsupported,
        }
    }
}

/// 字段语义标识镜像（docs/03 §4.2）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDesignation {
    /// 用户名
    Username,
    /// 密码
    Password,
    /// TOTP
    Totp,
    /// 备注
    NotesPlain,
    /// 邮箱
    Email,
    /// 保留原始 designation 字符串（1Password 无损往返）
    Other {
        /// 原始 designation 字符串
        value: String,
    },
}

impl From<Designation> for FfiDesignation {
    fn from(d: Designation) -> Self {
        match d {
            Designation::Username => Self::Username,
            Designation::Password => Self::Password,
            Designation::Totp => Self::Totp,
            Designation::NotesPlain => Self::NotesPlain,
            Designation::Email => Self::Email,
            Designation::Other(s) => Self::Other { value: s },
        }
    }
}

impl From<FfiDesignation> for Designation {
    fn from(d: FfiDesignation) -> Self {
        match d {
            FfiDesignation::Username => Self::Username,
            FfiDesignation::Password => Self::Password,
            FfiDesignation::Totp => Self::Totp,
            FfiDesignation::NotesPlain => Self::NotesPlain,
            FfiDesignation::Email => Self::Email,
            FfiDesignation::Other { value } => Self::Other(value),
        }
    }
}

// ============================================================ 库级

/// 库元数据（只读 header.json 非敏感字段，docs/03 §1.3）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultBrief {
    /// 库 UUID（UUIDv7 文本）
    pub vault_uuid: String,
    /// 展示名（锁定时也可见）
    pub display_name: String,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）
    pub modified_at: i64,
    /// 容器格式版本
    pub format_version: u16,
}

impl From<DomainVaultBrief> for FfiVaultBrief {
    fn from(v: DomainVaultBrief) -> Self {
        Self {
            vault_uuid: v.uuid.to_string(),
            display_name: v.display_name,
            created_at: v.created_at,
            modified_at: v.modified_at,
            format_version: v.format_version,
        }
    }
}

/// 解锁成功后的库信息（docs/07 §2.3 `VaultSession.unlock` 返回值）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultInfo {
    /// 库 UUID（UUIDv7 文本）
    pub vault_uuid: String,
    /// 库显示名
    pub display_name: String,
    /// 条目计数（meta.item_count）
    pub item_count: i64,
}

impl From<VaultInfo> for FfiVaultInfo {
    fn from(i: VaultInfo) -> Self {
        Self {
            vault_uuid: i.vault_uuid,
            display_name: i.display_name,
            item_count: i.item_count,
        }
    }
}

/// FR-14.4 本地诊断摘要（FFI 镜像，docs/22 §3.4；docs/23 §1.5 TC-DIAG 组）。
///
/// **字段集白名单**（FR-14.4 红线，docs/23 §1.5 TC-DIAG-03）：只含计数 /
/// 时间 / uuid 前缀类非敏感字段——结构上不存在密码明文 / 条目标题 /
/// secret / 密钥材料读路径（非仅 UI 不展示）。新增字段须经
/// `tests/diag_ffi_semantics.rs` 白名单钉住测试（编译期穷尽构造）复核。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDiagnosticSummary {
    /// 条目数（`meta.item_count`）
    pub item_count: i64,
    /// 附件数（`attachments` 表行数；纯计数）
    pub attachment_count: i64,
    /// 库创建时间（`header.created_at`，Unix 秒 UTC）
    pub vault_created_at: i64,
    /// 最后成功备份时间（Unix 秒；从未备份为 `None`）
    pub last_backup_at: Option<i64>,
    /// 库 UUID 前 8 字符前缀（非敏感）
    pub vault_uuid_prefix: String,
}

impl From<cf_session::DiagnosticSummary> for FfiDiagnosticSummary {
    fn from(s: cf_session::DiagnosticSummary) -> Self {
        Self {
            item_count: s.item_count,
            attachment_count: s.attachment_count,
            vault_created_at: s.vault_created_at,
            last_backup_at: s.last_backup_at,
            vault_uuid_prefix: s.vault_uuid_prefix,
        }
    }
}

// ============================================================ 列表过滤

/// 条目列表过滤（docs/07 §2.3 `ItemFilter`）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemFilter {
    /// 按状态过滤；`None` 不过滤
    pub state: Option<FfiItemState>,
    /// 按类别过滤；`None` 不过滤
    pub category: Option<FfiItemCategory>,
    /// 分页偏移；`None` 视为 0
    pub offset: Option<i64>,
    /// 每页上限；`None` 不限量
    pub limit: Option<i64>,
}

impl From<FfiItemFilter> for DomainItemListFilter {
    fn from(f: FfiItemFilter) -> Self {
        Self {
            state: f.state.map(ItemState::from),
            category: f.category.map(DomainItemCategory::from),
            offset: f.offset,
            limit: f.limit,
        }
    }
}

// ============================================================ 条目读侧

/// 条目摘要（列表 / 搜索结果）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemSummary {
    /// 条目 ID（UUIDv7 文本）
    pub uuid: String,
    /// 类别
    pub category: FfiItemCategory,
    /// 状态
    pub state: FfiItemState,
    /// 是否收藏
    pub is_favorite: bool,
    /// 最后修改时间（Unix 秒 UTC）
    pub updated_at: i64,
    /// 标题（已解密）
    pub title: String,
}

impl From<ItemSummary> for FfiItemSummary {
    fn from(s: ItemSummary) -> Self {
        Self {
            uuid: s.uuid.to_string(),
            category: s.category.into(),
            state: s.state.into(),
            is_favorite: s.is_favorite,
            updated_at: s.updated_at,
            title: s.title,
        }
    }
}

/// URL 读取态。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiUrlDetail {
    /// URL 行 ID
    pub uuid: String,
    /// 标签，可为空
    pub label: Option<String>,
    /// URL 明文
    pub url: String,
    /// 是否主 URL
    pub is_primary: bool,
    /// 排序位置
    pub position: i64,
}

/// 分区读取态。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSectionDetail {
    /// 分区 ID
    pub uuid: String,
    /// 分区标题
    pub title: String,
    /// 排序位置
    pub position: i64,
}

/// 字段读取态。
///
/// **掩码纪律**（docs/07 §4.2）：`field_type == Concealed` 时 `value`
/// 恒为 `None`——真实值仅经 `get_field_value(item_id, field_id)` 按需取。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFieldDetail {
    /// 字段 ID
    pub uuid: String,
    /// 所属分区；`None` 表示直接挂在条目下
    pub section_uuid: Option<String>,
    /// 字段数据类型
    pub field_type: FfiFieldType,
    /// 语义标识，可为空
    pub designation: Option<FfiDesignation>,
    /// 字段名
    pub name: String,
    /// 字段值（Concealed 恒为 `None`，见掩码纪律）
    pub value: Option<String>,
    /// 排序位置
    pub position: i64,
}

/// TOTP 元数据读取态（刻意不含共享密钥：验证码经 `totp_code` 按需生成）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTotpDetail {
    /// TOTP 记录 ID
    pub uuid: String,
    /// 哈希算法（运行时仅支持 sha1）
    pub algo: String,
    /// 口令位数（6 或 8）
    pub digits: u8,
    /// 时间窗口秒数
    pub period: u32,
    /// 发行方显示名（可选）
    pub issuer: Option<String>,
    /// 账户名（可选）
    pub account: Option<String>,
}

/// TOTP 元数据读取态（`totpConfig` 专用；刻意不含共享密钥，也不含记录
/// ID —— 供编辑界面展示「已有 TOTP（SHA-1 · 6 位 · 30s）」并默认保留）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTotpMeta {
    /// 哈希算法（运行时仅支持 sha1）
    pub algo: String,
    /// 口令位数（6 或 8）
    pub digits: u8,
    /// 时间窗口秒数
    pub period: u32,
    /// 发行方显示名（可选）
    pub issuer: Option<String>,
    /// 账户名（可选）
    pub account: Option<String>,
}

impl From<TotpDetail> for FfiTotpMeta {
    fn from(t: TotpDetail) -> Self {
        Self {
            algo: t.algo,
            digits: t.digits,
            period: t.period,
            issuer: t.issuer,
            account: t.account,
        }
    }
}

/// 条目完整详情（docs/07 §2.3 `ItemDetails`）。
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiItemDetails {
    /// 条目 ID
    pub uuid: String,
    /// 类别
    pub category: FfiItemCategory,
    /// 状态
    pub state: FfiItemState,
    /// 是否收藏
    pub is_favorite: bool,
    /// 收藏排序索引
    pub fav_index: i64,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）
    pub updated_at: i64,
    /// 标题
    pub title: String,
    /// URL 列表
    pub urls: Vec<FfiUrlDetail>,
    /// 标签
    pub tags: Vec<String>,
    /// 分区列表
    pub sections: Vec<FfiSectionDetail>,
    /// 字段列表（Concealed 值已掩码，见 [`FfiFieldDetail`]）
    pub fields: Vec<FfiFieldDetail>,
    /// TOTP 元数据（若有）
    pub totp: Option<FfiTotpDetail>,
}

impl From<FieldDetail> for FfiFieldDetail {
    fn from(f: FieldDetail) -> Self {
        // 掩码纪律：Concealed 字段值不下发（docs/07 §4.2 第 1 条）
        let value = if f.field_type == FieldType::Concealed {
            None
        } else {
            f.value.map(|v| v.expose().to_owned())
        };
        Self {
            uuid: f.uuid.clone(),
            section_uuid: f.section_uuid,
            field_type: f.field_type.into(),
            designation: f.designation.map(Into::into),
            name: f.name.expose().to_owned(),
            value,
            position: f.position,
        }
    }
}

impl From<UrlDetail> for FfiUrlDetail {
    fn from(u: UrlDetail) -> Self {
        Self {
            uuid: u.uuid.clone(),
            label: u.label.map(|l| l.expose().to_owned()),
            url: u.url.expose().to_owned(),
            is_primary: u.is_primary,
            position: u.position,
        }
    }
}

impl From<SectionDetail> for FfiSectionDetail {
    fn from(s: SectionDetail) -> Self {
        Self {
            uuid: s.uuid.clone(),
            title: s.title.expose().to_owned(),
            position: s.position,
        }
    }
}

impl From<TotpDetail> for FfiTotpDetail {
    fn from(t: TotpDetail) -> Self {
        Self {
            uuid: t.uuid,
            algo: t.algo,
            digits: t.digits,
            period: t.period,
            issuer: t.issuer,
            account: t.account,
        }
    }
}

impl From<ItemDetails> for FfiItemDetails {
    fn from(i: ItemDetails) -> Self {
        Self {
            uuid: i.uuid,
            category: i.category.into(),
            state: i.state.into(),
            is_favorite: i.is_favorite,
            fav_index: i.fav_index,
            created_at: i.created_at,
            updated_at: i.updated_at,
            title: i.title.expose().to_owned(),
            urls: i.urls.into_iter().map(Into::into).collect(),
            tags: i.tags.iter().map(|t| t.expose().to_owned()).collect(),
            sections: i.sections.into_iter().map(Into::into).collect(),
            fields: i.fields.into_iter().map(Into::into).collect(),
            totp: i.totp.map(Into::into),
        }
    }
}

// ============================================================ 条目写侧

/// URL 草稿。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiUrlDraft {
    /// 标签，可为空
    pub label: Option<String>,
    /// URL
    pub url: String,
    /// 是否主 URL
    pub is_primary: bool,
    /// 排序位置
    pub position: i32,
}

/// 分区草稿。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSectionDraft {
    /// 分区标题
    pub title: String,
    /// 排序位置
    pub position: i32,
}

/// 字段草稿。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFieldDraft {
    /// 字段名
    pub name: String,
    /// 字段值，可空
    pub value: Option<String>,
    /// 字段数据类型
    pub field_type: FfiFieldType,
    /// 语义标识，可为空
    pub designation: Option<FfiDesignation>,
    /// 所属分区下标（指向 sections 列表；`None` 直接挂条目下）
    pub section_index: Option<i64>,
    /// 排序位置
    pub position: i32,
}

/// TOTP 草稿（共享密钥以原始字节跨 FFI：建条目必须写入，随用随弃）。
///
/// 算法固定 SHA-1——v0.1 仅支持 SHA-1（cf-session 显式拒绝其余算法）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTotpDraft {
    /// 共享密钥原始字节（≥ 10 字节）
    pub secret: Vec<u8>,
    /// 口令位数（6 或 8）
    pub digits: u8,
    /// 时间窗口秒数
    pub period: u32,
    /// 发行方（可选，UI 展示用）
    pub issuer: Option<String>,
    /// 账户名（可选）
    pub account: Option<String>,
}

impl From<cf_importer::OtpauthData> for FfiTotpDraft {
    fn from(o: cf_importer::OtpauthData) -> Self {
        Self {
            secret: o.secret,
            digits: o.digits,
            period: o.period,
            issuer: o.issuer,
            account: o.account,
        }
    }
}

impl FfiTotpDraft {
    /// → 领域 [`TotpData`]（算法固定 SHA-1，校验交给 validate_item）。
    #[must_use]
    pub fn to_domain(&self) -> TotpData {
        TotpData {
            secret: self.secret.clone(),
            algo: TotpAlgo::Sha1,
            digits: self.digits,
            period: self.period,
        }
    }
}

/// TOTP 更新三态（**更新路径专用**，`updateItemWithTotp` 参数）。
///
/// 背景：FFI 刻意不下发 TOTP secret（安全设计），编辑条目时调用方
/// 无法「重提交」原密钥，`Option` 草稿的 `None` 又无法区分「删 / 留」。
/// 故更新路径用显式三态：
///
/// - `keep`：保留既有加密行（**默认**，secret 不出会话层）；
/// - `replace { draft }`：粘贴了新 otpauth URI，删旧插新；
/// - `remove`：显式移除既有 TOTP。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiTotpUpdate {
    /// 保留既有 TOTP（编辑入口默认）
    Keep,
    /// 删旧插新：写入新配置
    Replace {
        /// 新 TOTP 配置（共享密钥原始字节，随用随弃）
        draft: FfiTotpDraft,
    },
    /// 移除既有 TOTP
    Remove,
}

impl FfiTotpUpdate {
    /// → 领域 [`TotpUpdate`]（Replace 载荷校验交给 cf-session 编排层）。
    #[must_use]
    pub fn to_domain(&self) -> TotpUpdate {
        match self {
            Self::Keep => TotpUpdate::Keep,
            Self::Replace { draft } => TotpUpdate::Replace(draft.to_domain()),
            Self::Remove => TotpUpdate::Remove,
        }
    }
}

/// 条目创建/更新草稿（docs/07 §2.3 `ItemDraft`）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemDraft {
    /// 标题（非空、≤ 512 字符）
    pub title: String,
    /// 条目类别
    pub category: FfiItemCategory,
    /// URL 草稿列表
    pub urls: Vec<FfiUrlDraft>,
    /// 标签列表
    pub tags: Vec<String>,
    /// 分区草稿列表
    pub sections: Vec<FfiSectionDraft>,
    /// 字段草稿列表
    pub fields: Vec<FfiFieldDraft>,
    /// TOTP 配置（若有；`createItem` 路径用。更新路径请走
    /// `updateItemWithTotp` 的三态参数 —— 本字段在更新时被忽略）
    pub totp: Option<FfiTotpDraft>,
}

impl FfiItemDraft {
    /// → 领域 [`ItemDraft`]（校验在 cf-session 编排层前置执行）。
    ///
    /// # Errors
    ///
    /// `section_index` 越界（< 0 或超出 usize）→ `FfiError`（5002）。
    pub fn to_domain(&self) -> Result<ItemDraft, FfiError> {
        let section_index = |idx: i64| -> Result<usize, FfiError> {
            usize::try_from(idx).map_err(|_| {
                FfiError::from(cf_domain::CfError::InvalidArgument(
                    "field section_index out of range".into(),
                ))
            })
        };
        Ok(ItemDraft {
            title: self.title.clone(),
            category: self.category.into(),
            urls: self
                .urls
                .iter()
                .map(|u| cf_domain::item::UrlDraft {
                    label: u.label.clone(),
                    url: u.url.clone(),
                    is_primary: u.is_primary,
                    position: u.position,
                })
                .collect(),
            tags: self.tags.clone(),
            sections: self
                .sections
                .iter()
                .map(|s| cf_domain::item::SectionDraft {
                    title: s.title.clone(),
                    position: s.position,
                })
                .collect(),
            fields: self
                .fields
                .iter()
                .map(|f| {
                    Ok(cf_domain::item::FieldDraft {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        field_type: f.field_type.into(),
                        designation: f.designation.clone().map(Into::into),
                        section_index: f.section_index.map(section_index).transpose()?,
                        position: f.position,
                    })
                })
                .collect::<Result<Vec<_>, FfiError>>()?,
            totp: self.totp.as_ref().map(FfiTotpDraft::to_domain),
        })
    }
}

// ============================================================ 取值与生成器

/// TOTP 当前验证码。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTotpCode {
    /// 当前验证码（6 或 8 位数字）
    pub code: String,
    /// 距下一个时间窗口的剩余秒数（倒计时环）
    pub secs_remaining: i64,
}

impl From<TotpCode> for FfiTotpCode {
    fn from(c: TotpCode) -> Self {
        Self {
            code: c.code,
            secs_remaining: i64::try_from(c.secs_remaining).unwrap_or(i64::MAX),
        }
    }
}

/// 密码生成器参数（docs/07 §2.3 `PasswordGenOptions`）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasswordGenOptions {
    /// 密码长度（字符数）
    pub length: u32,
    /// 包含数字
    pub numbers: bool,
    /// 包含小写字母
    pub lowercase_letters: bool,
    /// 包含大写字母
    pub uppercase_letters: bool,
    /// 包含符号
    pub symbols: bool,
    /// 排除易混淆字符（`iI1loO0"'`|`）
    pub exclude_similar_characters: bool,
}

impl TryFrom<FfiPasswordGenOptions> for cf_audit::PasswordGenOptions {
    type Error = FfiError;

    fn try_from(o: FfiPasswordGenOptions) -> Result<Self, FfiError> {
        Ok(Self {
            length: usize::try_from(o.length).map_err(|_| {
                FfiError::from(cf_domain::CfError::InvalidArgument(
                    "password length out of range".into(),
                ))
            })?,
            numbers: o.numbers,
            lowercase_letters: o.lowercase_letters,
            uppercase_letters: o.uppercase_letters,
            symbols: o.symbols,
            exclude_similar_characters: o.exclude_similar_characters,
        })
    }
}

/// 密码短语生成参数（FR-3.3，docs/15 §3.3.4；镜像
/// `cf_audit::PassphraseOptions`，usize 不跨 FFI → wordCount 用 u32）。
///
/// 门禁：词数 3..=10、分隔符 1..=3 个可打印字符，越界 → 码 1012
/// （内核校验）。wordCount 的 u32→usize 转换溢出 → 码 5002
/// （[`TryFrom`] 实现的防御性路径，64 位平台不可达）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPassphraseOptions {
    /// 词数（3..=10）。
    pub word_count: u32,
    /// 词间分隔符（1..=3 个可打印字符）。
    pub separator: String,
    /// 词首大写（Title Case）。
    pub capitalize: bool,
    /// 末尾追加随机数字 0–9。
    pub number_suffix: bool,
}

impl TryFrom<FfiPassphraseOptions> for cf_audit::PassphraseOptions {
    type Error = FfiError;

    fn try_from(o: FfiPassphraseOptions) -> Result<Self, FfiError> {
        Ok(Self {
            word_count: usize::try_from(o.word_count).map_err(|_| {
                FfiError::from(cf_domain::CfError::InvalidArgument(
                    "passphrase word count out of range".into(),
                ))
            })?,
            separator: o.separator,
            capitalize: o.capitalize,
            number_suffix: o.number_suffix,
        })
    }
}

/// 密码强度评估结果（docs/07 §2.3 `StrengthEstimate`）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiStrengthEstimate {
    /// zxcvbn 分数 0–4（≥ 3 可用于建库门禁）
    pub score: u8,
    /// 改进建议（zxcvbn feedback；英文原文，UI 可自行本地化）
    pub warnings: Vec<String>,
}

// ============================================================ 导出与备份

/// Argon2id KDF 档位（FR-1.8 改密可选升级，docs/09 §3.2）。
///
/// 与 header `kdf` 节同构；合法性（`m_cost_kib >= 8 MiB` 等）由
/// `cf_crypto::kdf::KdfParams::new` 在 `to_domain` 时校验，越界 → 5002。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiKdfParams {
    /// 内存成本（KiB）
    pub m_cost_kib: u32,
    /// 时间成本（迭代次数）
    pub t_cost: u32,
    /// 并行度
    pub p_cost: u32,
}

impl FfiKdfParams {
    /// → 领域 [`cf_crypto::kdf::KdfParams`]（越界 → 5002）。
    ///
    /// # Errors
    ///
    /// 参数超出 cf-crypto 允许范围 → `FfiError`（5002 InvalidArgument）。
    pub fn to_domain(&self) -> Result<KdfParams, FfiError> {
        KdfParams::new(self.m_cost_kib, self.t_cost, self.p_cost).map_err(|_| {
            FfiError::from(cf_domain::CfError::InvalidArgument(
                "kdf params out of range".into(),
            ))
        })
    }
}

/// 加密备份导出结果（FR-8.1，docs/09 §3.1 冻结契约镜像）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBackupExportResult {
    /// 备份文件路径
    pub file_path: String,
    /// 打包的文件数（不含目录条目）
    pub file_count: u64,
    /// 备份文件字节数
    pub size_bytes: u64,
    /// 导出后自动执行了一次结构校验（FR-8.6）且通过
    pub verified: bool,
}

impl From<cf_exporter::BackupExportResult> for FfiBackupExportResult {
    fn from(r: cf_exporter::BackupExportResult) -> Self {
        Self {
            file_path: r.file_path.to_string_lossy().into_owned(),
            file_count: u64::try_from(r.file_count).unwrap_or(u64::MAX),
            size_bytes: r.size_bytes,
            verified: r.verified,
        }
    }
}

/// 备份结构校验报告（FR-8.6，docs/09 §3.1 冻结契约镜像）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBackupVerifyReport {
    /// 包内 `header.json` 声明的库 UUID
    pub vault_uuid: String,
    /// 包内声明的容器格式版本（恒为当前支持版本）
    pub format_version: u16,
    /// 包内文件条目数（不含目录条目）
    pub file_count: u64,
}

impl From<cf_exporter::BackupVerifyReport> for FfiBackupVerifyReport {
    fn from(r: cf_exporter::BackupVerifyReport) -> Self {
        Self {
            vault_uuid: r.vault_uuid,
            format_version: r.format_version,
            file_count: u64::try_from(r.file_count).unwrap_or(u64::MAX),
        }
    }
}

/// 疑似公式注入单元格（CSV 预检；原值保留仅告警，docs/07 §3.2）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFormulaCell {
    /// 文件行号（1 起、表头为第 1 行）
    pub row: u32,
    /// 列名
    pub column: String,
}

/// CSV 预检报告（docs/07 §3.3 最小形态）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCsvPrecheckReport {
    /// 数据行总数（不含表头，含全空行）
    pub total_rows: u32,
    /// 可导入行数
    pub valid_rows: u32,
    /// 全空行号
    pub skipped_rows: Vec<u32>,
    /// 缺失 Title 的行号
    pub rows_without_title: Vec<u32>,
    /// otpauth 解析失败的行号（行仍导入，值并入 Notes）
    pub rows_with_bad_totp: Vec<u32>,
    /// 未识别的数据列名
    pub unmapped_columns: Vec<String>,
    /// 疑似公式注入单元格
    pub formula_like_cells: Vec<FfiFormulaCell>,
    /// 告警文本
    pub warnings: Vec<String>,
}

impl From<cf_importer::CsvPrecheckReport> for FfiCsvPrecheckReport {
    fn from(r: cf_importer::CsvPrecheckReport) -> Self {
        Self {
            total_rows: r.total_rows,
            valid_rows: r.valid_rows,
            skipped_rows: r.skipped_rows,
            rows_without_title: r.rows_without_title,
            rows_with_bad_totp: r.rows_with_bad_totp,
            unmapped_columns: r.unmapped_columns,
            formula_like_cells: r
                .formula_like_cells
                .into_iter()
                .map(|(row, column)| FfiFormulaCell { row, column })
                .collect(),
            warnings: r.warnings,
        }
    }
}

/// CSV 导入结果（v0.1 固定「全部新建」策略）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiCsvImportResult {
    /// 实际导入（新建）的条目数
    pub imported_rows: u32,
}

impl From<cf_importer::CsvImportResult> for FfiCsvImportResult {
    fn from(r: cf_importer::CsvImportResult) -> Self {
        Self {
            imported_rows: r.imported_rows,
        }
    }
}

// ---------------------------------------------- CSV 导出（FR-8.3，v0.2.0-T06）

/// CSV 明文导出结果（`cf_exporter::CsvExportResult` 映射）。
#[derive(uniffi::Record)]
pub struct FfiCsvExportResult {
    /// 实际写入的数据行数（不含表头）。
    pub row_count: u64,
    /// 因处于回收站而跳过的条目数。
    pub skipped_trashed: u64,
}

impl From<cf_exporter::CsvExportResult> for FfiCsvExportResult {
    fn from(r: cf_exporter::CsvExportResult) -> Self {
        Self {
            row_count: r.row_count as u64,
            skipped_trashed: r.skipped_trashed as u64,
        }
    }
}

// ------------------------------------- 1PUX 导出（FR-8.2，v0.7.0-T04）

/// 1PUX 导出降级报告（`cf_exporter::PuxExportReport` 映射；TC-EXP-06/14
/// 素材，不静默）。
#[derive(uniffi::Record)]
pub struct FfiPuxExportReport {
    /// 无 1P 承载码而降级为 Text 的字段（`条目uuid:字段名`）。
    pub degraded_fields: Vec<String>,
    /// 非 SHA-1 TOTP 导出数（跨导入方可能不支持而降级）。
    pub non_sha1_totp: u64,
}

impl From<cf_exporter::PuxExportReport> for FfiPuxExportReport {
    fn from(r: cf_exporter::PuxExportReport) -> Self {
        Self {
            degraded_fields: r.degraded_fields,
            non_sha1_totp: r.non_sha1_totp as u64,
        }
    }
}

/// 1PUX 明文导出结果（`cf_exporter::PuxExportResult` 映射；usize 不跨界，
/// 计数统一 u64，对齐 [`FfiCsvExportResult`] 先例）。
#[derive(uniffi::Record)]
pub struct FfiPuxExportResult {
    /// 实际导出条目数（不含回收站跳过）。
    pub item_count: u64,
    /// 导出附件文件数。
    pub attachment_count: u64,
    /// 因处于回收站而跳过的条目数。
    pub skipped_trashed: u64,
    /// 因不支持导出而跳过的 passkey 数（显式计数，不静默）。
    pub skipped_passkeys: u64,
    /// 降级 / 非 SHA-1 TOTP 的显式报告。
    pub report: FfiPuxExportReport,
}

impl From<cf_exporter::PuxExportResult> for FfiPuxExportResult {
    fn from(r: cf_exporter::PuxExportResult) -> Self {
        Self {
            item_count: r.item_count as u64,
            attachment_count: r.attachment_count as u64,
            skipped_trashed: r.skipped_trashed as u64,
            skipped_passkeys: r.skipped_passkeys as u64,
            report: r.report.into(),
        }
    }
}

// -------------------------------------------- 审计日志查询（FR-12.6，v0.2.0-T06）

/// 审计事件类型（`cf_store::AuditEvent` 映射；只读——写入仅由内核动作打点）。
#[derive(uniffi::Enum)]
pub enum FfiAuditEvent {
    /// 加密备份导出成功（FR-8.1）。
    BackupExport,
    /// 备份恢复完成（FR-8.1 回环）。
    BackupRestore,
    /// CSV 明文导出成功（FR-8.3）。
    CsvExport,
    /// 1PUX 明文导出成功（FR-8.2，v0.7.0）。
    PuxExport,
    /// 修改主密码成功（FR-1.8）。
    PasswordChange,
    /// 跨库复制成功（FR-2.10，源库与目标库各一条）。
    ItemCopy,
    /// 生物识别重置主密码成功（FR-17.1，v2.5.0）。
    PasswordResetByBio,
    /// 恢复码重置主密码成功（FR-17.2，v2.5.0）。
    PasswordResetByRecovery,
    /// 启用 / 重新生成恢复码成功（FR-17.2，v2.5.0）。
    RecoveryCodeEnabled,
}

impl From<cf_store::AuditEvent> for FfiAuditEvent {
    fn from(e: cf_store::AuditEvent) -> Self {
        match e {
            cf_store::AuditEvent::BackupExport => Self::BackupExport,
            cf_store::AuditEvent::BackupRestore => Self::BackupRestore,
            cf_store::AuditEvent::CsvExport => Self::CsvExport,
            cf_store::AuditEvent::PuxExport => Self::PuxExport,
            cf_store::AuditEvent::PasswordChange => Self::PasswordChange,
            cf_store::AuditEvent::ItemCopy => Self::ItemCopy,
            cf_store::AuditEvent::PasswordResetByBio => Self::PasswordResetByBio,
            cf_store::AuditEvent::PasswordResetByRecovery => Self::PasswordResetByRecovery,
            cf_store::AuditEvent::RecoveryCodeEnabled => Self::RecoveryCodeEnabled,
        }
    }
}

/// 审计日志条目（`cf_store::AuditEntry` 映射，按时间倒序分页）。
#[derive(uniffi::Record)]
pub struct FfiAuditEntry {
    /// 行 id（自增）。
    pub id: i64,
    /// 事件时间（Unix 秒）。
    pub ts: i64,
    /// 事件类型。
    pub event: FfiAuditEvent,
    /// 非敏感上下文（如条目 UUID）；无则 `None`。
    pub detail: Option<String>,
}

impl From<cf_store::AuditEntry> for FfiAuditEntry {
    fn from(e: cf_store::AuditEntry) -> Self {
        Self {
            id: e.id,
            ts: e.ts,
            event: e.event.into(),
            detail: e.detail,
        }
    }
}

// ---------------------------------------------- 1PUX 导入（FR-7，v0.3.0-T05）

/// 类别分布单项（`PuxPrecheckReport.category_distribution` 的展开形态，
/// UniFFI 不支持元组Vec）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCategoryCount {
    /// 类别名（降级条目按 secure_note 计入）。
    pub category: String,
    /// 该类别条目数。
    pub count: u32,
}

impl From<(String, u32)> for FfiCategoryCount {
    fn from((category, count): (String, u32)) -> Self {
        Self { category, count }
    }
}

/// 未识别类别单项（E-4：降级条目计入导入成功，但预检必须 surface）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiUnknownCategory {
    /// 1PUX 原始条目 uuid。
    pub item_uuid: String,
    /// 原始 categoryUuid。
    pub category_uuid: String,
}

impl From<(String, String)> for FfiUnknownCategory {
    fn from((item_uuid, category_uuid): (String, String)) -> Self {
        Self {
            item_uuid,
            category_uuid,
        }
    }
}

/// 一条未导入项（FR-7.6 逐条列出，不静默丢弃）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotImportedItem {
    /// 1PUX 原始条目 uuid。
    pub uuid: String,
    /// 标题（缺失时为兜底标题）。
    pub title: String,
    /// 未导入原因（人类可读）。
    pub reason: String,
}

impl From<cf_importer::NotImportedItem> for FfiNotImportedItem {
    fn from(i: cf_importer::NotImportedItem) -> Self {
        Self {
            uuid: i.uuid,
            title: i.title,
            reason: i.reason,
        }
    }
}

/// 1PUX 预检报告（FR-7.4~7.7，`docs/09` v0.3.0 冻结字段镜像）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPuxPrecheckReport {
    /// 条目总数（全部 vault 合计，含 Tombstone / 附件缺失等未导入项）。
    pub total_items: u32,
    /// 可导入条目数（含未知类别降级——计入导入成功，E-4）。
    pub importable_items: u32,
    /// 按类别分布（降级条目按 secure_note 计入）。
    pub category_distribution: Vec<FfiCategoryCount>,
    /// 附件总数。
    pub attachment_count: u32,
    /// 检测到的疑似 passkey 字段数（docs/17 §4.2 PK2 增量字段，向后
    /// 兼容；1PUX 桌面导出恒为 0——恒空快速路径）。
    pub passkey_count: u32,
    /// 未识别类别清单。
    pub unknown_categories: Vec<FfiUnknownCategory>,
    /// 回收站条目数（state=trashed）。
    pub trashed_count: u32,
    /// 丢弃的密码历史条目总数（FR-2.9 语义不同构）。
    pub password_history_dropped: u32,
    /// 未识别的类型化 value 顶层 key（去重排序；值已保留不丢）。
    pub unmapped_value_types: Vec<String>,
    /// 出现 ≥ 2 次的 documentId（官方形态；导入全部保留）。
    pub duplicate_document_ids: Vec<String>,
    /// 未导入项逐条清单（FR-7.6 不静默丢弃）。
    pub not_imported: Vec<FfiNotImportedItem>,
    /// 告警文本（降级、未知状态、坏 otpauth、重复 documentId 等）。
    pub warnings: Vec<String>,
}

impl From<cf_importer::PuxPrecheckReport> for FfiPuxPrecheckReport {
    fn from(r: cf_importer::PuxPrecheckReport) -> Self {
        Self {
            total_items: r.total_items,
            importable_items: r.importable_items,
            category_distribution: r
                .category_distribution
                .into_iter()
                .map(Into::into)
                .collect(),
            attachment_count: r.attachment_count,
            passkey_count: r.passkey_count,
            unknown_categories: r.unknown_categories.into_iter().map(Into::into).collect(),
            trashed_count: r.trashed_count,
            password_history_dropped: r.password_history_dropped,
            unmapped_value_types: r.unmapped_value_types,
            duplicate_document_ids: r.duplicate_document_ids,
            not_imported: r.not_imported.into_iter().map(Into::into).collect(),
            warnings: r.warnings,
        }
    }
}

/// 已导入但降级的条目（D-6 删源建议的条目级明细）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDegradedItem {
    /// 条目 uuid 或 CSV 行号。
    pub key: String,
    /// 降级原因（人类可读）。
    pub reason: String,
}

impl From<(String, String)> for FfiDegradedItem {
    fn from((key, reason): (String, String)) -> Self {
        Self { key, reason }
    }
}

/// 源文件删除建议（FR-7.8，D-6 数据驱动裁决镜像）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSourceDeletionAdvice {
    /// 当且仅当本次导入零信息损失时为 true（可提示删除源文件）。
    pub can_delete: bool,
    /// 阻止删除的原因（人类可读，逐条，供结果页直接展示）。
    pub blockers: Vec<String>,
    /// 已导入但降级的条目。
    pub degraded_items: Vec<FfiDegradedItem>,
}

impl From<cf_importer::SourceDeletionAdvice> for FfiSourceDeletionAdvice {
    fn from(a: cf_importer::SourceDeletionAdvice) -> Self {
        Self {
            can_delete: a.can_delete,
            blockers: a.blockers,
            degraded_items: a.degraded_items.into_iter().map(Into::into).collect(),
        }
    }
}

/// 1PUX 导入结果（FR-7.7 导入结果页素材）。
///
/// `deletion_advice` 由 [`cf_importer::advise_pux_source_deletion`] 对
/// 本次导入的报告即时组装（D-6：传入预检报告而非导入结果，见其模块
/// 文档「为什么只接收预检报告」）——Swift 侧无需再调建议函数。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPuxImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（与本次导入同管线产出，FR-7.4 所见即所得）。
    pub report: FfiPuxPrecheckReport,
    /// FR-7.8 删源建议（数据驱动，D-6）。
    pub deletion_advice: FfiSourceDeletionAdvice,
}

impl From<cf_importer::PuxImportResult> for FfiPuxImportResult {
    fn from(r: cf_importer::PuxImportResult) -> Self {
        let deletion_advice = cf_importer::advise_pux_source_deletion(&r.report).into();
        Self {
            imported_items: r.imported_items,
            report: r.report.into(),
            deletion_advice,
        }
    }
}

// -------------------------------------------- OPVault 导入（FR-7.3，v0.7.0-T05）

/// 一条未导入项（TC-OPV-11：Tombstone 099 逐条列出，不静默）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotImportedOpvaultItem {
    /// 原始条目 uuid。
    pub uuid: String,
    /// 标题（结构层无密码时不可知，为空字符串）。
    pub title: String,
    /// 未导入原因（人类可读）。
    pub reason: String,
}

impl From<cf_importer::opvault::NotImportedOpvaultItem> for FfiNotImportedOpvaultItem {
    fn from(i: cf_importer::opvault::NotImportedOpvaultItem) -> Self {
        Self {
            uuid: i.uuid,
            title: i.title,
            reason: i.reason,
        }
    }
}

/// OPVault 预检报告（`cf_importer::OpvaultPrecheckReport` 映射）。
///
/// TC-OPV-05 语义偏差（docs/22 §2.2.3 显式标注）：结构字段（profile /
/// KDF 参数 / band 与附件文件数）恒填充；**全量分析字段（total/分布等）
/// 属解锁后内容，`precheck_opvault` 恒空**——完整报告由
/// [`crate::api::VaultSession::import_opvault`] 内部解密后产出。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOpvaultPrecheckReport {
    /// profile 名（`default`）。
    pub profile_name: String,
    /// profile UUID。
    pub profile_uuid: String,
    /// PBKDF2 迭代次数（KDF 参数读数）。
    pub iterations: u32,
    /// 密码提示（profile.js 明文，官方不混淆）。
    pub password_hint: Option<String>,
    /// 存在的 `band_*.js` 文件数（0~16）。
    pub band_file_count: u32,
    /// 附件文件数（out-of-scope，跳过+计数，TC-OPV-10）。
    pub attachment_count: u32,
    /// 除 `default/` 外的其他 profile 目录（列出不导入，TC-OPV-10）。
    pub other_profiles: Vec<String>,
    /// 条目总数（含 Tombstone 等未导入项）。
    pub total_items: u32,
    /// 可导入条目数（含未知类别降级——计入导入成功）。
    pub importable_items: u32,
    /// 按类别分布（降级条目按 secure_note 计入）。
    pub category_distribution: Vec<FfiCategoryCount>,
    /// 文件夹数（folders.js）。
    pub folder_count: u32,
    /// 归档（trashed）条目数。
    pub trashed_items: u32,
    /// 未识别的字段 type/k 码（去重排序；值已按 Text 降级保留）。
    pub unknown_field_types: Vec<String>,
    /// 未识别分类码清单：(条目 uuid, 原始分类码)。
    pub unknown_categories: Vec<FfiUnknownCategory>,
    /// 未导入项逐条清单（TC-OPV-11）。
    pub not_imported: Vec<FfiNotImportedOpvaultItem>,
    /// 告警文本。
    pub warnings: Vec<String>,
}

impl From<cf_importer::OpvaultPrecheckReport> for FfiOpvaultPrecheckReport {
    fn from(r: cf_importer::OpvaultPrecheckReport) -> Self {
        Self {
            profile_name: r.profile_name,
            profile_uuid: r.profile_uuid,
            iterations: r.iterations,
            password_hint: r.password_hint,
            band_file_count: r.band_file_count,
            attachment_count: r.attachment_count,
            other_profiles: r.other_profiles,
            total_items: r.total_items,
            importable_items: r.importable_items,
            category_distribution: r
                .category_distribution
                .into_iter()
                .map(Into::into)
                .collect(),
            folder_count: r.folder_count,
            trashed_items: r.trashed_items,
            unknown_field_types: r.unknown_field_types,
            unknown_categories: r.unknown_categories.into_iter().map(Into::into).collect(),
            not_imported: r.not_imported.into_iter().map(Into::into).collect(),
            warnings: r.warnings,
        }
    }
}

/// OPVault 导入结果（`cf_importer::OpvaultImportResult` 映射；TC-OPV-03
/// 密码错 2002 零落库）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOpvaultImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（与本次导入同管线产出，TC-OPV-05 完整档）。
    pub report: FfiOpvaultPrecheckReport,
}

impl From<cf_importer::OpvaultImportResult> for FfiOpvaultImportResult {
    fn from(r: cf_importer::OpvaultImportResult) -> Self {
        Self {
            imported_items: r.imported_items,
            report: r.report.into(),
        }
    }
}

// ---------------------------------------------- 条目历史（FR-2.9，v0.3.0-T05）

/// 历史版本条目（元数据镜像；快照明文不跨 FFI，回滚是唯一消费路径）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHistoryEntry {
    /// 历史行 UUID。
    pub history_uuid: String,
    /// 版本号（条目内自增，1 起）。
    pub version: i64,
    /// 快照写入时间（Unix 秒）。
    pub created_at: i64,
}

impl From<cf_session::HistoryEntry> for FfiHistoryEntry {
    fn from(e: cf_session::HistoryEntry) -> Self {
        Self {
            history_uuid: e.history_uuid,
            version: e.version,
            created_at: e.created_at,
        }
    }
}

// ---------------------------------------------- 体检报告（FR-6.7，v0.3.0-T05）

/// 泄露启发式命中规则（FR-6.5 / AUD-05 镜像）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLeakRule {
    /// 明文精确命中内置字典。
    DictionaryExact,
    /// 常见 leet 替换归一后命中字典。
    LeetNormalized,
    /// 8 位纯数字生日形态（YYYYMMDD）。
    BirthdayPattern,
    /// 包含键盘行序列（qwerty 等）。
    KeyboardSequence,
}

impl From<cf_audit::CommonPasswordRule> for FfiLeakRule {
    fn from(r: cf_audit::CommonPasswordRule) -> Self {
        match r {
            cf_audit::CommonPasswordRule::DictionaryExact => Self::DictionaryExact,
            cf_audit::CommonPasswordRule::LeetNormalized => Self::LeetNormalized,
            cf_audit::CommonPasswordRule::BirthdayPattern => Self::BirthdayPattern,
            cf_audit::CommonPasswordRule::KeyboardSequence => Self::KeyboardSequence,
        }
    }
}

/// 启发式置信度（漏报优先：只报有明确形态依据的项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLeakConfidence {
    /// 低置信度（形态启发，仅提示）。
    Low,
    /// 中置信度（leet 归一后命中字典）。
    Medium,
    /// 高置信度（明文精确命中字典）。
    High,
}

impl From<cf_audit::Confidence> for FfiLeakConfidence {
    fn from(c: cf_audit::Confidence) -> Self {
        match c {
            cf_audit::Confidence::Low => Self::Low,
            cf_audit::Confidence::Medium => Self::Medium,
            cf_audit::Confidence::High => Self::High,
        }
    }
}

/// 单条体检 finding 的通用载荷：条目 + 解密标题（非敏感，展示用）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
}

impl From<cf_session::usecase::health::ItemFinding> for FfiItemFinding {
    fn from(f: cf_session::usecase::health::ItemFinding) -> Self {
        Self {
            item_id: f.item_id,
            title: f.title,
        }
    }
}

/// 重复密码组 finding（FR-6.2）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDuplicateGroupFinding {
    /// 共享同一密码指纹的条目 ID（≥2）。
    pub item_ids: Vec<String>,
    /// 与 `item_ids` 一一对应的解密标题。
    pub titles: Vec<String>,
}

impl From<cf_session::usecase::health::DuplicateGroupFinding> for FfiDuplicateGroupFinding {
    fn from(g: cf_session::usecase::health::DuplicateGroupFinding) -> Self {
        Self {
            item_ids: g.item_ids,
            titles: g.titles,
        }
    }
}

/// 陈旧密码 finding（FR-6.4）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiStaleFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
    /// 距上次修改的整天数（非敏感元数据，UI 展示用）。
    pub days_since_update: i64,
}

impl From<cf_session::usecase::health::StaleFinding> for FfiStaleFinding {
    fn from(f: cf_session::usecase::health::StaleFinding) -> Self {
        Self {
            item_id: f.item_id,
            title: f.title,
            days_since_update: f.days_since_update,
        }
    }
}

/// 泄露启发式 finding（FR-6.5，Should 非门禁；不覆盖真实泄露事件）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiLeakFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
    /// 命中规则。
    pub rule: FfiLeakRule,
    /// 置信度。
    pub confidence: FfiLeakConfidence,
}

impl From<cf_session::usecase::health::LeakFinding> for FfiLeakFinding {
    fn from(f: cf_session::usecase::health::LeakFinding) -> Self {
        Self {
            item_id: f.item_id,
            title: f.title,
            rule: f.rule.into(),
            confidence: f.confidence.into(),
        }
    }
}

/// 五类体检汇总统计（与 [`FfiHealthReport`] 各清单一一对应）。
///
/// usize → u32 饱和转换（`u32::try_from().unwrap_or(u32::MAX)`）：计数
/// 达 2^32 属不可达规模，不为此引入错误分支。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHealthSummary {
    /// 重复密码组数（FR-6.2，按组计）。
    pub duplicate_group_count: u32,
    /// 弱 URL 条目数（FR-6.3）。
    pub weak_url_count: u32,
    /// 陈旧密码条目数（FR-6.4）。
    pub stale_count: u32,
    /// 泄露启发式命中条目数（FR-6.5）。
    pub leak_suspect_count: u32,
    /// 无 2FA 提示条目数（FR-6.6）。
    pub missing_totp_count: u32,
    /// 各类计数的总和（重复组按组计）。
    pub total_findings: u32,
}

impl From<cf_session::usecase::health::HealthSummary> for FfiHealthSummary {
    fn from(s: cf_session::usecase::health::HealthSummary) -> Self {
        let saturate = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Self {
            duplicate_group_count: saturate(s.duplicate_group_count),
            weak_url_count: saturate(s.weak_url_count),
            stale_count: saturate(s.stale_count),
            leak_suspect_count: saturate(s.leak_suspect_count),
            missing_totp_count: saturate(s.missing_totp_count),
            total_findings: saturate(s.total_findings),
        }
    }
}

/// 五类体检报告（FR-6.7，覆盖 FR-6.2 / 6.3 / 6.4 / 6.5 / 6.6 镜像）。
///
/// 明文纪律：报告不携带密码明文与隐藏字段值（cf-session usecase::health
/// 模块文档），本镜像不引入任何新字段。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHealthReport {
    /// 共享同一密码指纹的分组（≥2 才报，FR-6.2）。
    pub duplicate_groups: Vec<FfiDuplicateGroupFinding>,
    /// 任一 URL 以 `http://` 开头的条目（FR-6.3）。
    pub http_url_items: Vec<FfiItemFinding>,
    /// 陈旧密码条目（FR-6.4）。
    pub stale_items: Vec<FfiStaleFinding>,
    /// 泄露启发式命中条目（FR-6.5，每条目至多一条）。
    pub leak_suspects: Vec<FfiLeakFinding>,
    /// 白名单域名且未配置 TOTP 的条目（FR-6.6）。
    pub missing_totp_items: Vec<FfiItemFinding>,
    /// 汇总统计。
    pub summary: FfiHealthSummary,
}

impl From<cf_session::usecase::health::HealthReport> for FfiHealthReport {
    fn from(r: cf_session::usecase::health::HealthReport) -> Self {
        Self {
            duplicate_groups: r.duplicate_groups.into_iter().map(Into::into).collect(),
            http_url_items: r.http_url_items.into_iter().map(Into::into).collect(),
            stale_items: r.stale_items.into_iter().map(Into::into).collect(),
            leak_suspects: r.leak_suspects.into_iter().map(Into::into).collect(),
            missing_totp_items: r.missing_totp_items.into_iter().map(Into::into).collect(),
            summary: r.summary.into(),
        }
    }
}

// ---------------------------------------------- 附件（FR-9.3 / 9.4，v0.4）

/// 附件元数据（docs/15 §3.1.2 冻结契约；镜像
/// `cf_session::AttachmentInfo`，时间戳恒 i64 Unix 秒）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAttachmentMeta {
    /// 附件行 UUID（旁路文件名同名）。
    pub attachment_uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// 文件名（解密后明文）。
    pub filename: String,
    /// 明文长度（字节；usize 不跨 FFI → i64）。
    pub size_bytes: i64,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

impl From<cf_session::AttachmentInfo> for FfiAttachmentMeta {
    fn from(info: cf_session::AttachmentInfo) -> Self {
        Self {
            attachment_uuid: info.uuid,
            item_uuid: info.item_uuid,
            filename: info.filename,
            size_bytes: info.size_bytes,
            created_at: info.created_at,
        }
    }
}

// ---------------------------------------------- Passkey（FR-10.2 / 10.5，v0.5）

/// Passkey 元数据（docs/17 §4.1 冻结契约镜像）。
///
/// **无私钥字段**——FR-10.2 红线：`enc_private_key` / `enc_user_handle`
/// 不出现在任何查询返回中，展示面结构上就不存在私钥材料。时间戳恒
/// `i64` Unix 秒；`usize` 不跨 FFI → 计数收窄为 `u32`。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskeyMeta {
    /// passkey 行 UUID（主键）。
    pub passkey_uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// Relying Party ID（解密后明文，如 `github.com`）。
    pub rp_id: String,
    /// RP 显示名（可选，解密后）。
    pub rp_name: Option<String>,
    /// 用户名（可选，解密后）。
    pub user_name: Option<String>,
    /// 凭据 ID（base64；非密钥，FR-10.2 允许展示）。
    pub credential_id_b64: String,
    /// COSE alg 编号（-7 = ES256）。
    pub algorithm: i32,
    /// 签名计数器。
    pub sign_count: u32,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
    /// 最后使用时间（Unix 秒；本版无断言路径，恒 `None`）。
    pub last_used_at: Option<i64>,
}

impl From<cf_store::PasskeyMeta> for FfiPasskeyMeta {
    fn from(m: cf_store::PasskeyMeta) -> Self {
        Self {
            passkey_uuid: m.uuid,
            item_uuid: m.item_uuid,
            rp_id: m.rp_id,
            rp_name: m.rp_name,
            user_name: m.user_name,
            credential_id_b64: m.credential_id_b64,
            algorithm: i32::try_from(m.algorithm).unwrap_or(i32::MIN),
            sign_count: u32::try_from(m.sign_count).unwrap_or(u32::MAX),
            created_at: m.created_at,
            last_used_at: m.last_used_at,
        }
    }
}

// ------------------------------------- Bitwarden 预检/导入（FR-10.1，v0.5）

/// 坏 passkey 行的结构化分类（L-2：#18 审查裁定——分类按数据不按文案，
/// reason 只是展示层，措辞漂移不迁移分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiBwPasskeyFailureKind {
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

impl From<cf_importer::BwPasskeyFailureKind> for FfiBwPasskeyFailureKind {
    fn from(k: cf_importer::BwPasskeyFailureKind) -> Self {
        match k {
            cf_importer::BwPasskeyFailureKind::KeyAlgorithmMismatch => Self::KeyAlgorithmMismatch,
            cf_importer::BwPasskeyFailureKind::KeyCurveMismatch => Self::KeyCurveMismatch,
            cf_importer::BwPasskeyFailureKind::MissingRpId => Self::MissingRpId,
            cf_importer::BwPasskeyFailureKind::InvalidCredentialId => Self::InvalidCredentialId,
            cf_importer::BwPasskeyFailureKind::InvalidCounter => Self::InvalidCounter,
            cf_importer::BwPasskeyFailureKind::MissingPrivateKey => Self::MissingPrivateKey,
            cf_importer::BwPasskeyFailureKind::EncryptedPrivateKey => Self::EncryptedPrivateKey,
            cf_importer::BwPasskeyFailureKind::UnparseablePrivateKey => Self::UnparseablePrivateKey,
        }
    }
}

/// 一条不可导入的 passkey 行（预检显式列出，FR-7.8 不静默丢弃）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBwPasskeyFailure {
    /// 所属条目 ID（Bitwarden 原始 id）。
    pub item_id: String,
    /// 所属条目标题。
    pub item_title: String,
    /// 行在该条目 `fido2Credentials[]` 中的下标（0 起；usize 不跨 FFI → u32）。
    pub index: u32,
    /// 结构化分类（程序判定唯一依据，L-2）。
    pub kind: FfiBwPasskeyFailureKind,
    /// 拒绝原因（人类可读，面向导入结果页；**不作分类依据**）。
    pub reason: String,
}

impl From<cf_importer::BwPasskeyFailure> for FfiBwPasskeyFailure {
    fn from(f: cf_importer::BwPasskeyFailure) -> Self {
        Self {
            item_id: f.item_id,
            item_title: f.item_title,
            index: u32::try_from(f.index).unwrap_or(u32::MAX),
            kind: f.kind.into(),
            reason: f.reason,
        }
    }
}

/// Bitwarden 预检报告（docs/17 §4.2 冻结语义镜像）。
///
/// 与 1PUX 预检同纪律：**报告与导入同一条管线产出**（FR-7.4 所见即所
/// 得），坏 passkey 行逐条列出、不静默丢弃（TCB-7）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBwPrecheckReport {
    /// 条目总数（含回收站 / 降级条目）。
    pub total_items: u32,
    /// 可导入条目数（降级计入导入成功，E-4 同纪律）。
    pub importable_items: u32,
    /// passkey 行总数（含不可导入行）。
    pub passkey_total: u32,
    /// 可导入 passkey 行数。
    pub passkey_importable: u32,
    /// 含 ≥ 1 条可导入 passkey 的条目数。
    pub passkey_item_count: u32,
    /// **「含密码且含 passkey 的条目数」**（FR-10.6 可测试证据，D-6）。
    pub items_with_password_and_passkey: u32,
    /// 非 ES256 passkey 行显式列表（TCB-7）。
    pub non_es256: Vec<FfiBwPasskeyFailure>,
    /// 其余坏 passkey 行逐条清单（EncString / 坏 credentialId / 缺 rpId /
    /// 负 counter；导入跳过该行不丢条目）。
    pub bad_passkeys: Vec<FfiBwPasskeyFailure>,
    /// 回收站条目数（deletedDate 非空）。
    pub trashed_count: u32,
    /// 丢弃的密码历史条目数（FR-2.9 语义不同构，1PUX 同裁决）。
    pub password_history_dropped: u32,
    /// 告警文本（未知 fido2 键、降级、坏 totp、Linked 字段跳过等）。
    pub warnings: Vec<String>,
}

impl From<cf_importer::BwPrecheckReport> for FfiBwPrecheckReport {
    fn from(r: cf_importer::BwPrecheckReport) -> Self {
        Self {
            total_items: r.total_items,
            importable_items: r.importable_items,
            passkey_total: r.passkey_total,
            passkey_importable: r.passkey_importable,
            passkey_item_count: r.passkey_item_count,
            items_with_password_and_passkey: r.items_with_password_and_passkey,
            non_es256: r.non_es256.into_iter().map(Into::into).collect(),
            bad_passkeys: r.bad_passkeys.into_iter().map(Into::into).collect(),
            trashed_count: r.trashed_count,
            password_history_dropped: r.password_history_dropped,
            warnings: r.warnings,
        }
    }
}

/// Bitwarden 导入结果（FR-10.1，与 1PUX 的 [`FfiPuxImportResult`] 同体裁：
/// 结果页计数 + 与本次导入同管线产出的预检报告）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiBwImportResult {
    /// 实际导入（新建）的条目数。
    pub imported_items: u32,
    /// 预检报告（FR-7.4 所见即所得同纪律）。
    pub report: FfiBwPrecheckReport,
}

impl From<cf_importer::BwImportResult> for FfiBwImportResult {
    fn from(r: cf_importer::BwImportResult) -> Self {
        Self {
            imported_items: r.imported_items,
            report: r.report.into(),
        }
    }
}
